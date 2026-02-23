package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cubeos-api/internal/circuitbreaker"
	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/middleware"

	"github.com/rs/zerolog/log"
)

// CircuitBreakerAccessor provides named access to a circuit breaker's state.
type CircuitBreakerAccessor struct {
	Name      string
	StateFunc func() circuitbreaker.State
}

// MetricsHandler serves Prometheus-format metrics at GET /api/v1/metrics.
type MetricsHandler struct {
	collector     *middleware.MetricsCollector
	breakers      []CircuitBreakerAccessor
	workflowStore *flowengine.WorkflowStore
	swarmMgr      *managers.SwarmManager
}

// NewMetricsHandler creates a handler wired to the metrics collector and system state accessors.
func NewMetricsHandler(
	collector *middleware.MetricsCollector,
	breakers []CircuitBreakerAccessor,
	workflowStore *flowengine.WorkflowStore,
	swarmMgr *managers.SwarmManager,
) *MetricsHandler {
	return &MetricsHandler{
		collector:     collector,
		breakers:      breakers,
		workflowStore: workflowStore,
		swarmMgr:      swarmMgr,
	}
}

// cbStates enumerates the possible circuit breaker states for gauge emission.
var cbStates = []string{"closed", "open", "half_open"}

// cbStateLabel normalizes circuitbreaker.State.String() for Prometheus labels.
// Converts "half-open" to "half_open" (Prometheus convention).
func cbStateLabel(s circuitbreaker.State) string {
	return strings.ReplaceAll(s.String(), "-", "_")
}

// GetMetrics godoc
// @Summary Prometheus metrics
// @Description Returns system metrics in Prometheus text exposition format. Includes HTTP request counters, latency histograms, circuit breaker states, active workflow counts, and Docker service health. No authentication required (designed for Prometheus scraping).
// @Tags Metrics
// @Produce text/plain
// @Success 200 {string} string "Prometheus metrics in text exposition format"
// @Router /metrics [get]
func (h *MetricsHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	counts, hists := h.collector.Snapshot()

	// --- 1. cubeos_http_requests_total (counter) ---
	fmt.Fprintf(w, "# HELP cubeos_http_requests_total Total number of HTTP requests.\n")
	fmt.Fprintf(w, "# TYPE cubeos_http_requests_total counter\n")
	for _, c := range counts {
		fmt.Fprintf(w, "cubeos_http_requests_total{method=%q,path=%q,status=%q} %d\n",
			c.Method, c.Path, c.Status, c.Count)
	}

	// --- 2. cubeos_http_duration_seconds (histogram) ---
	fmt.Fprintf(w, "# HELP cubeos_http_duration_seconds Duration of HTTP requests in seconds.\n")
	fmt.Fprintf(w, "# TYPE cubeos_http_duration_seconds histogram\n")
	for _, hs := range hists {
		for i, bound := range hs.Buckets {
			fmt.Fprintf(w, "cubeos_http_duration_seconds_bucket{method=%q,path=%q,le=%q} %d\n",
				hs.Method, hs.Path, formatFloat(bound), hs.Counts[i])
		}
		fmt.Fprintf(w, "cubeos_http_duration_seconds_bucket{method=%q,path=%q,le=\"+Inf\"} %d\n",
			hs.Method, hs.Path, hs.Count)
		fmt.Fprintf(w, "cubeos_http_duration_seconds_sum{method=%q,path=%q} %g\n",
			hs.Method, hs.Path, hs.Sum)
		fmt.Fprintf(w, "cubeos_http_duration_seconds_count{method=%q,path=%q} %d\n",
			hs.Method, hs.Path, hs.Count)
	}

	// --- 3. cubeos_circuit_breaker_state (gauge) ---
	fmt.Fprintf(w, "# HELP cubeos_circuit_breaker_state Current circuit breaker state (1 = active state).\n")
	fmt.Fprintf(w, "# TYPE cubeos_circuit_breaker_state gauge\n")
	for _, cb := range h.breakers {
		current := cbStateLabel(cb.StateFunc())
		for _, state := range cbStates {
			val := 0
			if state == current {
				val = 1
			}
			fmt.Fprintf(w, "cubeos_circuit_breaker_state{name=%q,state=%q} %d\n",
				cb.Name, state, val)
		}
	}

	// --- 4. cubeos_workflow_active (gauge) ---
	fmt.Fprintf(w, "# HELP cubeos_workflow_active Number of active (non-terminal) workflows.\n")
	fmt.Fprintf(w, "# TYPE cubeos_workflow_active gauge\n")
	h.writeWorkflowMetrics(w)

	// --- 5 & 6. cubeos_docker_services_total / cubeos_docker_services_healthy (gauge) ---
	fmt.Fprintf(w, "# HELP cubeos_docker_services_total Total number of Docker Swarm services.\n")
	fmt.Fprintf(w, "# TYPE cubeos_docker_services_total gauge\n")
	fmt.Fprintf(w, "# HELP cubeos_docker_services_healthy Swarm services with all replicas running.\n")
	fmt.Fprintf(w, "# TYPE cubeos_docker_services_healthy gauge\n")
	h.writeDockerMetrics(w)
}

// writeWorkflowMetrics queries active workflows and groups by (type, state).
func (h *MetricsHandler) writeWorkflowMetrics(w http.ResponseWriter) {
	if h.workflowStore == nil {
		return
	}

	workflows, err := h.workflowStore.GetIncompleteWorkflows()
	if err != nil {
		log.Warn().Err(err).Msg("metrics: failed to query active workflows")
		return
	}

	// Group by (workflow_type, current_state)
	type wfKey struct{ typ, state string }
	grouped := make(map[wfKey]int)
	for _, wf := range workflows {
		k := wfKey{typ: wf.WorkflowType, state: string(wf.CurrentState)}
		grouped[k]++
	}

	for k, count := range grouped {
		fmt.Fprintf(w, "cubeos_workflow_active{type=%q,state=%q} %d\n",
			k.typ, k.state, count)
	}
}

// writeDockerMetrics queries Swarm services for total/healthy counts.
func (h *MetricsHandler) writeDockerMetrics(w http.ResponseWriter) {
	if h.swarmMgr == nil {
		fmt.Fprintf(w, "cubeos_docker_services_total 0\n")
		fmt.Fprintf(w, "cubeos_docker_services_healthy 0\n")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	total, healthy, err := h.swarmMgr.GetServiceCounts(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("metrics: failed to query Docker services")
		fmt.Fprintf(w, "cubeos_docker_services_total 0\n")
		fmt.Fprintf(w, "cubeos_docker_services_healthy 0\n")
		return
	}

	fmt.Fprintf(w, "cubeos_docker_services_total %d\n", total)
	fmt.Fprintf(w, "cubeos_docker_services_healthy %d\n", healthy)
}

// formatFloat renders a float without trailing zeros (Prometheus le convention).
func formatFloat(f float64) string {
	return fmt.Sprintf("%g", f)
}
