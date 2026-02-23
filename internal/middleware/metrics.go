package middleware

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Default histogram buckets for HTTP request duration (seconds).
var defaultBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}

// requestKey identifies a unique counter label combination.
type requestKey struct {
	Method string
	Path   string
	Status string
}

// histogramKey identifies a unique histogram label combination.
type histogramKey struct {
	Method string
	Path   string
}

// histogramData holds cumulative bucket counts and totals.
type histogramData struct {
	Counts []uint64 // cumulative count per bucket boundary
	Sum    float64
	Count  uint64
}

// MetricsCollector records HTTP request counts and latency histograms.
// All methods are safe for concurrent use.
type MetricsCollector struct {
	mu        sync.Mutex
	requests  map[requestKey]uint64
	durations map[histogramKey]*histogramData
	buckets   []float64
}

// NewMetricsCollector creates a ready-to-use collector with default buckets.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		requests:  make(map[requestKey]uint64),
		durations: make(map[histogramKey]*histogramData),
		buckets:   defaultBuckets,
	}
}

// statusWriter captures the HTTP status code written by downstream handlers.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if !sw.written {
		sw.status = code
		sw.written = true
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.written {
		sw.status = http.StatusOK
		sw.written = true
	}
	return sw.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying ResponseWriter for http.ResponseController.
func (sw *statusWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}

// Flush forwards flush calls (required for SSE streaming).
func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware returns a chi middleware that records request metrics.
// Skips recording for /api/v1/metrics to avoid self-referential inflation.
func (mc *MetricsCollector) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()

			next.ServeHTTP(sw, r)

			duration := time.Since(start).Seconds()
			path := normalizeRoutePath(r)
			status := fmt.Sprintf("%d", sw.status)

			mc.record(r.Method, path, status, duration)
		})
	}
}

// record adds one observation to the counter and histogram maps.
func (mc *MetricsCollector) record(method, path, status string, duration float64) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	rk := requestKey{Method: method, Path: path, Status: status}
	mc.requests[rk]++

	hk := histogramKey{Method: method, Path: path}
	hd, ok := mc.durations[hk]
	if !ok {
		hd = &histogramData{
			Counts: make([]uint64, len(mc.buckets)),
		}
		mc.durations[hk] = hd
	}
	// Cumulative: increment every bucket whose boundary >= observation
	for i, bound := range mc.buckets {
		if duration <= bound {
			hd.Counts[i]++
		}
	}
	hd.Sum += duration
	hd.Count++
}

// normalizeRoutePath extracts the chi route pattern and converts {param} to :param.
// Falls back to "unmatched" for requests that didn't match any route (404).
func normalizeRoutePath(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx != nil {
		pattern := rctx.RoutePattern()
		if pattern != "" {
			return convertChiPattern(pattern)
		}
	}
	return "unmatched"
}

// convertChiPattern converts chi-style {param} to Prometheus-friendly :param.
func convertChiPattern(pattern string) string {
	var b strings.Builder
	b.Grow(len(pattern))
	for _, c := range pattern {
		switch {
		case c == '{':
			b.WriteByte(':')
		case c == '}':
			// skip closing brace
		default:
			b.WriteRune(c)
		}
	}
	// Remove trailing slash for consistency (except root)
	result := b.String()
	if len(result) > 1 && result[len(result)-1] == '/' {
		result = result[:len(result)-1]
	}
	return result
}

// RequestCount holds a single counter data point for snapshotting.
type RequestCount struct {
	Method string
	Path   string
	Status string
	Count  uint64
}

// HistogramSnapshot holds a single histogram series for snapshotting.
type HistogramSnapshot struct {
	Method  string
	Path    string
	Buckets []float64
	Counts  []uint64
	Sum     float64
	Count   uint64
}

// Snapshot returns a consistent, sorted copy of all collected metrics.
func (mc *MetricsCollector) Snapshot() ([]RequestCount, []HistogramSnapshot) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	counts := make([]RequestCount, 0, len(mc.requests))
	for k, v := range mc.requests {
		counts = append(counts, RequestCount{
			Method: k.Method, Path: k.Path, Status: k.Status, Count: v,
		})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Path != counts[j].Path {
			return counts[i].Path < counts[j].Path
		}
		if counts[i].Method != counts[j].Method {
			return counts[i].Method < counts[j].Method
		}
		return counts[i].Status < counts[j].Status
	})

	hists := make([]HistogramSnapshot, 0, len(mc.durations))
	for k, v := range mc.durations {
		bucketsCopy := make([]float64, len(mc.buckets))
		copy(bucketsCopy, mc.buckets)
		countsCopy := make([]uint64, len(v.Counts))
		copy(countsCopy, v.Counts)
		hists = append(hists, HistogramSnapshot{
			Method:  k.Method,
			Path:    k.Path,
			Buckets: bucketsCopy,
			Counts:  countsCopy,
			Sum:     v.Sum,
			Count:   v.Count,
		})
	}
	sort.Slice(hists, func(i, j int) bool {
		if hists[i].Path != hists[j].Path {
			return hists[i].Path < hists[j].Path
		}
		return hists[i].Method < hists[j].Method
	})

	return counts, hists
}
