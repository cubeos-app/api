package api

import (
	"bufio"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/nuclearlighters/cubeos/internal/docker"
)

// ServicesHandler handles container/service-related API endpoints.
type ServicesHandler struct {
	docker *docker.Manager
}

// NewServicesHandler creates a new ServicesHandler.
func NewServicesHandler(dockerManager *docker.Manager) *ServicesHandler {
	return &ServicesHandler{
		docker: dockerManager,
	}
}

// List handles GET /api/v1/services
// Returns all containers with their status.
func (h *ServicesHandler) List(w http.ResponseWriter, r *http.Request) {
	// Query param: all=true to include stopped containers
	all := r.URL.Query().Get("all") == "true"

	containers, err := h.docker.ListContainers(r.Context(), all)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list containers")
		writeError(w, http.StatusInternalServerError, "Failed to list containers")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"services": containers,
		"count":    len(containers),
	})
}

// Get handles GET /api/v1/services/{name}
// Returns detailed information about a single container.
func (h *ServicesHandler) Get(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	container, err := h.docker.GetContainer(r.Context(), name)
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to get container")
		writeError(w, http.StatusNotFound, "Service not found: "+name)
		return
	}

	writeJSON(w, http.StatusOK, container)
}

// Start handles POST /api/v1/services/{name}/start
// Starts a stopped container.
func (h *ServicesHandler) Start(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	// Check if it's a core service
	container, err := h.docker.GetContainer(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Service not found: "+name)
		return
	}

	log.Info().Str("name", name).Msg("Starting service")

	if err := h.docker.StartContainer(r.Context(), name); err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to start container")
		writeError(w, http.StatusInternalServerError, "Failed to start service: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Service started",
		"service": name,
		"is_core": container.IsCore,
	})
}

// Stop handles POST /api/v1/services/{name}/stop
// Stops a running container.
func (h *ServicesHandler) Stop(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	// Check if it's a core service
	container, err := h.docker.GetContainer(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Service not found: "+name)
		return
	}

	// Warn but don't prevent stopping core services (admin override)
	if container.IsCore {
		log.Warn().Str("name", name).Msg("Stopping core service - this may affect system stability")
	}

	// Parse optional timeout from query params (default 30s)
	timeout := 30 * time.Second
	if t := r.URL.Query().Get("timeout"); t != "" {
		if secs, err := strconv.Atoi(t); err == nil {
			timeout = time.Duration(secs) * time.Second
		}
	}

	log.Info().Str("name", name).Dur("timeout", timeout).Msg("Stopping service")

	if err := h.docker.StopContainer(r.Context(), name, timeout); err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to stop container")
		writeError(w, http.StatusInternalServerError, "Failed to stop service: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Service stopped",
		"service": name,
		"is_core": container.IsCore,
	})
}

// Restart handles POST /api/v1/services/{name}/restart
// Restarts a container.
func (h *ServicesHandler) Restart(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	container, err := h.docker.GetContainer(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Service not found: "+name)
		return
	}

	timeout := 30 * time.Second
	if t := r.URL.Query().Get("timeout"); t != "" {
		if secs, err := strconv.Atoi(t); err == nil {
			timeout = time.Duration(secs) * time.Second
		}
	}

	log.Info().Str("name", name).Dur("timeout", timeout).Msg("Restarting service")

	if err := h.docker.RestartContainer(r.Context(), name, timeout); err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to restart container")
		writeError(w, http.StatusInternalServerError, "Failed to restart service: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Service restarted",
		"service": name,
		"is_core": container.IsCore,
	})
}

// Logs handles GET /api/v1/services/{name}/logs
// Returns container logs.
func (h *ServicesHandler) Logs(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	// Parse query parameters
	opts := docker.LogOptions{
		Tail:       r.URL.Query().Get("tail"),
		Since:      r.URL.Query().Get("since"),
		Until:      r.URL.Query().Get("until"),
		Timestamps: r.URL.Query().Get("timestamps") == "true",
		Follow:     false, // Streaming not implemented yet
	}

	// Default to last 100 lines if not specified
	if opts.Tail == "" {
		opts.Tail = "100"
	}

	logs, err := h.docker.GetContainerLogs(r.Context(), name, opts)
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to get container logs")
		writeError(w, http.StatusInternalServerError, "Failed to get logs: "+err.Error())
		return
	}
	defer logs.Close()

	// Read logs and strip Docker multiplexing header (first 8 bytes per line)
	var lines []string
	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Docker log lines have 8-byte header when attached
		if len(line) > 8 {
			lines = append(lines, string(line[8:]))
		} else {
			lines = append(lines, string(line))
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"service": name,
		"logs":    lines,
		"count":   len(lines),
	})
}

// Stats handles GET /api/v1/services/{name}/stats
// Returns container resource usage statistics.
func (h *ServicesHandler) Stats(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Service name is required")
		return
	}

	stats, err := h.docker.GetContainerStats(r.Context(), name)
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("Failed to get container stats")
		writeError(w, http.StatusInternalServerError, "Failed to get stats: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"service": name,
		"stats":   stats,
	})
}

// Status handles GET /api/v1/services/status
// Returns a quick status overview of all services.
func (h *ServicesHandler) Status(w http.ResponseWriter, r *http.Request) {
	containers, err := h.docker.ListContainers(r.Context(), true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list containers")
		return
	}

	// Build status map: name -> state
	status := make(map[string]string)
	running := 0
	stopped := 0

	for _, c := range containers {
		status[c.Name] = c.State
		if c.State == "running" {
			running++
		} else {
			stopped++
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  status,
		"running": running,
		"stopped": stopped,
		"total":   len(containers),
	})
}
