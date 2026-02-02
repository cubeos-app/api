package handlers

import (
	"encoding/json"
	"net/http"

	"cubeos-api/internal/managers"

	"github.com/go-chi/chi/v5"
)

// NPMHandler handles NPM-related API endpoints
type NPMHandler struct {
	npm *managers.NPMManager
}

// NewNPMHandler creates a new NPM handler
func NewNPMHandler(npm *managers.NPMManager) *NPMHandler {
	return &NPMHandler{npm: npm}
}

// Routes returns the router for NPM endpoints
func (h *NPMHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/status", h.GetStatus)
	r.Get("/hosts", h.ListHosts)

	return r
}

// NPMStatusResponse represents the NPM status response
type NPMStatusResponse struct {
	Healthy   bool   `json:"healthy"`
	URL       string `json:"url"`
	Message   string `json:"message,omitempty"`
	HostCount int    `json:"host_count,omitempty"`
}

// NPMHostResponse represents a simplified proxy host for the API
type NPMHostResponse struct {
	ID            int      `json:"id"`
	DomainNames   []string `json:"domain_names"`
	ForwardHost   string   `json:"forward_host"`
	ForwardPort   int      `json:"forward_port"`
	ForwardScheme string   `json:"forward_scheme"`
	SSLForced     bool     `json:"ssl_forced"`
	Enabled       bool     `json:"enabled"`
	CreatedOn     string   `json:"created_on,omitempty"`
	ModifiedOn    string   `json:"modified_on,omitempty"`
}

// GetStatus returns NPM health and status
// GET /api/v1/npm/status
func (h *NPMHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	healthy := h.npm.IsHealthy()

	status := NPMStatusResponse{
		Healthy: healthy,
		URL:     "http://10.42.24.1:81", // NPM admin URL
	}

	if healthy {
		status.Message = "NPM is running and accessible"
		// Try to get host count
		if hosts, err := h.npm.ListProxyHosts(); err == nil {
			status.HostCount = len(hosts)
		}
	} else {
		status.Message = "NPM is not accessible or not authenticated"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// ListHosts returns all NPM proxy hosts
// GET /api/v1/npm/hosts
func (h *NPMHandler) ListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.npm.ListProxyHosts()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to retrieve proxy hosts: " + err.Error(),
		})
		return
	}

	// Convert to simplified response
	response := make([]NPMHostResponse, len(hosts))
	for i, host := range hosts {
		response[i] = NPMHostResponse{
			ID:            host.ID,
			DomainNames:   host.DomainNames,
			ForwardHost:   host.ForwardHost,
			ForwardPort:   host.ForwardPort,
			ForwardScheme: host.ForwardScheme,
			SSLForced:     host.SSLForced,
			Enabled:       bool(host.Enabled),
			CreatedOn:     host.CreatedOn,
			ModifiedOn:    host.ModifiedOn,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts": response,
		"total": len(response),
	})
}
