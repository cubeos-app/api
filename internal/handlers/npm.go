// internal/handlers/npm.go
// NPM (Nginx Proxy Manager) API handlers
// Uses NPMManager for service account authentication

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"cubeos-api/internal/managers"
	"github.com/go-chi/chi/v5"
)

// NPMHandler handles NPM-related API requests
type NPMHandler struct {
	npmManager *managers.NPMManager
}

// NewNPMHandler creates a new NPM handler
func NewNPMHandler(npmManager *managers.NPMManager) *NPMHandler {
	return &NPMHandler{
		npmManager: npmManager,
	}
}

// Routes returns the NPM routes
func (h *NPMHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/status", h.GetStatus)
	r.Get("/hosts", h.GetHosts)
	r.Post("/hosts", h.CreateHost)
	r.Delete("/hosts/{id}", h.DeleteHost)
	return r
}

// NPMStatus represents NPM service status
type NPMStatus struct {
	Online        bool   `json:"online"`
	Authenticated bool   `json:"authenticated"`
	Version       string `json:"version"`
	HostCount     int    `json:"host_count"`
	BaseURL       string `json:"base_url"`
}

// CreateProxyHostRequest for creating new proxy hosts
type CreateProxyHostRequest struct {
	DomainNames    []string `json:"domain_names"`
	ForwardHost    string   `json:"forward_host"`
	ForwardPort    int      `json:"forward_port"`
	ForwardScheme  string   `json:"forward_scheme"`
	SSLForced      bool     `json:"ssl_forced"`
	CachingEnabled bool     `json:"caching_enabled"`
	BlockExploits  bool     `json:"block_exploits"`
	AdvancedConfig string   `json:"advanced_config"`
}

// GetStatus returns NPM service status
func (h *NPMHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := NPMStatus{
		Online:        h.npmManager.IsHealthy(),
		Authenticated: h.npmManager.IsAuthenticated(),
		BaseURL:       h.npmManager.GetBaseURL(),
		Version:       "2.x",
	}

	// Get host count if authenticated
	if status.Authenticated {
		hosts, err := h.npmManager.ListProxyHosts()
		if err == nil {
			status.HostCount = len(hosts)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// GetHosts returns all NPM proxy hosts
func (h *NPMHandler) GetHosts(w http.ResponseWriter, r *http.Request) {
	if !h.npmManager.IsAuthenticated() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "NPM authentication not configured",
		})
		return
	}

	hosts, err := h.npmManager.ListProxyHosts()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Failed to fetch NPM hosts: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts": hosts,
	})
}

// CreateHost creates a new NPM proxy host
func (h *NPMHandler) CreateHost(w http.ResponseWriter, r *http.Request) {
	if !h.npmManager.IsAuthenticated() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "NPM authentication not configured",
		})
		return
	}

	var req CreateProxyHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid request body",
		})
		return
	}

	// Convert to NPMProxyHostExtended
	host := &managers.NPMProxyHostExtended{
		DomainNames:    req.DomainNames,
		ForwardHost:    req.ForwardHost,
		ForwardPort:    req.ForwardPort,
		ForwardScheme:  req.ForwardScheme,
		SSLForced:      req.SSLForced,
		CachingEnabled: req.CachingEnabled,
		BlockExploits:  req.BlockExploits,
		AdvancedConfig: req.AdvancedConfig,
	}

	created, err := h.npmManager.CreateProxyHost(host)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Failed to create proxy host: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

// DeleteHost deletes an NPM proxy host
func (h *NPMHandler) DeleteHost(w http.ResponseWriter, r *http.Request) {
	if !h.npmManager.IsAuthenticated() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "NPM authentication not configured",
		})
		return
	}

	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Host ID required",
		})
		return
	}

	var id int
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid host ID",
		})
		return
	}

	if err := h.npmManager.DeleteProxyHost(id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Failed to delete proxy host: %v", err),
		})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
