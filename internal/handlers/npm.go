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
	r.Put("/hosts/{id}", h.UpdateHost)
	r.Delete("/hosts/{id}", h.DeleteHost)
	r.Get("/certificates", h.ListCertificates)
	r.Delete("/certificates/{id}", h.DeleteCertificate)
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

// CreateProxyHostRequest for creating/updating proxy hosts
type CreateProxyHostRequest struct {
	DomainNames    []string `json:"domain_names"`
	ForwardHost    string   `json:"forward_host"`
	ForwardPort    int      `json:"forward_port"`
	ForwardScheme  string   `json:"forward_scheme"`
	SSLForced      bool     `json:"ssl_forced"`
	CertificateID  int      `json:"certificate_id"`
	CachingEnabled bool     `json:"caching_enabled"`
	BlockExploits  bool     `json:"block_exploits"`
	AdvancedConfig string   `json:"advanced_config"`
}

// GetStatus godoc
// @Summary Get NPM service status
// @Description Returns Nginx Proxy Manager service status including health, authentication state, and proxy host count
// @Tags NPM
// @Produce json
// @Security BearerAuth
// @Success 200 {object} NPMStatus "NPM status with online, authenticated, version, host_count, base_url"
// @Router /npm/status [get]
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

// GetHosts godoc
// @Summary List NPM proxy hosts
// @Description Returns all configured Nginx Proxy Manager proxy hosts
// @Tags NPM
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "hosts: array of proxy host configurations"
// @Failure 500 {object} ErrorResponse "Failed to fetch NPM hosts"
// @Failure 503 {object} ErrorResponse "NPM authentication not configured"
// @Router /npm/hosts [get]
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

// CreateHost godoc
// @Summary Create NPM proxy host
// @Description Creates a new Nginx Proxy Manager proxy host with domain routing, forwarding, SSL, and caching options
// @Tags NPM
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateProxyHostRequest true "Proxy host configuration"
// @Success 201 {object} managers.NPMProxyHostExtended "Created proxy host"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to create proxy host"
// @Failure 503 {object} ErrorResponse "NPM authentication not configured"
// @Router /npm/hosts [post]
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
		CertificateID:  req.CertificateID,
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

// DeleteHost godoc
// @Summary Delete NPM proxy host
// @Description Deletes an Nginx Proxy Manager proxy host by ID
// @Tags NPM
// @Security BearerAuth
// @Param id path integer true "Proxy host ID"
// @Success 204 "Proxy host deleted successfully"
// @Failure 400 {object} ErrorResponse "Host ID required or invalid"
// @Failure 500 {object} ErrorResponse "Failed to delete proxy host"
// @Failure 503 {object} ErrorResponse "NPM authentication not configured"
// @Router /npm/hosts/{id} [delete]
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

// UpdateHost godoc
// @Summary Update NPM proxy host
// @Description Updates an existing Nginx Proxy Manager proxy host by ID
// @Tags NPM
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path integer true "Proxy host ID"
// @Param request body CreateProxyHostRequest true "Updated proxy host configuration"
// @Success 200 {object} managers.NPMProxyHostExtended "Updated proxy host"
// @Failure 400 {object} ErrorResponse "Invalid request body or host ID"
// @Failure 500 {object} ErrorResponse "Failed to update proxy host"
// @Failure 503 {object} ErrorResponse "NPM authentication not configured"
// @Router /npm/hosts/{id} [put]
func (h *NPMHandler) UpdateHost(w http.ResponseWriter, r *http.Request) {
	if !h.npmManager.IsAuthenticated() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "NPM authentication not configured",
		})
		return
	}

	idStr := chi.URLParam(r, "id")
	var id int
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid host ID",
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

	host := &managers.NPMProxyHostExtended{
		DomainNames:    req.DomainNames,
		ForwardHost:    req.ForwardHost,
		ForwardPort:    req.ForwardPort,
		ForwardScheme:  req.ForwardScheme,
		CertificateID:  req.CertificateID,
		SSLForced:      req.SSLForced,
		CachingEnabled: req.CachingEnabled,
		BlockExploits:  req.BlockExploits,
		AdvancedConfig: req.AdvancedConfig,
	}

	updated, err := h.npmManager.UpdateProxyHost(id, host)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Failed to update proxy host: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

// ListCertificates godoc
// @Summary List NPM certificates
// @Description Returns all certificates configured in Nginx Proxy Manager
// @Tags NPM
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "certificates: array of certificate objects"
// @Failure 500 {object} ErrorResponse "Failed to fetch certificates"
// @Failure 503 {object} ErrorResponse "NPM authentication not configured"
// @Router /npm/certificates [get]
func (h *NPMHandler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	if !h.npmManager.IsAuthenticated() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "NPM authentication not configured",
		})
		return
	}

	certs, err := h.npmManager.ListCertificates()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Failed to fetch certificates: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"certificates": certs,
	})
}

// DeleteCertificate godoc
// @Summary Delete NPM certificate
// @Description Deletes a certificate from Nginx Proxy Manager by ID
// @Tags NPM
// @Security BearerAuth
// @Param id path integer true "Certificate ID"
// @Success 204 "Certificate deleted successfully"
// @Failure 400 {object} ErrorResponse "Certificate ID required or invalid"
// @Failure 500 {object} ErrorResponse "Failed to delete certificate"
// @Failure 503 {object} ErrorResponse "NPM authentication not configured"
// @Router /npm/certificates/{id} [delete]
func (h *NPMHandler) DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.npmManager.IsAuthenticated() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "NPM authentication not configured",
		})
		return
	}

	idStr := chi.URLParam(r, "id")
	var id int
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid certificate ID",
		})
		return
	}

	if err := h.npmManager.DeleteCertificate(id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Failed to delete certificate: %v", err),
		})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
