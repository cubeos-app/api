// internal/handlers/fqdns.go
// Sprint 4B: FQDN Management API
// Manages DNS entries and reverse proxy mappings

package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// FQDNsHandler handles FQDN management endpoints
type FQDNsHandler struct {
	db     *sql.DB
	npm    NPMClient
	pihole PiholeClient
}

// NPMClient interface for Nginx Proxy Manager operations
type NPMClient interface {
	CreateProxyHost(subdomain string, backendPort int) (int, error)
	DeleteProxyHost(proxyID int) error
}

// PiholeClient interface for Pi-hole DNS operations
type PiholeClient interface {
	AddDNSRecord(fqdn, ip string) error
	DeleteDNSRecord(fqdn string) error
}

// FQDN represents a DNS entry with proxy mapping
type FQDN struct {
	ID          int64     `json:"id"`
	AppID       int64     `json:"app_id"`
	AppName     string    `json:"app_name,omitempty"`
	FQDN        string    `json:"fqdn"`
	Subdomain   string    `json:"subdomain"`
	BackendPort int       `json:"backend_port"`
	SSLEnabled  bool      `json:"ssl_enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateFQDNRequest represents a request to create an FQDN
type CreateFQDNRequest struct {
	AppID       int64  `json:"app_id"`
	Subdomain   string `json:"subdomain"`
	BackendPort int    `json:"backend_port"`
	SSLEnabled  bool   `json:"ssl_enabled"`
}

// UpdateFQDNRequest represents a request to update an FQDN
type UpdateFQDNRequest struct {
	BackendPort *int  `json:"backend_port,omitempty"`
	SSLEnabled  *bool `json:"ssl_enabled,omitempty"`
}

// NewFQDNsHandler creates a new FQDNs handler
func NewFQDNsHandler(db *sql.DB, npm NPMClient, pihole PiholeClient) *FQDNsHandler {
	return &FQDNsHandler{
		db:     db,
		npm:    npm,
		pihole: pihole,
	}
}

// Routes returns the router for FQDN endpoints
func (h *FQDNsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListFQDNs)
	r.Post("/", h.CreateFQDN)
	r.Get("/{fqdn}", h.GetFQDN)
	r.Put("/{fqdn}", h.UpdateFQDN)
	r.Delete("/{fqdn}", h.DeleteFQDN)

	return r
}

// ListFQDNs returns all FQDNs
func (h *FQDNsHandler) ListFQDNs(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT f.id, f.app_id, COALESCE(a.name, '') as app_name,
		       f.fqdn, f.subdomain, f.backend_port, f.ssl_enabled, f.created_at
		FROM fqdns f
		LEFT JOIN apps a ON f.app_id = a.id
		ORDER BY f.subdomain
	`

	rows, err := h.db.Query(query)
	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query FQDNs: %v", err))
		return
	}
	defer rows.Close()

	fqdns := []FQDN{}
	for rows.Next() {
		var f FQDN
		err := rows.Scan(&f.ID, &f.AppID, &f.AppName, &f.FQDN, &f.Subdomain,
			&f.BackendPort, &f.SSLEnabled, &f.CreatedAt)
		if err != nil {
			fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to scan FQDN: %v", err))
			return
		}
		fqdns = append(fqdns, f)
	}

	// Get stats
	var total int
	h.db.QueryRow("SELECT COUNT(*) FROM fqdns").Scan(&total)

	var withSSL int
	h.db.QueryRow("SELECT COUNT(*) FROM fqdns WHERE ssl_enabled = 1").Scan(&withSSL)

	fqdnRespondJSON(w, http.StatusOK, map[string]interface{}{
		"fqdns": fqdns,
		"stats": map[string]interface{}{
			"total":         total,
			"with_ssl":      withSSL,
			"without_ssl":   total - withSSL,
			"domain_suffix": ".cubeos.cube",
		},
	})
}

// GetFQDN returns a single FQDN by its full domain name
func (h *FQDNsHandler) GetFQDN(w http.ResponseWriter, r *http.Request) {
	fqdnParam := chi.URLParam(r, "fqdn")

	query := `
		SELECT f.id, f.app_id, COALESCE(a.name, '') as app_name,
		       f.fqdn, f.subdomain, f.backend_port, f.ssl_enabled, f.created_at
		FROM fqdns f
		LEFT JOIN apps a ON f.app_id = a.id
		WHERE f.fqdn = ? OR f.subdomain = ?
	`

	var f FQDN
	err := h.db.QueryRow(query, fqdnParam, fqdnParam).Scan(
		&f.ID, &f.AppID, &f.AppName, &f.FQDN, &f.Subdomain,
		&f.BackendPort, &f.SSLEnabled, &f.CreatedAt)

	if err == sql.ErrNoRows {
		fqdnRespondError(w, http.StatusNotFound, "FQDN not found")
		return
	}
	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query FQDN: %v", err))
		return
	}

	fqdnRespondJSON(w, http.StatusOK, f)
}

// CreateFQDN creates a new FQDN entry
func (h *FQDNsHandler) CreateFQDN(w http.ResponseWriter, r *http.Request) {
	var req CreateFQDNRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fqdnRespondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Validate subdomain
	req.Subdomain = strings.ToLower(strings.TrimSpace(req.Subdomain))
	if req.Subdomain == "" {
		fqdnRespondError(w, http.StatusBadRequest, "Subdomain is required")
		return
	}

	// Validate subdomain format (alphanumeric and hyphens only)
	for _, c := range req.Subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			fqdnRespondError(w, http.StatusBadRequest, "Subdomain can only contain lowercase letters, numbers, and hyphens")
			return
		}
	}

	// Validate backend port
	if req.BackendPort < 1 || req.BackendPort > 65535 {
		fqdnRespondError(w, http.StatusBadRequest, "Backend port must be between 1 and 65535")
		return
	}

	// Validate app exists if app_id provided
	if req.AppID > 0 {
		var exists int
		err := h.db.QueryRow("SELECT COUNT(*) FROM apps WHERE id = ?", req.AppID).Scan(&exists)
		if err != nil || exists == 0 {
			fqdnRespondError(w, http.StatusBadRequest, "App not found")
			return
		}
	}

	// Build full FQDN
	fullFQDN := fmt.Sprintf("%s.cubeos.cube", req.Subdomain)

	// Check for duplicates
	var count int
	h.db.QueryRow("SELECT COUNT(*) FROM fqdns WHERE fqdn = ? OR subdomain = ?",
		fullFQDN, req.Subdomain).Scan(&count)
	if count > 0 {
		fqdnRespondError(w, http.StatusConflict, fmt.Sprintf("FQDN %s already exists", fullFQDN))
		return
	}

	// Insert into database
	result, err := h.db.Exec(`
		INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port, ssl_enabled)
		VALUES (?, ?, ?, ?, ?)
	`, req.AppID, fullFQDN, req.Subdomain, req.BackendPort, req.SSLEnabled)

	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create FQDN: %v", err))
		return
	}

	id, _ := result.LastInsertId()

	// Create NPM proxy host if client available
	if h.npm != nil {
		_, err := h.npm.CreateProxyHost(req.Subdomain, req.BackendPort)
		if err != nil {
			// Log but don't fail - FQDN is created
			fmt.Printf("Warning: Failed to create NPM proxy host: %v\n", err)
		}
	}

	// Add Pi-hole DNS record if client available
	if h.pihole != nil {
		err := h.pihole.AddDNSRecord(fullFQDN, "10.42.24.1")
		if err != nil {
			fmt.Printf("Warning: Failed to add Pi-hole DNS record: %v\n", err)
		}
	}

	// Return created FQDN
	fqdn := FQDN{
		ID:          id,
		AppID:       req.AppID,
		FQDN:        fullFQDN,
		Subdomain:   req.Subdomain,
		BackendPort: req.BackendPort,
		SSLEnabled:  req.SSLEnabled,
		CreatedAt:   time.Now(),
	}

	fqdnRespondJSON(w, http.StatusCreated, fqdn)
}

// UpdateFQDN updates an existing FQDN
func (h *FQDNsHandler) UpdateFQDN(w http.ResponseWriter, r *http.Request) {
	fqdnParam := chi.URLParam(r, "fqdn")

	// Check if FQDN exists
	var id int64
	var currentPort int
	var currentSSL bool
	err := h.db.QueryRow("SELECT id, backend_port, ssl_enabled FROM fqdns WHERE fqdn = ? OR subdomain = ?",
		fqdnParam, fqdnParam).Scan(&id, &currentPort, &currentSSL)

	if err == sql.ErrNoRows {
		fqdnRespondError(w, http.StatusNotFound, "FQDN not found")
		return
	}
	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query FQDN: %v", err))
		return
	}

	var req UpdateFQDNRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fqdnRespondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Apply updates
	newPort := currentPort
	newSSL := currentSSL

	if req.BackendPort != nil {
		if *req.BackendPort < 1 || *req.BackendPort > 65535 {
			fqdnRespondError(w, http.StatusBadRequest, "Backend port must be between 1 and 65535")
			return
		}
		newPort = *req.BackendPort
	}

	if req.SSLEnabled != nil {
		newSSL = *req.SSLEnabled
	}

	// Update database
	_, err = h.db.Exec("UPDATE fqdns SET backend_port = ?, ssl_enabled = ? WHERE id = ?",
		newPort, newSSL, id)
	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to update FQDN: %v", err))
		return
	}

	// Return updated FQDN
	h.GetFQDN(w, r)
}

// DeleteFQDN deletes an FQDN
func (h *FQDNsHandler) DeleteFQDN(w http.ResponseWriter, r *http.Request) {
	fqdnParam := chi.URLParam(r, "fqdn")

	// Get FQDN details before deleting
	var id int64
	var fullFQDN string
	err := h.db.QueryRow("SELECT id, fqdn FROM fqdns WHERE fqdn = ? OR subdomain = ?",
		fqdnParam, fqdnParam).Scan(&id, &fullFQDN)

	if err == sql.ErrNoRows {
		fqdnRespondError(w, http.StatusNotFound, "FQDN not found")
		return
	}
	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query FQDN: %v", err))
		return
	}

	// Delete from database
	_, err = h.db.Exec("DELETE FROM fqdns WHERE id = ?", id)
	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete FQDN: %v", err))
		return
	}

	// Delete Pi-hole DNS record if client available
	if h.pihole != nil {
		err := h.pihole.DeleteDNSRecord(fullFQDN)
		if err != nil {
			fmt.Printf("Warning: Failed to delete Pi-hole DNS record: %v\n", err)
		}
	}

	fqdnRespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("FQDN %s deleted", fullFQDN),
		"fqdn":    fullFQDN,
	})
}

// Helper functions for FQDN handler responses

func fqdnRespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func fqdnRespondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": message,
		"code":  status,
	})
}
