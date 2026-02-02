// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/models"
)

// FQDNsHandler handles FQDN (domain) management endpoints.
type FQDNsHandler struct {
	db         *sql.DB
	npmManager interface {
		CreateProxyHost(subdomain string, backendPort int) (int, error)
		DeleteProxyHost(proxyID int) error
	}
	piholeManager interface {
		AddDNSEntry(fqdn, ip string) error
		RemoveDNSEntry(fqdn string) error
	}
}

// NewFQDNsHandler creates a new FQDNsHandler instance.
func NewFQDNsHandler(db *sql.DB, npmManager interface{}, piholeManager interface{}) *FQDNsHandler {
	h := &FQDNsHandler{db: db}

	// Type assert managers if they implement the interfaces
	if npm, ok := npmManager.(interface {
		CreateProxyHost(subdomain string, backendPort int) (int, error)
		DeleteProxyHost(proxyID int) error
	}); ok {
		h.npmManager = npm
	}

	if pihole, ok := piholeManager.(interface {
		AddDNSEntry(fqdn, ip string) error
		RemoveDNSEntry(fqdn string) error
	}); ok {
		h.piholeManager = pihole
	}

	return h
}

// Routes returns the router for FQDN endpoints.
func (h *FQDNsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListFQDNs)
	r.Post("/", h.AddFQDN)
	r.Get("/{fqdn}", h.GetFQDN)
	r.Delete("/{fqdn}", h.DeleteFQDN)
	r.Put("/{fqdn}", h.UpdateFQDN)

	return r
}

// FQDNResponse represents an FQDN record for API responses.
type FQDNResponse struct {
	ID          int64     `json:"id"`
	AppID       int64     `json:"app_id"`
	AppName     string    `json:"app_name,omitempty"`
	FQDN        string    `json:"fqdn"`
	Subdomain   string    `json:"subdomain"`
	BackendPort int       `json:"backend_port"`
	SSLEnabled  bool      `json:"ssl_enabled"`
	NPMProxyID  *int      `json:"npm_proxy_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListFQDNs returns all FQDNs.
// GET /api/v1/fqdns
func (h *FQDNsHandler) ListFQDNs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`
		SELECT f.id, f.app_id, COALESCE(a.name, '') as app_name, f.fqdn, f.subdomain, 
		       f.backend_port, f.ssl_enabled, f.npm_proxy_id, f.created_at
		FROM fqdns f
		LEFT JOIN apps a ON f.app_id = a.id
		ORDER BY f.fqdn
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to query FQDNs: "+err.Error())
		return
	}
	defer rows.Close()

	fqdns := make([]FQDNResponse, 0)
	for rows.Next() {
		var f FQDNResponse
		var npmProxyID sql.NullInt64
		err := rows.Scan(&f.ID, &f.AppID, &f.AppName, &f.FQDN, &f.Subdomain,
			&f.BackendPort, &f.SSLEnabled, &npmProxyID, &f.CreatedAt)
		if err != nil {
			continue
		}
		if npmProxyID.Valid {
			proxyID := int(npmProxyID.Int64)
			f.NPMProxyID = &proxyID
		}
		fqdns = append(fqdns, f)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"fqdns": fqdns,
		"count": len(fqdns),
	})
}

// AddFQDNRequest is the request body for adding an FQDN.
type AddFQDNRequest struct {
	AppID       int64  `json:"app_id"`
	Subdomain   string `json:"subdomain"`
	BackendPort int    `json:"backend_port"`
	SSLEnabled  bool   `json:"ssl_enabled"`
	CreateProxy bool   `json:"create_proxy"` // Whether to create NPM proxy host
	CreateDNS   bool   `json:"create_dns"`   // Whether to create Pi-hole DNS entry
}

// AddFQDN creates a new FQDN entry.
// POST /api/v1/fqdns
func (h *FQDNsHandler) AddFQDN(w http.ResponseWriter, r *http.Request) {
	var req AddFQDNRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.AppID == 0 {
		writeError(w, http.StatusBadRequest, "app_id is required")
		return
	}
	if req.Subdomain == "" {
		writeError(w, http.StatusBadRequest, "subdomain is required")
		return
	}
	if req.BackendPort == 0 {
		writeError(w, http.StatusBadRequest, "backend_port is required")
		return
	}

	// Validate subdomain format
	subdomain := strings.ToLower(strings.TrimSpace(req.Subdomain))
	if !isValidSubdomain(subdomain) {
		writeError(w, http.StatusBadRequest, "invalid subdomain format")
		return
	}

	// Construct full FQDN
	fqdn := fmt.Sprintf("%s.cubeos.cube", subdomain)

	// Check if FQDN already exists
	var count int
	h.db.QueryRow("SELECT COUNT(*) FROM fqdns WHERE fqdn = ?", fqdn).Scan(&count)
	if count > 0 {
		writeError(w, http.StatusConflict, "FQDN already exists")
		return
	}

	// Create NPM proxy host if requested
	var npmProxyID *int
	if req.CreateProxy && h.npmManager != nil {
		proxyID, err := h.npmManager.CreateProxyHost(subdomain, req.BackendPort)
		if err != nil {
			// Log error but don't fail - proxy can be created manually
			// log.Printf("Failed to create NPM proxy host: %v", err)
		} else {
			npmProxyID = &proxyID
		}
	}

	// Create DNS entry if requested
	if req.CreateDNS && h.piholeManager != nil {
		gatewayIP := "10.42.24.1" // TODO: Get from config
		if err := h.piholeManager.AddDNSEntry(fqdn, gatewayIP); err != nil {
			// Log error but don't fail
			// log.Printf("Failed to create DNS entry: %v", err)
		}
	}

	// Insert FQDN record
	result, err := h.db.Exec(`
		INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port, ssl_enabled, npm_proxy_id)
		VALUES (?, ?, ?, ?, ?, ?)
	`, req.AppID, fqdn, subdomain, req.BackendPort, req.SSLEnabled, npmProxyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create FQDN: "+err.Error())
		return
	}

	id, _ := result.LastInsertId()

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"success":      true,
		"message":      "FQDN created successfully",
		"id":           id,
		"fqdn":         fqdn,
		"npm_proxy_id": npmProxyID,
	})
}

// GetFQDN returns a single FQDN by its domain name.
// GET /api/v1/fqdns/{fqdn}
func (h *FQDNsHandler) GetFQDN(w http.ResponseWriter, r *http.Request) {
	fqdnParam := chi.URLParam(r, "fqdn")

	var f FQDNResponse
	var npmProxyID sql.NullInt64
	err := h.db.QueryRow(`
		SELECT f.id, f.app_id, COALESCE(a.name, '') as app_name, f.fqdn, f.subdomain,
		       f.backend_port, f.ssl_enabled, f.npm_proxy_id, f.created_at
		FROM fqdns f
		LEFT JOIN apps a ON f.app_id = a.id
		WHERE f.fqdn = ? OR f.subdomain = ?
	`, fqdnParam, fqdnParam).Scan(&f.ID, &f.AppID, &f.AppName, &f.FQDN, &f.Subdomain,
		&f.BackendPort, &f.SSLEnabled, &npmProxyID, &f.CreatedAt)

	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "FQDN not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to query FQDN: "+err.Error())
		return
	}

	if npmProxyID.Valid {
		proxyID := int(npmProxyID.Int64)
		f.NPMProxyID = &proxyID
	}

	writeJSON(w, http.StatusOK, f)
}

// DeleteFQDN removes an FQDN entry.
// DELETE /api/v1/fqdns/{fqdn}
func (h *FQDNsHandler) DeleteFQDN(w http.ResponseWriter, r *http.Request) {
	fqdnParam := chi.URLParam(r, "fqdn")

	// Get the FQDN record to get npm_proxy_id
	var fqdnRecord struct {
		FQDN       string
		NPMProxyID sql.NullInt64
	}
	err := h.db.QueryRow(`
		SELECT fqdn, npm_proxy_id FROM fqdns WHERE fqdn = ? OR subdomain = ?
	`, fqdnParam, fqdnParam).Scan(&fqdnRecord.FQDN, &fqdnRecord.NPMProxyID)

	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "FQDN not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to query FQDN: "+err.Error())
		return
	}

	// Delete NPM proxy host if it exists
	if fqdnRecord.NPMProxyID.Valid && h.npmManager != nil {
		proxyID := int(fqdnRecord.NPMProxyID.Int64)
		if err := h.npmManager.DeleteProxyHost(proxyID); err != nil {
			// Log but don't fail
		}
	}

	// Remove DNS entry
	if h.piholeManager != nil {
		if err := h.piholeManager.RemoveDNSEntry(fqdnRecord.FQDN); err != nil {
			// Log but don't fail
		}
	}

	// Delete from database
	result, err := h.db.Exec("DELETE FROM fqdns WHERE fqdn = ? OR subdomain = ?", fqdnParam, fqdnParam)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete FQDN: "+err.Error())
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		writeError(w, http.StatusNotFound, "FQDN not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "FQDN deleted successfully",
	})
}

// UpdateFQDNRequest is the request body for updating an FQDN.
type UpdateFQDNRequest struct {
	BackendPort *int  `json:"backend_port,omitempty"`
	SSLEnabled  *bool `json:"ssl_enabled,omitempty"`
}

// UpdateFQDN updates an existing FQDN entry.
// PUT /api/v1/fqdns/{fqdn}
func (h *FQDNsHandler) UpdateFQDN(w http.ResponseWriter, r *http.Request) {
	fqdnParam := chi.URLParam(r, "fqdn")

	var req UpdateFQDNRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Check if FQDN exists
	var id int64
	err := h.db.QueryRow("SELECT id FROM fqdns WHERE fqdn = ? OR subdomain = ?", fqdnParam, fqdnParam).Scan(&id)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "FQDN not found")
		return
	}

	// Build update query dynamically
	updates := []string{}
	args := []interface{}{}

	if req.BackendPort != nil {
		updates = append(updates, "backend_port = ?")
		args = append(args, *req.BackendPort)
	}
	if req.SSLEnabled != nil {
		updates = append(updates, "ssl_enabled = ?")
		args = append(args, *req.SSLEnabled)
	}

	if len(updates) == 0 {
		writeError(w, http.StatusBadRequest, "No fields to update")
		return
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE fqdns SET %s WHERE id = ?", strings.Join(updates, ", "))

	_, err = h.db.Exec(query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update FQDN: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "FQDN updated successfully",
	})
}

// isValidSubdomain checks if a subdomain is valid.
func isValidSubdomain(subdomain string) bool {
	if len(subdomain) == 0 || len(subdomain) > 63 {
		return false
	}

	// Must start and end with alphanumeric
	if !isAlphanumeric(subdomain[0]) || !isAlphanumeric(subdomain[len(subdomain)-1]) {
		return false
	}

	// Can only contain alphanumeric and hyphens
	for _, c := range subdomain {
		if !isAlphanumeric(byte(c)) && c != '-' {
			return false
		}
	}

	return true
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// Ensure models.FQDN is used somewhere to avoid unused import
var _ = models.FQDN{}
