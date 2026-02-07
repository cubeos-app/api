// internal/handlers/fqdns.go
// Sprint 4B: FQDN Management API
// Manages DNS entries and reverse proxy mappings

package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"cubeos-api/internal/managers"
	"github.com/go-chi/chi/v5"
)

// FQDNsHandler handles FQDN management endpoints
type FQDNsHandler struct {
	db     *sql.DB
	npm    *managers.NPMManager
	pihole *managers.PiholeManager
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
func NewFQDNsHandler(db *sql.DB, npm *managers.NPMManager, pihole *managers.PiholeManager) *FQDNsHandler {
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

// ListFQDNs godoc
// @Summary List all FQDNs
// @Description Returns all configured FQDNs with their associated apps, backend ports, and SSL status. Includes stats for total, with_ssl, and without_ssl counts.
// @Tags FQDNs
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "fqdns: array of FQDN objects, stats: count summaries"
// @Failure 500 {object} ErrorResponse "Failed to query FQDNs"
// @Router /fqdns [get]
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
	if err := rows.Err(); err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to iterate FQDNs: %v", err))
		return
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

// GetFQDN godoc
// @Summary Get an FQDN
// @Description Returns a single FQDN by its full domain name or subdomain
// @Tags FQDNs
// @Produce json
// @Security BearerAuth
// @Param fqdn path string true "Full FQDN (e.g., myapp.cubeos.cube) or subdomain (e.g., myapp)"
// @Success 200 {object} FQDN "FQDN details"
// @Failure 404 {object} ErrorResponse "FQDN not found"
// @Failure 500 {object} ErrorResponse "Failed to query FQDN"
// @Router /fqdns/{fqdn} [get]
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

// CreateFQDN godoc
// @Summary Create an FQDN
// @Description Creates a new FQDN entry with DNS record (Pi-hole) and reverse proxy (NPM). Subdomain is automatically suffixed with .cubeos.cube domain.
// @Tags FQDNs
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateFQDNRequest true "FQDN creation request"
// @Success 201 {object} FQDN "Created FQDN"
// @Failure 400 {object} ErrorResponse "Invalid request, missing subdomain, invalid port, or app not found"
// @Failure 409 {object} ErrorResponse "FQDN already exists"
// @Failure 500 {object} ErrorResponse "Failed to create FQDN"
// @Router /fqdns [post]
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

	// Validate app_id is provided and app exists
	if req.AppID <= 0 {
		fqdnRespondError(w, http.StatusBadRequest, "app_id is required and must be a positive integer")
		return
	}
	var appExists int
	err := h.db.QueryRow("SELECT COUNT(*) FROM apps WHERE id = ?", req.AppID).Scan(&appExists)
	if err != nil || appExists == 0 {
		fqdnRespondError(w, http.StatusBadRequest, "App not found")
		return
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

	// Create NPM proxy host if manager available
	var npmProxyID int
	if h.npm != nil {
		host := &managers.NPMProxyHostExtended{
			DomainNames:   []string{fullFQDN},
			ForwardPort:   req.BackendPort,
			ForwardScheme: "http",
		}
		created, err := h.npm.CreateProxyHost(host)
		if err != nil {
			log.Printf("Warning: Failed to create NPM proxy host for %s: %v", fullFQDN, err)
		} else if created != nil {
			npmProxyID = created.ID
		}
	}

	// Add Pi-hole DNS record if manager available
	if h.pihole != nil {
		if err := h.pihole.AddEntry(fullFQDN, ""); err != nil {
			log.Printf("Warning: Failed to add Pi-hole DNS record for %s: %v", fullFQDN, err)
		} else {
			if err := h.pihole.ReloadDNS(); err != nil {
				log.Printf("Warning: Failed to reload Pi-hole DNS after adding %s: %v", fullFQDN, err)
			}
		}
	}

	// Insert into database (include npm_proxy_id for cleanup on delete)
	result, err := h.db.Exec(`
		INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port, ssl_enabled, npm_proxy_id)
		VALUES (?, ?, ?, ?, ?, ?)
	`, req.AppID, fullFQDN, req.Subdomain, req.BackendPort, req.SSLEnabled, npmProxyID)

	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create FQDN: %v", err))
		return
	}

	id, _ := result.LastInsertId()

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

// UpdateFQDN godoc
// @Summary Update an FQDN
// @Description Updates an existing FQDN's backend port and/or SSL status
// @Tags FQDNs
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param fqdn path string true "Full FQDN or subdomain"
// @Param request body UpdateFQDNRequest true "FQDN update request (partial update supported)"
// @Success 200 {object} FQDN "Updated FQDN"
// @Failure 400 {object} ErrorResponse "Invalid JSON or invalid port"
// @Failure 404 {object} ErrorResponse "FQDN not found"
// @Failure 500 {object} ErrorResponse "Failed to update FQDN"
// @Router /fqdns/{fqdn} [put]
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

// DeleteFQDN godoc
// @Summary Delete an FQDN
// @Description Deletes an FQDN and removes associated DNS record from Pi-hole
// @Tags FQDNs
// @Produce json
// @Security BearerAuth
// @Param fqdn path string true "Full FQDN or subdomain"
// @Success 200 {object} map[string]interface{} "message: deletion confirmation, fqdn: deleted domain"
// @Failure 404 {object} ErrorResponse "FQDN not found"
// @Failure 500 {object} ErrorResponse "Failed to delete FQDN"
// @Router /fqdns/{fqdn} [delete]
func (h *FQDNsHandler) DeleteFQDN(w http.ResponseWriter, r *http.Request) {
	fqdnParam := chi.URLParam(r, "fqdn")

	// Get FQDN details before deleting
	var id int64
	var fullFQDN string
	var npmProxyID int
	err := h.db.QueryRow("SELECT id, fqdn, COALESCE(npm_proxy_id, 0) FROM fqdns WHERE fqdn = ? OR subdomain = ?",
		fqdnParam, fqdnParam).Scan(&id, &fullFQDN, &npmProxyID)

	if err == sql.ErrNoRows {
		fqdnRespondError(w, http.StatusNotFound, "FQDN not found")
		return
	}
	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query FQDN: %v", err))
		return
	}

	// Delete from database first
	_, err = h.db.Exec("DELETE FROM fqdns WHERE id = ?", id)
	if err != nil {
		fqdnRespondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete FQDN: %v", err))
		return
	}

	// Cleanup: Delete NPM proxy host if we have the ID and manager is available
	if h.npm != nil && npmProxyID > 0 {
		if err := h.npm.DeleteProxyHost(npmProxyID); err != nil {
			log.Printf("Warning: Failed to delete NPM proxy host %d for %s: %v", npmProxyID, fullFQDN, err)
		}
	} else if h.npm != nil {
		// Fallback: try to find proxy host by domain name
		host, err := h.npm.FindProxyHostByDomain(fullFQDN)
		if err != nil {
			log.Printf("Warning: Failed to find NPM proxy host for %s: %v", fullFQDN, err)
		} else if host != nil {
			if err := h.npm.DeleteProxyHost(host.ID); err != nil {
				log.Printf("Warning: Failed to delete NPM proxy host for %s: %v", fullFQDN, err)
			}
		}
	}

	// Cleanup: Delete Pi-hole DNS record if manager available
	if h.pihole != nil {
		if err := h.pihole.RemoveEntry(fullFQDN); err != nil {
			log.Printf("Warning: Failed to delete Pi-hole DNS record for %s: %v", fullFQDN, err)
		} else {
			if err := h.pihole.ReloadDNS(); err != nil {
				log.Printf("Warning: Failed to reload Pi-hole DNS after deleting %s: %v", fullFQDN, err)
			}
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
