// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
)

// PortsHandler handles port allocation endpoints.
type PortsHandler struct {
	portManager *managers.PortManager
}

// NewPortsHandler creates a new PortsHandler instance.
func NewPortsHandler(portManager *managers.PortManager) *PortsHandler {
	return &PortsHandler{
		portManager: portManager,
	}
}

// Routes returns the router for port endpoints.
func (h *PortsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListPorts)
	r.Get("/available", h.GetAvailablePort)
	r.Post("/", h.AddPort)
	r.Get("/stats", h.GetPortStats)
	r.Get("/reserved", h.GetReservedPorts)
	r.Delete("/{port}", h.DeletePort)

	return r
}

// ListPorts godoc
// @Summary List all port allocations
// @Description Returns all port allocations with statistics. Ports are allocated in the 6xxx range per CubeOS port scheme.
// @Tags Ports
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "ports: array of allocations, stats: allocation statistics"
// @Failure 500 {object} ErrorResponse "Failed to get port allocations"
// @Router /ports [get]
func (h *PortsHandler) ListPorts(w http.ResponseWriter, r *http.Request) {
	allocations, err := h.portManager.GetAllAllocations()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get port allocations: "+err.Error())
		return
	}

	// Get stats for additional info
	stats, _ := h.portManager.GetPortStats()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ports": allocations,
		"stats": stats,
	})
}

// GetAvailablePort godoc
// @Summary Get next available port
// @Description Returns the next available (unallocated) port in the specified range type. Range types: infrastructure (6000-6009), platform (6010-6019), network (6020-6029), ai (6030-6039), user (6100-6999).
// @Tags Ports
// @Produce json
// @Security BearerAuth
// @Param type query string false "Port range type (default: user)" Enums(infrastructure, platform, network, ai, user)
// @Success 200 {object} map[string]interface{} "port: available port number, type: range type"
// @Failure 404 {object} ErrorResponse "No available ports in range"
// @Failure 500 {object} ErrorResponse "Failed to find available port"
// @Router /ports/available [get]
func (h *PortsHandler) GetAvailablePort(w http.ResponseWriter, r *http.Request) {
	portType := r.URL.Query().Get("type")
	if portType == "" {
		portType = "user"
	}

	// Define port ranges per type
	ranges := map[string][2]int{
		"infrastructure": {6000, 6009},
		"platform":       {6010, 6019},
		"network":        {6020, 6029},
		"ai":             {6030, 6039},
		"user":           {managers.UserPortMin, managers.UserPortMax},
	}

	portRange, ok := ranges[portType]
	if !ok {
		writeError(w, http.StatusBadRequest, "Invalid port type. Must be one of: infrastructure, platform, network, ai, user")
		return
	}

	// For "user" range, use the optimized PortManager method
	if portType == "user" {
		port, err := h.portManager.AllocateUserPort()
		if err != nil {
			writeError(w, http.StatusNotFound, "No available ports in user range: "+err.Error())
			return
		}
		// We allocated a port, but we only wanted to find one — deallocate it
		// so this is a pure query (the caller will allocate explicitly via POST /ports)
		_ = h.portManager.DeallocatePort(port, "tcp")

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"port":  port,
			"type":  portType,
			"range": fmt.Sprintf("%d-%d", portRange[0], portRange[1]),
		})
		return
	}

	// For system ranges, scan for the first unallocated port
	allocations, err := h.portManager.GetAllAllocations()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to query port allocations: "+err.Error())
		return
	}

	allocated := make(map[int]bool)
	for _, a := range allocations {
		allocated[a.Port] = true
	}
	// Also exclude reserved system ports
	for port := range managers.ReservedSystemPorts {
		allocated[port] = true
	}

	for p := portRange[0]; p <= portRange[1]; p++ {
		if !allocated[p] {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"port":  p,
				"type":  portType,
				"range": fmt.Sprintf("%d-%d", portRange[0], portRange[1]),
			})
			return
		}
	}

	writeError(w, http.StatusNotFound, fmt.Sprintf("No available ports in %s range (%d-%d)", portType, portRange[0], portRange[1]))
}

// AddPortRequest is the request body for adding a port allocation.
type AddPortRequest struct {
	AppID       int64  `json:"app_id"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	IsPrimary   bool   `json:"is_primary"`
}

// AddPort godoc
// @Summary Allocate a port
// @Description Allocates a port for an app. If port is 0 or omitted, auto-allocates from the user range (6100-6999). Reserved system ports cannot be allocated.
// @Tags Ports
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AddPortRequest true "Port allocation request"
// @Success 201 {object} map[string]interface{} "success: true, message, port: allocated port number"
// @Failure 400 {object} ErrorResponse "Invalid request, missing app_id, invalid protocol, or reserved port"
// @Failure 409 {object} ErrorResponse "Port already allocated"
// @Router /ports [post]
func (h *PortsHandler) AddPort(w http.ResponseWriter, r *http.Request) {
	var req AddPortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate app_id is provided
	if req.AppID == 0 {
		writeError(w, http.StatusBadRequest, "app_id is required")
		return
	}

	// Default protocol to tcp
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	// Validate protocol
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		writeError(w, http.StatusBadRequest, "protocol must be 'tcp' or 'udp'")
		return
	}

	// Check if port is reserved
	if req.Port != 0 && h.portManager.IsPortReserved(req.Port) {
		writeError(w, http.StatusBadRequest, "port is reserved for system use")
		return
	}

	// Allocate the port (if port is 0, it will auto-allocate)
	err := h.portManager.AllocatePort(req.AppID, req.Port, req.Protocol, req.Description, req.IsPrimary)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	// If auto-allocated, we need to get the allocated port
	allocatedPort := req.Port
	if req.Port == 0 {
		// Get the app's ports to find the newly allocated one
		ports, _ := h.portManager.GetAppPorts(req.AppID)
		if len(ports) > 0 {
			allocatedPort = ports[len(ports)-1]
		}
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Port allocated successfully",
		"port":    allocatedPort,
	})
}

// DeletePort godoc
// @Summary Deallocate a port
// @Description Removes a port allocation. Protocol defaults to TCP if not specified.
// @Tags Ports
// @Produce json
// @Security BearerAuth
// @Param port path integer true "Port number"
// @Param protocol query string false "Protocol (tcp or udp, defaults to tcp)"
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 400 {object} ErrorResponse "Invalid port number"
// @Failure 404 {object} ErrorResponse "Port not allocated"
// @Failure 500 {object} ErrorResponse "Failed to check or deallocate port"
// @Router /ports/{port} [delete]
func (h *PortsHandler) DeletePort(w http.ResponseWriter, r *http.Request) {
	portStr := chi.URLParam(r, "port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid port number")
		return
	}

	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "tcp"
	}

	// Check if port is allocated
	allocated, err := h.portManager.IsPortAllocated(port, protocol)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check port: "+err.Error())
		return
	}

	if !allocated {
		writeError(w, http.StatusNotFound, "Port not allocated")
		return
	}

	// Deallocate the port
	if err := h.portManager.DeallocatePort(port, protocol); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to deallocate port: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Port deallocated successfully",
	})
}

// GetPortStats godoc
// @Summary Get port allocation statistics
// @Description Returns statistics about port allocations including total allocated, available, and per-range breakdowns
// @Tags Ports
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Port allocation statistics"
// @Failure 500 {object} ErrorResponse "Failed to get port stats"
// @Router /ports/stats [get]
func (h *PortsHandler) GetPortStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.portManager.GetPortStats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get port stats: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// GetReservedPorts godoc
// @Summary Get reserved system ports
// @Description Returns the list of reserved system ports and CubeOS port range definitions (system: 6000-6009, platform: 6010-6019, network: 6020-6029, ai: 6030-6039, user: 6100-6999)
// @Tags Ports
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "reserved_ports: array with port/description, ranges: port range definitions"
// @Router /ports/reserved [get]
func (h *PortsHandler) GetReservedPorts(w http.ResponseWriter, r *http.Request) {
	reserved := make([]map[string]interface{}, 0)
	for port, desc := range managers.ReservedSystemPorts {
		reserved = append(reserved, map[string]interface{}{
			"port":        port,
			"description": desc,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"reserved_ports": reserved,
		"ranges": map[string]string{
			"system":   "6000-6009",
			"platform": "6010-6019",
			"network":  "6020-6029",
			"ai":       "6030-6039",
			"user":     "6100-6999",
		},
	})
}
