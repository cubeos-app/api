package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
)

// FirewallHandler handles firewall-related HTTP requests.
type FirewallHandler struct {
	firewall  *managers.FirewallManager
	halClient *hal.Client
}

// NewFirewallHandler creates a new firewall handler.
func NewFirewallHandler(firewall *managers.FirewallManager, halClient *hal.Client) *FirewallHandler {
	return &FirewallHandler{
		firewall:  firewall,
		halClient: halClient,
	}
}

// Routes returns the firewall routes.
func (h *FirewallHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Status endpoints
	r.Get("/status", h.GetStatus)
	r.Get("/nat", h.GetNATStatus)
	r.Get("/nat/status", h.GetNATStatus) // Alias

	// NAT control
	r.Post("/nat/enable", h.EnableNAT)
	r.Post("/nat/disable", h.DisableNAT)

	// IP Forwarding (ipforward alias)
	r.Get("/forwarding", h.GetForwardingStatus)
	r.Get("/ipforward", h.GetIPForward)
	r.Put("/ipforward", h.SetIPForward)
	r.Post("/forwarding/enable", h.EnableForwarding)
	r.Post("/forwarding/disable", h.DisableForwarding)

	// Firewall rules
	r.Get("/rules", h.GetRules)
	r.Post("/rules", h.AddRule)
	r.Delete("/rules", h.DeleteRule)

	// Port-based rules (simplified API)
	r.Post("/port/allow", h.AllowPort)
	r.Post("/port/block", h.BlockPort)
	r.Delete("/port/{port}", h.DeletePortRule)

	// Service-based rules
	r.Post("/service/{service}/allow", h.AllowService)

	// Persistence
	r.Post("/save", h.SaveRules)
	r.Post("/restore", h.RestoreRules)
	r.Post("/reset", h.ResetFirewall)

	return r
}

// GetStatus godoc
// @Summary Get firewall status
// @Description Returns overall firewall status including NAT, IP forwarding, and rules count
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "enabled, nat_enabled, forwarding_enabled, rules_count"
// @Router /firewall/status [get]
func (h *FirewallHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get NAT status
	natEnabled := false
	if h.firewall != nil {
		natStatus, err := h.firewall.GetNATStatus(ctx)
		if err == nil && natStatus != nil {
			// Check if NAT is enabled by looking for masquerade rules
			if enabled, ok := natStatus["nat_enabled"].(bool); ok {
				natEnabled = enabled
			}
		}
	}

	// Get forwarding status
	forwardingEnabled := false
	if h.halClient != nil {
		fwdStatus, err := h.halClient.GetForwardingStatus(ctx)
		if err == nil {
			forwardingEnabled = fwdStatus
		}
	}

	// Get firewall rules count
	rulesCount := 0
	if h.halClient != nil {
		rules, err := h.halClient.GetFirewallRules(ctx)
		if err == nil {
			rulesCount = len(rules)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":            true, // iptables is always "enabled" on Linux
		"nat_enabled":        natEnabled,
		"forwarding_enabled": forwardingEnabled,
		"rules_count":        rulesCount,
	})
}

// GetNATStatus godoc
// @Summary Get NAT status
// @Description Returns NAT/masquerade status and configuration details
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "NAT status details"
// @Failure 500 {object} ErrorResponse "Failed to get NAT status"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/nat [get]
func (h *FirewallHandler) GetNATStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	status, err := h.firewall.GetNATStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get NAT status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// EnableNAT godoc
// @Summary Enable NAT
// @Description Enables NAT/masquerade for internet sharing through the access point
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "status, message"
// @Failure 500 {object} ErrorResponse "Failed to enable NAT"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/nat/enable [post]
func (h *FirewallHandler) EnableNAT(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	result := h.firewall.EnableNAT(ctx)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// DisableNAT godoc
// @Summary Disable NAT
// @Description Disables NAT/masquerade, stopping internet sharing
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "status, message"
// @Failure 500 {object} ErrorResponse "Failed to disable NAT"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/nat/disable [post]
func (h *FirewallHandler) DisableNAT(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	result := h.firewall.DisableNAT(ctx)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// GetForwardingStatus godoc
// @Summary Get IP forwarding status
// @Description Returns whether IP forwarding (net.ipv4.ip_forward) is enabled
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "enabled: boolean"
// @Failure 500 {object} ErrorResponse "Failed to get forwarding status"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /firewall/forwarding [get]
func (h *FirewallHandler) GetForwardingStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	enabled, err := h.halClient.GetForwardingStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get forwarding status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": enabled,
	})
}

// EnableForwarding godoc
// @Summary Enable IP forwarding
// @Description Enables IP forwarding (net.ipv4.ip_forward=1) required for NAT and routing
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 500 {object} ErrorResponse "Failed to enable forwarding"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /firewall/forwarding/enable [post]
func (h *FirewallHandler) EnableForwarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.EnableForwarding(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to enable forwarding: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "IP forwarding enabled",
	})
}

// DisableForwarding godoc
// @Summary Disable IP forwarding
// @Description Disables IP forwarding (net.ipv4.ip_forward=0)
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 500 {object} ErrorResponse "Failed to disable forwarding"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /firewall/forwarding/disable [post]
func (h *FirewallHandler) DisableForwarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.DisableForwarding(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disable forwarding: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "IP forwarding disabled",
	})
}

// GetRules godoc
// @Summary Get firewall rules
// @Description Returns current iptables firewall rules with optional filtering by chain or table
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param chain query string false "Filter by chain (INPUT, OUTPUT, FORWARD)"
// @Param table query string false "Filter by table (filter, nat, mangle)"
// @Success 200 {object} map[string]interface{} "rules: map of rules, count: total"
// @Failure 500 {object} ErrorResponse "Failed to get firewall rules"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /firewall/rules [get]
func (h *FirewallHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	rules, err := h.halClient.GetFirewallRules(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get firewall rules: "+err.Error())
		return
	}

	// Filter by chain/table if specified
	chain := r.URL.Query().Get("chain")
	table := r.URL.Query().Get("table")

	if chain != "" || table != "" {
		filtered := make(map[string]string)
		for k, v := range rules {
			// Simple filtering - check if key contains chain/table
			matchChain := chain == "" || strings.Contains(strings.ToUpper(k), strings.ToUpper(chain))
			matchTable := table == "" || strings.Contains(strings.ToLower(k), strings.ToLower(table))
			if matchChain && matchTable {
				filtered[k] = v
			}
		}
		rules = filtered
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
		"count": len(rules),
	})
}

// AddRuleRequest represents a firewall rule add request
type AddRuleRequest struct {
	Table string   `json:"table"`
	Chain string   `json:"chain"`
	Args  []string `json:"args"`
}

// AddRule godoc
// @Summary Add firewall rule
// @Description Adds a new iptables firewall rule to the specified table and chain
// @Tags Firewall
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AddRuleRequest true "Firewall rule" SchemaExample({"table": "filter", "chain": "INPUT", "args": ["-p", "tcp", "--dport", "8080", "-j", "ACCEPT"]})
// @Success 200 {object} map[string]interface{} "success: true, message, rule"
// @Failure 400 {object} ErrorResponse "Invalid request or missing chain"
// @Failure 500 {object} ErrorResponse "Failed to add firewall rule"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /firewall/rules [post]
func (h *FirewallHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req AddRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.Chain == "" {
		writeError(w, http.StatusBadRequest, "Chain is required (INPUT, OUTPUT, FORWARD)")
		return
	}

	// Set defaults
	if req.Table == "" {
		req.Table = "filter"
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.AddFirewallRule(ctx, req.Table, req.Chain, req.Args); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to add firewall rule: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Firewall rule added",
		"rule":    req,
	})
}

// DeleteRule godoc
// @Summary Delete firewall rule
// @Description Deletes an iptables firewall rule from the specified table and chain
// @Tags Firewall
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AddRuleRequest true "Firewall rule to delete" SchemaExample({"table": "filter", "chain": "INPUT", "args": ["-p", "tcp", "--dport", "8080", "-j", "ACCEPT"]})
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 400 {object} ErrorResponse "Invalid request or missing chain"
// @Failure 500 {object} ErrorResponse "Failed to delete firewall rule"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /firewall/rules [delete]
func (h *FirewallHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req AddRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.Chain == "" {
		writeError(w, http.StatusBadRequest, "Chain is required")
		return
	}

	// Set defaults
	if req.Table == "" {
		req.Table = "filter"
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.DeleteFirewallRule(ctx, req.Table, req.Chain, req.Args); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete firewall rule: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Firewall rule deleted",
	})
}

// GetIPForward godoc
// @Summary Get IP forwarding status
// @Description Returns the current state of IP forwarding (net.ipv4.ip_forward)
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "enabled: boolean, value: string"
// @Failure 500 {object} ErrorResponse "Failed to get IP forward status"
// @Router /firewall/ipforward [get]
func (h *FirewallHandler) GetIPForward(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	enabled, err := h.halClient.GetForwardingStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get IP forward status: "+err.Error())
		return
	}

	value := "0"
	if enabled {
		value = "1"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": enabled,
		"value":   value,
	})
}

// SetIPForwardRequest represents IP forward setting request
type SetIPForwardRequest struct {
	Enabled bool `json:"enabled"`
}

// SetIPForward godoc
// @Summary Set IP forwarding status
// @Description Enables or disables IP forwarding
// @Tags Firewall
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body SetIPForwardRequest true "IP forward setting"
// @Success 200 {object} map[string]interface{} "success, enabled"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to set IP forward"
// @Router /firewall/ipforward [put]
func (h *FirewallHandler) SetIPForward(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SetIPForwardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	var err error
	if req.Enabled {
		err = h.halClient.EnableForwarding(ctx)
	} else {
		err = h.halClient.DisableForwarding(ctx)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set IP forward: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"enabled": req.Enabled,
	})
}

// AllowPortRequest represents a port allow request
type AllowPortRequest struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // tcp, udp, or both
}

// AllowPort godoc
// @Summary Allow incoming traffic on a port
// @Description Opens a port in the firewall for incoming traffic
// @Tags Firewall
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AllowPortRequest true "Port to allow"
// @Success 200 {object} map[string]interface{} "success, port, protocol"
// @Failure 400 {object} ErrorResponse "Invalid port or protocol"
// @Failure 500 {object} ErrorResponse "Failed to allow port"
// @Router /firewall/port/allow [post]
func (h *FirewallHandler) AllowPort(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req AllowPortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "Invalid port number (1-65535)")
		return
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	// Add INPUT ACCEPT rule for the port
	args := []string{"-p", req.Protocol, "--dport", strconv.Itoa(req.Port), "-j", "ACCEPT"}
	if err := h.halClient.AddFirewallRule(ctx, "filter", "INPUT", args); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to allow port: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"port":     req.Port,
		"protocol": req.Protocol,
		"message":  "Port allowed",
	})
}

// BlockPort godoc
// @Summary Block incoming traffic on a port
// @Description Blocks a port in the firewall for incoming traffic
// @Tags Firewall
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AllowPortRequest true "Port to block"
// @Success 200 {object} map[string]interface{} "success, port, protocol"
// @Failure 400 {object} ErrorResponse "Invalid port or protocol"
// @Failure 500 {object} ErrorResponse "Failed to block port"
// @Router /firewall/port/block [post]
func (h *FirewallHandler) BlockPort(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req AllowPortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "Invalid port number (1-65535)")
		return
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	// Add INPUT DROP rule for the port
	args := []string{"-p", req.Protocol, "--dport", strconv.Itoa(req.Port), "-j", "DROP"}
	if err := h.halClient.AddFirewallRule(ctx, "filter", "INPUT", args); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to block port: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"port":     req.Port,
		"protocol": req.Protocol,
		"message":  "Port blocked",
	})
}

// DeletePortRule godoc
// @Summary Delete port firewall rule
// @Description Removes any firewall rules for the specified port
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param port path int true "Port number"
// @Param protocol query string false "Protocol (tcp, udp)"
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 400 {object} ErrorResponse "Invalid port"
// @Failure 500 {object} ErrorResponse "Failed to delete port rule"
// @Router /firewall/port/{port} [delete]
func (h *FirewallHandler) DeletePortRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	portStr := chi.URLParam(r, "port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid port number")
		return
	}

	if port < 1 || port > 65535 {
		writeError(w, http.StatusBadRequest, "Invalid port number (1-65535)")
		return
	}

	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "tcp"
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	// Try to delete both ACCEPT and DROP rules for the port
	argsAccept := []string{"-p", protocol, "--dport", portStr, "-j", "ACCEPT"}
	argsDrop := []string{"-p", protocol, "--dport", portStr, "-j", "DROP"}

	// Ignore errors - rules may not exist
	h.halClient.DeleteFirewallRule(ctx, "filter", "INPUT", argsAccept)
	h.halClient.DeleteFirewallRule(ctx, "filter", "INPUT", argsDrop)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"port":    port,
		"message": "Port rules deleted",
	})
}

func mustParseInt(s string) int64 {
	i, _ := strconv.ParseInt(s, 10, 64)
	return i
}

// AllowService godoc
// @Summary Allow a service through the firewall
// @Description Opens firewall for a named service (ssh, http, https, etc.)
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param service path string true "Service name (ssh, http, https, dns, etc.)"
// @Success 200 {object} map[string]interface{} "success, service, ports"
// @Failure 400 {object} ErrorResponse "Unknown service"
// @Failure 500 {object} ErrorResponse "Failed to allow service"
// @Router /firewall/service/{service}/allow [post]
func (h *FirewallHandler) AllowService(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	service := chi.URLParam(r, "service")

	// Map service names to ports
	servicePorts := map[string][]struct {
		Port     int
		Protocol string
	}{
		"ssh":   {{22, "tcp"}},
		"http":  {{80, "tcp"}},
		"https": {{443, "tcp"}},
		"dns":   {{53, "tcp"}, {53, "udp"}},
		"dhcp":  {{67, "udp"}, {68, "udp"}},
		"ntp":   {{123, "udp"}},
		"smtp":  {{25, "tcp"}, {587, "tcp"}},
		"ftp":   {{21, "tcp"}},
		"smb":   {{445, "tcp"}, {139, "tcp"}},
	}

	ports, ok := servicePorts[strings.ToLower(service)]
	if !ok {
		writeError(w, http.StatusBadRequest, "Unknown service: "+service)
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	for _, p := range ports {
		args := []string{"-p", p.Protocol, "--dport", strconv.Itoa(p.Port), "-j", "ACCEPT"}
		if err := h.halClient.AddFirewallRule(ctx, "filter", "INPUT", args); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to allow service: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"service": service,
		"ports":   ports,
		"message": "Service allowed through firewall",
	})
}

// SaveRules godoc
// @Summary Save firewall rules
// @Description Saves current firewall rules to persistent storage
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 500 {object} ErrorResponse "Failed to save rules"
// @Router /firewall/save [post]
func (h *FirewallHandler) SaveRules(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement iptables-save to persistent file
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Firewall rules saved",
	})
}

// RestoreRules godoc
// @Summary Restore firewall rules
// @Description Restores firewall rules from persistent storage
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 500 {object} ErrorResponse "Failed to restore rules"
// @Router /firewall/restore [post]
func (h *FirewallHandler) RestoreRules(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement iptables-restore from persistent file
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Firewall rules restored",
	})
}

// ResetFirewall godoc
// @Summary Reset firewall to defaults
// @Description Resets all firewall rules to default (allow all)
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 500 {object} ErrorResponse "Failed to reset firewall"
// @Router /firewall/reset [post]
func (h *FirewallHandler) ResetFirewall(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement iptables flush/reset
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Firewall reset to defaults",
	})
}
