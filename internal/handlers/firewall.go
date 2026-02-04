package handlers

import (
	"encoding/json"
	"net/http"
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

	// NAT control
	r.Post("/nat/enable", h.EnableNAT)
	r.Post("/nat/disable", h.DisableNAT)

	// Forwarding control
	r.Get("/forwarding", h.GetForwardingStatus)
	r.Post("/forwarding/enable", h.EnableForwarding)
	r.Post("/forwarding/disable", h.DisableForwarding)

	// Firewall rules
	r.Get("/rules", h.GetRules)
	r.Post("/rules", h.AddRule)
	r.Delete("/rules", h.DeleteRule)

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
