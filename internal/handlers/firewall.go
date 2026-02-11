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
// All rule operations are routed through the FirewallManager (which uses HAL).
// The halClient is used for consolidated HAL-based firewall status.
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
	r.Get("/hal/status", h.GetHALFirewallStatus)
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
// @Failure 500 {object} ErrorResponse "Failed to get firewall status"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/status [get]
func (h *FirewallHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	status, err := h.firewall.GetStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get firewall status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetHALFirewallStatus godoc
// @Summary Get consolidated HAL firewall status
// @Description Returns consolidated firewall status directly from the HAL, including active state, rule count, NAT, and forwarding status
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} hal.FirewallStatusResponse "Consolidated firewall status"
// @Failure 500 {object} ErrorResponse "Failed to get HAL firewall status"
// @Failure 503 {object} ErrorResponse "HAL service unavailable"
// @Router /firewall/hal/status [get]
func (h *FirewallHandler) GetHALFirewallStatus(w http.ResponseWriter, r *http.Request) {
	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	status, err := h.halClient.GetHALFirewallStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get HAL firewall status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
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
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	status, err := h.firewall.GetNATStatus(r.Context())
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
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	result := h.firewall.EnableNAT(r.Context())
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
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	result := h.firewall.DisableNAT(r.Context())
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/forwarding [get]
func (h *FirewallHandler) GetForwardingStatus(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	enabled, err := h.firewall.GetForwardingStatus(r.Context())
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/forwarding/enable [post]
func (h *FirewallHandler) EnableForwarding(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	if err := h.firewall.SetForwarding(r.Context(), true); err != nil {
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/forwarding/disable [post]
func (h *FirewallHandler) DisableForwarding(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	if err := h.firewall.SetForwarding(r.Context(), false); err != nil {
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
// @Description Returns current iptables firewall rules with optional filtering by chain, table, or user_only mode
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param chain query string false "Filter by chain (INPUT, OUTPUT, FORWARD)"
// @Param table query string false "Filter by table (filter, nat, mangle)"
// @Param user_only query string false "Filter out Docker/system rules (true/false)"
// @Success 200 {object} map[string]interface{} "rules: map of rules, count: total"
// @Failure 400 {object} ErrorResponse "Invalid table or chain name"
// @Failure 500 {object} ErrorResponse "Failed to get firewall rules"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/rules [get]
func (h *FirewallHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	// Validate query params if provided
	chainFilter := r.URL.Query().Get("chain")
	tableFilter := r.URL.Query().Get("table")
	userOnly := r.URL.Query().Get("user_only") == "true"

	if tableFilter != "" {
		if err := managers.ValidateTable(tableFilter); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if chainFilter != "" {
		if err := managers.ValidateChain(chainFilter); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Get detailed rules from manager
	rulesResp, err := h.firewall.GetRulesDetailed(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get firewall rules: "+err.Error())
		return
	}

	// Docker/system chains to exclude when user_only=true
	systemChains := map[string]bool{
		"DOCKER": true, "DOCKER-ISOLATION-STAGE-1": true, "DOCKER-ISOLATION-STAGE-2": true,
		"DOCKER-USER": true, "DOCKER-INGRESS": true, "DOCKER_OUTPUT": true,
		"DOCKER_POSTROUTING": true, "KUBE-SERVICES": true, "KUBE-POSTROUTING": true,
		"KUBE-FIREWALL": true,
	}

	// Normalize a single HAL rule into a user-friendly format
	normalizeRule := func(rule hal.FirewallRule, table string) map[string]interface{} {
		// Map target → action
		action := strings.ToLower(rule.Target)
		switch action {
		case "accept":
			action = "allow"
		case "drop":
			action = "deny"
		case "reject":
			action = "reject"
		}

		// Map chain → direction
		direction := ""
		switch rule.Chain {
		case "INPUT":
			direction = "in"
		case "OUTPUT":
			direction = "out"
		case "FORWARD":
			direction = "forward"
		default:
			direction = strings.ToLower(rule.Chain)
		}

		// Normalize source/destination (0.0.0.0/0 = any)
		from := rule.Source
		if from == "0.0.0.0/0" || from == "anywhere" {
			from = ""
		}
		to := rule.Destination
		if to == "0.0.0.0/0" || to == "anywhere" {
			to = ""
		}

		// Protocol
		protocol := rule.Prot
		if protocol == "all" || protocol == "0" {
			protocol = ""
		}

		// Port (prefer dport, fall back to sport)
		port := rule.DPort
		if port == "" {
			port = rule.SPort
		}

		result := map[string]interface{}{
			"action":    action,
			"direction": direction,
			"protocol":  protocol,
			"from":      from,
			"to":        to,
			"chain":     rule.Chain,
			"target":    rule.Target,
			"table":     table,
		}

		if port != "" {
			result["port"] = port
		}
		if rule.DPort != "" {
			result["destination_port"] = rule.DPort
		}
		if rule.SPort != "" {
			result["source_port"] = rule.SPort
		}
		if rule.InInterface != "" && rule.InInterface != "*" {
			result["in_interface"] = rule.InInterface
		}
		if rule.OutInterface != "" && rule.OutInterface != "*" {
			result["out_interface"] = rule.OutInterface
		}
		// Extract actual iptables comment from /* ... */ markers
		if rule.Options != "" {
			if start := strings.Index(rule.Options, "/*"); start >= 0 {
				if end := strings.Index(rule.Options[start:], "*/"); end >= 0 {
					comment := strings.TrimSpace(rule.Options[start+2 : start+end])
					if comment != "" {
						result["comment"] = comment
					}
				}
			}
		}

		return result
	}

	// isSystemRule checks if a rule should be excluded in user_only mode
	isSystemRule := func(rule hal.FirewallRule) bool {
		if systemChains[rule.Chain] {
			return true
		}
		// Chains starting with DOCKER are system-managed
		if strings.HasPrefix(rule.Chain, "DOCKER") {
			return true
		}
		// Rules targeting Docker chains
		if strings.HasPrefix(rule.Target, "DOCKER") {
			return true
		}
		return false
	}

	// Build response grouped by "table:chain"
	rulesByTableChain := make(map[string][]interface{})

	addRules := func(halRules []hal.FirewallRule, table string) {
		for _, rule := range halRules {
			if userOnly && isSystemRule(rule) {
				continue
			}
			key := table + ":" + rule.Chain
			rulesByTableChain[key] = append(rulesByTableChain[key], normalizeRule(rule, table))
		}
	}

	// When user_only, only include filter table rules
	if userOnly {
		addRules(rulesResp.Filter, "filter")
	} else {
		addRules(rulesResp.Filter, "filter")
		addRules(rulesResp.NAT, "nat")
		addRules(rulesResp.Mangle, "mangle")
		addRules(rulesResp.Raw, "raw")
	}

	// Filter by chain/table if specified
	totalCount := 0
	if chainFilter != "" || tableFilter != "" {
		filtered := make(map[string][]interface{})
		for k, rules := range rulesByTableChain {
			parts := strings.SplitN(k, ":", 2)
			if len(parts) != 2 {
				continue
			}
			table := parts[0]
			chain := parts[1]

			matchChain := chainFilter == "" || strings.EqualFold(chain, chainFilter)
			matchTable := tableFilter == "" || strings.EqualFold(table, tableFilter)
			if matchChain && matchTable {
				filtered[k] = rules
				totalCount += len(rules)
			}
		}
		rulesByTableChain = filtered
	} else {
		for _, rules := range rulesByTableChain {
			totalCount += len(rules)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rulesByTableChain,
		"count": totalCount,
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/rules [post]
func (h *FirewallHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

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

	if err := managers.ValidateChain(req.Chain); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Set defaults
	if req.Table == "" {
		req.Table = "filter"
	}

	if err := managers.ValidateTable(req.Table); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(req.Args) == 0 {
		writeError(w, http.StatusBadRequest, "Args cannot be empty")
		return
	}

	if err := h.firewall.AddRule(r.Context(), req.Table, req.Chain, req.Args); err != nil {
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/rules [delete]
func (h *FirewallHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

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

	if err := managers.ValidateChain(req.Chain); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Set defaults
	if req.Table == "" {
		req.Table = "filter"
	}

	if err := managers.ValidateTable(req.Table); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(req.Args) == 0 {
		writeError(w, http.StatusBadRequest, "Args cannot be empty")
		return
	}

	if err := h.firewall.DeleteRule(r.Context(), req.Table, req.Chain, req.Args); err != nil {
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/ipforward [get]
func (h *FirewallHandler) GetIPForward(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	enabled, err := h.firewall.GetForwardingStatus(r.Context())
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/ipforward [put]
func (h *FirewallHandler) SetIPForward(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	var req SetIPForwardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.firewall.SetForwarding(r.Context(), req.Enabled); err != nil {
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/port/allow [post]
func (h *FirewallHandler) AllowPort(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

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

	if err := managers.ValidateProtocol(req.Protocol); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result := h.firewall.AllowPort(r.Context(), req.Port, req.Protocol, "")
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, "Failed to allow port: "+result.Message)
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/port/block [post]
func (h *FirewallHandler) BlockPort(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

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

	if err := managers.ValidateProtocol(req.Protocol); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result := h.firewall.BlockPort(r.Context(), req.Port, req.Protocol)
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, "Failed to block port: "+result.Message)
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
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/port/{port} [delete]
func (h *FirewallHandler) DeletePortRule(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

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

	if err := managers.ValidateProtocol(protocol); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Delete both ACCEPT and DROP rules for the port (best-effort)
	h.firewall.DeletePortRules(r.Context(), port, protocol)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"port":    port,
		"message": "Port rules deleted",
	})
}

// AllowService godoc
// @Summary Allow a service through the firewall
// @Description Opens firewall for a named service (ssh, http, https, etc.)
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Param service path string true "Service name (ssh, http, https, dns, etc.)"
// @Success 200 {object} map[string]interface{} "success, service, message"
// @Failure 400 {object} ErrorResponse "Unknown service"
// @Failure 500 {object} ErrorResponse "Failed to allow service"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/service/{service}/allow [post]
func (h *FirewallHandler) AllowService(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	service := chi.URLParam(r, "service")

	result := h.firewall.AllowService(r.Context(), service)
	if result.Status == "error" {
		// Check if it's an unknown service vs HAL failure
		if strings.Contains(result.Message, "Unknown service") {
			writeError(w, http.StatusBadRequest, result.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to allow service: "+result.Message)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"service": service,
		"message": result.Message,
	})
}

// SaveRules godoc
// @Summary Save firewall rules
// @Description Saves current firewall rules to persistent storage so they survive reboots
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "status, message"
// @Failure 500 {object} ErrorResponse "Failed to save rules"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/save [post]
func (h *FirewallHandler) SaveRules(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	result := h.firewall.SaveRules(r.Context())
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// RestoreRules godoc
// @Summary Restore firewall rules
// @Description Restores firewall rules from persistent storage
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "status, message"
// @Failure 500 {object} ErrorResponse "Failed to restore rules"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/restore [post]
func (h *FirewallHandler) RestoreRules(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	result := h.firewall.RestoreRules(r.Context())
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ResetFirewall godoc
// @Summary Reset firewall to defaults
// @Description Flushes all firewall rules and resets to default allow-all policy
// @Tags Firewall
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "status, message"
// @Failure 500 {object} ErrorResponse "Failed to reset firewall"
// @Failure 503 {object} ErrorResponse "Firewall service unavailable"
// @Router /firewall/reset [post]
func (h *FirewallHandler) ResetFirewall(w http.ResponseWriter, r *http.Request) {
	if h.firewall == nil {
		writeError(w, http.StatusServiceUnavailable, "Firewall service unavailable")
		return
	}

	result := h.firewall.ResetFirewall(r.Context())
	if result.Status == "error" {
		writeError(w, http.StatusInternalServerError, result.Message)
		return
	}

	writeJSON(w, http.StatusOK, result)
}
