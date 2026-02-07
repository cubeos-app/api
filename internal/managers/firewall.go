// Package managers provides firewall/iptables management for CubeOS.
// This version uses the HAL (Hardware Abstraction Layer) service for
// firewall operations since the API runs in a Swarm container without
// direct access to host iptables commands.
package managers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"cubeos-api/internal/config"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/models"
)

// FirewallManager handles iptables firewall operations via HAL
type FirewallManager struct {
	cfg *config.Config
	hal *hal.Client
}

// NewFirewallManager creates a new FirewallManager
func NewFirewallManager(cfg *config.Config, halClient *hal.Client) *FirewallManager {
	if halClient == nil {
		halClient = hal.NewClient("")
	}
	return &FirewallManager{
		cfg: cfg,
		hal: halClient,
	}
}

// validTables is the set of valid iptables table names
var validTables = map[string]bool{
	"filter": true,
	"nat":    true,
	"mangle": true,
	"raw":    true,
}

// validChains is the set of valid iptables built-in chain names
var validChains = map[string]bool{
	"INPUT":       true,
	"OUTPUT":      true,
	"FORWARD":     true,
	"PREROUTING":  true,
	"POSTROUTING": true,
}

// validProtocols is the set of valid protocol names
var validProtocols = map[string]bool{
	"tcp":  true,
	"udp":  true,
	"icmp": true,
	"all":  true,
}

// ValidateTable checks if a table name is valid
func ValidateTable(table string) error {
	if !validTables[strings.ToLower(table)] {
		return fmt.Errorf("invalid table: %s (must be filter, nat, mangle, or raw)", table)
	}
	return nil
}

// ValidateChain checks if a chain name is valid
func ValidateChain(chain string) error {
	if !validChains[strings.ToUpper(chain)] {
		return fmt.Errorf("invalid chain: %s (must be INPUT, OUTPUT, FORWARD, PREROUTING, or POSTROUTING)", chain)
	}
	return nil
}

// ValidateProtocol checks if a protocol name is valid
func ValidateProtocol(protocol string) error {
	if !validProtocols[strings.ToLower(protocol)] {
		return fmt.Errorf("invalid protocol: %s (must be tcp, udp, icmp, or all)", protocol)
	}
	return nil
}

// GetStatus returns complete firewall status via HAL
func (m *FirewallManager) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	// Get NAT status
	natEnabled := false
	natStatus, err := m.GetNATStatus(ctx)
	if err == nil && natStatus != nil {
		if enabled, ok := natStatus["nat_enabled"].(bool); ok {
			natEnabled = enabled
		}
	}

	// Get forwarding status
	forwardingEnabled, _ := m.GetForwardingStatus(ctx)

	// Get rules count
	rulesCount := 0
	rulesResp, err := m.hal.GetFirewallRulesDetailed(ctx)
	if err == nil && rulesResp != nil {
		rulesCount = len(rulesResp.Filter) + len(rulesResp.NAT) + len(rulesResp.Mangle) + len(rulesResp.Raw)
	}

	return map[string]interface{}{
		"enabled":            true, // iptables is always "enabled" on Linux
		"nat_enabled":        natEnabled,
		"forwarding_enabled": forwardingEnabled,
		"rules_count":        rulesCount,
	}, nil
}

// GetNATStatus returns NAT/masquerade status via HAL
func (m *FirewallManager) GetNATStatus(ctx context.Context) (map[string]interface{}, error) {
	status, err := m.hal.GetNetworkStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get NAT status: %w", err)
	}
	return status, nil
}

// EnableNAT enables NAT/masquerade via HAL
func (m *FirewallManager) EnableNAT(ctx context.Context) *models.SuccessResponse {
	// Enable IP forwarding first
	if err := m.hal.EnableIPForward(ctx); err != nil {
		return &models.SuccessResponse{Status: "error", Message: fmt.Sprintf("Failed to enable IP forward: %v", err)}
	}

	// Enable NAT
	if err := m.hal.EnableNAT(ctx, m.cfg.APInterface, m.cfg.WANInterface); err != nil {
		return &models.SuccessResponse{Status: "error", Message: fmt.Sprintf("Failed to enable NAT: %v", err)}
	}

	return &models.SuccessResponse{Status: "success", Message: "NAT enabled"}
}

// DisableNAT disables NAT/masquerade via HAL
func (m *FirewallManager) DisableNAT(ctx context.Context) *models.SuccessResponse {
	if err := m.hal.DisableNAT(ctx); err != nil {
		return &models.SuccessResponse{Status: "error", Message: fmt.Sprintf("Failed to disable NAT: %v", err)}
	}

	return &models.SuccessResponse{Status: "success", Message: "NAT disabled"}
}

// GetForwardingStatus returns IP forwarding status via HAL
func (m *FirewallManager) GetForwardingStatus(ctx context.Context) (bool, error) {
	return m.hal.GetForwardingStatus(ctx)
}

// SetForwarding enables or disables IP forwarding via HAL
func (m *FirewallManager) SetForwarding(ctx context.Context, enabled bool) error {
	if enabled {
		return m.hal.EnableIPForward(ctx)
	}
	return m.hal.DisableIPForward(ctx)
}

// GetRulesDetailed returns structured firewall rules grouped by table from HAL
func (m *FirewallManager) GetRulesDetailed(ctx context.Context) (*hal.FirewallRulesResponse, error) {
	resp, err := m.hal.GetFirewallRulesDetailed(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get firewall rules: %w", err)
	}
	return resp, nil
}

// GetRules returns firewall rules for a specific table from HAL
func (m *FirewallManager) GetRules(ctx context.Context, table string) ([]models.FirewallRule, error) {
	resp, err := m.hal.GetFirewallRulesDetailed(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get firewall rules: %w", err)
	}

	var halRules []hal.FirewallRule
	switch strings.ToLower(table) {
	case "filter":
		halRules = resp.Filter
	case "nat":
		halRules = resp.NAT
	case "mangle":
		halRules = resp.Mangle
	case "raw":
		halRules = resp.Raw
	default:
		halRules = resp.Filter
	}

	// Convert HAL rules to model rules
	rules := make([]models.FirewallRule, 0, len(halRules))
	for _, hr := range halRules {
		rules = append(rules, models.FirewallRule{
			Chain:       hr.Chain,
			Target:      hr.Target,
			Protocol:    hr.Prot,
			Source:      hr.Source,
			Destination: hr.Destination,
		})
	}

	return rules, nil
}

// AddRule adds a generic iptables rule via HAL
func (m *FirewallManager) AddRule(ctx context.Context, table, chain string, args []string) error {
	if err := m.hal.AddFirewallRule(ctx, table, chain, args); err != nil {
		return fmt.Errorf("failed to add firewall rule: %w", err)
	}
	return nil
}

// DeleteRule removes a generic iptables rule via HAL
func (m *FirewallManager) DeleteRule(ctx context.Context, table, chain string, args []string) error {
	if err := m.hal.DeleteFirewallRule(ctx, table, chain, args); err != nil {
		return fmt.Errorf("failed to delete firewall rule: %w", err)
	}
	return nil
}

// AllowPort allows incoming traffic on a port via HAL
func (m *FirewallManager) AllowPort(ctx context.Context, port int, protocol, comment string) *models.SuccessResponse {
	args := []string{"-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	if comment != "" {
		args = append(args, "-m", "comment", "--comment", comment)
	}

	if err := m.hal.AddFirewallRule(ctx, "filter", "INPUT", args); err != nil {
		return &models.SuccessResponse{Status: "error", Message: err.Error()}
	}

	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("Allowed port %d/%s", port, protocol),
	}
}

// BlockPort blocks incoming traffic on a port via HAL
func (m *FirewallManager) BlockPort(ctx context.Context, port int, protocol string) *models.SuccessResponse {
	args := []string{"-p", protocol, "--dport", strconv.Itoa(port), "-j", "DROP"}

	if err := m.hal.AddFirewallRule(ctx, "filter", "INPUT", args); err != nil {
		return &models.SuccessResponse{Status: "error", Message: err.Error()}
	}

	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("Blocked port %d/%s", port, protocol),
	}
}

// RemovePortRule removes a port rule via HAL
func (m *FirewallManager) RemovePortRule(ctx context.Context, port int, protocol, action string) *models.SuccessResponse {
	args := []string{"-p", protocol, "--dport", strconv.Itoa(port), "-j", action}

	if err := m.hal.DeleteFirewallRule(ctx, "filter", "INPUT", args); err != nil {
		return &models.SuccessResponse{Status: "error", Message: err.Error()}
	}

	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("Removed port rule %d/%s", port, protocol),
	}
}

// DeletePortRules removes both ACCEPT and DROP rules for a port via HAL.
// Errors are ignored since the rules may not exist.
func (m *FirewallManager) DeletePortRules(ctx context.Context, port int, protocol string) {
	portStr := strconv.Itoa(port)
	argsAccept := []string{"-p", protocol, "--dport", portStr, "-j", "ACCEPT"}
	argsDrop := []string{"-p", protocol, "--dport", portStr, "-j", "DROP"}

	// Best-effort: rules may not exist
	_ = m.hal.DeleteFirewallRule(ctx, "filter", "INPUT", argsAccept)
	_ = m.hal.DeleteFirewallRule(ctx, "filter", "INPUT", argsDrop)
}

// SetIPForward enables or disables IP forwarding via HAL
func (m *FirewallManager) SetIPForward(ctx context.Context, enabled bool) *models.SuccessResponse {
	var err error
	if enabled {
		err = m.hal.EnableIPForward(ctx)
	} else {
		err = m.hal.DisableIPForward(ctx)
	}

	if err != nil {
		return &models.SuccessResponse{Status: "error", Message: err.Error()}
	}

	value := "0"
	if enabled {
		value = "1"
	}
	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("IP forwarding set to %s", value),
	}
}

// ServicePorts maps common service names to their port/protocol pairs
var ServicePorts = map[string][]struct {
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

// AllowService allows traffic for a common service by name
func (m *FirewallManager) AllowService(ctx context.Context, service string) *models.SuccessResponse {
	ports, ok := ServicePorts[strings.ToLower(service)]
	if !ok {
		return &models.SuccessResponse{Status: "error", Message: fmt.Sprintf("Unknown service: %s", service)}
	}

	for _, p := range ports {
		result := m.AllowPort(ctx, p.Port, p.Protocol, fmt.Sprintf("Allow %s", service))
		if result.Status == "error" {
			return result
		}
	}

	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("Service %s allowed through firewall", service),
	}
}

// SaveRules saves current iptables rules to persistent storage via HAL
func (m *FirewallManager) SaveRules(ctx context.Context) *models.SuccessResponse {
	if err := m.hal.SaveFirewallRules(ctx); err != nil {
		return &models.SuccessResponse{Status: "error", Message: fmt.Sprintf("Failed to save firewall rules: %v", err)}
	}
	return &models.SuccessResponse{Status: "success", Message: "Firewall rules saved"}
}

// RestoreRules restores iptables rules from persistent storage via HAL
func (m *FirewallManager) RestoreRules(ctx context.Context) *models.SuccessResponse {
	if err := m.hal.RestoreFirewallRules(ctx); err != nil {
		return &models.SuccessResponse{Status: "error", Message: fmt.Sprintf("Failed to restore firewall rules: %v", err)}
	}
	return &models.SuccessResponse{Status: "success", Message: "Firewall rules restored"}
}

// ResetFirewall flushes all iptables rules and resets to defaults via HAL
func (m *FirewallManager) ResetFirewall(ctx context.Context) *models.SuccessResponse {
	if err := m.hal.ResetFirewall(ctx); err != nil {
		return &models.SuccessResponse{Status: "error", Message: fmt.Sprintf("Failed to reset firewall: %v", err)}
	}
	return &models.SuccessResponse{Status: "success", Message: "Firewall reset to defaults"}
}
