// Package managers provides firewall/iptables management for CubeOS.
// This version uses the HAL (Hardware Abstraction Layer) service for
// firewall operations since the API runs in a Swarm container without
// direct access to host iptables commands.
package managers

import (
	"context"
	"fmt"
	"strconv"

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

// GetStatus returns complete firewall status via HAL
func (m *FirewallManager) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	rules, err := m.hal.GetFirewallRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get firewall rules: %w", err)
	}

	// Get NAT status
	natStatus, _ := m.hal.GetNetworkStatus(ctx)

	return map[string]interface{}{
		"rules":      rules,
		"nat_status": natStatus,
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

// Common service ports
var ServicePorts = map[string]struct {
	Port     int
	Protocol string
}{
	"ssh":   {22, "tcp"},
	"http":  {80, "tcp"},
	"https": {443, "tcp"},
	"dns":   {53, "udp"},
}

// AllowService allows traffic for a common service by name
func (m *FirewallManager) AllowService(ctx context.Context, service string) *models.SuccessResponse {
	svc, ok := ServicePorts[service]
	if !ok {
		return &models.SuccessResponse{Status: "error", Message: fmt.Sprintf("Unknown service: %s", service)}
	}
	return m.AllowPort(ctx, svc.Port, svc.Protocol, fmt.Sprintf("Allow %s", service))
}

// GetRules returns all firewall rules (simplified for HAL)
func (m *FirewallManager) GetRules(ctx context.Context, table string) ([]models.FirewallRule, error) {
	rules, err := m.hal.GetFirewallRules(ctx)
	if err != nil {
		return nil, err
	}

	// HAL returns raw iptables output - we need to parse it
	// For now, return empty slice - full parsing would require HAL changes
	var parsedRules []models.FirewallRule

	// The HAL returns a map with table names as keys and raw output as values
	// In future, HAL should return structured data
	_ = rules

	return parsedRules, nil
}

// SaveRules saves iptables rules (requires HAL endpoint)
func (m *FirewallManager) SaveRules(ctx context.Context) *models.SuccessResponse {
	// This would need a new HAL endpoint: POST /hal/firewall/save
	return &models.SuccessResponse{
		Status:  "warning",
		Message: "Save rules via HAL not yet implemented",
	}
}

// RestoreRules restores iptables rules (requires HAL endpoint)
func (m *FirewallManager) RestoreRules(ctx context.Context) *models.SuccessResponse {
	// This would need a new HAL endpoint: POST /hal/firewall/restore
	return &models.SuccessResponse{
		Status:  "warning",
		Message: "Restore rules via HAL not yet implemented",
	}
}

// ResetFirewall resets firewall to default (requires HAL endpoint)
func (m *FirewallManager) ResetFirewall(ctx context.Context) *models.SuccessResponse {
	// This would need a new HAL endpoint: POST /hal/firewall/reset
	return &models.SuccessResponse{
		Status:  "warning",
		Message: "Reset firewall via HAL not yet implemented",
	}
}
