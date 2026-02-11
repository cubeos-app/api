// Package managers provides VPN client management for CubeOS.
// Supports WireGuard and OpenVPN configurations.
// This version uses the HAL (Hardware Abstraction Layer) service for
// VPN operations since the API runs in a Swarm container without
// direct access to host VPN commands.
package managers

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/hal"
)

// VPNType represents the type of VPN
type VPNType string

const (
	VPNTypeWireGuard VPNType = "wireguard"
	VPNTypeOpenVPN   VPNType = "openvpn"
)

var reInvalidVPNChar = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// sanitizeVPNName replaces characters invalid in Linux interface names with hyphens.
// WireGuard uses the config name as the interface name, so it must be [a-zA-Z0-9_-]{1,15}.
func sanitizeVPNName(name string) string {
	s := reInvalidVPNChar.ReplaceAllString(name, "-")
	// Collapse multiple hyphens
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	// Linux interface names are max 15 chars
	if len(s) > 15 {
		s = s[:15]
	}
	s = strings.TrimRight(s, "-")
	return s
}

// VPNConfig represents a VPN configuration
type VPNConfig struct {
	ID          int64     `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Type        VPNType   `json:"type" db:"type"`
	ConfigPath  string    `json:"config_path" db:"config_path"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	AutoConnect bool      `json:"auto_connect" db:"auto_connect"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// VPNStatus represents the current VPN connection status
type VPNStatus struct {
	Connected     bool      `json:"connected"`
	ActiveConfig  string    `json:"active_config,omitempty"`
	Type          VPNType   `json:"type,omitempty"`
	PublicIP      string    `json:"public_ip,omitempty"`
	ConnectedAt   time.Time `json:"connected_at,omitempty"`
	BytesSent     int64     `json:"bytes_sent,omitempty"`
	BytesReceived int64     `json:"bytes_received,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"`
}

// VPNManager handles VPN client operations via HAL
type VPNManager struct {
	cfg              *config.Config
	hal              *hal.Client
	wireGuardConfDir string
	openVPNConfDir   string
}

// NewVPNManager creates a new VPN manager
func NewVPNManager(cfg *config.Config, halClient *hal.Client) *VPNManager {
	return &VPNManager{
		cfg:              cfg,
		hal:              halClient,
		wireGuardConfDir: "/cubeos/config/vpn/wireguard",
		openVPNConfDir:   "/cubeos/config/vpn/openvpn",
	}
}

// ListConfigs returns all VPN configurations
func (m *VPNManager) ListConfigs(ctx context.Context) ([]*VPNConfig, error) {
	var configs []*VPNConfig

	// List WireGuard configs
	wgConfigs, err := m.listWireGuardConfigs()
	if err == nil {
		configs = append(configs, wgConfigs...)
	}

	// List OpenVPN configs
	ovpnConfigs, err := m.listOpenVPNConfigs()
	if err == nil {
		configs = append(configs, ovpnConfigs...)
	}

	// Check active status via HAL
	halStatus, err := m.hal.GetVPNStatus(ctx)
	if err == nil {
		for _, cfg := range configs {
			if cfg.Type == VPNTypeWireGuard && halStatus.WireGuard.Active {
				// Check if this specific interface is active
				for _, iface := range halStatus.WireGuard.Interfaces {
					if iface == cfg.Name {
						cfg.IsActive = true
						break
					}
				}
			} else if cfg.Type == VPNTypeOpenVPN && halStatus.OpenVPN.Active {
				cfg.IsActive = true
			}
		}
	}

	return configs, nil
}

// GetConfig returns a specific VPN configuration by ID or name
func (m *VPNManager) GetConfig(ctx context.Context, nameOrID string) (*VPNConfig, error) {
	configs, err := m.ListConfigs(ctx)
	if err != nil {
		return nil, err
	}

	for _, cfg := range configs {
		if cfg.Name == nameOrID || fmt.Sprintf("%d", cfg.ID) == nameOrID {
			return cfg, nil
		}
	}

	return nil, fmt.Errorf("VPN configuration not found: %s", nameOrID)
}

// AddConfig adds a new VPN configuration
func (m *VPNManager) AddConfig(ctx context.Context, name string, vpnType VPNType, configData string, username, password string) (*VPNConfig, error) {
	// Validate name
	if name == "" {
		return nil, fmt.Errorf("configuration name is required")
	}

	// Sanitize name: replace invalid chars with hyphen, then validate
	// WireGuard interface names must match [a-zA-Z0-9_-] and be max 15 chars
	sanitized := sanitizeVPNName(name)
	if sanitized == "" || sanitized == "-" {
		return nil, fmt.Errorf("configuration name contains only invalid characters")
	}
	name = sanitized

	// Decode base64 config if needed
	decoded, err := base64.StdEncoding.DecodeString(configData)
	if err != nil {
		// Assume it's plain text
		decoded = []byte(configData)
	}

	var configPath string
	switch vpnType {
	case VPNTypeWireGuard:
		configPath = filepath.Join(m.wireGuardConfDir, name+".conf")
	case VPNTypeOpenVPN:
		configPath = filepath.Join(m.openVPNConfDir, name+".ovpn")
	default:
		return nil, fmt.Errorf("unsupported VPN type: %s", vpnType)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write config file
	if err := os.WriteFile(configPath, decoded, 0600); err != nil {
		return nil, fmt.Errorf("failed to write config file: %w", err)
	}

	// Write OpenVPN auth credentials file if provided
	if vpnType == VPNTypeOpenVPN && username != "" && password != "" {
		authPath := filepath.Join(m.openVPNConfDir, name+".auth")
		authData := username + "\n" + password + "\n"
		if err := os.WriteFile(authPath, []byte(authData), 0600); err != nil {
			return nil, fmt.Errorf("failed to write auth file: %w", err)
		}
	}

	return &VPNConfig{
		Name:       name,
		Type:       vpnType,
		ConfigPath: configPath,
		IsActive:   false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}, nil
}

// DeleteConfig removes a VPN configuration
func (m *VPNManager) DeleteConfig(ctx context.Context, name string) error {
	cfg, err := m.GetConfig(ctx, name)
	if err != nil {
		return err
	}

	// Disconnect first if active
	if cfg.IsActive {
		if err := m.Disconnect(ctx, name); err != nil {
			return fmt.Errorf("failed to disconnect before deletion: %w", err)
		}
	}

	// Remove config file
	if err := os.Remove(cfg.ConfigPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %w", err)
	}

	// Remove auth file if it exists (OpenVPN credentials)
	authPath := strings.TrimSuffix(cfg.ConfigPath, filepath.Ext(cfg.ConfigPath)) + ".auth"
	_ = os.Remove(authPath) // Ignore error if not exists

	return nil
}

// Connect establishes a VPN connection via HAL
func (m *VPNManager) Connect(ctx context.Context, name string) error {
	cfg, err := m.GetConfig(ctx, name)
	if err != nil {
		return err
	}

	switch cfg.Type {
	case VPNTypeWireGuard:
		return m.hal.WireGuardUp(ctx, name)
	case VPNTypeOpenVPN:
		return m.hal.OpenVPNUp(ctx, name)
	default:
		return fmt.Errorf("unsupported VPN type: %s", cfg.Type)
	}
}

// Disconnect terminates a VPN connection via HAL
func (m *VPNManager) Disconnect(ctx context.Context, name string) error {
	cfg, err := m.GetConfig(ctx, name)
	if err != nil {
		return err
	}

	switch cfg.Type {
	case VPNTypeWireGuard:
		return m.hal.WireGuardDown(ctx, name)
	case VPNTypeOpenVPN:
		return m.hal.OpenVPNDown(ctx, name)
	default:
		return fmt.Errorf("unsupported VPN type: %s", cfg.Type)
	}
}

// GetStatus returns the current VPN connection status via HAL
func (m *VPNManager) GetStatus(ctx context.Context) (*VPNStatus, error) {
	status := &VPNStatus{
		Connected: false,
	}

	halStatus, err := m.hal.GetVPNStatus(ctx)
	if err != nil {
		return status, nil // Return empty status on error
	}

	// Check WireGuard first
	if halStatus.WireGuard.Active {
		status.Connected = true
		status.Type = VPNTypeWireGuard
		if len(halStatus.WireGuard.Interfaces) > 0 {
			status.ActiveConfig = halStatus.WireGuard.Interfaces[0]
		}
		return status, nil
	}

	// Check OpenVPN
	if halStatus.OpenVPN.Active {
		status.Connected = true
		status.Type = VPNTypeOpenVPN
		status.ActiveConfig = "openvpn"
		return status, nil
	}

	return status, nil
}

// SetAutoConnect enables or disables auto-connect for a VPN config via HAL
func (m *VPNManager) SetAutoConnect(ctx context.Context, name string, autoConnect bool) error {
	cfg, err := m.GetConfig(ctx, name)
	if err != nil {
		return err
	}

	// For WireGuard, use systemd service via HAL
	if cfg.Type == VPNTypeWireGuard {
		// HAL doesn't have enable/disable service yet - this would need to be added
		// For now, we can use start/stop as a workaround
		if autoConnect {
			return fmt.Errorf("auto-connect via HAL not yet implemented")
		}
	}

	return nil
}

// GetPublicIP returns the current public IP address via HAL (host network).
// HAL runs on the host, so its outbound traffic goes through VPN tunnels when active.
// The API runs in a Swarm container where traffic doesn't route through VPN.
func (m *VPNManager) GetPublicIP(ctx context.Context) (string, error) {
	ip, err := m.hal.GetPublicIP(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get public IP via HAL: %w", err)
	}
	return ip, nil
}

// WireGuard-specific methods

func (m *VPNManager) listWireGuardConfigs() ([]*VPNConfig, error) {
	var configs []*VPNConfig

	files, err := os.ReadDir(m.wireGuardConfDir)
	if err != nil {
		if os.IsNotExist(err) {
			return configs, nil
		}
		return nil, err
	}

	for i, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".conf") {
			name := strings.TrimSuffix(f.Name(), ".conf")
			info, _ := f.Info()
			configs = append(configs, &VPNConfig{
				ID:         int64(i + 1),
				Name:       name,
				Type:       VPNTypeWireGuard,
				ConfigPath: filepath.Join(m.wireGuardConfDir, f.Name()),
				CreatedAt:  info.ModTime(),
				UpdatedAt:  info.ModTime(),
			})
		}
	}

	return configs, nil
}

// OpenVPN-specific methods

func (m *VPNManager) listOpenVPNConfigs() ([]*VPNConfig, error) {
	var configs []*VPNConfig

	files, err := os.ReadDir(m.openVPNConfDir)
	if err != nil {
		if os.IsNotExist(err) {
			return configs, nil
		}
		return nil, err
	}

	baseID := 1000 // Offset to avoid ID conflicts with WireGuard
	for i, f := range files {
		if !f.IsDir() && (strings.HasSuffix(f.Name(), ".ovpn") || strings.HasSuffix(f.Name(), ".conf")) {
			name := strings.TrimSuffix(strings.TrimSuffix(f.Name(), ".ovpn"), ".conf")
			info, _ := f.Info()
			configs = append(configs, &VPNConfig{
				ID:         int64(baseID + i + 1),
				Name:       name,
				Type:       VPNTypeOpenVPN,
				ConfigPath: filepath.Join(m.openVPNConfDir, f.Name()),
				CreatedAt:  info.ModTime(),
				UpdatedAt:  info.ModTime(),
			})
		}
	}

	return configs, nil
}
