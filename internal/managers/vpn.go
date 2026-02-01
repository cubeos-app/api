// Package managers provides VPN client management for CubeOS.
// Supports WireGuard and OpenVPN configurations.
package managers

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/config"
)

// VPNType represents the type of VPN
type VPNType string

const (
	VPNTypeWireGuard VPNType = "wireguard"
	VPNTypeOpenVPN   VPNType = "openvpn"
)

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

// VPNManager handles VPN client operations
type VPNManager struct {
	cfg              *config.Config
	wireGuardConfDir string
	openVPNConfDir   string
}

// NewVPNManager creates a new VPN manager
func NewVPNManager(cfg *config.Config) *VPNManager {
	return &VPNManager{
		cfg:              cfg,
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

	// Check which one is active
	activeWG := m.isWireGuardActive()
	activeOVPN := m.isOpenVPNActive()

	for _, cfg := range configs {
		if cfg.Type == VPNTypeWireGuard && activeWG {
			// Check if this specific config is active
			cfg.IsActive = m.isWireGuardConfigActive(cfg.Name)
		} else if cfg.Type == VPNTypeOpenVPN && activeOVPN {
			cfg.IsActive = true // OpenVPN typically has one active connection
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
func (m *VPNManager) AddConfig(ctx context.Context, name string, vpnType VPNType, configData string) (*VPNConfig, error) {
	// Validate name
	if name == "" {
		return nil, fmt.Errorf("configuration name is required")
	}
	if strings.ContainsAny(name, "/\\. ") {
		return nil, fmt.Errorf("configuration name contains invalid characters")
	}

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

	return nil
}

// Connect establishes a VPN connection
func (m *VPNManager) Connect(ctx context.Context, name string) error {
	cfg, err := m.GetConfig(ctx, name)
	if err != nil {
		return err
	}

	switch cfg.Type {
	case VPNTypeWireGuard:
		return m.connectWireGuard(cfg)
	case VPNTypeOpenVPN:
		return m.connectOpenVPN(cfg)
	default:
		return fmt.Errorf("unsupported VPN type: %s", cfg.Type)
	}
}

// Disconnect terminates a VPN connection
func (m *VPNManager) Disconnect(ctx context.Context, name string) error {
	cfg, err := m.GetConfig(ctx, name)
	if err != nil {
		return err
	}

	switch cfg.Type {
	case VPNTypeWireGuard:
		return m.disconnectWireGuard(cfg)
	case VPNTypeOpenVPN:
		return m.disconnectOpenVPN()
	default:
		return fmt.Errorf("unsupported VPN type: %s", cfg.Type)
	}
}

// GetStatus returns the current VPN connection status
func (m *VPNManager) GetStatus(ctx context.Context) (*VPNStatus, error) {
	status := &VPNStatus{
		Connected: false,
	}

	// Check WireGuard first
	if m.isWireGuardActive() {
		status.Connected = true
		status.Type = VPNTypeWireGuard
		status.ActiveConfig = m.getActiveWireGuardConfig()
		m.populateWireGuardStats(status)
		return status, nil
	}

	// Check OpenVPN
	if m.isOpenVPNActive() {
		status.Connected = true
		status.Type = VPNTypeOpenVPN
		status.ActiveConfig = "openvpn"
		return status, nil
	}

	return status, nil
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

func (m *VPNManager) isWireGuardActive() bool {
	cmd := exec.Command("wg", "show")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(output) > 0
}

func (m *VPNManager) isWireGuardConfigActive(name string) bool {
	cmd := exec.Command("wg", "show", name)
	err := cmd.Run()
	return err == nil
}

func (m *VPNManager) getActiveWireGuardConfig() string {
	cmd := exec.Command("wg", "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	interfaces := strings.TrimSpace(string(output))
	if interfaces != "" {
		// Return first interface
		return strings.Split(interfaces, "\n")[0]
	}
	return ""
}

func (m *VPNManager) populateWireGuardStats(status *VPNStatus) {
	iface := status.ActiveConfig
	if iface == "" {
		return
	}

	cmd := exec.Command("wg", "show", iface, "transfer")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	// Parse transfer stats: "peer_pubkey\trx_bytes\ttx_bytes"
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			fmt.Sscanf(parts[1], "%d", &status.BytesReceived)
			fmt.Sscanf(parts[2], "%d", &status.BytesSent)
		}
	}

	// Get endpoint
	cmd = exec.Command("wg", "show", iface, "endpoints")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				status.Endpoint = parts[1]
				break
			}
		}
	}
}

func (m *VPNManager) connectWireGuard(cfg *VPNConfig) error {
	// Use wg-quick to bring up the interface
	cmd := exec.Command("wg-quick", "up", cfg.ConfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to connect WireGuard: %s: %w", string(output), err)
	}
	return nil
}

func (m *VPNManager) disconnectWireGuard(cfg *VPNConfig) error {
	// Use wg-quick to bring down the interface
	cmd := exec.Command("wg-quick", "down", cfg.ConfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disconnect WireGuard: %s: %w", string(output), err)
	}
	return nil
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

func (m *VPNManager) isOpenVPNActive() bool {
	// Check if openvpn process is running
	cmd := exec.Command("pgrep", "-x", "openvpn")
	err := cmd.Run()
	return err == nil
}

func (m *VPNManager) connectOpenVPN(cfg *VPNConfig) error {
	// Disconnect any existing connection first
	m.disconnectOpenVPN()

	// Start OpenVPN in daemon mode
	cmd := exec.Command("openvpn", "--config", cfg.ConfigPath, "--daemon")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to connect OpenVPN: %s: %w", string(output), err)
	}

	// Wait a moment for connection to establish
	time.Sleep(2 * time.Second)

	if !m.isOpenVPNActive() {
		return fmt.Errorf("OpenVPN failed to start")
	}

	return nil
}

func (m *VPNManager) disconnectOpenVPN() error {
	// Kill openvpn process
	cmd := exec.Command("pkill", "-x", "openvpn")
	cmd.Run() // Ignore errors - process might not be running
	return nil
}

// SetAutoConnect enables or disables auto-connect for a VPN config
func (m *VPNManager) SetAutoConnect(ctx context.Context, name string, autoConnect bool) error {
	cfg, err := m.GetConfig(ctx, name)
	if err != nil {
		return err
	}

	// For WireGuard, we can use systemd to enable/disable the service
	if cfg.Type == VPNTypeWireGuard {
		serviceName := fmt.Sprintf("wg-quick@%s", name)
		var cmd *exec.Cmd
		if autoConnect {
			cmd = exec.Command("systemctl", "enable", serviceName)
		} else {
			cmd = exec.Command("systemctl", "disable", serviceName)
		}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set auto-connect: %w", err)
		}
	}

	// For OpenVPN, we'd need to manage a systemd service or startup script
	// This is a simplified implementation

	return nil
}

// GetPublicIP returns the current public IP address
func (m *VPNManager) GetPublicIP(ctx context.Context) (string, error) {
	cmd := exec.Command("curl", "-s", "--max-time", "5", "https://api.ipify.org")
	output, err := cmd.Output()
	if err != nil {
		// Try alternative
		cmd = exec.Command("curl", "-s", "--max-time", "5", "https://ifconfig.me")
		output, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to get public IP: %w", err)
		}
	}
	return strings.TrimSpace(string(output)), nil
}
