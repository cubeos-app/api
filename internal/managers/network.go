// Package managers provides network mode management for CubeOS.
// Network Modes V2: Supports 5 modes (OFFLINE, ONLINE_ETH, ONLINE_WIFI, SERVER_ETH, SERVER_WIFI)
// plus VPN overlay (None, WireGuard, OpenVPN, Tor)
package managers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/models"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

// NetworkMode, VPNMode, WiFiNetwork, and NetworkConfig types are defined in
// models/network.go — this package uses them via the models import.

// Default interface names - can be overridden via environment
const (
	DefaultAPInterface         = "wlan0"
	DefaultWANInterface        = "eth0"
	DefaultWiFiClientInterface = "wlan1"         // Fallback; overridden by CUBEOS_WIFI_CLIENT_INTERFACE or runtime detection
	DefaultFallbackIP          = "192.168.1.242" // V2: Server mode fallback
	DefaultFallbackGateway     = "192.168.1.1"   // V2: Server mode fallback gateway
)

// WiFiNetwork is defined in models/network.go

// NetworkStatus represents the current network status (V2: extended)
type NetworkStatus struct {
	Mode       models.NetworkMode `json:"mode"`
	Internet   bool               `json:"internet"`
	AP         *AccessPointStatus `json:"ap,omitempty"`
	Upstream   *UpstreamStatus    `json:"upstream,omitempty"`
	Subnet     string             `json:"subnet"`
	GatewayIP  string             `json:"gateway_ip"`
	VPNMode    models.VPNMode     `json:"vpn_mode"`              // V2
	VPNActive  bool               `json:"vpn_active"`            // V2
	VPNConfig  string             `json:"vpn_config,omitempty"`  // V2: Active config name
	PublicIP   string             `json:"public_ip,omitempty"`   // V2
	IsServer   bool               `json:"is_server"`             // V2: True for SERVER_* modes
	FallbackIP string             `json:"fallback_ip,omitempty"` // V2: For SERVER modes
}

// AccessPointStatus represents WiFi AP status
type AccessPointStatus struct {
	SSID      string `json:"ssid"`
	Interface string `json:"interface"`
	Clients   int    `json:"clients"`
	Channel   int    `json:"channel"`
	Hidden    bool   `json:"hidden"` // V2
}

// UpstreamStatus represents upstream connection status
type UpstreamStatus struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Gateway   string `json:"gateway"`
	Type      string `json:"type"` // "ethernet" or "wifi"
	SSID      string `json:"ssid,omitempty"`
}

// NetworkConfig is defined in models/network.go

// NetworkManager handles network mode and WiFi operations via HAL (V2: extended)
type NetworkManager struct {
	cfg                 *config.Config
	hal                 *hal.Client
	db                  *sqlx.DB
	currentMode         models.NetworkMode
	currentVPNMode      models.VPNMode // V2
	apInterface         string
	wanInterface        string
	wifiClientInterface string
	apSSID              string
	fallbackIP          string // V2
	fallbackGateway     string // V2: Gateway for static fallback
	piholeURL           string // Pi-hole API base URL (e.g. http://10.42.24.1:6001)
	piholePassword      string // Pi-hole API password
}

// NewNetworkManager creates a new network manager (V2: loads VPN mode too)
func NewNetworkManager(cfg *config.Config, halClient *hal.Client, db *sqlx.DB) *NetworkManager {
	// Get interface names from environment or use defaults
	apIface := getEnvOrDefault("CUBEOS_AP_INTERFACE", DefaultAPInterface)
	wanIface := getEnvOrDefault("CUBEOS_WAN_INTERFACE", DefaultWANInterface)
	wifiClientIface := getEnvOrDefault("CUBEOS_WIFI_CLIENT_INTERFACE", DefaultWiFiClientInterface)
	apSSID := getEnvOrDefault("CUBEOS_AP_SSID", "CubeOS")
	fallbackIP := getEnvOrDefault("CUBEOS_FALLBACK_IP", DefaultFallbackIP)
	fallbackGateway := getEnvOrDefault("CUBEOS_FALLBACK_GATEWAY", DefaultFallbackGateway)

	// Pi-hole configuration (runs on host network, port 6001)
	piholeURL := getEnvOrDefault("PIHOLE_URL", "http://10.42.24.1:6001")
	piholePassword := getEnvOrDefault("PIHOLE_PASSWORD", "cubeos")

	// Load mode and VPN from database
	mode, vpnMode := loadConfigFromDB(db)
	log.Info().Str("mode", string(mode)).Str("vpn", string(vpnMode)).Msg("NetworkManager: loaded config from database")

	return &NetworkManager{
		cfg:                 cfg,
		hal:                 halClient,
		db:                  db,
		currentMode:         mode,
		currentVPNMode:      vpnMode,
		apInterface:         apIface,
		wanInterface:        wanIface,
		wifiClientInterface: wifiClientIface,
		apSSID:              apSSID,
		fallbackIP:          fallbackIP,
		fallbackGateway:     fallbackGateway,
		piholeURL:           piholeURL,
		piholePassword:      piholePassword,
	}
}

// loadConfigFromDB loads the network mode and VPN mode from database (V2)
func loadConfigFromDB(db *sqlx.DB) (models.NetworkMode, models.VPNMode) {
	if db == nil {
		log.Warn().Msg("NetworkManager: no database connection, defaulting to offline")
		return models.NetworkModeOffline, models.VPNModeNone
	}

	var mode, vpnMode string
	err := db.QueryRow("SELECT mode, COALESCE(vpn_mode, 'none') FROM network_config WHERE id = 1").Scan(&mode, &vpnMode)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Info().Msg("NetworkManager: no network_config row, defaulting to offline")
		} else {
			log.Error().Err(err).Msg("NetworkManager: failed to load config from database")
		}
		return models.NetworkModeOffline, models.VPNModeNone
	}

	return parseNetworkMode(mode), parseVPNMode(vpnMode)
}

// parseNetworkMode converts string to models.NetworkMode (V2: includes SERVER modes)
func parseNetworkMode(mode string) models.NetworkMode {
	switch models.NetworkMode(mode) {
	case models.NetworkModeOnlineETH:
		return models.NetworkModeOnlineETH
	case models.NetworkModeOnlineWiFi:
		return models.NetworkModeOnlineWiFi
	case models.NetworkModeOnlineTether:
		return models.NetworkModeOnlineTether
	case models.NetworkModeServerETH:
		return models.NetworkModeServerETH
	case models.NetworkModeServerWiFi:
		return models.NetworkModeServerWiFi
	default:
		return models.NetworkModeOffline
	}
}

// parseVPNMode converts string to models.VPNMode (V2)
func parseVPNMode(mode string) models.VPNMode {
	switch models.VPNMode(mode) {
	case models.VPNModeWireGuard:
		return models.VPNModeWireGuard
	case models.VPNModeOpenVPN:
		return models.VPNModeOpenVPN
	case models.VPNModeTor:
		return models.VPNModeTor
	default:
		return models.VPNModeNone
	}
}

// saveConfigToDB persists the network config to database (V2: extended)
func (m *NetworkManager) saveConfigToDB(mode models.NetworkMode, vpnMode models.VPNMode, wifiSSID, wifiPassword string, staticIP models.StaticIPConfig) {
	if m.db == nil {
		return
	}

	_, err := m.db.Exec(`
		INSERT INTO network_config (id, mode, vpn_mode, wifi_ssid, wifi_password,
			use_static_ip, static_ip_address, static_ip_netmask, static_ip_gateway,
			static_dns_primary, static_dns_secondary, updated_at) 
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			mode = excluded.mode, 
			vpn_mode = excluded.vpn_mode,
			wifi_ssid = excluded.wifi_ssid, 
			wifi_password = excluded.wifi_password,
			use_static_ip = excluded.use_static_ip,
			static_ip_address = excluded.static_ip_address,
			static_ip_netmask = excluded.static_ip_netmask,
			static_ip_gateway = excluded.static_ip_gateway,
			static_dns_primary = excluded.static_dns_primary,
			static_dns_secondary = excluded.static_dns_secondary,
			updated_at = CURRENT_TIMESTAMP`,
		string(mode), string(vpnMode), wifiSSID, wifiPassword,
		staticIP.UseStaticIP, staticIP.StaticIPAddress, staticIP.StaticIPNetmask,
		staticIP.StaticIPGateway, staticIP.StaticDNSPrimary, staticIP.StaticDNSSecondary)
	if err != nil {
		log.Error().Err(err).Msg("NetworkManager: failed to persist config to database")
	} else {
		log.Info().Str("mode", string(mode)).Str("vpn", string(vpnMode)).
			Bool("static_ip", staticIP.UseStaticIP).Msg("NetworkManager: persisted config to database")
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// isValidDNSAddress validates a DNS server address (IPv4 or IPv6)
func isValidDNSAddress(addr string) bool {
	// Simple validation: must have at least one dot (IPv4) or colon (IPv6)
	// and must not contain dangerous characters
	if addr == "" {
		return false
	}
	// Check for valid IPv4 format (basic check)
	parts := strings.Split(addr, ".")
	if len(parts) == 4 {
		for _, p := range parts {
			if len(p) == 0 || len(p) > 3 {
				return false
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					return false
				}
			}
			var num int
			if _, err := fmt.Sscanf(p, "%d", &num); err != nil || num < 0 || num > 255 {
				return false
			}
		}
		return true
	}
	// Check for IPv6 (contains colons)
	if strings.Contains(addr, ":") {
		// Basic IPv6 validation: only hex digits, colons, and dots (for mapped)
		for _, c := range addr {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.') {
				return false
			}
		}
		return true
	}
	return false
}

// GetStatus returns the current network status (V2: extended with VPN and server info)
func (m *NetworkManager) GetStatus(ctx context.Context) (*NetworkStatus, error) {
	status := &NetworkStatus{
		Mode:      m.currentMode,
		VPNMode:   m.currentVPNMode,
		Subnet:    m.cfg.Subnet,
		GatewayIP: m.cfg.GatewayIP,
		IsServer:  m.IsServerMode(),
	}

	// Check internet connectivity
	status.Internet = m.checkInternetConnectivity()

	// Get interface status from HAL
	interfaces, err := m.hal.ListInterfaces(ctx)
	if err != nil {
		return status, nil
	}

	// Find AP interface (wlan0) - only for non-server modes
	if !m.IsServerMode() {
		// Try HAL for live AP data first (real SSID/channel from hostapd)
		if m.hal != nil {
			halAPStatus, halErr := m.hal.GetAPStatus(ctx)
			if halErr == nil && halAPStatus != nil && halAPStatus.SSID != "" {
				status.AP = &AccessPointStatus{
					Interface: halAPStatus.Interface,
					SSID:      halAPStatus.SSID,
					Channel:   halAPStatus.Channel,
				}
				if halAPStatus.Interface == "" {
					status.AP.Interface = m.apInterface
				}
			}
		}
		// Fall back to interface list + stored SSID if HAL didn't work
		if status.AP == nil {
			for _, iface := range interfaces {
				if iface.Name == m.apInterface {
					status.AP = &AccessPointStatus{
						Interface: iface.Name,
						SSID:      m.apSSID,
					}
					break
				}
			}
		}
	}

	// Find upstream interface based on mode
	switch m.currentMode {
	case models.NetworkModeOnlineETH, models.NetworkModeServerETH:
		for _, iface := range interfaces {
			if iface.Name == m.wanInterface && len(iface.IPv4Addresses) > 0 {
				status.Upstream = &UpstreamStatus{
					Interface: iface.Name,
					IP:        iface.IPv4Addresses[0],
					Type:      "ethernet",
				}
				break
			}
		}
	case models.NetworkModeOnlineWiFi, models.NetworkModeServerWiFi:
		resolvedIface := m.resolveWiFiClientInterface(ctx)
		for _, iface := range interfaces {
			if iface.Name == resolvedIface && len(iface.IPv4Addresses) > 0 {
				status.Upstream = &UpstreamStatus{
					Interface: iface.Name,
					IP:        iface.IPv4Addresses[0],
					Type:      "wifi",
				}
				break
			}
		}
	case models.NetworkModeOnlineTether:
		// Tethering interface has dynamic name (enx*) — find it via HAL or interface list
		tetherStatus, tetherErr := m.hal.GetAndroidTetheringStatus(ctx)
		if tetherErr == nil && tetherStatus.Connected && tetherStatus.Interface != "" {
			for _, iface := range interfaces {
				if iface.Name == tetherStatus.Interface && len(iface.IPv4Addresses) > 0 {
					status.Upstream = &UpstreamStatus{
						Interface: iface.Name,
						IP:        iface.IPv4Addresses[0],
						Type:      "usb_tether",
					}
					break
				}
			}
		}
	}

	// V2: Check VPN status
	if m.currentVPNMode != models.VPNModeNone {
		vpnStatus, err := m.hal.GetVPNStatus(ctx)
		if err == nil && vpnStatus != nil {
			status.VPNActive = vpnStatus.WireGuard.Active || vpnStatus.OpenVPN.Active
			if vpnStatus.WireGuard.Active || vpnStatus.OpenVPN.Active {
			}
		}
	}

	// V2: Add fallback IP for server modes
	if m.IsServerMode() {
		status.FallbackIP = m.fallbackIP
	}

	return status, nil
}

// checkInternetConnectivity checks if internet is reachable
func (m *NetworkManager) checkInternetConnectivity() bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// Try multiple endpoints for reliability
	endpoints := []string{
		"http://connectivitycheck.gstatic.com/generate_204",
		"http://www.gstatic.com/generate_204",
		"http://www.msftconnecttest.com/connecttest.txt",
	}

	for _, url := range endpoints {
		resp, err := client.Head(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 204 || resp.StatusCode == 200 {
				return true
			}
		}
	}
	return false
}

// IsServerMode returns true if current mode is a server mode (V2)
func (m *NetworkManager) IsServerMode() bool {
	return m.currentMode == models.NetworkModeServerETH || m.currentMode == models.NetworkModeServerWiFi
}

// HasInternet returns true if current mode has internet capability (V2)
func (m *NetworkManager) HasInternet() bool {
	switch m.currentMode {
	case models.NetworkModeOnlineETH, models.NetworkModeOnlineWiFi, models.NetworkModeOnlineTether,
		models.NetworkModeServerETH, models.NetworkModeServerWiFi:
		return true
	default:
		return false
	}
}

// HasAP returns true if current mode runs an access point (V2)
func (m *NetworkManager) HasAP() bool {
	return !m.IsServerMode() // Server modes don't run AP
}

// GetCurrentMode returns the current network mode
func (m *NetworkManager) GetCurrentMode() models.NetworkMode {
	return m.currentMode
}

// GetCurrentVPNMode returns the current VPN mode (V2)
func (m *NetworkManager) GetCurrentVPNMode() models.VPNMode {
	return m.currentVPNMode
}

// SetMode changes the network operating mode (V2: supports 5 modes)
func (m *NetworkManager) SetMode(ctx context.Context, mode models.NetworkMode, wifiSSID, wifiPassword string, staticIP models.StaticIPConfig) error {
	var err error

	switch mode {
	case models.NetworkModeOffline:
		err = m.setOfflineMode(ctx)
	case models.NetworkModeOnlineETH:
		err = m.setOnlineETHMode(ctx, staticIP)
	case models.NetworkModeOnlineWiFi:
		if wifiSSID == "" {
			return fmt.Errorf("wifi SSID required for ONLINE_WIFI mode")
		}
		err = m.setOnlineWiFiMode(ctx, wifiSSID, wifiPassword, staticIP)
	case models.NetworkModeOnlineTether:
		err = m.setOnlineTetherMode(ctx)
	case models.NetworkModeServerETH:
		err = m.setServerETHMode(ctx, staticIP)
	case models.NetworkModeServerWiFi:
		if wifiSSID == "" {
			return fmt.Errorf("wifi SSID required for SERVER_WIFI mode")
		}
		err = m.setServerWiFiMode(ctx, wifiSSID, wifiPassword, staticIP)
	default:
		return fmt.Errorf("unknown network mode: %s", mode)
	}

	if err != nil {
		return err
	}

	// If switching to mode without internet, disable VPN
	if !m.HasInternet() && m.currentVPNMode != models.VPNModeNone {
		log.Warn().Msg("NetworkManager: disabling VPN because mode has no internet")
		_ = m.SetVPNMode(ctx, models.VPNModeNone, nil)
	}

	// Persist to database (including static IP config)
	m.saveConfigToDB(mode, m.currentVPNMode, wifiSSID, wifiPassword, staticIP)

	return nil
}

// SetVPNMode changes the VPN overlay mode (V2)
func (m *NetworkManager) SetVPNMode(ctx context.Context, mode models.VPNMode, configID *int64) error {
	// VPN requires internet
	if mode != models.VPNModeNone && !m.HasInternet() {
		return fmt.Errorf("VPN requires a network mode with internet access")
	}

	// Stop current VPN if active
	if m.currentVPNMode != models.VPNModeNone {
		if err := m.stopVPN(ctx); err != nil {
			log.Error().Err(err).Msg("NetworkManager: failed to stop current VPN")
		}
	}

	// Start new VPN if not none
	if mode != models.VPNModeNone {
		if err := m.startVPN(ctx, mode, configID); err != nil {
			return fmt.Errorf("failed to start VPN: %w", err)
		}
	}

	m.currentVPNMode = mode
	m.saveConfigToDB(m.currentMode, mode, "", "", models.StaticIPConfig{})
	return nil
}

// startVPN starts the specified VPN (V2)
func (m *NetworkManager) startVPN(ctx context.Context, mode models.VPNMode, configID *int64) error {
	switch mode {
	case models.VPNModeWireGuard:
		configName := "wg0"
		if configID != nil {
			// Look up config name from database
			var name string
			err := m.db.Get(&name, "SELECT name FROM vpn_configs WHERE id = ?", *configID)
			if err == nil {
				configName = name
			}
		}
		return m.hal.StartWireGuard(ctx, configName)
	case models.VPNModeOpenVPN:
		configName := "client"
		if configID != nil {
			var name string
			err := m.db.Get(&name, "SELECT name FROM vpn_configs WHERE id = ?", *configID)
			if err == nil {
				configName = name
			}
		}
		return m.hal.StartOpenVPN(ctx, configName)
	case models.VPNModeTor:
		return m.hal.StartTor(ctx)
	default:
		return nil
	}
}

// stopVPN stops the current VPN (V2)
func (m *NetworkManager) stopVPN(ctx context.Context) error {
	switch m.currentVPNMode {
	case models.VPNModeWireGuard:
		return m.hal.StopWireGuard(ctx, "wg0")
	case models.VPNModeOpenVPN:
		return m.hal.StopOpenVPN(ctx, "client")
	case models.VPNModeTor:
		return m.hal.StopTor(ctx)
	default:
		return nil
	}
}

// =============================================================================
// Netplan Generation (T10 — API writes netplan for reboot persistence)
// =============================================================================

// generateNetplanYAML produces the netplan YAML for the given mode.
// Must match write_netplan_for_mode() in cubeos-boot-lib.sh exactly.
func (m *NetworkManager) generateNetplanYAML(mode models.NetworkMode, wifiSSID, wifiPassword string, staticIP models.StaticIPConfig) string {
	gatewayIP := m.cfg.GatewayIP
	if gatewayIP == "" {
		gatewayIP = "10.42.24.1"
	}

	switch mode {
	case models.NetworkModeOffline:
		// OFFLINE: Air-gapped operation. wlan0 (AP) serves 10.42.24.0/24.
		// B92/B92b: eth0 has NO address — dual-IP on the same subnet causes
		// ARP conflicts killing connectivity. Must match cubeos-boot-lib.sh.
		return fmt.Sprintf(`# CubeOS netplan — OFFLINE mode
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      link-local: []
      optional: true
    wlan0:
      addresses:
        - %s/24
      link-local: []
      optional: true
`, gatewayIP)

	case models.NetworkModeOnlineTether:
		// ONLINE_TETHER: AP + NAT via Android USB tethering.
		// Tethering interface (enx*) has dynamic name and is managed manually via HAL
		// (ip link set up + dhclient), NOT via netplan. Only wlan0 (AP) goes in netplan.
		return fmt.Sprintf(`# CubeOS netplan — ONLINE_TETHER mode
# Auto-generated by CubeOS API — do not edit manually.
# Android tethering interface (enx*) managed outside netplan.
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      link-local: []
      optional: true
    wlan0:
      addresses:
        - %s/24
      link-local: []
      optional: true
`, gatewayIP)

	case models.NetworkModeOnlineETH:
		if staticIP.IsConfigured() {
			// Static IP on eth0 — user-defined upstream address
			cidr := staticIP.NetmaskToCIDR()
			dnsBlock := m.buildDNSBlock(staticIP, gatewayIP)
			return fmt.Sprintf(`# CubeOS netplan — ONLINE_ETH mode (static IP)
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - %s/%d
      routes:
        - to: default
          via: %s
%s      optional: true
    wlan0:
      addresses:
        - %s/24
      link-local: []
      optional: true
`, staticIP.StaticIPAddress, cidr, staticIP.StaticIPGateway, dnsBlock, gatewayIP)
		}
		// DHCP on eth0 (default)
		return fmt.Sprintf(`# CubeOS netplan — ONLINE_ETH mode
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      dhcp-identifier: mac
      optional: true
      dhcp4-overrides:
        use-dns: false
      nameservers:
        addresses:
          - %s
    wlan0:
      addresses:
        - %s/24
      link-local: []
      optional: true
`, gatewayIP, gatewayIP)

	case models.NetworkModeOnlineWiFi:
		if staticIP.IsConfigured() {
			// Static IP on wlan1 — user-defined upstream address
			cidr := staticIP.NetmaskToCIDR()
			dnsBlock := m.buildDNSBlock(staticIP, gatewayIP)
			return fmt.Sprintf(`# CubeOS netplan — ONLINE_WIFI mode (static IP)
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  ethernets: {}
  wifis:
    wlan0:
      addresses:
        - %s/24
      link-local: []
      optional: true
    wlan1:
      addresses:
        - %s/%d
      routes:
        - to: default
          via: %s
%s      optional: true
      access-points:
        "%s":
          password: "%s"
`, gatewayIP, staticIP.StaticIPAddress, cidr, staticIP.StaticIPGateway, dnsBlock, wifiSSID, wifiPassword)
		}
		// DHCP on wlan1 (default)
		return fmt.Sprintf(`# CubeOS netplan — ONLINE_WIFI mode
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  ethernets: {}
  wifis:
    wlan0:
      addresses:
        - %s/24
      link-local: []
      optional: true
    wlan1:
      dhcp4: true
      optional: true
      dhcp4-overrides:
        use-dns: false
      nameservers:
        addresses:
          - %s
      access-points:
        "%s":
          password: "%s"
`, gatewayIP, gatewayIP, wifiSSID, wifiPassword)

	case models.NetworkModeServerETH:
		if staticIP.IsConfigured() {
			cidr := staticIP.NetmaskToCIDR()
			dnsBlock := m.buildDNSBlock(staticIP, "")
			return fmt.Sprintf(`# CubeOS netplan — SERVER_ETH mode (static IP)
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - %s/%d
      routes:
        - to: default
          via: %s
%s      optional: true
`, staticIP.StaticIPAddress, cidr, staticIP.StaticIPGateway, dnsBlock)
		}
		return `# CubeOS netplan — SERVER_ETH mode
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      dhcp-identifier: mac
      optional: true
`

	case models.NetworkModeServerWiFi:
		if staticIP.IsConfigured() {
			cidr := staticIP.NetmaskToCIDR()
			dnsBlock := m.buildDNSBlock(staticIP, "")
			return fmt.Sprintf(`# CubeOS netplan — SERVER_WIFI mode (static IP)
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  wifis:
    wlan0:
      addresses:
        - %s/%d
      routes:
        - to: default
          via: %s
%s      optional: true
      access-points:
        "%s":
          password: "%s"
`, staticIP.StaticIPAddress, cidr, staticIP.StaticIPGateway, dnsBlock, wifiSSID, wifiPassword)
		}
		return fmt.Sprintf(`# CubeOS netplan — SERVER_WIFI mode
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  wifis:
    wlan0:
      dhcp4: true
      optional: true
      access-points:
        "%s":
          password: "%s"
`, wifiSSID, wifiPassword)

	default:
		// Safety fallback: OFFLINE — same as NetworkModeOffline above
		// B92b: eth0 has NO address to prevent ARP conflicts with wlan0.
		return fmt.Sprintf(`# CubeOS netplan — OFFLINE mode (fallback)
# Auto-generated by CubeOS API — do not edit manually.
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      link-local: []
      optional: true
    wlan0:
      addresses:
        - %s/24
      link-local: []
      optional: true
`, gatewayIP)
	}
}

// buildDNSBlock generates the nameservers: YAML block for static IP netplan templates.
// If user provided DNS servers, those are used. Otherwise falls back to gatewayIP (Pi-hole)
// for AP modes, or common public DNS for server modes.
func (m *NetworkManager) buildDNSBlock(staticIP models.StaticIPConfig, gatewayIP string) string {
	var servers []string
	if staticIP.StaticDNSPrimary != "" {
		servers = append(servers, staticIP.StaticDNSPrimary)
	}
	if staticIP.StaticDNSSecondary != "" {
		servers = append(servers, staticIP.StaticDNSSecondary)
	}
	// Fallback: Pi-hole for AP modes, 1.1.1.1 for server modes
	if len(servers) == 0 {
		if gatewayIP != "" {
			servers = []string{gatewayIP}
		} else {
			servers = []string{"1.1.1.1", "8.8.8.8"}
		}
	}
	block := "      nameservers:\n        addresses:\n"
	for _, s := range servers {
		block += fmt.Sprintf("          - %s\n", s)
	}
	return block
}

// writeAndApplyNetplan writes netplan YAML via HAL and optionally reconfigures an interface.
// This ensures reboot persistence — the next boot uses the correct netplan for the current mode.
func (m *NetworkManager) writeAndApplyNetplan(ctx context.Context, mode models.NetworkMode, wifiSSID, wifiPassword, reconfigureIface string, staticIP models.StaticIPConfig) {
	yaml := m.generateNetplanYAML(mode, wifiSSID, wifiPassword, staticIP)

	if err := m.hal.WriteNetplan(ctx, yaml, reconfigureIface); err != nil {
		log.Error().Err(err).Str("mode", string(mode)).
			Msg("writeAndApplyNetplan: failed to write netplan via HAL")
		return
	}
	log.Info().Str("mode", string(mode)).Str("reconfigure", reconfigureIface).
		Bool("static_ip", staticIP.UseStaticIP).
		Msg("writeAndApplyNetplan: netplan written and applied")
}

// pollForIP polls a network interface for an IPv4 address using HAL.
// B88: Replaces sleep-based DHCP verification with active polling.
// Returns nil when an IP is acquired, or error on timeout/context cancellation.
func (m *NetworkManager) pollForIP(ctx context.Context, iface string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++
		info, err := m.hal.GetInterface(ctx, iface)
		if err == nil && len(info.IPv4Addresses) > 0 {
			log.Info().
				Str("ip", info.IPv4Addresses[0]).
				Str("iface", iface).
				Int("attempts", attempt).
				Msg("NetworkManager: IP acquired via netplan DHCP")
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}

	return fmt.Errorf("timeout waiting for IP on %s after %s (%d attempts)", iface, timeout, attempt)
}

// setOfflineMode configures offline (AP only) mode
func (m *NetworkManager) setOfflineMode(ctx context.Context) error {
	// Disable NAT - ignore errors (might already be disabled)
	_ = m.hal.DisableNAT(ctx)
	_ = m.hal.DisableIPForward(ctx)

	// Disconnect any upstream WiFi
	if m.currentMode == models.NetworkModeOnlineWiFi || m.currentMode == models.NetworkModeServerWiFi {
		_ = m.hal.DisconnectWiFi(ctx, m.resolveWiFiClientInterface(ctx))
	}

	// Ensure AP is running (for non-server recovery)
	if m.IsServerMode() {
		if err := m.hal.StartAP(ctx, m.apInterface); err != nil {
			log.Error().Err(err).Msg("NetworkManager: failed to start AP")
		}
	}

	m.currentMode = models.NetworkModeOffline

	// T09: Configure Pi-hole DHCP for OFFLINE (active on all interfaces)
	m.configurePiholeDHCPForMode(ctx, models.NetworkModeOffline)

	// T10: Write netplan for reboot persistence
	m.writeAndApplyNetplan(ctx, models.NetworkModeOffline, "", "", "", models.StaticIPConfig{})

	return nil
}

// setOnlineETHMode configures online via Ethernet mode
// setOnlineETHMode configures online via Ethernet mode
// B88: DHCP path uses netplan write+apply+poll instead of HAL RequestDHCP
func (m *NetworkManager) setOnlineETHMode(ctx context.Context, staticIP models.StaticIPConfig) error {
	// Check if ethernet is up
	iface, err := m.hal.GetInterface(ctx, m.wanInterface)
	if err != nil {
		return fmt.Errorf("ethernet interface not available: %w", err)
	}
	if !iface.IsUp {
		if err := m.hal.BringInterfaceUp(ctx, m.wanInterface); err != nil {
			return fmt.Errorf("failed to bring up ethernet: %w", err)
		}
	}

	// Configure upstream IP: static or DHCP
	if staticIP.IsConfigured() {
		log.Info().Str("ip", staticIP.StaticIPAddress).Str("gw", staticIP.StaticIPGateway).
			Msg("NetworkManager: setting static IP on ethernet")
		if err := m.hal.SetStaticIP(ctx, m.wanInterface, staticIP.StaticIPAddress, staticIP.StaticIPGateway); err != nil {
			return fmt.Errorf("failed to set static IP on %s: %w", m.wanInterface, err)
		}
		time.Sleep(2 * time.Second)
	} else if len(iface.IPv4Addresses) == 0 {
		// B88: Write netplan with dhcp4:true → netplan apply → networkd handles DHCP.
		// This replaces the fragile hal.RequestDHCP()+sleep pattern.
		log.Info().Str("iface", m.wanInterface).
			Msg("NetworkManager: writing DHCP netplan for ethernet (B88)")
		yaml := m.generateNetplanYAML(models.NetworkModeOnlineETH, "", "", staticIP)
		if err := m.hal.WriteNetplan(ctx, yaml, m.wanInterface); err != nil {
			return fmt.Errorf("failed to write/apply DHCP netplan on %s: %w", m.wanInterface, err)
		}

		// Poll for IP acquisition (systemd-networkd handles DHCP natively).
		// B94: DHCP timeout is non-fatal — networkd continues retrying in the background.
		// This matches ONLINE_WIFI behavior where DHCP failure is a warning, not an error.
		if err := m.pollForIP(ctx, m.wanInterface, 30*time.Second); err != nil {
			log.Warn().Err(err).Str("iface", m.wanInterface).
				Msg("NetworkManager: ethernet DHCP timeout — networkd will keep retrying in background")
		}
	}

	// B94: Set mode optimistically BEFORE NAT/AP setup.
	// Netplan is written, so the system is transitioning to ONLINE_ETH regardless
	// of whether DHCP has resolved yet. This prevents state desync on timeout.
	m.currentMode = models.NetworkModeOnlineETH

	// Ensure AP is running (recover if switching from server mode)
	if m.IsServerMode() {
		if err := m.hal.StartAP(ctx, m.apInterface); err != nil {
			log.Error().Err(err).Msg("NetworkManager: failed to start AP")
		}
	}

	// Enable IP forwarding
	if err := m.hal.EnableIPForward(ctx); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Enable NAT: AP interface -> WAN interface
	if err := m.hal.EnableNAT(ctx, m.apInterface, m.wanInterface); err != nil {
		return fmt.Errorf("failed to enable NAT: %w", err)
	}

	// T09: Configure Pi-hole DHCP (active, no-dhcp-interface=eth0)
	m.configurePiholeDHCPForMode(ctx, models.NetworkModeOnlineETH)

	// Write netplan for reboot persistence.
	// DHCP path already wrote+applied netplan above, but we call this unconditionally
	// to handle the static IP path (which uses runtime SetStaticIP and needs persistence).
	// For the DHCP path this is a no-op write (same YAML).
	m.writeAndApplyNetplan(ctx, models.NetworkModeOnlineETH, "", "", "", staticIP)

	return nil
}

// setOnlineTetherMode configures online via Android USB tethering.
// The tethering interface (enx*) has a dynamic name based on the phone's MAC,
// so we can't use netplan for it. Instead:
//  1. Write OFFLINE-style netplan (wlan0 AP only) for persistence
//  2. Detect the tethering interface via HAL
//  3. Bring it UP + DHCP via HAL's EnableAndroidTethering (B96b: includes ip link set up)
//  4. Enable IP forwarding + NAT on the detected interface
func (m *NetworkManager) setOnlineTetherMode(ctx context.Context) error {
	// Detect Android tethering interface via HAL
	tetherStatus, err := m.hal.GetAndroidTetheringStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to check Android tethering: %w", err)
	}
	if !tetherStatus.Connected {
		return fmt.Errorf("no Android tethering device detected — connect a phone with USB tethering enabled")
	}

	tetherIface := tetherStatus.Interface
	log.Info().Str("iface", tetherIface).Msg("NetworkManager: detected Android tethering interface")

	// Write OFFLINE-style netplan (wlan0 AP only, tether interface managed manually)
	yaml := m.generateNetplanYAML(models.NetworkModeOnlineTether, "", "", models.StaticIPConfig{})
	if err := m.hal.WriteNetplan(ctx, yaml, ""); err != nil {
		log.Warn().Err(err).Msg("NetworkManager: failed to write tether netplan (non-fatal)")
	}

	// Enable tethering: HAL brings interface UP + runs DHCP (B96b fix)
	if err := m.hal.EnableAndroidTethering(ctx); err != nil {
		return fmt.Errorf("failed to enable Android tethering on %s: %w", tetherIface, err)
	}

	// Poll for IP on the tethering interface
	if err := m.pollForIP(ctx, tetherIface, 15*time.Second); err != nil {
		log.Warn().Err(err).Str("iface", tetherIface).
			Msg("NetworkManager: tether DHCP timeout — will keep retrying")
	}

	// Set mode optimistically (same pattern as ONLINE_ETH / B94)
	m.currentMode = models.NetworkModeOnlineTether

	// Ensure AP is running (recover if switching from server mode)
	if m.IsServerMode() {
		if err := m.hal.StartAP(ctx, m.apInterface); err != nil {
			log.Error().Err(err).Msg("NetworkManager: failed to start AP")
		}
	}

	// Enable IP forwarding
	if err := m.hal.EnableIPForward(ctx); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Enable NAT: AP interface -> tethering interface
	if err := m.hal.EnableNAT(ctx, m.apInterface, tetherIface); err != nil {
		return fmt.Errorf("failed to enable NAT on %s: %w", tetherIface, err)
	}

	// Configure Pi-hole DHCP (exclude tethering interface from DHCP)
	m.configurePiholeDHCPForMode(ctx, models.NetworkModeOnlineTether)

	return nil
}

// setOnlineWiFiMode configures online via WiFi client mode
// setOnlineWiFiMode configures online via WiFi client mode
// B88: DHCP path uses netplan write+apply+poll instead of HAL RequestDHCP
func (m *NetworkManager) setOnlineWiFiMode(ctx context.Context, ssid, password string, staticIP models.StaticIPConfig) error {
	// Dynamically detect WiFi client interface (USB dongle with wlx* prefix)
	// Falls back to configured m.wifiClientInterface (default: wlan1)
	iface := m.wifiClientInterface
	if detected, err := m.DetectWiFiClientInterface(ctx); err == nil && detected != "" {
		iface = detected
	}
	if iface == "" {
		return fmt.Errorf("no USB WiFi dongle detected")
	}

	// Bring up WiFi client interface
	ifaceInfo, err := m.hal.GetInterface(ctx, iface)
	if err != nil {
		return fmt.Errorf("WiFi client interface not available: %w", err)
	}
	if !ifaceInfo.IsUp {
		if err := m.hal.BringInterfaceUp(ctx, iface); err != nil {
			return fmt.Errorf("failed to bring up WiFi client interface: %w", err)
		}
		time.Sleep(time.Second) // Wait for interface to be ready
	}

	// Connect to upstream WiFi
	if err := m.hal.ConnectWiFi(ctx, iface, ssid, password); err != nil {
		return fmt.Errorf("failed to connect to WiFi: %w", err)
	}

	// Wait for WiFi association
	time.Sleep(5 * time.Second)

	// Configure upstream IP: static or DHCP
	if staticIP.IsConfigured() {
		log.Info().Str("ip", staticIP.StaticIPAddress).Str("gw", staticIP.StaticIPGateway).
			Msg("NetworkManager: setting static IP on WiFi client")
		if err := m.hal.SetStaticIP(ctx, iface, staticIP.StaticIPAddress, staticIP.StaticIPGateway); err != nil {
			log.Warn().Err(err).Str("iface", iface).Msg("NetworkManager: static IP on WiFi failed")
		}
		time.Sleep(2 * time.Second)
	} else {
		// B88: Write netplan with dhcp4:true for WiFi client → networkd handles DHCP.
		// The netplan also includes access-points block with WiFi credentials.
		log.Info().Str("iface", iface).Str("ssid", ssid).
			Msg("NetworkManager: writing DHCP netplan for WiFi client (B88)")
		yaml := m.generateNetplanYAML(models.NetworkModeOnlineWiFi, ssid, password, staticIP)
		if err := m.hal.WriteNetplan(ctx, yaml, iface); err != nil {
			log.Warn().Err(err).Str("iface", iface).
				Msg("NetworkManager: failed to write WiFi DHCP netplan, may not have internet")
		} else {
			// Poll for IP — WiFi DHCP can be slower, use 30s timeout
			if err := m.pollForIP(ctx, iface, 30*time.Second); err != nil {
				log.Warn().Err(err).Str("iface", iface).
					Msg("NetworkManager: WiFi DHCP timeout, may not have internet")
			}
		}
	}

	// Ensure AP is running
	if m.IsServerMode() {
		if err := m.hal.StartAP(ctx, m.apInterface); err != nil {
			log.Error().Err(err).Msg("NetworkManager: failed to start AP")
		}
	}

	// Enable IP forwarding
	if err := m.hal.EnableIPForward(ctx); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Enable NAT: AP interface -> WiFi client interface
	if err := m.hal.EnableNAT(ctx, m.apInterface, iface); err != nil {
		return fmt.Errorf("failed to enable NAT: %w", err)
	}

	m.currentMode = models.NetworkModeOnlineWiFi

	// T09: Configure Pi-hole DHCP (active, no-dhcp-interface=wlan1)
	m.configurePiholeDHCPForMode(ctx, models.NetworkModeOnlineWiFi)

	// T10: Write netplan for reboot persistence (includes wlan1 WiFi creds).
	// For DHCP path, netplan was already written above — this is a no-op write.
	// For static IP path, this provides persistence.
	m.writeAndApplyNetplan(ctx, models.NetworkModeOnlineWiFi, ssid, password, iface, staticIP)

	return nil
}

// setServerETHMode configures server mode via Ethernet (V2)
// No AP, just connects to existing network
func (m *NetworkManager) setServerETHMode(ctx context.Context, staticIP models.StaticIPConfig) error {
	log.Info().Msg("NetworkManager: switching to SERVER_ETH mode")

	// Stop the access point
	if err := m.hal.StopAP(ctx, m.apInterface); err != nil {
		log.Warn().Err(err).Msg("NetworkManager: failed to stop AP (may not be running)")
	}

	// Disable NAT (we're a client now, not a router)
	_ = m.hal.DisableNAT(ctx)
	_ = m.hal.DisableIPForward(ctx)

	// Bring up ethernet interface
	if err := m.hal.BringInterfaceUp(ctx, m.wanInterface); err != nil {
		return fmt.Errorf("failed to bring up ethernet: %w", err)
	}

	// Configure upstream IP: static, DHCP, or fallback
	if staticIP.IsConfigured() {
		log.Info().Str("ip", staticIP.StaticIPAddress).Str("gw", staticIP.StaticIPGateway).
			Msg("NetworkManager: setting static IP on ethernet (server mode)")
		if err := m.hal.SetStaticIP(ctx, m.wanInterface, staticIP.StaticIPAddress, staticIP.StaticIPGateway); err != nil {
			return fmt.Errorf("failed to set static IP: %w", err)
		}
	} else {
		// B88: Use netplan write+apply+poll instead of HAL RequestDHCP
		log.Info().Str("iface", m.wanInterface).
			Msg("NetworkManager: writing DHCP netplan for server ethernet (B88)")
		yaml := m.generateNetplanYAML(models.NetworkModeServerETH, "", "", staticIP)
		if err := m.hal.WriteNetplan(ctx, yaml, m.wanInterface); err != nil {
			log.Warn().Err(err).Str("fallbackIP", m.fallbackIP).
				Msg("NetworkManager: netplan write failed, using fallback static IP")
			if err := m.hal.SetStaticIP(ctx, m.wanInterface, m.fallbackIP, m.fallbackGateway); err != nil {
				return fmt.Errorf("failed to set fallback IP: %w", err)
			}
		} else if err := m.pollForIP(ctx, m.wanInterface, 15*time.Second); err != nil {
			log.Warn().Err(err).Str("fallbackIP", m.fallbackIP).Str("fallbackGateway", m.fallbackGateway).
				Msg("NetworkManager: DHCP timeout, using fallback static IP")
			if err := m.hal.SetStaticIP(ctx, m.wanInterface, m.fallbackIP, m.fallbackGateway); err != nil {
				return fmt.Errorf("failed to set fallback IP: %w", err)
			}
		}
	}

	// Wait for network to settle
	time.Sleep(2 * time.Second)

	m.currentMode = models.NetworkModeServerETH

	// T09: Disable Pi-hole DHCP (no AP, no local clients)
	m.configurePiholeDHCPForMode(ctx, models.NetworkModeServerETH)

	// T10: Write netplan for reboot persistence
	m.writeAndApplyNetplan(ctx, models.NetworkModeServerETH, "", "", m.wanInterface, staticIP)

	return nil
}

// setServerWiFiMode configures server mode via WiFi (V2)
// No AP, connects wlan0 to existing WiFi network
func (m *NetworkManager) setServerWiFiMode(ctx context.Context, ssid, password string, staticIP models.StaticIPConfig) error {
	log.Info().Str("ssid", ssid).Msg("NetworkManager: switching to SERVER_WIFI mode")

	// Stop the access point (this frees wlan0 for client use)
	if err := m.hal.StopAP(ctx, m.apInterface); err != nil {
		log.Warn().Err(err).Msg("NetworkManager: failed to stop AP")
	}

	// Disable NAT
	_ = m.hal.DisableNAT(ctx)
	_ = m.hal.DisableIPForward(ctx)

	// Give hostapd time to release the interface
	time.Sleep(2 * time.Second)

	// Connect wlan0 to the WiFi network (not the USB dongle)
	if err := m.hal.ConnectWiFi(ctx, m.apInterface, ssid, password); err != nil {
		return fmt.Errorf("failed to connect to WiFi: %w", err)
	}

	// Wait for connection
	time.Sleep(5 * time.Second)

	// Configure upstream IP: static or DHCP
	if staticIP.IsConfigured() {
		log.Info().Str("ip", staticIP.StaticIPAddress).Str("gw", staticIP.StaticIPGateway).
			Msg("NetworkManager: setting static IP on wlan0 (server WiFi mode)")
		if err := m.hal.SetStaticIP(ctx, m.apInterface, staticIP.StaticIPAddress, staticIP.StaticIPGateway); err != nil {
			log.Warn().Err(err).Msg("NetworkManager: static IP on wlan0 failed")
		}
	} else {
		// B88: Use netplan write+apply+poll instead of checking for existing IP only.
		// The WiFi connect above may not have triggered DHCP via networkd yet.
		log.Info().Str("iface", m.apInterface).Str("ssid", ssid).
			Msg("NetworkManager: writing DHCP netplan for server WiFi (B88)")
		yaml := m.generateNetplanYAML(models.NetworkModeServerWiFi, ssid, password, staticIP)
		if err := m.hal.WriteNetplan(ctx, yaml, m.apInterface); err != nil {
			log.Warn().Err(err).Msg("NetworkManager: server WiFi netplan write failed")
		}

		// Poll for IP — fall back to static if DHCP fails
		if err := m.pollForIP(ctx, m.apInterface, 15*time.Second); err != nil {
			log.Warn().Str("fallbackIP", m.fallbackIP).Str("fallbackGateway", m.fallbackGateway).
				Msg("NetworkManager: no IP assigned, using fallback")
			if err := m.hal.SetStaticIP(ctx, m.apInterface, m.fallbackIP, m.fallbackGateway); err != nil {
				return fmt.Errorf("failed to set fallback IP: %w", err)
			}
		}
	}

	m.currentMode = models.NetworkModeServerWiFi

	// T09: Disable Pi-hole DHCP (no AP, no local clients)
	m.configurePiholeDHCPForMode(ctx, models.NetworkModeServerWiFi)

	// T10: Write netplan for reboot persistence (includes wlan0 WiFi creds)
	m.writeAndApplyNetplan(ctx, models.NetworkModeServerWiFi, ssid, password, m.apInterface, staticIP)

	return nil
}

// ScanWiFiNetworks scans for available WiFi networks
func (m *NetworkManager) ScanWiFiNetworks(ctx context.Context) ([]models.WiFiNetwork, error) {
	// Determine which interface to scan with
	scanInterface := m.wifiClientInterface

	// For SERVER_WIFI mode, use wlan0
	if m.currentMode == models.NetworkModeServerWiFi {
		scanInterface = m.apInterface
	} else {
		// Try dynamic detection first — finds any USB WiFi dongle (wlx* interface)
		// regardless of MAC address. This fixes the hardcoded interface name issue.
		detected, err := m.DetectWiFiClientInterface(ctx)
		if err == nil && detected != "" {
			log.Info().Str("interface", detected).Msg("NetworkManager: WiFi scan using detected interface")
			scanInterface = detected
		} else {
			log.Debug().Err(err).Str("fallback", scanInterface).
				Msg("NetworkManager: no USB WiFi dongle detected, using configured interface")
		}
	}

	// Try the selected interface first
	networks, err := m.hal.ScanWiFi(ctx, scanInterface)
	if err != nil {
		// If the detected/configured interface failed and it's not wlan0, try wlan0
		// Note: wlan0 in AP mode may not scan, but it's worth trying as a last resort
		if scanInterface != m.apInterface {
			log.Warn().Str("failed_iface", scanInterface).
				Msg("NetworkManager: scan failed on selected interface, trying wlan0")
			networks, err = m.hal.ScanWiFi(ctx, m.apInterface)
			if err != nil {
				return nil, fmt.Errorf("WiFi scan failed on all interfaces: %w", err)
			}
		} else {
			return nil, fmt.Errorf("WiFi scan failed: %w", err)
		}
	}

	var result []models.WiFiNetwork
	for _, n := range networks {
		result = append(result, models.WiFiNetwork{
			SSID:      n.SSID,
			BSSID:     n.BSSID,
			Signal:    n.Signal,
			Frequency: n.Frequency,
			Security:  n.Security,
			Channel:   n.Channel,
		})
	}
	return result, nil
}

// ConnectToWiFi connects to a WiFi network (upstream for ONLINE_WIFI mode)
func (m *NetworkManager) ConnectToWiFi(ctx context.Context, ssid, password string) error {
	// For regular modes, use USB dongle (dynamically detected). For SERVER_WIFI, use wlan0.
	iface := m.wifiClientInterface
	if m.currentMode == models.NetworkModeServerWiFi {
		iface = m.apInterface
	} else {
		// Try dynamic detection for USB WiFi dongle
		if detected, err := m.DetectWiFiClientInterface(ctx); err == nil && detected != "" {
			iface = detected
		}
	}

	return m.hal.ConnectWiFi(ctx, iface, ssid, password)
}

// DisconnectWiFi disconnects from upstream WiFi
func (m *NetworkManager) DisconnectWiFi(ctx context.Context) error {
	iface := m.wifiClientInterface
	if m.currentMode == models.NetworkModeServerWiFi {
		iface = m.apInterface
	} else {
		if detected, err := m.DetectWiFiClientInterface(ctx); err == nil && detected != "" {
			iface = detected
		}
	}
	return m.hal.DisconnectWiFi(ctx, iface)
}

// DetectWiFiClientInterface attempts to detect the WiFi client interface.
// Post-Batch 1: udev renames USB WiFi to wlan1, so wlx* matching is obsolete.
// New logic: find any wireless interface that isn't the AP interface (wlan0).
// @Summary Detect WiFi client interface
// @Description Finds any wireless interface that is not the AP interface
// @Tags network
// @Success 200 {string} string "interface name"
// @Failure 404 {string} string "no WiFi client interface found"
// @Router /internal/detect-wifi-client [get]
func (m *NetworkManager) DetectWiFiClientInterface(ctx context.Context) (string, error) {
	interfaces, err := m.hal.ListInterfaces(ctx)
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		// Find wireless interfaces that are NOT the AP interface
		if iface.IsWireless && iface.Name != m.apInterface {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no WiFi client interface found (need USB dongle or second radio)")
}

// resolveWiFiClientInterface returns the WiFi client interface to use.
// Tries dynamic USB dongle detection first, falls back to configured default.
func (m *NetworkManager) resolveWiFiClientInterface(ctx context.Context) string {
	if detected, err := m.DetectWiFiClientInterface(ctx); err == nil && detected != "" {
		return detected
	}
	return m.wifiClientInterface
}

// GetNetworkConfig returns the persisted network configuration (V2)
func (m *NetworkManager) GetNetworkConfig(ctx context.Context) (*models.NetworkConfig, error) {
	if m.db == nil {
		return &models.NetworkConfig{
			Mode:      models.NetworkModeOffline,
			VPNMode:   models.VPNModeNone,
			GatewayIP: models.DefaultGatewayIP,
			Subnet:    models.DefaultSubnet,
		}, nil
	}

	var cfg models.NetworkConfig
	err := m.db.Get(&cfg, `
		SELECT mode, COALESCE(vpn_mode, 'none') as vpn_mode, vpn_config_id,
		       wifi_ssid, COALESCE(gateway_ip, '10.42.24.1') as gateway_ip,
		       COALESCE(subnet, '10.42.24.0/24') as subnet,
		       COALESCE(dhcp_range_start, '10.42.24.10') as dhcp_range_start,
		       COALESCE(dhcp_range_end, '10.42.24.250') as dhcp_range_end,
		       COALESCE(fallback_static_ip, '192.168.1.242') as fallback_static_ip,
		       COALESCE(ap_ssid, 'CubeOS') as ap_ssid,
		       COALESCE(ap_channel, 7) as ap_channel,
		       COALESCE(ap_hidden, 0) as ap_hidden,
		       COALESCE(server_mode_warning_dismissed, 0) as server_mode_warning_dismissed
		FROM network_config WHERE id = 1`)
	if err != nil {
		if err == sql.ErrNoRows {
			return &models.NetworkConfig{
				Mode:      models.NetworkModeOffline,
				VPNMode:   models.VPNModeNone,
				GatewayIP: models.DefaultGatewayIP,
				Subnet:    models.DefaultSubnet,
			}, nil
		}
		return nil, err
	}
	return &cfg, nil
}

// UpdateNetworkConfig updates network configuration (V2)
func (m *NetworkManager) UpdateNetworkConfig(ctx context.Context, cfg *models.NetworkConfig) error {
	if m.db == nil {
		return fmt.Errorf("database not available")
	}

	_, err := m.db.Exec(`
		INSERT INTO network_config (id, mode, vpn_mode, gateway_ip, subnet, 
		                           dhcp_range_start, dhcp_range_end, fallback_static_ip,
		                           ap_ssid, ap_password, ap_channel, ap_hidden,
		                           server_mode_warning_dismissed, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			mode = excluded.mode,
			vpn_mode = excluded.vpn_mode,
			gateway_ip = excluded.gateway_ip,
			subnet = excluded.subnet,
			dhcp_range_start = excluded.dhcp_range_start,
			dhcp_range_end = excluded.dhcp_range_end,
			fallback_static_ip = excluded.fallback_static_ip,
			ap_ssid = excluded.ap_ssid,
			ap_password = excluded.ap_password,
			ap_channel = excluded.ap_channel,
			ap_hidden = excluded.ap_hidden,
			server_mode_warning_dismissed = excluded.server_mode_warning_dismissed,
			updated_at = CURRENT_TIMESTAMP`,
		string(cfg.Mode), string(cfg.VPNMode), cfg.GatewayIP, cfg.Subnet,
		cfg.DHCPRangeStart, cfg.DHCPRangeEnd, cfg.FallbackStaticIP,
		cfg.APSSID, cfg.APPassword, cfg.APChannel, cfg.APHidden,
		cfg.ServerModeWarningDismissed)
	return err
}

// DismissServerModeWarning dismisses the server mode warning (V2)
func (m *NetworkManager) DismissServerModeWarning(ctx context.Context) error {
	if m.db == nil {
		return nil
	}
	_, err := m.db.Exec(`UPDATE network_config SET server_mode_warning_dismissed = 1 WHERE id = 1`)
	return err
}

// GetAPClients returns connected AP clients
func (m *NetworkManager) GetAPClients(ctx context.Context) ([]models.APClient, error) {
	if m.IsServerMode() {
		return []models.APClient{}, nil // No AP in server mode
	}

	// Try HAL AP clients endpoint (hostapd_cli all_sta)
	resp, err := m.hal.GetAPClients(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("NetworkManager: HAL GetAPClients failed, trying DHCP lease fallback")

		// Fallback: parse DHCP leases from Pi-hole/dnsmasq
		// Pi-hole stores DHCP leases in /etc/pihole/dhcp.leases (dnsmasq format)
		leaseClients := m.parseDHCPLeases(ctx)
		if len(leaseClients) > 0 {
			log.Info().Int("count", len(leaseClients)).Msg("NetworkManager: got clients from DHCP leases")
			return leaseClients, nil
		}

		return []models.APClient{}, nil // Graceful degradation: empty list, not error
	}

	if resp == nil || len(resp.Clients) == 0 {
		log.Debug().Msg("NetworkManager: HAL returned 0 AP clients")
		return []models.APClient{}, nil
	}

	// Fetch blocklist to populate Blocked field (best-effort)
	blockedMACs := make(map[string]bool)
	if blocklist, err := m.hal.GetAPBlocklist(ctx); err == nil {
		for _, mac := range blocklist.MACs {
			blockedMACs[strings.ToUpper(mac)] = true
		}
	}

	// Convert hal.APClient to models.APClient
	clients := make([]models.APClient, len(resp.Clients))
	for i, c := range resp.Clients {
		clients[i] = models.APClient{
			MACAddress:    c.MACAddress,
			IPAddress:     c.IPAddress,
			Hostname:      c.Hostname,
			ConnectedTime: c.ConnectedTime,
			Signal:        c.Signal,
			TXBytes:       c.TXBytes,
			RXBytes:       c.RXBytes,
			Blocked:       blockedMACs[strings.ToUpper(c.MACAddress)],
		}
	}

	log.Debug().Int("count", len(clients)).Msg("NetworkManager: got AP clients from HAL")
	return clients, nil
}

// parseDHCPLeases reads DHCP leases from dnsmasq/Pi-hole lease file.
// This serves as a fallback when hostapd_cli is unavailable.
// Lease format: <epoch> <mac> <ip> <hostname> <client-id>
func (m *NetworkManager) parseDHCPLeases(ctx context.Context) []models.APClient {
	leasePaths := []string{
		"/cubeos/coreapps/pihole/appdata/etc-pihole/dhcp.leases",
		"/host-root/cubeos/coreapps/pihole/appdata/etc-pihole/dhcp.leases",
		// Pi-hole v6 stores leases in a different location
		"/cubeos/coreapps/pihole/appdata/etc-dnsmasq.d/dhcp.leases",
		"/host-root/cubeos/coreapps/pihole/appdata/etc-dnsmasq.d/dhcp.leases",
		// Standard dnsmasq lease paths
		"/host-root/var/lib/misc/dnsmasq.leases",
		"/var/lib/misc/dnsmasq.leases",
		// Alternative Pi-hole paths
		"/host-root/etc/pihole/dhcp.leases",
		"/etc/pihole/dhcp.leases",
	}

	for _, path := range leasePaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var clients []models.APClient
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			var connTime int64
			if _, err := fmt.Sscanf(fields[0], "%d", &connTime); err != nil {
				continue
			}

			hostname := fields[3]
			if hostname == "*" {
				hostname = ""
			}

			clients = append(clients, models.APClient{
				MACAddress:    fields[1],
				IPAddress:     fields[2],
				Hostname:      hostname,
				ConnectedTime: connTime,
			})
		}

		if len(clients) > 0 {
			return clients
		}
	}

	return nil
}

// IsValidMode checks if a mode string is valid (V2)
func IsValidMode(mode string) bool {
	switch models.NetworkMode(mode) {
	case models.NetworkModeOffline, models.NetworkModeOnlineETH, models.NetworkModeOnlineWiFi,
		models.NetworkModeOnlineTether, models.NetworkModeServerETH, models.NetworkModeServerWiFi:
		return true
	default:
		return false
	}
}

// IsValidVPNMode checks if a VPN mode string is valid (V2)
func IsValidVPNMode(mode string) bool {
	switch models.VPNMode(mode) {
	case models.VPNModeNone, models.VPNModeWireGuard, models.VPNModeOpenVPN, models.VPNModeTor:
		return true
	default:
		return false
	}
}

// GetConnectedClients returns connected AP clients (alias for monitoring)
func (m *NetworkManager) GetConnectedClients(ctx context.Context) ([]models.APClient, error) {
	return m.GetAPClients(ctx)
}

// APConfig represents WiFi Access Point configuration
type APConfig struct {
	SSID     string `json:"ssid"`
	Channel  int    `json:"channel"`
	Hidden   bool   `json:"hidden"`
	Password string `json:"password,omitempty"`
}

// GetAPConfig returns current AP configuration.
// Priority: HAL live hostapd status → DB → environment/defaults.
// This ensures the dashboard shows the ACTUAL running SSID/channel,
// not a stale DB value or hardcoded default.
func (m *NetworkManager) GetAPConfig(ctx context.Context) (*APConfig, error) {
	// 1. Try HAL live AP status first (reads from actual hostapd)
	if m.hal != nil {
		halStatus, err := m.hal.GetAPStatus(ctx)
		if err == nil && halStatus != nil && halStatus.SSID != "" {
			log.Debug().Str("ssid", halStatus.SSID).Int("channel", halStatus.Channel).
				Msg("NetworkManager: GetAPConfig from live HAL")

			// Merge hidden flag from DB (HAL doesn't report this)
			hidden := false
			if m.db != nil {
				var dbHidden bool
				dbErr := m.db.QueryRowContext(ctx,
					`SELECT COALESCE(ap_hidden, 0) FROM network_config WHERE id = 1`).Scan(&dbHidden)
				if dbErr == nil {
					hidden = dbHidden
				}
			}

			return &APConfig{
				SSID:    halStatus.SSID,
				Channel: halStatus.Channel,
				Hidden:  hidden,
			}, nil
		}
		if err != nil {
			log.Warn().Err(err).Msg("NetworkManager: HAL GetAPStatus failed, falling back to DB")
		}
	}

	// 2. Fall back to database
	if m.db != nil {
		var apSSID string
		var apChannel int
		var apHidden bool
		err := m.db.QueryRowContext(ctx,
			`SELECT COALESCE(ap_ssid, 'CubeOS'), COALESCE(ap_channel, 7), COALESCE(ap_hidden, 0) 
			 FROM network_config WHERE id = 1`).Scan(&apSSID, &apChannel, &apHidden)
		if err == nil {
			return &APConfig{
				SSID:    apSSID,
				Channel: apChannel,
				Hidden:  apHidden,
			}, nil
		}
		if err != sql.ErrNoRows {
			log.Error().Err(err).Msg("NetworkManager: failed to read AP config from DB")
		}
	}

	// 3. Fallback to defaults from environment/config
	return &APConfig{
		SSID:    m.apSSID,
		Channel: 7,
		Hidden:  false,
	}, nil
}

// UpdateAPConfig updates AP configuration and applies it live.
// Persists to DB, writes hostapd.conf, and restarts hostapd (B58 fix).
func (m *NetworkManager) UpdateAPConfig(ctx context.Context, ssid, password string, channel int, hidden bool) error {
	if m.db == nil {
		return fmt.Errorf("AP configuration update not yet implemented: no database available")
	}

	// Persist the config to database
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO network_config (id, ap_ssid, ap_password, ap_channel, ap_hidden, updated_at)
		VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			ap_ssid = excluded.ap_ssid,
			ap_password = CASE WHEN excluded.ap_password = '' THEN network_config.ap_password ELSE excluded.ap_password END,
			ap_channel = excluded.ap_channel,
			ap_hidden = excluded.ap_hidden,
			updated_at = CURRENT_TIMESTAMP`,
		ssid, password, channel, hidden)
	if err != nil {
		return fmt.Errorf("failed to persist AP config: %w", err)
	}

	log.Info().Str("ssid", ssid).Int("channel", channel).Bool("hidden", hidden).Msg("NetworkManager: AP config persisted to DB")

	// Apply config live: write hostapd.conf and restart hostapd
	if applyErr := m.applyAPConfig(ssid, password, channel, hidden); applyErr != nil {
		log.Warn().Err(applyErr).Msg("NetworkManager: failed to apply AP config live — will take effect on next boot")
		// Don't return error — config is persisted, just not live-applied
	}

	return nil
}

// applyAPConfig writes hostapd.conf and restarts the hostapd service via HAL.
// Uses the host-root mount (/host-root) for writing config files.
func (m *NetworkManager) applyAPConfig(ssid, password string, channel int, hidden bool) error {
	// Resolve the actual password if empty (keep existing)
	if password == "" {
		// Read current password from hostapd.conf
		data, err := os.ReadFile("/host-root/etc/hostapd/hostapd.conf")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "wpa_passphrase=") {
					password = strings.TrimPrefix(line, "wpa_passphrase=")
					break
				}
			}
		}
		if password == "" {
			return fmt.Errorf("no password provided and could not read existing password")
		}
	}

	hiddenVal := 0
	if hidden {
		hiddenVal = 1
	}

	// Write hostapd.conf via host-root mount
	hostapdConf := fmt.Sprintf(`# CubeOS WiFi Access Point Configuration
# Updated by API at %s

interface=wlan0
driver=nl80211

ssid=%s

hw_mode=g
channel=%d
ieee80211n=1
ieee80211ac=0

wpa=2
wpa_passphrase=%s
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP

wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=%d
max_num_sta=32

logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
`, time.Now().Format(time.RFC3339), ssid, channel, password, hiddenVal)

	hostRootPath := os.Getenv("CUBEOS_HOST_ROOT")
	if hostRootPath == "" {
		hostRootPath = "/host-root"
	}
	confPath := filepath.Join(hostRootPath, "etc", "hostapd", "hostapd.conf")

	if err := os.WriteFile(confPath, []byte(hostapdConf), 0600); err != nil {
		return fmt.Errorf("failed to write hostapd.conf: %w", err)
	}
	log.Info().Str("path", confPath).Msg("NetworkManager: wrote hostapd.conf")

	// Restart hostapd via HAL (HAL owns the host namespace)
	ctx := context.Background()
	if err := m.hal.RestartService(ctx, "hostapd"); err != nil {
		log.Warn().Err(err).Msg("NetworkManager: HAL hostapd restart failed")
		return fmt.Errorf("hostapd restart failed via HAL: %w", err)
	}

	log.Info().Msg("NetworkManager: hostapd restarted successfully via HAL")
	return nil
}

// IsServerModeWarningDismissed checks if server mode warning has been dismissed
func (m *NetworkManager) IsServerModeWarningDismissed(ctx context.Context) (bool, error) {
	if m.db == nil {
		return false, nil
	}
	var dismissed int
	err := m.db.QueryRow(`SELECT COALESCE(server_mode_warning_dismissed, 0) FROM network_config WHERE id = 1`).Scan(&dismissed)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return dismissed == 1, nil
}

// =============================================================================
// NEW METHODS: DNS Configuration and WiFi Status
// =============================================================================

// DNSConfig represents DNS configuration
type DNSConfig struct {
	PrimaryDNS   string   `json:"primary_dns"`
	SecondaryDNS string   `json:"secondary_dns,omitempty"`
	SearchDomain string   `json:"search_domain,omitempty"`
	DNSServers   []string `json:"dns_servers,omitempty"`
}

// GetDNSConfig returns the current DNS configuration.
// Priority: Pi-hole API (upstream servers) → resolv.conf fallback.
// In CubeOS, Pi-hole is the DNS server. The "DNS config" exposed to users
// is Pi-hole's upstream forwarders, NOT the system's resolv.conf nameservers.
func (m *NetworkManager) GetDNSConfig(ctx context.Context) (*DNSConfig, error) {
	// 1. Try Pi-hole API for upstream DNS servers
	upstreams, err := m.getPiholeUpstreams(ctx)
	if err == nil && len(upstreams) > 0 {
		config := &DNSConfig{
			PrimaryDNS: upstreams[0],
			DNSServers: upstreams,
		}
		if len(upstreams) > 1 {
			config.SecondaryDNS = upstreams[1]
		}
		log.Debug().Strs("upstreams", upstreams).Msg("NetworkManager: got DNS config from Pi-hole")
		return config, nil
	}
	if err != nil {
		log.Warn().Err(err).Msg("NetworkManager: Pi-hole API failed, falling back to resolv.conf")
	}

	// 2. Fallback: read from resolv.conf (legacy behavior)
	config := &DNSConfig{
		PrimaryDNS: models.DefaultGatewayIP, // Pi-hole default
		DNSServers: []string{models.DefaultGatewayIP},
	}

	resolvPaths := []string{"/host-root/etc/resolv.conf", "/etc/resolv.conf"}
	for _, path := range resolvPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		var servers []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					servers = append(servers, parts[1])
				}
			} else if strings.HasPrefix(line, "search") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					config.SearchDomain = parts[1]
				}
			}
		}

		if len(servers) > 0 {
			config.PrimaryDNS = servers[0]
			config.DNSServers = servers
			if len(servers) > 1 {
				config.SecondaryDNS = servers[1]
			}
		}
		break
	}

	return config, nil
}

// SetDNSConfig sets the DNS configuration.
// Primary target: Pi-hole upstream servers (via Pi-hole API).
// Fallback: writes to resolv.conf (legacy behavior for non-Pi-hole setups).
func (m *NetworkManager) SetDNSConfig(ctx context.Context, cfg *DNSConfig) error {
	if cfg == nil {
		return fmt.Errorf("DNS config cannot be nil")
	}

	if cfg.PrimaryDNS == "" {
		return fmt.Errorf("primary DNS server is required")
	}

	// Validate DNS server addresses
	if !isValidDNSAddress(cfg.PrimaryDNS) {
		return fmt.Errorf("invalid primary DNS server address: %s", cfg.PrimaryDNS)
	}
	if cfg.SecondaryDNS != "" && !isValidDNSAddress(cfg.SecondaryDNS) {
		return fmt.Errorf("invalid secondary DNS server address: %s", cfg.SecondaryDNS)
	}

	// Build upstream list
	upstreams := []string{cfg.PrimaryDNS}
	if cfg.SecondaryDNS != "" {
		upstreams = append(upstreams, cfg.SecondaryDNS)
	}

	// 1. Try Pi-hole API to set upstream DNS servers
	if err := m.setPiholeUpstreams(ctx, upstreams); err != nil {
		log.Warn().Err(err).Msg("NetworkManager: Pi-hole API failed, falling back to resolv.conf")
	} else {
		log.Info().Strs("upstreams", upstreams).Msg("NetworkManager: DNS upstreams updated via Pi-hole")
		return nil
	}

	// 2. Fallback: write to resolv.conf (legacy behavior)
	var lines []string
	if cfg.SearchDomain != "" {
		lines = append(lines, fmt.Sprintf("search %s", cfg.SearchDomain))
	}
	lines = append(lines, fmt.Sprintf("nameserver %s", cfg.PrimaryDNS))
	if cfg.SecondaryDNS != "" {
		lines = append(lines, fmt.Sprintf("nameserver %s", cfg.SecondaryDNS))
	}

	content := strings.Join(lines, "\n") + "\n"

	resolvPaths := []string{"/host-root/etc/resolv.conf", "/etc/resolv.conf"}
	var lastErr error
	for _, path := range resolvPaths {
		if err := os.WriteFile(path, []byte(content), 0644); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	// If direct write fails, try using resolvconf command
	cmd := exec.CommandContext(ctx, "resolvconf", "-a", "eth0")
	cmd.Stdin = strings.NewReader(content)
	if err := cmd.Run(); err == nil {
		return nil
	}

	return fmt.Errorf("failed to set DNS config: %w", lastErr)
}

// =============================================================================
// Pi-hole API Integration
// =============================================================================

// piholeAuth authenticates with the Pi-hole v6 API and returns a session ID (SID).
func (m *NetworkManager) piholeAuth(ctx context.Context) (string, error) {
	authURL := m.piholeURL + "/api/auth"
	payload, _ := json.Marshal(map[string]string{"password": m.piholePassword})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Pi-hole auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Pi-hole auth failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	// Pi-hole v6 returns: {"session": {"valid": true, "sid": "xxx", ...}}
	var authResp struct {
		Session struct {
			Valid bool   `json:"valid"`
			SID   string `json:"sid"`
		} `json:"session"`
	}
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", fmt.Errorf("failed to parse Pi-hole auth response: %w", err)
	}

	if !authResp.Session.Valid || authResp.Session.SID == "" {
		return "", fmt.Errorf("Pi-hole auth returned invalid session")
	}

	return authResp.Session.SID, nil
}

// getPiholeUpstreams reads the upstream DNS servers from Pi-hole's API.
func (m *NetworkManager) getPiholeUpstreams(ctx context.Context) ([]string, error) {
	sid, err := m.piholeAuth(ctx)
	if err != nil {
		return nil, err
	}

	reqURL := m.piholeURL + "/api/config/dns/upstreams"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-FTL-SID", sid)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Pi-hole config request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Pi-hole config request failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	// Pi-hole v6 returns: {"config": {"dns": {"upstreams": ["1.1.1.1", "8.8.8.8"]}}}
	// or possibly: {"dns": {"upstreams": ["1.1.1.1", "8.8.8.8"]}}
	// Try multiple response structures for robustness
	var configResp struct {
		Config struct {
			DNS struct {
				Upstreams []string `json:"upstreams"`
			} `json:"dns"`
		} `json:"config"`
		DNS struct {
			Upstreams []string `json:"upstreams"`
		} `json:"dns"`
		Upstreams []string `json:"upstreams"`
	}
	if err := json.Unmarshal(body, &configResp); err != nil {
		return nil, fmt.Errorf("failed to parse Pi-hole config: %w", err)
	}

	// Check all possible response structures
	if len(configResp.Config.DNS.Upstreams) > 0 {
		return configResp.Config.DNS.Upstreams, nil
	}
	if len(configResp.DNS.Upstreams) > 0 {
		return configResp.DNS.Upstreams, nil
	}
	if len(configResp.Upstreams) > 0 {
		return configResp.Upstreams, nil
	}

	return nil, fmt.Errorf("Pi-hole returned no upstream DNS servers")
}

// setPiholeUpstreams updates the upstream DNS servers via Pi-hole's API.
func (m *NetworkManager) setPiholeUpstreams(ctx context.Context, upstreams []string) error {
	sid, err := m.piholeAuth(ctx)
	if err != nil {
		return err
	}

	// Pi-hole v6 PATCH /api/config/dns/upstreams
	reqURL := m.piholeURL + "/api/config/dns/upstreams"
	payload, _ := json.Marshal(upstreams)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FTL-SID", sid)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Pi-hole config update failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		// Try PATCH if PUT didn't work
		req2, _ := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewReader(payload))
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("X-FTL-SID", sid)
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return fmt.Errorf("Pi-hole config update failed (PUT %d: %s, PATCH: %v)", resp.StatusCode, string(body), err2)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusCreated {
			body2, _ := io.ReadAll(resp2.Body)
			return fmt.Errorf("Pi-hole config update failed (PUT %d, PATCH %d): %s", resp.StatusCode, resp2.StatusCode, string(body2))
		}
	}

	return nil
}

// =============================================================================
// Pi-hole DHCP Management (T06 — Pi-hole v6 REST API)
// =============================================================================

// setPiholeDHCPActive enables or disables the Pi-hole DHCP server via REST API.
// Pi-hole v6 uses PATCH /api/config/dhcp/active with the SID auth pattern.
// Includes retry logic for when Pi-hole container is still starting.
// @Summary Set Pi-hole DHCP active state
// @Description Enables or disables Pi-hole DHCP server via v6 REST API
// @Tags network,pihole
// @Param active body bool true "DHCP active state"
// @Success 200
// @Failure 500 {string} string "Pi-hole DHCP update failed"
// @Router /internal/pihole-dhcp [patch]
func (m *NetworkManager) setPiholeDHCPActive(ctx context.Context, active bool) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}

		sid, err := m.piholeAuth(ctx)
		if err != nil {
			lastErr = fmt.Errorf("Pi-hole auth failed (attempt %d): %w", attempt+1, err)
			log.Warn().Err(err).Int("attempt", attempt+1).Msg("setPiholeDHCPActive: auth retry")
			continue
		}

		reqURL := m.piholeURL + "/api/config/dhcp/active"
		// Pi-hole v6 requires {"config":{"dhcp":{"active":...}}} wrapper
		payload := []byte(fmt.Sprintf(`{"config":{"dhcp":{"active":%t}}}`, active))

		req, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-FTL-SID", sid)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("Pi-hole DHCP request failed (attempt %d): %w", attempt+1, err)
			log.Warn().Err(err).Int("attempt", attempt+1).Msg("setPiholeDHCPActive: request retry")
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			log.Info().Bool("active", active).Msg("Pi-hole DHCP active state updated")
			return nil
		}

		body, _ := io.ReadAll(resp.Body)
		lastErr = fmt.Errorf("Pi-hole DHCP update failed (HTTP %d): %s", resp.StatusCode, string(body))
		log.Warn().Int("status", resp.StatusCode).Str("body", string(body)).Int("attempt", attempt+1).
			Msg("setPiholeDHCPActive: unexpected status")
	}

	return lastErr
}

// setPiholeDnsmasqLines sets custom dnsmasq directives via Pi-hole v6 REST API.
// Used for per-mode DHCP interface control (no-dhcp-interface=eth0, etc.)
// and the wildcard cubeos.cube DNS entry.
// @Summary Set Pi-hole dnsmasq lines
// @Description Sets custom dnsmasq directives via v6 REST API
// @Tags network,pihole
// @Param lines body []string true "Dnsmasq directive lines"
// @Success 200
// @Failure 500 {string} string "Pi-hole dnsmasq update failed"
// @Router /internal/pihole-dnsmasq [patch]
func (m *NetworkManager) setPiholeDnsmasqLines(ctx context.Context, lines []string) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}

		sid, err := m.piholeAuth(ctx)
		if err != nil {
			lastErr = fmt.Errorf("Pi-hole auth failed (attempt %d): %w", attempt+1, err)
			log.Warn().Err(err).Int("attempt", attempt+1).Msg("setPiholeDnsmasqLines: auth retry")
			continue
		}

		reqURL := m.piholeURL + "/api/config/misc/dnsmasq_lines"
		// Pi-hole v6 requires {"config":{"misc":{"dnsmasq_lines":[...]}}} wrapper
		linesJSON, _ := json.Marshal(lines)
		payload := []byte(fmt.Sprintf(`{"config":{"misc":{"dnsmasq_lines":%s}}}`, string(linesJSON)))

		req, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-FTL-SID", sid)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("Pi-hole dnsmasq request failed (attempt %d): %w", attempt+1, err)
			log.Warn().Err(err).Int("attempt", attempt+1).Msg("setPiholeDnsmasqLines: request retry")
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			log.Info().Strs("lines", lines).Msg("Pi-hole dnsmasq lines updated")
			return nil
		}

		body, _ := io.ReadAll(resp.Body)
		lastErr = fmt.Errorf("Pi-hole dnsmasq update failed (HTTP %d): %s", resp.StatusCode, string(body))
		log.Warn().Int("status", resp.StatusCode).Str("body", string(body)).Int("attempt", attempt+1).
			Msg("setPiholeDnsmasqLines: unexpected status")
	}

	return lastErr
}

// configurePiholeDHCPForMode configures Pi-hole DHCP settings for the given network mode.
// This is the single source of truth for which modes enable DHCP and on which interfaces.
// See Section 15.3 of the execution plan for the full matrix.
func (m *NetworkManager) configurePiholeDHCPForMode(ctx context.Context, mode models.NetworkMode) {
	// Wildcard DNS for cubeos.cube — always included since FTLCONF_misc_dnsmasq_lines
	// was removed from env vars in Batch 1 (must be API-managed now)
	wildcard := "address=/cubeos.cube/10.42.24.1"

	var dhcpActive bool
	var dnsmasqLines []string

	switch mode {
	case models.NetworkModeOffline:
		// DHCP on all interfaces — both wlan0 and eth0 serve CubeOS clients
		dhcpActive = true
		dnsmasqLines = []string{wildcard}

	case models.NetworkModeOnlineETH:
		// DHCP on wlan0 AP only; eth0 is upstream DHCP client
		dhcpActive = true
		dnsmasqLines = []string{wildcard, "no-dhcp-interface=eth0"}

	case models.NetworkModeOnlineWiFi:
		// DHCP on wlan0 AP only; wlan1 is upstream WiFi client
		dhcpActive = true
		dnsmasqLines = []string{wildcard, "no-dhcp-interface=wlan1"}

	case models.NetworkModeOnlineTether:
		// DHCP on wlan0 AP only; tethering interface (enx*) is upstream.
		// The tethering interface is on a different subnet so dnsmasq won't
		// serve DHCP on it, but we exclude eth0 to prevent conflicts.
		dhcpActive = true
		dnsmasqLines = []string{wildcard, "no-dhcp-interface=eth0"}

	case models.NetworkModeServerETH, models.NetworkModeServerWiFi:
		// No AP, no DHCP — CubeOS is a client on existing network
		dhcpActive = false
		dnsmasqLines = []string{wildcard}
	}

	if err := m.setPiholeDHCPActive(ctx, dhcpActive); err != nil {
		log.Error().Err(err).Str("mode", string(mode)).Bool("active", dhcpActive).
			Msg("configurePiholeDHCPForMode: failed to set DHCP active state")
	}
	if err := m.setPiholeDnsmasqLines(ctx, dnsmasqLines); err != nil {
		log.Error().Err(err).Str("mode", string(mode)).Strs("lines", dnsmasqLines).
			Msg("configurePiholeDHCPForMode: failed to set dnsmasq lines")
	}
}

// WiFiStatus represents the current WiFi connection status
type WiFiStatus struct {
	Connected      bool     `json:"connected"`
	SSID           string   `json:"ssid,omitempty"`
	BSSID          string   `json:"bssid,omitempty"`
	Signal         int      `json:"signal,omitempty"`
	SignalDBM      int      `json:"signal_dbm,omitempty"`
	Frequency      int      `json:"frequency,omitempty"`
	Channel        int      `json:"channel,omitempty"`
	Security       string   `json:"security,omitempty"`
	IPAddress      string   `json:"ip_address,omitempty"`
	Netmask        string   `json:"netmask,omitempty"`
	Gateway        string   `json:"gateway,omitempty"`
	DNS            []string `json:"dns,omitempty"`
	Interface      string   `json:"interface"`
	MACAddress     string   `json:"mac_address,omitempty"`
	WiFiGeneration string   `json:"wifi_generation,omitempty"`
	TxBitrate      string   `json:"tx_bitrate,omitempty"`
}

// GetWiFiStatus returns the current WiFi connection status
func (m *NetworkManager) GetWiFiStatus(ctx context.Context) (*WiFiStatus, error) {
	// Determine which interface to check
	iface := m.resolveWiFiClientInterface(ctx)
	if m.currentMode == models.NetworkModeServerWiFi {
		iface = m.apInterface
	}

	status := &WiFiStatus{
		Connected: false,
		Interface: iface,
	}

	// Get comprehensive status from HAL (runs on host with access to wpa_cli, iw, etc.)
	if m.hal != nil {
		halStatus, err := m.hal.GetWiFiStatus(ctx, iface)
		if err == nil {
			status.Connected = halStatus.Connected
			status.SSID = halStatus.SSID
			status.BSSID = halStatus.BSSID
			status.Signal = halStatus.SignalPercent
			status.SignalDBM = halStatus.SignalDBM
			status.Frequency = halStatus.Frequency
			status.Channel = halStatus.Channel
			status.Security = halStatus.Security
			status.IPAddress = halStatus.IPAddress
			status.Netmask = halStatus.Netmask
			status.Gateway = halStatus.Gateway
			status.DNS = halStatus.DNS
			status.MACAddress = halStatus.MACAddress
			status.WiFiGeneration = halStatus.WiFiGeneration
			status.TxBitrate = halStatus.TxBitrate
			return status, nil
		}
		log.Warn().Err(err).Msg("NetworkManager: HAL GetWiFiStatus failed, returning basic status")
	}

	return status, nil
}

// SavedNetwork represents a saved WiFi network
type SavedNetwork struct {
	SSID     string `json:"ssid"`
	Security string `json:"security,omitempty"`
	AutoJoin bool   `json:"auto_join"`
}

// GetSavedNetworks returns a list of saved WiFi networks
func (m *NetworkManager) GetSavedNetworks(ctx context.Context) ([]SavedNetwork, error) {
	var networks []SavedNetwork

	// Try HAL first (works from container)
	if m.hal != nil {
		iface := m.resolveWiFiClientInterface(ctx)
		halNetworks, err := m.hal.GetSavedWiFiNetworks(ctx, iface)
		if err == nil && halNetworks != nil && len(halNetworks.Networks) > 0 {
			for _, n := range halNetworks.Networks {
				networks = append(networks, SavedNetwork{
					SSID:     n.SSID,
					Security: n.Security,
					AutoJoin: n.AutoJoin,
				})
			}
			return networks, nil
		}
		// Fall through to local methods if HAL fails
		log.Warn().Err(err).Msg("NetworkManager: HAL GetSavedWiFiNetworks failed, trying local methods")
	}

	// Try NetworkManager first (nmcli)
	cmd := exec.CommandContext(ctx, "nmcli", "-t", "-f", "NAME,TYPE,AUTOCONNECT", "connection", "show")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 && parts[1] == "802-11-wireless" {
				autoJoin := parts[2] == "yes"
				networks = append(networks, SavedNetwork{
					SSID:     parts[0],
					AutoJoin: autoJoin,
				})
			}
		}
		return networks, nil
	}

	// Try wpa_supplicant config file
	wpaConfPaths := []string{
		"/host-root/etc/wpa_supplicant/wpa_supplicant.conf",
		"/etc/wpa_supplicant/wpa_supplicant.conf",
		"/host-root/etc/wpa_supplicant/wpa_supplicant-wlan0.conf",
		"/etc/wpa_supplicant/wpa_supplicant-wlan0.conf",
	}

	for _, path := range wpaConfPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Simple parsing of wpa_supplicant.conf
		content := string(data)
		networkBlocks := strings.Split(content, "network={")
		for i := 1; i < len(networkBlocks); i++ {
			block := networkBlocks[i]
			endIdx := strings.Index(block, "}")
			if endIdx < 0 {
				continue
			}
			block = block[:endIdx]

			var ssid string
			lines := strings.Split(block, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ssid=") {
					ssid = strings.Trim(line[5:], "\"")
					break
				}
			}

			if ssid != "" {
				networks = append(networks, SavedNetwork{
					SSID:     ssid,
					AutoJoin: true, // wpa_supplicant networks auto-join by default
				})
			}
		}

		if len(networks) > 0 {
			break
		}
	}

	return networks, nil
}

// ForgetNetwork removes a saved WiFi network
func (m *NetworkManager) ForgetNetwork(ctx context.Context, ssid string) error {
	if ssid == "" {
		return fmt.Errorf("SSID cannot be empty")
	}

	iface := m.resolveWiFiClientInterface(ctx)

	// Try HAL first (works from container)
	if m.hal != nil {
		err := m.hal.ForgetWiFiNetwork(ctx, ssid, iface)
		if err == nil {
			return nil
		}
		// Fall through to local methods if HAL fails
		log.Warn().Err(err).Msg("NetworkManager: HAL ForgetWiFiNetwork failed, trying local methods")
	}

	// Try NetworkManager first (nmcli)
	cmd := exec.CommandContext(ctx, "nmcli", "connection", "delete", ssid)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Try wpa_cli
	cmd = exec.CommandContext(ctx, "wpa_cli", "-i", iface, "list_networks")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list networks: %w", err)
	}

	// Parse network list to find the network ID
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			// Skip header line
			if fields[0] == "network" {
				continue
			}
			// Check if SSID matches
			if len(fields) >= 2 && fields[1] == ssid {
				networkID := fields[0]
				// Remove the network
				cmd = exec.CommandContext(ctx, "wpa_cli", "-i", iface, "remove_network", networkID)
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to remove network: %w", err)
				}
				// Save configuration
				cmd = exec.CommandContext(ctx, "wpa_cli", "-i", iface, "save_config")
				cmd.Run() // Ignore error
				return nil
			}
		}
	}

	return fmt.Errorf("network '%s' not found in saved networks", ssid)
}
