// Package managers provides network mode management for CubeOS.
// Network Modes V2: Supports 5 modes (OFFLINE, ONLINE_ETH, ONLINE_WIFI, SERVER_ETH, SERVER_WIFI)
// plus VPN overlay (None, WireGuard, OpenVPN, Tor)
package managers

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/models"

	"github.com/jmoiron/sqlx"
)

// NetworkMode represents the network operating mode (V2: 5 modes)
type NetworkMode string

const (
	NetworkModeOffline    NetworkMode = "offline"
	NetworkModeOnlineETH  NetworkMode = "online_eth"
	NetworkModeOnlineWiFi NetworkMode = "online_wifi"
	NetworkModeServerETH  NetworkMode = "server_eth"  // V2: Server mode via Ethernet
	NetworkModeServerWiFi NetworkMode = "server_wifi" // V2: Server mode via WiFi
)

// VPNMode represents the VPN overlay mode (V2)
type VPNMode string

const (
	VPNModeNone      VPNMode = "none"
	VPNModeWireGuard VPNMode = "wireguard"
	VPNModeOpenVPN   VPNMode = "openvpn"
	VPNModeTor       VPNMode = "tor"
)

// Default interface names - can be overridden via environment
const (
	DefaultAPInterface         = "wlan0"
	DefaultWANInterface        = "eth0"
	DefaultWiFiClientInterface = "wlxccbabdb4dd07" // USB dongle
	DefaultFallbackIP          = "192.168.1.242"   // V2: Server mode fallback
)

// WiFiNetwork represents a scanned WiFi network
type WiFiNetwork struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Signal    int    `json:"signal"`
	Frequency int    `json:"frequency"`
	Security  string `json:"security"`
	Channel   int    `json:"channel"`
}

// NetworkStatus represents the current network status (V2: extended)
type NetworkStatus struct {
	Mode       NetworkMode        `json:"mode"`
	Internet   bool               `json:"internet"`
	AP         *AccessPointStatus `json:"ap,omitempty"`
	Upstream   *UpstreamStatus    `json:"upstream,omitempty"`
	Subnet     string             `json:"subnet"`
	GatewayIP  string             `json:"gateway_ip"`
	VPNMode    VPNMode            `json:"vpn_mode"`              // V2
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

// NetworkConfig represents persisted network configuration (V2: extended)
type NetworkConfig struct {
	Mode                       NetworkMode `db:"mode" json:"mode"`
	VPNMode                    VPNMode     `db:"vpn_mode" json:"vpn_mode"`
	VPNConfigID                *int64      `db:"vpn_config_id" json:"vpn_config_id,omitempty"`
	WiFiSSID                   string      `db:"wifi_ssid" json:"wifi_ssid"`
	WiFiPassword               string      `db:"wifi_password" json:"-"` // Never expose
	GatewayIP                  string      `db:"gateway_ip" json:"gateway_ip"`
	Subnet                     string      `db:"subnet" json:"subnet"`
	DHCPRangeStart             string      `db:"dhcp_range_start" json:"dhcp_range_start"`
	DHCPRangeEnd               string      `db:"dhcp_range_end" json:"dhcp_range_end"`
	FallbackStaticIP           string      `db:"fallback_static_ip" json:"fallback_static_ip"`
	APSSID                     string      `db:"ap_ssid" json:"ap_ssid"`
	APPassword                 string      `db:"ap_password" json:"-"` // Never expose
	APChannel                  int         `db:"ap_channel" json:"ap_channel"`
	APHidden                   bool        `db:"ap_hidden" json:"ap_hidden"`
	ServerModeWarningDismissed bool        `db:"server_mode_warning_dismissed" json:"server_mode_warning_dismissed"`
}

// NetworkManager handles network mode and WiFi operations via HAL (V2: extended)
type NetworkManager struct {
	cfg                 *config.Config
	hal                 *hal.Client
	db                  *sqlx.DB
	currentMode         NetworkMode
	currentVPNMode      VPNMode // V2
	apInterface         string
	wanInterface        string
	wifiClientInterface string
	apSSID              string
	fallbackIP          string // V2
}

// NewNetworkManager creates a new network manager (V2: loads VPN mode too)
func NewNetworkManager(cfg *config.Config, halClient *hal.Client, db *sqlx.DB) *NetworkManager {
	if halClient == nil {
		halClient = hal.NewClient("")
	}

	// Get interface names from environment or use defaults
	apIface := getEnvOrDefault("CUBEOS_AP_INTERFACE", DefaultAPInterface)
	wanIface := getEnvOrDefault("CUBEOS_WAN_INTERFACE", DefaultWANInterface)
	wifiClientIface := getEnvOrDefault("CUBEOS_WIFI_CLIENT_INTERFACE", DefaultWiFiClientInterface)
	apSSID := getEnvOrDefault("CUBEOS_AP_SSID", "CubeOS")
	fallbackIP := getEnvOrDefault("CUBEOS_FALLBACK_IP", DefaultFallbackIP)

	// Load mode and VPN from database
	mode, vpnMode := loadConfigFromDB(db)
	log.Printf("NetworkManager: loaded mode '%s', vpn '%s' from database", mode, vpnMode)

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
	}
}

// loadConfigFromDB loads the network mode and VPN mode from database (V2)
func loadConfigFromDB(db *sqlx.DB) (NetworkMode, VPNMode) {
	if db == nil {
		log.Printf("NetworkManager: no database connection, defaulting to offline")
		return NetworkModeOffline, VPNModeNone
	}

	var mode, vpnMode string
	err := db.QueryRow("SELECT mode, COALESCE(vpn_mode, 'none') FROM network_config WHERE id = 1").Scan(&mode, &vpnMode)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("NetworkManager: no network_config row, defaulting to offline")
		} else {
			log.Printf("NetworkManager: failed to load config from database: %v", err)
		}
		return NetworkModeOffline, VPNModeNone
	}

	return parseNetworkMode(mode), parseVPNMode(vpnMode)
}

// parseNetworkMode converts string to NetworkMode (V2: includes SERVER modes)
func parseNetworkMode(mode string) NetworkMode {
	switch NetworkMode(mode) {
	case NetworkModeOnlineETH:
		return NetworkModeOnlineETH
	case NetworkModeOnlineWiFi:
		return NetworkModeOnlineWiFi
	case NetworkModeServerETH:
		return NetworkModeServerETH
	case NetworkModeServerWiFi:
		return NetworkModeServerWiFi
	default:
		return NetworkModeOffline
	}
}

// parseVPNMode converts string to VPNMode (V2)
func parseVPNMode(mode string) VPNMode {
	switch VPNMode(mode) {
	case VPNModeWireGuard:
		return VPNModeWireGuard
	case VPNModeOpenVPN:
		return VPNModeOpenVPN
	case VPNModeTor:
		return VPNModeTor
	default:
		return VPNModeNone
	}
}

// saveConfigToDB persists the network config to database (V2: extended)
func (m *NetworkManager) saveConfigToDB(mode NetworkMode, vpnMode VPNMode, wifiSSID string) {
	if m.db == nil {
		return
	}

	_, err := m.db.Exec(`
		INSERT INTO network_config (id, mode, vpn_mode, wifi_ssid, updated_at) 
		VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET 
			mode = excluded.mode, 
			vpn_mode = excluded.vpn_mode,
			wifi_ssid = excluded.wifi_ssid, 
			updated_at = CURRENT_TIMESTAMP`,
		string(mode), string(vpnMode), wifiSSID)
	if err != nil {
		log.Printf("NetworkManager: failed to persist config to database: %v", err)
	} else {
		log.Printf("NetworkManager: persisted mode '%s', vpn '%s' to database", mode, vpnMode)
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
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

	// Find upstream interface based on mode
	switch m.currentMode {
	case NetworkModeOnlineETH, NetworkModeServerETH:
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
	case NetworkModeOnlineWiFi, NetworkModeServerWiFi:
		for _, iface := range interfaces {
			if iface.Name == m.wifiClientInterface && len(iface.IPv4Addresses) > 0 {
				status.Upstream = &UpstreamStatus{
					Interface: iface.Name,
					IP:        iface.IPv4Addresses[0],
					Type:      "wifi",
				}
				break
			}
		}
	}

	// V2: Check VPN status
	if m.currentVPNMode != VPNModeNone {
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
	return m.currentMode == NetworkModeServerETH || m.currentMode == NetworkModeServerWiFi
}

// HasInternet returns true if current mode has internet capability (V2)
func (m *NetworkManager) HasInternet() bool {
	switch m.currentMode {
	case NetworkModeOnlineETH, NetworkModeOnlineWiFi, NetworkModeServerETH, NetworkModeServerWiFi:
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
func (m *NetworkManager) GetCurrentMode() NetworkMode {
	return m.currentMode
}

// GetCurrentVPNMode returns the current VPN mode (V2)
func (m *NetworkManager) GetCurrentVPNMode() VPNMode {
	return m.currentVPNMode
}

// SetMode changes the network operating mode (V2: supports 5 modes)
func (m *NetworkManager) SetMode(ctx context.Context, mode NetworkMode, wifiSSID, wifiPassword string) error {
	var err error

	switch mode {
	case NetworkModeOffline:
		err = m.setOfflineMode(ctx)
	case NetworkModeOnlineETH:
		err = m.setOnlineETHMode(ctx)
	case NetworkModeOnlineWiFi:
		if wifiSSID == "" {
			return fmt.Errorf("wifi SSID required for ONLINE_WIFI mode")
		}
		err = m.setOnlineWiFiMode(ctx, wifiSSID, wifiPassword)
	case NetworkModeServerETH:
		err = m.setServerETHMode(ctx)
	case NetworkModeServerWiFi:
		if wifiSSID == "" {
			return fmt.Errorf("wifi SSID required for SERVER_WIFI mode")
		}
		err = m.setServerWiFiMode(ctx, wifiSSID, wifiPassword)
	default:
		return fmt.Errorf("unknown network mode: %s", mode)
	}

	if err != nil {
		return err
	}

	// If switching to mode without internet, disable VPN
	if !m.HasInternet() && m.currentVPNMode != VPNModeNone {
		log.Printf("NetworkManager: disabling VPN because mode has no internet")
		_ = m.SetVPNMode(ctx, VPNModeNone, nil)
	}

	// Persist to database
	m.saveConfigToDB(mode, m.currentVPNMode, wifiSSID)

	return nil
}

// SetVPNMode changes the VPN overlay mode (V2)
func (m *NetworkManager) SetVPNMode(ctx context.Context, mode VPNMode, configID *int64) error {
	// VPN requires internet
	if mode != VPNModeNone && !m.HasInternet() {
		return fmt.Errorf("VPN requires a network mode with internet access")
	}

	// Stop current VPN if active
	if m.currentVPNMode != VPNModeNone {
		if err := m.stopVPN(ctx); err != nil {
			log.Printf("NetworkManager: failed to stop current VPN: %v", err)
		}
	}

	// Start new VPN if not none
	if mode != VPNModeNone {
		if err := m.startVPN(ctx, mode, configID); err != nil {
			return fmt.Errorf("failed to start VPN: %w", err)
		}
	}

	m.currentVPNMode = mode
	m.saveConfigToDB(m.currentMode, mode, "")
	return nil
}

// startVPN starts the specified VPN (V2)
func (m *NetworkManager) startVPN(ctx context.Context, mode VPNMode, configID *int64) error {
	switch mode {
	case VPNModeWireGuard:
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
	case VPNModeOpenVPN:
		configName := "client"
		if configID != nil {
			var name string
			err := m.db.Get(&name, "SELECT name FROM vpn_configs WHERE id = ?", *configID)
			if err == nil {
				configName = name
			}
		}
		return m.hal.StartOpenVPN(ctx, configName)
	case VPNModeTor:
		return m.hal.StartTor(ctx)
	default:
		return nil
	}
}

// stopVPN stops the current VPN (V2)
func (m *NetworkManager) stopVPN(ctx context.Context) error {
	switch m.currentVPNMode {
	case VPNModeWireGuard:
		return m.hal.StopWireGuard(ctx, "wg0")
	case VPNModeOpenVPN:
		return m.hal.StopOpenVPN(ctx, "client")
	case VPNModeTor:
		return m.hal.StopTor(ctx)
	default:
		return nil
	}
}

// setOfflineMode configures offline (AP only) mode
func (m *NetworkManager) setOfflineMode(ctx context.Context) error {
	// Disable NAT - ignore errors (might already be disabled)
	_ = m.hal.DisableNAT(ctx)
	_ = m.hal.DisableIPForward(ctx)

	// Disconnect any upstream WiFi
	if m.currentMode == NetworkModeOnlineWiFi || m.currentMode == NetworkModeServerWiFi {
		_ = m.hal.DisconnectWiFi(ctx, m.wifiClientInterface)
	}

	// Ensure AP is running (for non-server recovery)
	if m.IsServerMode() {
		if err := m.hal.StartAP(ctx, m.apInterface); err != nil {
			log.Printf("NetworkManager: failed to start AP: %v", err)
		}
	}

	m.currentMode = NetworkModeOffline
	return nil
}

// setOnlineETHMode configures online via Ethernet mode
func (m *NetworkManager) setOnlineETHMode(ctx context.Context) error {
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

	// Ensure AP is running
	if m.IsServerMode() {
		if err := m.hal.StartAP(ctx, m.apInterface); err != nil {
			log.Printf("NetworkManager: failed to start AP: %v", err)
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

	m.currentMode = NetworkModeOnlineETH
	return nil
}

// setOnlineWiFiMode configures online via WiFi client mode
func (m *NetworkManager) setOnlineWiFiMode(ctx context.Context, ssid, password string) error {
	// Bring up WiFi client interface (USB dongle)
	iface, err := m.hal.GetInterface(ctx, m.wifiClientInterface)
	if err != nil {
		return fmt.Errorf("WiFi client interface not available: %w", err)
	}
	if !iface.IsUp {
		if err := m.hal.BringInterfaceUp(ctx, m.wifiClientInterface); err != nil {
			return fmt.Errorf("failed to bring up WiFi client interface: %w", err)
		}
		time.Sleep(time.Second) // Wait for interface to be ready
	}

	// Connect to upstream WiFi
	if err := m.hal.ConnectWiFi(ctx, m.wifiClientInterface, ssid, password); err != nil {
		return fmt.Errorf("failed to connect to WiFi: %w", err)
	}

	// Wait for connection
	time.Sleep(5 * time.Second)

	// Ensure AP is running
	if m.IsServerMode() {
		if err := m.hal.StartAP(ctx, m.apInterface); err != nil {
			log.Printf("NetworkManager: failed to start AP: %v", err)
		}
	}

	// Enable IP forwarding
	if err := m.hal.EnableIPForward(ctx); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Enable NAT: AP interface -> WiFi client interface
	if err := m.hal.EnableNAT(ctx, m.apInterface, m.wifiClientInterface); err != nil {
		return fmt.Errorf("failed to enable NAT: %w", err)
	}

	m.currentMode = NetworkModeOnlineWiFi
	return nil
}

// setServerETHMode configures server mode via Ethernet (V2)
// No AP, just connects to existing network
func (m *NetworkManager) setServerETHMode(ctx context.Context) error {
	log.Printf("NetworkManager: switching to SERVER_ETH mode")

	// Stop the access point
	if err := m.hal.StopAP(ctx, m.apInterface); err != nil {
		log.Printf("NetworkManager: failed to stop AP (may not be running): %v", err)
	}

	// Disable NAT (we're a client now, not a router)
	_ = m.hal.DisableNAT(ctx)
	_ = m.hal.DisableIPForward(ctx)

	// Bring up ethernet interface
	if err := m.hal.BringInterfaceUp(ctx, m.wanInterface); err != nil {
		return fmt.Errorf("failed to bring up ethernet: %w", err)
	}

	// Request DHCP
	if err := m.hal.RequestDHCP(ctx, m.wanInterface); err != nil {
		log.Printf("NetworkManager: DHCP request failed, using fallback IP %s: %v", m.fallbackIP, err)
		// Fall back to static IP
		if err := m.hal.SetStaticIP(ctx, m.wanInterface, m.fallbackIP, "255.255.255.0"); err != nil {
			return fmt.Errorf("failed to set fallback IP: %w", err)
		}
	}

	// Wait for network
	time.Sleep(3 * time.Second)

	m.currentMode = NetworkModeServerETH
	return nil
}

// setServerWiFiMode configures server mode via WiFi (V2)
// No AP, connects wlan0 to existing WiFi network
func (m *NetworkManager) setServerWiFiMode(ctx context.Context, ssid, password string) error {
	log.Printf("NetworkManager: switching to SERVER_WIFI mode, connecting to %s", ssid)

	// Stop the access point (this frees wlan0 for client use)
	if err := m.hal.StopAP(ctx, m.apInterface); err != nil {
		log.Printf("NetworkManager: failed to stop AP: %v", err)
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

	// Verify we got an IP
	iface, err := m.hal.GetInterface(ctx, m.apInterface)
	if err != nil || len(iface.IPv4Addresses) == 0 {
		log.Printf("NetworkManager: no IP assigned, using fallback %s", m.fallbackIP)
		if err := m.hal.SetStaticIP(ctx, m.apInterface, m.fallbackIP, "255.255.255.0"); err != nil {
			return fmt.Errorf("failed to set fallback IP: %w", err)
		}
	}

	m.currentMode = NetworkModeServerWiFi
	return nil
}

// ScanWiFiNetworks scans for available WiFi networks
func (m *NetworkManager) ScanWiFiNetworks(ctx context.Context) ([]WiFiNetwork, error) {
	// Determine which interface to scan with
	scanInterface := m.wifiClientInterface

	// For SERVER_WIFI mode or when USB dongle not available, use wlan0
	if m.currentMode == NetworkModeServerWiFi {
		scanInterface = m.apInterface
	}

	// Try USB dongle first, fall back to wlan0
	networks, err := m.hal.ScanWiFi(ctx, scanInterface)
	if err != nil {
		// Try wlan0 if USB dongle failed
		if scanInterface != m.apInterface {
			networks, err = m.hal.ScanWiFi(ctx, m.apInterface)
			if err != nil {
				return nil, fmt.Errorf("WiFi scan failed: %w", err)
			}
		} else {
			return nil, fmt.Errorf("WiFi scan failed: %w", err)
		}
	}

	var result []WiFiNetwork
	for _, n := range networks {
		result = append(result, WiFiNetwork{
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
	// For regular modes, use USB dongle. For SERVER_WIFI, use wlan0
	iface := m.wifiClientInterface
	if m.currentMode == NetworkModeServerWiFi {
		iface = m.apInterface
	}

	return m.hal.ConnectWiFi(ctx, iface, ssid, password)
}

// DisconnectWiFi disconnects from upstream WiFi
func (m *NetworkManager) DisconnectWiFi(ctx context.Context) error {
	iface := m.wifiClientInterface
	if m.currentMode == NetworkModeServerWiFi {
		iface = m.apInterface
	}
	return m.hal.DisconnectWiFi(ctx, iface)
}

// DetectWiFiClientInterface attempts to detect the USB WiFi dongle interface
func (m *NetworkManager) DetectWiFiClientInterface(ctx context.Context) (string, error) {
	interfaces, err := m.hal.ListInterfaces(ctx)
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		// Look for wlx* interfaces (USB WiFi dongles)
		if strings.HasPrefix(iface.Name, "wlx") {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no USB WiFi dongle found")
}

// GetNetworkConfig returns the persisted network configuration (V2)
func (m *NetworkManager) GetNetworkConfig(ctx context.Context) (*NetworkConfig, error) {
	if m.db == nil {
		return &NetworkConfig{
			Mode:      NetworkModeOffline,
			VPNMode:   VPNModeNone,
			GatewayIP: "10.42.24.1",
			Subnet:    "10.42.24.0/24",
		}, nil
	}

	var cfg NetworkConfig
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
			return &NetworkConfig{
				Mode:      NetworkModeOffline,
				VPNMode:   VPNModeNone,
				GatewayIP: "10.42.24.1",
				Subnet:    "10.42.24.0/24",
			}, nil
		}
		return nil, err
	}
	return &cfg, nil
}

// UpdateNetworkConfig updates network configuration (V2)
func (m *NetworkManager) UpdateNetworkConfig(ctx context.Context, cfg *NetworkConfig) error {
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
// GetAPClients returns connected AP clients
func (m *NetworkManager) GetAPClients(ctx context.Context) ([]models.APClient, error) {
	if m.IsServerMode() {
		return []models.APClient{}, nil // No AP in server mode
	}

	resp, err := m.hal.GetAPClients(ctx)
	if err != nil {
		return nil, err
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
		}
	}
	return clients, nil
}

// IsValidMode checks if a mode string is valid (V2)
func IsValidMode(mode string) bool {
	switch NetworkMode(mode) {
	case NetworkModeOffline, NetworkModeOnlineETH, NetworkModeOnlineWiFi,
		NetworkModeServerETH, NetworkModeServerWiFi:
		return true
	default:
		return false
	}
}

// IsValidVPNMode checks if a VPN mode string is valid (V2)
func IsValidVPNMode(mode string) bool {
	switch VPNMode(mode) {
	case VPNModeNone, VPNModeWireGuard, VPNModeOpenVPN, VPNModeTor:
		return true
	default:
		return false
	}
}

// GetConnectedClients returns connected AP clients (alias for monitoring)
func (m *NetworkManager) GetConnectedClients() ([]models.APClient, error) {
	return m.GetAPClients(context.Background())
}

// APConfig represents WiFi Access Point configuration
type APConfig struct {
	SSID     string `json:"ssid"`
	Channel  int    `json:"channel"`
	Hidden   bool   `json:"hidden"`
	Password string `json:"password,omitempty"`
}

// GetAPConfig returns current AP configuration
func (m *NetworkManager) GetAPConfig(ctx context.Context) (*APConfig, error) {
	// Try to get from hostapd config or return defaults
	config := &APConfig{
		SSID:    "CubeOS",
		Channel: 7,
		Hidden:  false,
	}

	// Try to read from environment or config

	return config, nil
}

// UpdateAPConfig updates AP configuration
func (m *NetworkManager) UpdateAPConfig(ctx context.Context, ssid, password string, channel int, hidden bool) error {
	// TODO: Implement actual hostapd config update via HAL
	// For now, this is a stub that would need HAL support
	return fmt.Errorf("AP configuration update not yet implemented")
}
