// Package managers provides network mode management for CubeOS.
// This version uses the HAL (Hardware Abstraction Layer) service for
// network operations since the API runs in a Swarm container without
// direct access to host network commands (ip, iw, wpa_supplicant).
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

// NetworkMode represents the network operating mode
type NetworkMode string

const (
	NetworkModeOffline    NetworkMode = "offline"
	NetworkModeOnlineETH  NetworkMode = "online_eth"
	NetworkModeOnlineWiFi NetworkMode = "online_wifi"
)

// Default interface names - can be overridden via environment
const (
	DefaultAPInterface         = "wlan0"
	DefaultWANInterface        = "eth0"
	DefaultWiFiClientInterface = "wlxccbabdb4dd07" // USB dongle
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

// NetworkStatus represents the current network status
type NetworkStatus struct {
	Mode      NetworkMode        `json:"mode"`
	Internet  bool               `json:"internet"`
	AP        *AccessPointStatus `json:"ap,omitempty"`
	Upstream  *UpstreamStatus    `json:"upstream,omitempty"`
	Subnet    string             `json:"subnet"`
	GatewayIP string             `json:"gateway_ip"`
}

// AccessPointStatus represents WiFi AP status
type AccessPointStatus struct {
	SSID      string `json:"ssid"`
	Interface string `json:"interface"`
	Clients   int    `json:"clients"`
	Channel   int    `json:"channel"`
}

// UpstreamStatus represents upstream connection status
type UpstreamStatus struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Gateway   string `json:"gateway"`
	Type      string `json:"type"` // "ethernet" or "wifi"
	SSID      string `json:"ssid,omitempty"`
}

// NetworkManager handles network mode and WiFi operations via HAL
type NetworkManager struct {
	cfg                 *config.Config
	hal                 *hal.Client
	db                  *sqlx.DB
	currentMode         NetworkMode
	apInterface         string
	wanInterface        string
	wifiClientInterface string
	apSSID              string
}

// NewNetworkManager creates a new network manager
func NewNetworkManager(cfg *config.Config, halClient *hal.Client, db *sqlx.DB) *NetworkManager {
	if halClient == nil {
		halClient = hal.NewClient("")
	}

	// Get interface names from environment or use defaults
	apIface := getEnvOrDefault("CUBEOS_AP_INTERFACE", DefaultAPInterface)
	wanIface := getEnvOrDefault("CUBEOS_WAN_INTERFACE", DefaultWANInterface)
	wifiClientIface := getEnvOrDefault("CUBEOS_WIFI_CLIENT_INTERFACE", DefaultWiFiClientInterface)
	apSSID := getEnvOrDefault("CUBEOS_AP_SSID", "CubeOS")

	// Load mode from database
	mode := loadModeFromDB(db)
	log.Printf("NetworkManager: loaded mode '%s' from database", mode)

	return &NetworkManager{
		cfg:                 cfg,
		hal:                 halClient,
		db:                  db,
		currentMode:         mode,
		apInterface:         apIface,
		wanInterface:        wanIface,
		wifiClientInterface: wifiClientIface,
		apSSID:              apSSID,
	}
}

// loadModeFromDB loads the network mode from database
func loadModeFromDB(db *sqlx.DB) NetworkMode {
	if db == nil {
		log.Printf("NetworkManager: no database connection, defaulting to offline")
		return NetworkModeOffline
	}

	var mode string
	err := db.Get(&mode, "SELECT mode FROM network_config WHERE id = 1")
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("NetworkManager: no network_config row, defaulting to offline")
		} else {
			log.Printf("NetworkManager: failed to load mode from database: %v", err)
		}
		return NetworkModeOffline
	}

	switch NetworkMode(mode) {
	case NetworkModeOnlineETH:
		return NetworkModeOnlineETH
	case NetworkModeOnlineWiFi:
		return NetworkModeOnlineWiFi
	default:
		return NetworkModeOffline
	}
}

// saveModeToDBHelper persists the network mode to database
func (m *NetworkManager) saveModeToDB(mode NetworkMode, wifiSSID string) {
	if m.db == nil {
		return
	}

	_, err := m.db.Exec(`
		UPDATE network_config 
		SET mode = ?, wifi_ssid = ?, updated_at = CURRENT_TIMESTAMP 
		WHERE id = 1`,
		string(mode), wifiSSID)
	if err != nil {
		log.Printf("NetworkManager: failed to persist mode to database: %v", err)
	} else {
		log.Printf("NetworkManager: persisted mode '%s' to database", mode)
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// GetStatus returns the current network status
func (m *NetworkManager) GetStatus(ctx context.Context) (*NetworkStatus, error) {
	status := &NetworkStatus{
		Mode:      m.currentMode,
		Subnet:    m.cfg.Subnet,
		GatewayIP: m.cfg.GatewayIP,
	}

	// Get interface status from HAL
	interfaces, err := m.hal.ListInterfaces(ctx)
	if err != nil {
		// Still check internet even if HAL fails
		status.Internet = m.checkInternetConnectivity()
		return status, nil
	}

	// Find AP interface (wlan0)
	for _, iface := range interfaces {
		if iface.Name == m.apInterface {
			status.AP = &AccessPointStatus{
				Interface: iface.Name,
				SSID:      m.apSSID,
			}
		}

		// Find upstream interface based on mode
		if m.currentMode == NetworkModeOnlineETH && iface.Name == m.wanInterface {
			if len(iface.IPv4Addresses) > 0 {
				status.Upstream = &UpstreamStatus{
					Interface: iface.Name,
					IP:        iface.IPv4Addresses[0],
					Type:      "ethernet",
				}
			}
		}

		if m.currentMode == NetworkModeOnlineWiFi && iface.Name == m.wifiClientInterface {
			if len(iface.IPv4Addresses) > 0 {
				status.Upstream = &UpstreamStatus{
					Interface: iface.Name,
					IP:        iface.IPv4Addresses[0],
					Type:      "wifi",
				}
			}
		}
	}

	// Actually check internet connectivity regardless of mode
	status.Internet = m.checkInternetConnectivity()

	return status, nil
}

// checkInternetConnectivity performs an actual connectivity check
func (m *NetworkManager) checkInternetConnectivity() bool {
	// Create a client with short timeout
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// Try to reach a reliable endpoint (Google's connectivity check)
	resp, err := client.Head("http://connectivitycheck.gstatic.com/generate_204")
	if err != nil {
		// Try alternate endpoint
		resp, err = client.Head("http://www.gstatic.com/generate_204")
		if err != nil {
			return false
		}
	}
	defer resp.Body.Close()

	// 204 No Content is expected for connectivity checks
	// 200 OK is also acceptable
	return resp.StatusCode == 204 || resp.StatusCode == 200
}

// SetMode changes the network operating mode
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
	default:
		return fmt.Errorf("unknown network mode: %s", mode)
	}

	if err != nil {
		return err
	}

	// Persist to database
	m.saveModeToDB(mode, wifiSSID)

	return nil
}

// setOfflineMode configures offline (AP only) mode
func (m *NetworkManager) setOfflineMode(ctx context.Context) error {
	// Disable NAT - ignore errors (might already be disabled)
	_ = m.hal.DisableNAT(ctx)
	_ = m.hal.DisableIPForward(ctx)

	// Disconnect any upstream WiFi
	if m.currentMode == NetworkModeOnlineWiFi {
		_ = m.hal.DisconnectWiFi(ctx, m.wifiClientInterface)
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

// ScanWiFiNetworks scans for available WiFi networks via HAL
func (m *NetworkManager) ScanWiFiNetworks(ctx context.Context, iface string) ([]WiFiNetwork, error) {
	if iface == "" {
		iface = m.wifiClientInterface
	}

	// Ensure interface is up
	ifaceInfo, err := m.hal.GetInterface(ctx, iface)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %w", err)
	}
	if !ifaceInfo.IsUp {
		if err := m.hal.BringInterfaceUp(ctx, iface); err != nil {
			return nil, fmt.Errorf("failed to bring up interface: %w", err)
		}
		time.Sleep(time.Second)
	}

	// Scan via HAL
	halNetworks, err := m.hal.ScanWiFi(ctx, iface)
	if err != nil {
		return nil, fmt.Errorf("WiFi scan failed: %w", err)
	}

	// Convert HAL networks to our format
	networks := make([]WiFiNetwork, len(halNetworks))
	for i, n := range halNetworks {
		networks[i] = WiFiNetwork{
			SSID:      n.SSID,
			BSSID:     n.BSSID,
			Signal:    n.Signal,
			Frequency: n.Frequency,
			Security:  n.Security,
			Channel:   n.Channel,
		}
	}

	return networks, nil
}

// ConnectToWiFi connects to a WiFi network via HAL
func (m *NetworkManager) ConnectToWiFi(ctx context.Context, iface, ssid, password string) error {
	if iface == "" {
		iface = m.wifiClientInterface
	}
	return m.hal.ConnectWiFi(ctx, iface, ssid, password)
}

// DisconnectWiFi disconnects from WiFi via HAL
func (m *NetworkManager) DisconnectWiFi(ctx context.Context, iface string) error {
	if iface == "" {
		iface = m.wifiClientInterface
	}
	return m.hal.DisconnectWiFi(ctx, iface)
}

// GetInterfaces returns all network interfaces via HAL
func (m *NetworkManager) GetInterfaces(ctx context.Context) ([]models.NetworkInterface, error) {
	halInterfaces, err := m.hal.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	interfaces := make([]models.NetworkInterface, len(halInterfaces))
	for i, iface := range halInterfaces {
		interfaces[i] = models.NetworkInterface{
			Name:          iface.Name,
			IsUp:          iface.IsUp,
			MACAddress:    iface.MACAddress,
			IPv4Addresses: iface.IPv4Addresses,
			IPv6Addresses: iface.IPv6Addresses,
			MTU:           iface.MTU,
			IsWireless:    iface.IsWireless,
		}
	}

	return interfaces, nil
}

// GetConnectedClients returns the number of connected WiFi clients
// This is needed by MonitoringManager
func (m *NetworkManager) GetConnectedClients() ([]interface{}, error) {
	// Read from /var/lib/misc/dnsmasq.leases or hostapd
	// For now, return empty slice - could read from /proc via HAL
	return []interface{}{}, nil
}

// RestartAP restarts the access point via HAL
func (m *NetworkManager) RestartAP(ctx context.Context) error {
	return m.hal.RestartService(ctx, "hostapd")
}

// GetWiFiClientInterface returns the WiFi client interface name
func (m *NetworkManager) GetWiFiClientInterface() string {
	return m.wifiClientInterface
}

// DetectWiFiClientInterface detects available WiFi client interfaces
func (m *NetworkManager) DetectWiFiClientInterface(ctx context.Context) (string, error) {
	interfaces, err := m.hal.ListInterfaces(ctx)
	if err != nil {
		return "", err
	}

	// Look for wireless interfaces that are NOT the AP interface
	for _, iface := range interfaces {
		if iface.IsWireless && iface.Name != m.apInterface {
			// Prefer USB WiFi dongles (usually have longer names like wlx...)
			if strings.HasPrefix(iface.Name, "wlx") {
				return iface.Name, nil
			}
		}
	}

	// Fallback to any wireless interface that's not the AP
	for _, iface := range interfaces {
		if iface.IsWireless && iface.Name != m.apInterface {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no WiFi client interface found")
}

// CheckInternetConnectivity checks if internet is accessible (public method)
func (m *NetworkManager) CheckInternetConnectivity(ctx context.Context) bool {
	return m.checkInternetConnectivity()
}
