// internal/models/network.go
// Network Modes V2 - Extended Models
// This file REPLACES internal/models/network.go
//
// Changes from original:
// - Added SERVER_ETH and SERVER_WIFI network modes
// - Added VPNMode enum (none, wireguard, openvpn, tor) for system-wide VPN overlay
// - Extended NetworkStatus with VPN and Server mode fields
// - Extended NetworkConfig with all new database fields
// - Added SetVPNModeRequest, NetworkSettingsRequest structs
// - Extended SetNetworkModeRequest with AcknowledgeWarning field
// - Updated helper methods to handle 5 modes

package models

import "time"

// ============================================================================
// NETWORK MODES (Extended from 3 to 5 modes)
// ============================================================================

type NetworkMode string

const (
	// Original 3 modes
	NetworkModeOffline    NetworkMode = "offline"     // AP only, no internet
	NetworkModeOnlineETH  NetworkMode = "online_eth"  // AP + NAT via eth0
	NetworkModeOnlineWiFi NetworkMode = "online_wifi" // AP + NAT via USB dongle

	// NEW: Server modes (no AP, direct network)
	NetworkModeServerETH  NetworkMode = "server_eth"  // No AP, eth0 DHCP client
	NetworkModeServerWiFi NetworkMode = "server_wifi" // No AP, wlan0 WiFi client
)

// AllNetworkModes returns all valid network modes
func AllNetworkModes() []NetworkMode {
	return []NetworkMode{
		NetworkModeOffline,
		NetworkModeOnlineETH,
		NetworkModeOnlineWiFi,
		NetworkModeServerETH,
		NetworkModeServerWiFi,
	}
}

// IsValid checks if the network mode is valid
func (m NetworkMode) IsValid() bool {
	switch m {
	case NetworkModeOffline, NetworkModeOnlineETH, NetworkModeOnlineWiFi,
		NetworkModeServerETH, NetworkModeServerWiFi:
		return true
	}
	return false
}

// IsOffline returns true if no internet connectivity
func (m NetworkMode) IsOffline() bool {
	return m == NetworkModeOffline
}

// HasInternet returns true if mode has internet access
func (m NetworkMode) HasInternet() bool {
	return m != NetworkModeOffline
}

// IsServerMode returns true for server modes (no AP)
func (m NetworkMode) IsServerMode() bool {
	return m == NetworkModeServerETH || m == NetworkModeServerWiFi
}

// HasAP returns true if mode runs an access point
func (m NetworkMode) HasAP() bool {
	return !m.IsServerMode()
}

// RequiresWiFiCredentials returns true if mode needs SSID/password
func (m NetworkMode) RequiresWiFiCredentials() bool {
	return m == NetworkModeOnlineWiFi || m == NetworkModeServerWiFi
}

// String returns the string representation
func (m NetworkMode) String() string {
	return string(m)
}

// ============================================================================
// VPN MODE (System-wide VPN overlay)
// ============================================================================

type VPNMode string

const (
	VPNModeNone      VPNMode = "none"
	VPNModeWireGuard VPNMode = "wireguard"
	VPNModeOpenVPN   VPNMode = "openvpn"
	VPNModeTor       VPNMode = "tor"
)

// AllVPNModes returns all valid VPN modes
func AllVPNModes() []VPNMode {
	return []VPNMode{VPNModeNone, VPNModeWireGuard, VPNModeOpenVPN, VPNModeTor}
}

// IsValid checks if the VPN mode is valid
func (v VPNMode) IsValid() bool {
	switch v {
	case VPNModeNone, VPNModeWireGuard, VPNModeOpenVPN, VPNModeTor:
		return true
	}
	return false
}

// RequiresConfig returns true if VPN mode requires a config
func (v VPNMode) RequiresConfig() bool {
	return v == VPNModeWireGuard || v == VPNModeOpenVPN
}

// String returns the string representation
func (v VPNMode) String() string {
	return string(v)
}

// ============================================================================
// VPN TYPE (Legacy - for VPN config management, not overlay)
// ============================================================================

type VPNType string

const (
	VPNTypeWireGuard VPNType = "wireguard"
	VPNTypeOpenVPN   VPNType = "openvpn"
)

// ============================================================================
// NETWORK CONFIGURATION (Database model)
// ============================================================================

// NetworkConfig represents the full network configuration from database
type NetworkConfig struct {
	ID   int         `db:"id" json:"id"`
	Mode NetworkMode `db:"mode" json:"mode"`

	// VPN overlay
	VPNMode     VPNMode `db:"vpn_mode" json:"vpn_mode"`
	VPNConfigID *int64  `db:"vpn_config_id" json:"vpn_config_id,omitempty"`

	// WiFi client credentials (for online_wifi and server_wifi)
	WiFiSSID     string `db:"wifi_ssid" json:"wifi_ssid,omitempty"`
	WiFiPassword string `db:"wifi_password" json:"-"` // Never expose

	// Interfaces
	EthInterface        string `db:"eth_interface" json:"eth_interface"`
	WiFiAPInterface     string `db:"wifi_ap_interface" json:"wifi_ap_interface"`
	WiFiClientInterface string `db:"wifi_client_interface" json:"wifi_client_interface"`

	// DHCP server configuration (for AP modes)
	GatewayIP      string `db:"gateway_ip" json:"gateway_ip"`
	Subnet         string `db:"subnet" json:"subnet"`
	DHCPRangeStart string `db:"dhcp_range_start" json:"dhcp_range_start"`
	DHCPRangeEnd   string `db:"dhcp_range_end" json:"dhcp_range_end"`

	// Server mode fallback
	FallbackStaticIP string `db:"fallback_static_ip" json:"fallback_static_ip"`

	// Access Point configuration
	APSSID     string `db:"ap_ssid" json:"ap_ssid"`
	APPassword string `db:"ap_password" json:"-"` // Never expose
	APChannel  int    `db:"ap_channel" json:"ap_channel"`
	APHidden   bool   `db:"ap_hidden" json:"ap_hidden"`

	// UX state
	ServerModeWarningDismissed bool `db:"server_mode_warning_dismissed" json:"server_mode_warning_dismissed"`

	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// Default values
const (
	DefaultSubnet         = "10.42.24.0/24"
	DefaultGatewayIP      = "10.42.24.1"
	DefaultDHCPRangeStart = "10.42.24.10"
	DefaultDHCPRangeEnd   = "10.42.24.250"
	DefaultAPSSID         = "CubeOS"
	DefaultAPChannel      = 7
	DefaultFallbackIP     = "192.168.1.242"
)

// ============================================================================
// NETWORK STATUS (Runtime state)
// ============================================================================

// NetworkStatus represents the current network state
type NetworkStatus struct {
	Mode     NetworkMode `json:"mode"`
	Internet bool        `json:"internet"`

	// Access Point status (nil for server modes)
	AP *APStatus `json:"ap,omitempty"`

	// Upstream connection (eth0 or wlan1)
	Upstream *UpstreamInfo `json:"upstream,omitempty"`

	// Network configuration
	Subnet    string `json:"subnet"`
	GatewayIP string `json:"gateway_ip"`

	// VPN overlay status
	VPNMode   VPNMode `json:"vpn_mode"`
	VPNActive bool    `json:"vpn_active"`
	VPNConfig string  `json:"vpn_config,omitempty"` // Config name if active
	PublicIP  string  `json:"public_ip,omitempty"`  // Current public IP

	// Server mode specific
	IsServer   bool   `json:"is_server"`             // True for server_eth/server_wifi
	FallbackIP string `json:"fallback_ip,omitempty"` // Fallback IP for server modes
}

// APStatus represents access point state
type APStatus struct {
	Active    bool   `json:"active"`
	SSID      string `json:"ssid"`
	Interface string `json:"interface"`
	Channel   int    `json:"channel"`
	Hidden    bool   `json:"hidden"`
	Clients   int    `json:"clients"`
}

// UpstreamInfo represents the upstream internet connection
type UpstreamInfo struct {
	Interface string `json:"interface"`
	Type      string `json:"type"` // "ethernet", "wifi"
	IP        string `json:"ip"`
	Gateway   string `json:"gateway"`
	SSID      string `json:"ssid,omitempty"` // For WiFi upstream
}

// ============================================================================
// VPN CONFIGURATION (For managing VPN configs, not overlay)
// ============================================================================

// VPNConfig represents a stored VPN configuration
type VPNConfig struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Type        VPNType   `db:"type" json:"type"`
	ConfigPath  string    `db:"config_path" json:"config_path"`
	IsActive    bool      `db:"is_active" json:"is_active"`
	AutoConnect bool      `db:"auto_connect" json:"auto_connect"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// VPNStatus represents current VPN connection state
type VPNStatus struct {
	Connected      bool      `json:"connected"`
	Type           VPNType   `json:"type,omitempty"`
	ConfigName     string    `json:"config_name,omitempty"`
	PublicIP       string    `json:"public_ip,omitempty"`
	ConnectedSince time.Time `json:"connected_since,omitempty"`
}

// ============================================================================
// MOUNT CONFIGURATION
// ============================================================================

type MountType string

const (
	MountTypeSMB MountType = "smb"
	MountTypeNFS MountType = "nfs"
)

// Mount represents an SMB/NFS mount configuration
type Mount struct {
	ID         int64     `db:"id" json:"id"`
	Name       string    `db:"name" json:"name"`
	Type       MountType `db:"type" json:"type"`
	RemotePath string    `db:"remote_path" json:"remote_path"`
	LocalPath  string    `db:"local_path" json:"local_path"`
	Username   string    `db:"username" json:"username,omitempty"`
	Password   string    `db:"password" json:"-"` // Never expose
	Options    string    `db:"options" json:"options,omitempty"`
	AutoMount  bool      `db:"auto_mount" json:"auto_mount"`
	IsMounted  bool      `db:"is_mounted" json:"is_mounted"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

// ============================================================================
// WIFI TYPES
// ============================================================================

// WiFiNetwork represents a scanned WiFi network
type WiFiNetwork struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Signal    int    `json:"signal"`    // dBm
	Frequency int    `json:"frequency"` // MHz
	Security  string `json:"security"`  // WPA2, WPA3, OPEN, etc.
	Channel   int    `json:"channel"`
}

// WiFiCredentials for connecting to a network
type WiFiCredentials struct {
	SSID     string `json:"ssid"`
	Password string `json:"password"`
}

// ============================================================================
// API REQUEST TYPES
// ============================================================================

// SetNetworkModeRequest for changing network mode
type SetNetworkModeRequest struct {
	Mode               NetworkMode `json:"mode"`
	SSID               string      `json:"ssid,omitempty"`                // For wifi modes
	Password           string      `json:"password,omitempty"`            // For wifi modes
	AcknowledgeWarning bool        `json:"acknowledge_warning,omitempty"` // For server modes
}

// SetVPNModeRequest for changing VPN overlay
type SetVPNModeRequest struct {
	Mode     VPNMode `json:"mode"`                // none, wireguard, openvpn, tor
	ConfigID *int64  `json:"config_id,omitempty"` // Required for wireguard/openvpn
}

// NetworkSettingsRequest for updating network configuration
type NetworkSettingsRequest struct {
	GatewayIP        string `json:"gateway_ip,omitempty"`
	Subnet           string `json:"subnet,omitempty"`
	DHCPRangeStart   string `json:"dhcp_range_start,omitempty"`
	DHCPRangeEnd     string `json:"dhcp_range_end,omitempty"`
	FallbackStaticIP string `json:"fallback_static_ip,omitempty"`
}

// APConfigRequest for updating access point configuration
type APConfigRequest struct {
	SSID     string `json:"ssid,omitempty"`
	Password string `json:"password,omitempty"`
	Channel  *int   `json:"channel,omitempty"`
	Hidden   *bool  `json:"hidden,omitempty"`
}

// AddVPNConfigRequest for adding a VPN configuration
type AddVPNConfigRequest struct {
	Name        string  `json:"name"`
	Type        VPNType `json:"type"`
	Config      string  `json:"config"` // Base64 encoded config file
	AutoConnect bool    `json:"auto_connect,omitempty"`
}

// AddMountRequest for adding an SMB/NFS mount
type AddMountRequest struct {
	Name       string    `json:"name"`
	Type       MountType `json:"type"`
	RemotePath string    `json:"remote_path"`
	Username   string    `json:"username,omitempty"`
	Password   string    `json:"password,omitempty"`
	Options    string    `json:"options,omitempty"`
	AutoMount  bool      `json:"auto_mount,omitempty"`
}

// ============================================================================
// API RESPONSE TYPES
// ============================================================================

// NetworkModeResponse for mode change results
type NetworkModeResponse struct {
	Success         bool        `json:"success"`
	Mode            NetworkMode `json:"mode"`
	Message         string      `json:"message,omitempty"`
	WarningRequired bool        `json:"warning_required,omitempty"` // For server modes
	Warning         string      `json:"warning,omitempty"`
}

// VPNModeResponse for VPN overlay status
type VPNModeResponse struct {
	Mode       VPNMode `json:"mode"`
	Active     bool    `json:"active"`
	ConfigID   *int64  `json:"config_id,omitempty"`
	ConfigName string  `json:"config_name,omitempty"`
}

// APConfigResponse for access point configuration
type APConfigResponse struct {
	SSID    string `json:"ssid"`
	Channel int    `json:"channel"`
	Hidden  bool   `json:"hidden"`
	Active  bool   `json:"active"`
}

// WiFiScanResponse for WiFi scan results
type WiFiScanResponse struct {
	Networks  []WiFiNetwork `json:"networks"`
	Interface string        `json:"interface"`
}

// APClient represents a connected AP client (mirrors hal.APClient for models package)
type APClient struct {
	MACAddress    string `json:"mac_address" db:"mac_address"`
	IPAddress     string `json:"ip_address" db:"ip_address"`
	Hostname      string `json:"hostname" db:"hostname"`
	ConnectedTime int64  `json:"connected_time" db:"connected_time"`
	Signal        int    `json:"signal" db:"signal"`
	TXBytes       int64  `json:"tx_bytes" db:"tx_bytes"`
	RXBytes       int64  `json:"rx_bytes" db:"rx_bytes"`
	Blocked       bool   `json:"blocked" db:"blocked"`
}
