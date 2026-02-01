// Package models defines data structures for CubeOS.
package models

import (
	"time"
)

// NetworkMode represents the network operating mode.
type NetworkMode string

const (
	NetworkModeOffline    NetworkMode = "offline"     // AP only, air-gapped
	NetworkModeOnlineETH  NetworkMode = "online_eth"  // AP + NAT via Ethernet
	NetworkModeOnlineWiFi NetworkMode = "online_wifi" // AP + NAT via USB WiFi dongle
)

// NetworkConfig represents the network configuration.
type NetworkConfig struct {
	ID                  int         `db:"id" json:"id"`
	Mode                NetworkMode `db:"mode" json:"mode"`
	WiFiSSID            string      `db:"wifi_ssid" json:"wifi_ssid"`
	WiFiPassword        string      `db:"wifi_password" json:"-"` // Never expose in JSON
	EthInterface        string      `db:"eth_interface" json:"eth_interface"`
	WiFiAPInterface     string      `db:"wifi_ap_interface" json:"wifi_ap_interface"`
	WiFiClientInterface string      `db:"wifi_client_interface" json:"wifi_client_interface"`
	UpdatedAt           time.Time   `db:"updated_at" json:"updated_at"`
}

// NetworkStatus represents the current network status.
type NetworkStatus struct {
	Mode      NetworkMode   `json:"mode"`
	Internet  bool          `json:"internet"`
	AP        APStatus      `json:"ap"`
	Upstream  *UpstreamInfo `json:"upstream,omitempty"`
	Subnet    string        `json:"subnet"`
	GatewayIP string        `json:"gateway_ip"`
}

// APStatus represents the access point status.
type APStatus struct {
	SSID      string `json:"ssid"`
	Interface string `json:"interface"`
	Clients   int    `json:"clients"`
	Channel   int    `json:"channel,omitempty"`
	Active    bool   `json:"active"`
}

// UpstreamInfo represents the upstream connection info.
type UpstreamInfo struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Gateway   string `json:"gateway"`
	SSID      string `json:"ssid,omitempty"` // For WiFi client mode
}

// WiFiNetwork represents a scanned WiFi network.
type WiFiNetwork struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Signal    int    `json:"signal"` // dBm
	Security  string `json:"security"`
	Frequency int    `json:"frequency"`
	Channel   int    `json:"channel"`
}

// VPNType represents the type of VPN.
type VPNType string

const (
	VPNTypeWireGuard VPNType = "wireguard"
	VPNTypeOpenVPN   VPNType = "openvpn"
)

// VPNConfig represents a VPN configuration.
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

// VPNStatus represents the current VPN status.
type VPNStatus struct {
	ActiveConfig   string    `json:"active_config,omitempty"`
	Type           VPNType   `json:"type,omitempty"`
	Connected      bool      `json:"connected"`
	PublicIP       string    `json:"public_ip,omitempty"`
	ConnectedSince time.Time `json:"connected_since,omitempty"`
}

// MountType represents the type of network mount.
type MountType string

const (
	MountTypeSMB MountType = "smb"
	MountTypeNFS MountType = "nfs"
)

// Mount represents an SMB/NFS mount configuration.
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

// === Request Types ===

// SetNetworkModeRequest is the request to change network mode.
type SetNetworkModeRequest struct {
	Mode     NetworkMode `json:"mode"`
	SSID     string      `json:"ssid,omitempty"`     // For online_wifi
	Password string      `json:"password,omitempty"` // For online_wifi
}

// UpdateAPConfigRequest is the request to update AP configuration.
type UpdateAPConfigRequest struct {
	SSID     string `json:"ssid,omitempty"`
	Password string `json:"password,omitempty"`
	Channel  int    `json:"channel,omitempty"`
	Hidden   bool   `json:"hidden,omitempty"`
}

// AddVPNConfigRequest is the request to add a VPN configuration.
type AddVPNConfigRequest struct {
	Name        string  `json:"name"`
	Type        VPNType `json:"type"`
	Config      string  `json:"config"` // Base64-encoded config file
	AutoConnect bool    `json:"auto_connect,omitempty"`
}

// AddMountRequest is the request to add a network mount.
type AddMountRequest struct {
	Name       string    `json:"name"`
	Type       MountType `json:"type"`
	RemotePath string    `json:"remote_path"`
	Username   string    `json:"username,omitempty"`
	Password   string    `json:"password,omitempty"`
	Options    string    `json:"options,omitempty"`
	AutoMount  bool      `json:"auto_mount,omitempty"`
}

// === Response Types ===

// NetworkStatusResponse is the response containing network status.
type NetworkStatusResponse struct {
	NetworkStatus
}

// WiFiScanResponse is the response containing scanned WiFi networks.
type WiFiScanResponse struct {
	Networks []WiFiNetwork `json:"networks"`
}

// VPNConfigsResponse is the response containing VPN configurations.
type VPNConfigsResponse struct {
	Configs []VPNConfig `json:"configs"`
}

// VPNStatusResponse is the response containing VPN status.
type VPNStatusResponse struct {
	VPNStatus
}

// MountsResponse is the response containing network mounts.
type MountsResponse struct {
	Mounts []Mount `json:"mounts"`
}

// === Constants ===

// CubeOS Network Constants
const (
	DefaultSubnet    = "10.42.24.0/24"
	DefaultGatewayIP = "10.42.24.1"
	DefaultDHCPStart = "10.42.24.10"
	DefaultDHCPEnd   = "10.42.24.250"
	DefaultDomain    = "cubeos.cube"
	DefaultAPSSID    = "CubeOS"
	DefaultAPChannel = 7
)

// === Helper Methods ===

// IsOffline returns true if in offline mode.
func (nc *NetworkConfig) IsOffline() bool {
	return nc.Mode == NetworkModeOffline
}

// HasInternet returns true if the mode allows internet access.
func (nc *NetworkConfig) HasInternet() bool {
	return nc.Mode == NetworkModeOnlineETH || nc.Mode == NetworkModeOnlineWiFi
}

// IsValid validates the network mode.
func (m NetworkMode) IsValid() bool {
	switch m {
	case NetworkModeOffline, NetworkModeOnlineETH, NetworkModeOnlineWiFi:
		return true
	}
	return false
}

// IsValid validates the VPN type.
func (t VPNType) IsValid() bool {
	switch t {
	case VPNTypeWireGuard, VPNTypeOpenVPN:
		return true
	}
	return false
}

// IsValid validates the mount type.
func (t MountType) IsValid() bool {
	switch t {
	case MountTypeSMB, MountTypeNFS:
		return true
	}
	return false
}
