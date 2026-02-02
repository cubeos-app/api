// Package hal provides a client for the CubeOS Hardware Abstraction Layer service.
// HAL runs as a privileged container with host network access, allowing the
// unprivileged API container to control hardware through HTTP calls.
package hal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultHALURL is the default URL for the HAL service
	DefaultHALURL = "http://127.0.0.1:6005"
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 30 * time.Second
)

// Client is a HAL API client
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new HAL client
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultHALURL
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// NetworkInterface represents a network interface from HAL
type NetworkInterface struct {
	Name          string   `json:"name"`
	IsUp          bool     `json:"is_up"`
	MACAddress    string   `json:"mac_address"`
	IPv4Addresses []string `json:"ipv4_addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
	MTU           int      `json:"mtu"`
	IsWireless    bool     `json:"is_wireless"`
}

// WiFiNetwork represents a scanned WiFi network
type WiFiNetwork struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Signal    int    `json:"signal"`
	Frequency int    `json:"frequency"`
	Security  string `json:"security"`
	Channel   int    `json:"channel"`
}

// VPNStatus represents VPN connection status
type VPNStatus struct {
	WireGuard struct {
		Active     bool     `json:"active"`
		Interfaces []string `json:"interfaces"`
	} `json:"wireguard"`
	OpenVPN struct {
		Active bool `json:"active"`
	} `json:"openvpn"`
}

// ServiceStatus represents a systemd service status
type ServiceStatus struct {
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
}

// MountRequest represents a mount request
type MountRequest struct {
	Name       string `json:"name"`
	Type       string `json:"type"`        // "smb" or "nfs"
	RemotePath string `json:"remote_path"` // //server/share or server:/path
	LocalPath  string `json:"local_path"`  // /cubeos/mounts/name
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Options    string `json:"options,omitempty"`
}

// MountResponse represents a mount response
type MountResponse struct {
	Success   bool   `json:"success"`
	MountPath string `json:"mount_path"`
	Message   string `json:"message,omitempty"`
}

// APClient represents a connected AP client
type APClient struct {
	MACAddress    string `json:"mac_address"`
	IPAddress     string `json:"ip_address"`
	Hostname      string `json:"hostname"`
	ConnectedTime int64  `json:"connected_time"`
	Signal        int    `json:"signal"`
	TXBytes       int64  `json:"tx_bytes"`
	RXBytes       int64  `json:"rx_bytes"`
}

// APClientsResponse is the response from GetAPClients
type APClientsResponse struct {
	Clients []APClient `json:"clients"`
	Count   int        `json:"count"`
}

// =============================================================================
// Helper methods
// =============================================================================

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("HAL error: %s", errResp.Error)
		}
		return nil, fmt.Errorf("HAL error: status %d", resp.StatusCode)
	}

	return respBody, nil
}

// Health checks if HAL is running
func (c *Client) Health(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodGet, "/health", nil)
	return err
}

// =============================================================================
// Network Operations
// =============================================================================

// ListInterfaces returns all network interfaces
func (c *Client) ListInterfaces(ctx context.Context) ([]NetworkInterface, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/network/interfaces", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Interfaces []NetworkInterface `json:"interfaces"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Interfaces, nil
}

// GetInterface returns info about a specific interface
func (c *Client) GetInterface(ctx context.Context, name string) (*NetworkInterface, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/network/interface/"+name, nil)
	if err != nil {
		return nil, err
	}

	var iface NetworkInterface
	if err := json.Unmarshal(body, &iface); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &iface, nil
}

// BringInterfaceUp brings a network interface up
func (c *Client) BringInterfaceUp(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/interface/"+name+"/up", nil)
	return err
}

// BringInterfaceDown brings a network interface down
func (c *Client) BringInterfaceDown(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/interface/"+name+"/down", nil)
	return err
}

// ScanWiFi scans for WiFi networks on the specified interface
func (c *Client) ScanWiFi(ctx context.Context, iface string) ([]WiFiNetwork, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/network/wifi/scan/"+iface, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Networks  []WiFiNetwork `json:"networks"`
		Interface string        `json:"interface"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Networks, nil
}

// ConnectWiFi connects to a WiFi network
func (c *Client) ConnectWiFi(ctx context.Context, iface, ssid, password string) error {
	req := map[string]string{
		"interface": iface,
		"ssid":      ssid,
		"password":  password,
	}
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/wifi/connect", req)
	return err
}

// DisconnectWiFi disconnects from WiFi
func (c *Client) DisconnectWiFi(ctx context.Context, iface string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/wifi/disconnect/"+iface, nil)
	return err
}

// GetNetworkStatus returns overall network status
func (c *Client) GetNetworkStatus(ctx context.Context) (map[string]interface{}, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/network/status", nil)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp, nil
}

// =============================================================================
// AP Operations
// =============================================================================

// GetAPClients returns connected AP clients
func (c *Client) GetAPClients(ctx context.Context) (*APClientsResponse, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/network/ap/clients", nil)
	if err != nil {
		return nil, err
	}

	var result APClientsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// =============================================================================
// Firewall Operations
// =============================================================================

// EnableNAT enables NAT forwarding between interfaces
func (c *Client) EnableNAT(ctx context.Context, sourceInterface, destInterface string) error {
	req := map[string]string{
		"source_interface": sourceInterface,
		"dest_interface":   destInterface,
	}
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/firewall/nat/enable", req)
	return err
}

// DisableNAT disables NAT forwarding
func (c *Client) DisableNAT(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/firewall/nat/disable", nil)
	return err
}

// EnableIPForward enables IP forwarding
func (c *Client) EnableIPForward(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/firewall/forward/enable", nil)
	return err
}

// DisableIPForward disables IP forwarding
func (c *Client) DisableIPForward(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/firewall/forward/disable", nil)
	return err
}

// GetFirewallRules returns current iptables rules
func (c *Client) GetFirewallRules(ctx context.Context) (map[string]string, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/firewall/rules", nil)
	if err != nil {
		return nil, err
	}

	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp, nil
}

// AddFirewallRule adds a firewall rule
func (c *Client) AddFirewallRule(ctx context.Context, table, chain string, args []string) error {
	req := map[string]interface{}{
		"table": table,
		"chain": chain,
		"args":  args,
	}
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/firewall/rule", req)
	return err
}

// DeleteFirewallRule deletes a firewall rule
func (c *Client) DeleteFirewallRule(ctx context.Context, table, chain string, args []string) error {
	req := map[string]interface{}{
		"table": table,
		"chain": chain,
		"args":  args,
	}
	_, err := c.doRequest(ctx, http.MethodDelete, "/hal/firewall/rule", req)
	return err
}

// =============================================================================
// VPN Operations
// =============================================================================

// GetVPNStatus returns VPN connection status
func (c *Client) GetVPNStatus(ctx context.Context) (*VPNStatus, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/vpn/status", nil)
	if err != nil {
		return nil, err
	}

	var status VPNStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &status, nil
}

// WireGuardUp brings up a WireGuard interface
func (c *Client) WireGuardUp(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/vpn/wireguard/up/"+name, nil)
	return err
}

// WireGuardDown brings down a WireGuard interface
func (c *Client) WireGuardDown(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/vpn/wireguard/down/"+name, nil)
	return err
}

// OpenVPNUp starts OpenVPN with a config
func (c *Client) OpenVPNUp(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/vpn/openvpn/up/"+name, nil)
	return err
}

// OpenVPNDown stops OpenVPN
func (c *Client) OpenVPNDown(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/vpn/openvpn/down/"+name, nil)
	return err
}

// =============================================================================
// Mount Operations (SMB/NFS)
// =============================================================================

// MountSMB mounts an SMB/CIFS share
func (c *Client) MountSMB(ctx context.Context, req *MountRequest) (*MountResponse, error) {
	req.Type = "smb"
	body, err := c.doRequest(ctx, http.MethodPost, "/hal/mounts/smb", req)
	if err != nil {
		return nil, err
	}

	var resp MountResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// MountNFS mounts an NFS share
func (c *Client) MountNFS(ctx context.Context, req *MountRequest) (*MountResponse, error) {
	req.Type = "nfs"
	body, err := c.doRequest(ctx, http.MethodPost, "/hal/mounts/nfs", req)
	if err != nil {
		return nil, err
	}

	var resp MountResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// UnmountPath unmounts a path
func (c *Client) UnmountPath(ctx context.Context, path string) error {
	req := map[string]string{"path": path}
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/mounts/unmount", req)
	return err
}

// TestMountConnection tests connectivity to a remote share
func (c *Client) TestMountConnection(ctx context.Context, mountType, remotePath, username, password string) error {
	req := map[string]string{
		"type":        mountType,
		"remote_path": remotePath,
		"username":    username,
		"password":    password,
	}
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/mounts/test", req)
	return err
}

// ListMounts returns list of active mounts
func (c *Client) ListMounts(ctx context.Context) ([]map[string]interface{}, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/mounts/list", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Mounts []map[string]interface{} `json:"mounts"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Mounts, nil
}

// IsMounted checks if a path is currently mounted
func (c *Client) IsMounted(ctx context.Context, path string) (bool, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/mounts/check?path="+url.QueryEscape(path), nil)
	if err != nil {
		return false, err
	}

	var resp struct {
		Mounted bool `json:"mounted"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Mounted, nil
}

// =============================================================================
// USB Operations
// =============================================================================

// ListUSBDevices lists USB storage devices
func (c *Client) ListUSBDevices(ctx context.Context) (map[string]interface{}, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/usb/devices", nil)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp, nil
}

// MountUSB mounts a USB device
func (c *Client) MountUSB(ctx context.Context, device string) (string, error) {
	body, err := c.doRequest(ctx, http.MethodPost, "/hal/usb/mount/"+device, nil)
	if err != nil {
		return "", err
	}

	var resp struct {
		MountPath string `json:"mount_path"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.MountPath, nil
}

// UnmountUSB unmounts a USB device
func (c *Client) UnmountUSB(ctx context.Context, device string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/usb/unmount/"+device, nil)
	return err
}

// =============================================================================
// System Operations
// =============================================================================

// Reboot reboots the system
func (c *Client) Reboot(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/system/reboot", nil)
	return err
}

// Shutdown shuts down the system
func (c *Client) Shutdown(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/system/shutdown", nil)
	return err
}

// RestartService restarts a systemd service
func (c *Client) RestartService(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/system/service/"+name+"/restart", nil)
	return err
}

// StartService starts a systemd service
func (c *Client) StartService(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/system/service/"+name+"/start", nil)
	return err
}

// StopService stops a systemd service
func (c *Client) StopService(ctx context.Context, name string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/system/service/"+name+"/stop", nil)
	return err
}

// GetServiceStatus gets the status of a systemd service
func (c *Client) GetServiceStatus(ctx context.Context, name string) (*ServiceStatus, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/system/service/"+name+"/status", nil)
	if err != nil {
		return nil, err
	}

	var status ServiceStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &status, nil
}

// =============================================================================
// AP Client Management (Sprint 5C additions)
// =============================================================================

// KickAPClient disconnects a client from the AP by MAC address
func (c *Client) KickAPClient(ctx context.Context, mac string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/wifi/ap/kick/"+mac, nil)
	return err
}

// BlockAPClient blocks a MAC address from connecting to the AP
func (c *Client) BlockAPClient(ctx context.Context, mac string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/wifi/ap/block/"+mac, nil)
	return err
}

// UnblockAPClient removes a MAC address from the AP blocklist
func (c *Client) UnblockAPClient(ctx context.Context, mac string) error {
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/wifi/ap/unblock/"+mac, nil)
	return err
}

// =============================================================================
// Traffic Statistics (Sprint 5C additions)
// =============================================================================

// TrafficStats represents traffic statistics for interfaces
type TrafficStats struct {
	Interfaces []InterfaceTraffic `json:"interfaces"`
	Timestamp  int64              `json:"timestamp"`
}

// InterfaceTraffic represents traffic for a single interface
type InterfaceTraffic struct {
	Name      string `json:"name"`
	RXBytes   int64  `json:"rx_bytes"`
	TXBytes   int64  `json:"tx_bytes"`
	RXPackets int64  `json:"rx_packets"`
	TXPackets int64  `json:"tx_packets"`
	RXErrors  int64  `json:"rx_errors"`
	TXErrors  int64  `json:"tx_errors"`
}

// TrafficHistory represents historical traffic data
type TrafficHistory struct {
	Interface  string             `json:"interface"`
	Duration   string             `json:"duration"`
	DataPoints []TrafficDataPoint `json:"data_points"`
}

// TrafficDataPoint represents a single traffic measurement
type TrafficDataPoint struct {
	Timestamp int64 `json:"timestamp"`
	RXBytes   int64 `json:"rx_bytes"`
	TXBytes   int64 `json:"tx_bytes"`
}

// GetTrafficStats returns current traffic statistics for all interfaces
func (c *Client) GetTrafficStats(ctx context.Context) (*TrafficStats, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/network/traffic", nil)
	if err != nil {
		return nil, err
	}

	var stats TrafficStats
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &stats, nil
}

// GetTrafficHistory returns historical traffic data for an interface
func (c *Client) GetTrafficHistory(ctx context.Context, iface, duration string) (*TrafficHistory, error) {
	path := "/hal/network/traffic/" + iface + "/history"
	if duration != "" {
		path += "?duration=" + duration
	}

	body, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var history TrafficHistory
	if err := json.Unmarshal(body, &history); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &history, nil
}

// =============================================================================
// IP Forwarding Status (Sprint 5C additions)
// =============================================================================

// GetForwardingStatus returns whether IP forwarding is enabled
func (c *Client) GetForwardingStatus(ctx context.Context) (bool, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/hal/firewall/forwarding", nil)
	if err != nil {
		return false, err
	}

	var resp struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Enabled, nil
}

// EnableForwarding enables IP forwarding (alias for EnableIPForward)
func (c *Client) EnableForwarding(ctx context.Context) error {
	return c.EnableIPForward(ctx)
}

// DisableForwarding disables IP forwarding (alias for DisableIPForward)
func (c *Client) DisableForwarding(ctx context.Context) error {
	return c.DisableIPForward(ctx)
}

// =============================================================================
// VPN Control Methods (Sprint 5C - Full Fix)
// =============================================================================

// StartWireGuard starts a WireGuard interface
func (c *Client) StartWireGuard(ctx context.Context, name string) error {
	return c.WireGuardUp(ctx, name)
}

// StopWireGuard stops a WireGuard interface
func (c *Client) StopWireGuard(ctx context.Context, name string) error {
	return c.WireGuardDown(ctx, name)
}

// StartOpenVPN starts OpenVPN with a config
func (c *Client) StartOpenVPN(ctx context.Context, name string) error {
	return c.OpenVPNUp(ctx, name)
}

// StopOpenVPN stops OpenVPN
func (c *Client) StopOpenVPN(ctx context.Context, name string) error {
	return c.OpenVPNDown(ctx, name)
}

// StartTor starts the Tor service
func (c *Client) StartTor(ctx context.Context) error {
	return c.StartService(ctx, "tor")
}

// StopTor stops the Tor service
func (c *Client) StopTor(ctx context.Context) error {
	return c.StopService(ctx, "tor")
}

// =============================================================================
// AP Control Methods (Sprint 5C - Full Fix)
// =============================================================================

// StartAP starts the WiFi access point (hostapd)
func (c *Client) StartAP(ctx context.Context, iface string) error {
	return c.StartService(ctx, "hostapd")
}

// StopAP stops the WiFi access point (hostapd)
func (c *Client) StopAP(ctx context.Context, iface string) error {
	return c.StopService(ctx, "hostapd")
}

// =============================================================================
// DHCP and IP Configuration Methods
// =============================================================================

// RequestDHCP requests a DHCP lease on an interface
func (c *Client) RequestDHCP(ctx context.Context, iface string) error {
	req := map[string]string{"interface": iface}
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/dhcp/request", req)
	return err
}

// SetStaticIP sets a static IP address on an interface
func (c *Client) SetStaticIP(ctx context.Context, iface, ip, gateway string) error {
	req := map[string]string{
		"interface": iface,
		"ip":        ip,
		"gateway":   gateway,
	}
	_, err := c.doRequest(ctx, http.MethodPost, "/hal/network/ip/static", req)
	return err
}
