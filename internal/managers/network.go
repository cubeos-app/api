package managers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/models"
)

// WiFi Interface Constants
const (
	// APInterface is always the built-in Pi WiFi (wlan0)
	APInterface = "wlan0"
)

// NetworkManager handles network interfaces, WiFi AP, and DHCP
type NetworkManager struct {
	cfg *config.Config
}

// NewNetworkManager creates a new NetworkManager
func NewNetworkManager(cfg *config.Config) *NetworkManager {
	return &NetworkManager{cfg: cfg}
}

// DetectClientWiFiInterfaces returns all WiFi interfaces suitable for client/station mode.
// This excludes wlan0 which is reserved for AP mode.
func (m *NetworkManager) DetectClientWiFiInterfaces() []string {
	var clients []string

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return clients
	}

	for _, entry := range entries {
		name := entry.Name()

		// Skip the AP interface (always wlan0)
		if name == APInterface {
			continue
		}

		// Check for wlan* (wlan1, wlan2, etc.) or wlx* (MAC-based USB dongle names)
		if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wlx") {
			// Verify it's actually a wireless interface
			wirelessPath := filepath.Join("/sys/class/net", name, "wireless")
			if _, err := os.Stat(wirelessPath); err == nil {
				clients = append(clients, name)
			}
		}
	}

	return clients
}

// GetPreferredClientInterface returns the first available WiFi client interface.
// Returns empty string if no client interface is found.
func (m *NetworkManager) GetPreferredClientInterface() string {
	clients := m.DetectClientWiFiInterfaces()
	if len(clients) == 0 {
		return ""
	}
	// Prefer wlan1 if available (cleaner name), otherwise use first found
	for _, iface := range clients {
		if iface == "wlan1" {
			return iface
		}
	}
	return clients[0]
}

// bringInterfaceUp brings a network interface up.
func (m *NetworkManager) bringInterfaceUp(iface string) error {
	cmd := exec.Command("ip", "link", "set", iface, "up")
	return cmd.Run()
}

// isInterfaceUp checks if a network interface is up.
func (m *NetworkManager) isInterfaceUp(iface string) bool {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "operstate"))
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(data))
	return state == "up" || state == "unknown" // "unknown" can mean up for wireless
}

// GetAPConfig reads the hostapd configuration
func (m *NetworkManager) GetAPConfig() *models.WiFiAPConfig {
	cfg := &models.WiFiAPConfig{
		SSID:        "CubeOS",
		Channel:     6,
		HWMode:      "g",
		CountryCode: "NL",
	}

	data, err := os.ReadFile(m.cfg.HostapdConf)
	if err != nil {
		// Try host-mounted path
		data, err = os.ReadFile("/host" + m.cfg.HostapdConf)
		if err != nil {
			return cfg
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		switch key {
		case "ssid":
			cfg.SSID = value
		case "wpa_passphrase":
			cfg.Password = value
		case "channel":
			cfg.Channel, _ = strconv.Atoi(value)
		case "ignore_broadcast_ssid":
			cfg.Hidden = value == "1"
		case "hw_mode":
			cfg.HWMode = value
		case "country_code":
			cfg.CountryCode = value
		}
	}

	return cfg
}

// SetAPConfig updates the hostapd configuration
func (m *NetworkManager) SetAPConfig(cfg *models.WiFiAPConfig) error {
	hidden := "0"
	if cfg.Hidden {
		hidden = "1"
	}

	lines := []string{
		fmt.Sprintf("interface=%s", APInterface), // Always use wlan0 for AP
		"driver=nl80211",
		fmt.Sprintf("ssid=%s", cfg.SSID),
		fmt.Sprintf("hw_mode=%s", cfg.HWMode),
		fmt.Sprintf("channel=%d", cfg.Channel),
		fmt.Sprintf("country_code=%s", cfg.CountryCode),
		"ieee80211n=1",
		"wmm_enabled=1",
		fmt.Sprintf("ignore_broadcast_ssid=%s", hidden),
	}

	if cfg.Password != "" {
		lines = append(lines,
			"wpa=2",
			"wpa_key_mgmt=WPA-PSK",
			fmt.Sprintf("wpa_passphrase=%s", cfg.Password),
			"rsn_pairwise=CCMP",
		)
	}

	content := strings.Join(lines, "\n") + "\n"

	// Write to temp file first
	tmpFile := "/tmp/cubeos_hostapd.tmp"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		return err
	}

	// Copy to actual location (may need sudo)
	cmd := exec.Command("cp", tmpFile, m.cfg.HostapdConf)
	return cmd.Run()
}

// GetAPStatus returns WiFi Access Point status
func (m *NetworkManager) GetAPStatus() *models.WiFiAPStatus {
	cfg := m.GetAPConfig()

	status := &models.WiFiAPStatus{
		SSID:      cfg.SSID,
		Password:  cfg.Password,
		Channel:   cfg.Channel,
		Hidden:    cfg.Hidden,
		Interface: APInterface, // Always wlan0
		Frequency: "2.4GHz",
		Status:    "down",
	}

	// Check if hostapd is active
	cmd := exec.Command("systemctl", "is-active", "hostapd")
	if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) == "active" {
		status.Enabled = true
		status.Status = "up"
	}

	// Check interface status
	cmd = exec.Command("ip", "link", "show", APInterface)
	if output, err := cmd.Output(); err == nil && strings.Contains(string(output), "state UP") {
		status.Status = "up"
	}

	// Get channel/frequency from iw
	cmd = exec.Command("iw", "dev", APInterface, "info")
	if output, err := cmd.Output(); err == nil {
		// Parse channel
		if match := regexp.MustCompile(`channel (\d+)`).FindStringSubmatch(string(output)); len(match) > 1 {
			status.Channel, _ = strconv.Atoi(match[1])
		}
		// Parse frequency
		if match := regexp.MustCompile(`(\d+) MHz`).FindStringSubmatch(string(output)); len(match) > 1 {
			freq, _ := strconv.Atoi(match[1])
			if freq > 4000 {
				status.Frequency = "5GHz"
			}
		}
	}

	// Get client count
	clients := m.GetConnectedClients()
	status.ClientsConnected = len(clients)

	return status
}

// RestartAP restarts the WiFi Access Point
func (m *NetworkManager) RestartAP() error {
	cmd := exec.Command("systemctl", "restart", "hostapd")
	return cmd.Run()
}

// GetDHCPLeases returns current DHCP leases
func (m *NetworkManager) GetDHCPLeases() []models.DHCPLease {
	var leases []models.DHCPLease

	// Try multiple possible locations
	leasePaths := []string{
		"/var/lib/misc/dnsmasq.wlan0.leases",
		m.cfg.DnsmasqLeases,
		"/var/lib/misc/dnsmasq.leases",
		"/host/var/lib/misc/dnsmasq.wlan0.leases",
		"/host/var/lib/misc/dnsmasq.leases",
	}

	var data []byte
	var err error
	for _, path := range leasePaths {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}

	if err != nil {
		return leases
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}

		lease := models.DHCPLease{
			MACAddress: parts[1],
			IPAddress:  parts[2],
		}

		if parts[3] != "*" {
			lease.Hostname = parts[3]
		}

		if ts, err := strconv.ParseInt(parts[0], 10, 64); err == nil && ts > 0 {
			expiry := time.Unix(ts, 0)
			lease.LeaseExpiry = &expiry
		}

		leases = append(leases, lease)
	}

	return leases
}

// GetConnectedClients returns clients connected to WiFi AP
func (m *NetworkManager) GetConnectedClients() []models.WiFiClient {
	var clients []models.WiFiClient
	macs := make(map[string]bool)

	// Try hostapd_cli first (gives signal strength info)
	cmd := exec.Command("hostapd_cli", "-i", APInterface, "all_sta")
	if output, err := cmd.Output(); err == nil && len(output) > 10 {
		clients = m.parseHostapdClients(string(output))
		for _, c := range clients {
			macs[strings.ToLower(c.MACAddress)] = true
		}
	}

	// Fallback to iw if no clients found from hostapd
	if len(clients) == 0 {
		cmd = exec.Command("iw", "dev", APInterface, "station", "dump")
		if output, err := cmd.Output(); err == nil && len(output) > 10 {
			clients = m.parseIWClients(string(output))
			for _, c := range clients {
				macs[strings.ToLower(c.MACAddress)] = true
			}
		}
	}

	// Get DHCP leases - always useful
	leases := m.GetDHCPLeases()
	leaseMap := make(map[string]models.DHCPLease)
	for _, lease := range leases {
		leaseMap[strings.ToLower(lease.MACAddress)] = lease
	}

	// If we got clients from hostapd/iw, enrich them with DHCP data
	if len(clients) > 0 {
		for i := range clients {
			mac := strings.ToLower(clients[i].MACAddress)
			if lease, ok := leaseMap[mac]; ok {
				clients[i].IPAddress = lease.IPAddress
				clients[i].Hostname = lease.Hostname
			}
		}
	} else {
		// No clients from hostapd/iw - use DHCP leases as primary source
		// These are active leases, so clients are likely connected
		for _, lease := range leases {
			clients = append(clients, models.WiFiClient{
				MACAddress: lease.MACAddress,
				IPAddress:  lease.IPAddress,
				Hostname:   lease.Hostname,
			})
		}
	}

	return clients
}

func (m *NetworkManager) parseHostapdClients(output string) []models.WiFiClient {
	var clients []models.WiFiClient
	var currentClient *models.WiFiClient

	macRegex := regexp.MustCompile(`^([0-9a-fA-F:]{17})$`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if macRegex.MatchString(line) {
			if currentClient != nil {
				clients = append(clients, *currentClient)
			}
			currentClient = &models.WiFiClient{
				MACAddress: line,
			}
		} else if currentClient != nil {
			if strings.HasPrefix(line, "signal=") {
				if signal, err := strconv.Atoi(strings.TrimPrefix(line, "signal=")); err == nil {
					currentClient.SignalDBM = &signal
				}
			} else if strings.HasPrefix(line, "connected_time=") {
				if secs, err := strconv.Atoi(strings.TrimPrefix(line, "connected_time=")); err == nil {
					currentClient.ConnectedTimeSeconds = &secs
				}
			} else if strings.HasPrefix(line, "rx_bytes=") {
				if bytes, err := strconv.ParseUint(strings.TrimPrefix(line, "rx_bytes="), 10, 64); err == nil {
					currentClient.RxBytes = bytes
				}
			} else if strings.HasPrefix(line, "tx_bytes=") {
				if bytes, err := strconv.ParseUint(strings.TrimPrefix(line, "tx_bytes="), 10, 64); err == nil {
					currentClient.TxBytes = bytes
				}
			}
		}
	}

	if currentClient != nil {
		clients = append(clients, *currentClient)
	}

	return clients
}

func (m *NetworkManager) parseIWClients(output string) []models.WiFiClient {
	var clients []models.WiFiClient
	var currentClient *models.WiFiClient

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Station") {
			if currentClient != nil {
				clients = append(clients, *currentClient)
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentClient = &models.WiFiClient{
					MACAddress: parts[1],
				}
			}
		} else if currentClient != nil {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "signal:") {
				var signal int
				fmt.Sscanf(line, "signal: %d", &signal)
				currentClient.SignalDBM = &signal
			} else if strings.HasPrefix(line, "connected time:") {
				var secs int
				fmt.Sscanf(line, "connected time: %d", &secs)
				currentClient.ConnectedTimeSeconds = &secs
			} else if strings.HasPrefix(line, "rx bytes:") {
				var bytes uint64
				fmt.Sscanf(line, "rx bytes: %d", &bytes)
				currentClient.RxBytes = bytes
			} else if strings.HasPrefix(line, "tx bytes:") {
				var bytes uint64
				fmt.Sscanf(line, "tx bytes: %d", &bytes)
				currentClient.TxBytes = bytes
			}
		}
	}

	if currentClient != nil {
		clients = append(clients, *currentClient)
	}

	return clients
}

// GetInterfaces returns all network interfaces
func (m *NetworkManager) GetInterfaces() []models.NetworkInterface {
	var interfaces []models.NetworkInterface

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return interfaces
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue // Skip loopback
		}

		iface := models.NetworkInterface{
			Name: name,
		}

		// Get state (convert to IsUp bool)
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/operstate", name)); err == nil {
			state := strings.TrimSpace(string(data))
			iface.IsUp = (state == "up" || state == "unknown")
		}

		// Get MAC address
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", name)); err == nil {
			iface.MACAddress = strings.TrimSpace(string(data))
		}

		// Get MTU
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/mtu", name)); err == nil {
			if mtu, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				iface.MTU = mtu
			}
		}

		// Get RX/TX stats
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", name)); err == nil {
			iface.RxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", name)); err == nil {
			iface.TxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", name)); err == nil {
			iface.RxPackets, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", name)); err == nil {
			iface.TxPackets, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_errors", name)); err == nil {
			iface.RxErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/tx_errors", name)); err == nil {
			iface.TxErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		// Get IPv4 addresses
		cmd := exec.Command("ip", "-4", "addr", "show", name)
		if output, err := cmd.Output(); err == nil {
			matches := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`).FindAllStringSubmatch(string(output), -1)
			for _, match := range matches {
				if len(match) > 1 {
					iface.IPv4Addresses = append(iface.IPv4Addresses, match[1])
				}
			}
		}

		// Get IPv6 addresses
		cmd = exec.Command("ip", "-6", "addr", "show", name)
		if output, err := cmd.Output(); err == nil {
			matches := regexp.MustCompile(`inet6 ([0-9a-f:]+)`).FindAllStringSubmatch(string(output), -1)
			for _, match := range matches {
				if len(match) > 1 {
					iface.IPv6Addresses = append(iface.IPv6Addresses, match[1])
				}
			}
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces
}

// CheckInternet checks for internet connectivity
func (m *NetworkManager) CheckInternet() *models.InternetStatus {
	status := &models.InternetStatus{
		Connected: false,
	}

	// Try to ping a reliable host
	cmd := exec.Command("ping", "-c", "1", "-W", "3", "8.8.8.8")
	if err := cmd.Run(); err == nil {
		status.Connected = true
	}

	return status
}

// GetNetworkStatus returns the comprehensive network status including detected client interfaces.
func (m *NetworkManager) GetNetworkStatus() *models.NetworkStatus {
	status := &models.NetworkStatus{
		Mode:      models.NetworkModeOffline, // Default
		Internet:  false,
		Subnet:    models.DefaultSubnet,
		GatewayIP: models.DefaultGatewayIP,
	}

	// Get AP status
	apStatus := m.GetAPStatus()
	if apStatus != nil {
		status.AP = models.APStatus{
			SSID:      apStatus.SSID,
			Interface: APInterface, // Always wlan0
			Clients:   len(m.GetConnectedClients()),
			Active:    apStatus.Enabled,
		}
	}

	// Detect available client WiFi interfaces
	status.ClientInterfaces = m.DetectClientWiFiInterfaces()

	// Check internet connectivity
	internetStatus := m.CheckInternet()
	if internetStatus != nil && internetStatus.Connected {
		status.Internet = true
	}

	// Determine mode based on upstream
	interfaces := m.GetInterfaces()
	for _, iface := range interfaces {
		if iface.Name == "eth0" && iface.IsUp && len(iface.IPv4Addresses) > 0 {
			status.Mode = models.NetworkModeOnlineETH
			status.Upstream = &models.UpstreamInfo{
				Interface: "eth0",
				IP:        iface.IPv4Addresses[0],
				Gateway:   "",
			}
			break
		}
		// Check for any WiFi client interface (wlan1, wlan2, wlx*)
		if iface.Name != APInterface && (strings.HasPrefix(iface.Name, "wlan") || strings.HasPrefix(iface.Name, "wlx")) {
			if iface.IsUp && len(iface.IPv4Addresses) > 0 {
				status.Mode = models.NetworkModeOnlineWiFi
				status.Upstream = &models.UpstreamInfo{
					Interface: iface.Name,
					IP:        iface.IPv4Addresses[0],
					Gateway:   "",
				}
				break
			}
		}
	}

	return status
}

// SetNetworkMode switches the network operating mode.
func (m *NetworkManager) SetNetworkMode(mode models.NetworkMode, ssid, password string) error {
	switch mode {
	case models.NetworkModeOffline:
		return m.setOfflineMode()
	case models.NetworkModeOnlineETH:
		return m.setOnlineEthMode()
	case models.NetworkModeOnlineWiFi:
		return m.setOnlineWiFiMode(ssid, password)
	default:
		return fmt.Errorf("unknown network mode: %s", mode)
	}
}

// setOfflineMode configures the system for air-gapped operation.
func (m *NetworkManager) setOfflineMode() error {
	// Disable NAT forwarding
	if err := m.disableNAT(); err != nil {
		return fmt.Errorf("failed to disable NAT: %w", err)
	}

	// Disconnect WiFi client if connected
	clientIface := m.GetPreferredClientInterface()
	if clientIface != "" {
		exec.Command("wpa_cli", "-i", clientIface, "disconnect").Run()
	}

	return nil
}

// setOnlineEthMode configures NAT via Ethernet.
func (m *NetworkManager) setOnlineEthMode() error {
	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Configure NAT via iptables
	return m.enableNAT("eth0")
}

// setOnlineWiFiMode configures NAT via USB WiFi dongle.
func (m *NetworkManager) setOnlineWiFiMode(ssid, password string) error {
	if ssid == "" {
		return fmt.Errorf("WiFi SSID is required")
	}

	// Find WiFi client interface
	clientIface := m.GetPreferredClientInterface()
	if clientIface == "" {
		availableIfaces := m.DetectClientWiFiInterfaces()
		if len(availableIfaces) == 0 {
			return fmt.Errorf("no WiFi client interface found - USB WiFi dongle required for ONLINE_WIFI mode")
		}
		clientIface = availableIfaces[0]
	}

	// Connect to upstream WiFi
	if err := m.connectToWiFi(clientIface, ssid, password); err != nil {
		return fmt.Errorf("failed to connect to WiFi: %w", err)
	}

	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Configure NAT
	return m.enableNAT(clientIface)
}

// ScanWiFiNetworks scans for available WiFi networks using the first available client interface.
func (m *NetworkManager) ScanWiFiNetworks() ([]models.WiFiNetwork, error) {
	// Find WiFi client interface
	clientIface := m.GetPreferredClientInterface()
	if clientIface == "" {
		availableIfaces := m.DetectClientWiFiInterfaces()
		if len(availableIfaces) == 0 {
			return nil, fmt.Errorf("no WiFi client interface found - USB WiFi dongle required for scanning")
		}
		clientIface = availableIfaces[0]
	}

	// Ensure interface is UP before scanning
	if !m.isInterfaceUp(clientIface) {
		if err := m.bringInterfaceUp(clientIface); err != nil {
			return nil, fmt.Errorf("failed to bring up interface %s: %w", clientIface, err)
		}
		// Give interface time to initialize
		time.Sleep(500 * time.Millisecond)
	}

	// Trigger scan
	cmd := exec.Command("iw", clientIface, "scan")
	output, err := cmd.Output()
	if err != nil {
		// Interface might need sudo or might be busy, try with sudo
		cmd = exec.Command("sudo", "iw", clientIface, "scan")
		output, err = cmd.Output()
		if err != nil {
			// Check if device is busy (already scanning)
			if strings.Contains(err.Error(), "Device or resource busy") {
				time.Sleep(2 * time.Second)
				cmd = exec.Command("iw", clientIface, "scan")
				output, err = cmd.Output()
			}
			if err != nil {
				return nil, fmt.Errorf("failed to scan WiFi networks on %s: %w", clientIface, err)
			}
		}
	}

	networks := m.parseIWScan(string(output))

	// Filter out empty SSIDs (hidden networks)
	var visibleNetworks []models.WiFiNetwork
	for _, n := range networks {
		if n.SSID != "" {
			visibleNetworks = append(visibleNetworks, n)
		}
	}

	return visibleNetworks, nil
}

// ConnectToWiFi connects to a WiFi network.
func (m *NetworkManager) ConnectToWiFi(ssid, password string) error {
	clientIface := m.GetPreferredClientInterface()
	if clientIface == "" {
		availableIfaces := m.DetectClientWiFiInterfaces()
		if len(availableIfaces) == 0 {
			return fmt.Errorf("no WiFi client interface found - USB WiFi dongle required")
		}
		clientIface = availableIfaces[0]
	}
	return m.connectToWiFi(clientIface, ssid, password)
}

// connectToWiFi connects to a WiFi network using wpa_supplicant.
func (m *NetworkManager) connectToWiFi(iface, ssid, password string) error {
	// Ensure interface is up
	if err := m.bringInterfaceUp(iface); err != nil {
		return fmt.Errorf("failed to bring up interface %s: %w", iface, err)
	}

	// Create wpa_supplicant config
	configPath := fmt.Sprintf("/tmp/wpa_%s.conf", iface)
	config := fmt.Sprintf(`ctrl_interface=/var/run/wpa_supplicant
update_config=1

network={
    ssid="%s"
    psk="%s"
}
`, ssid, password)

	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write wpa_supplicant config: %w", err)
	}

	// Kill any existing wpa_supplicant on this interface
	exec.Command("pkill", "-f", fmt.Sprintf("wpa_supplicant.*%s", iface)).Run()
	time.Sleep(500 * time.Millisecond)

	// Start wpa_supplicant
	cmd := exec.Command("wpa_supplicant", "-B", "-i", iface, "-c", configPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start wpa_supplicant: %w", err)
	}

	// Wait for connection
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		output, _ := exec.Command("wpa_cli", "-i", iface, "status").Output()
		if strings.Contains(string(output), "wpa_state=COMPLETED") {
			// Request DHCP
			exec.Command("dhclient", "-v", iface).Run()
			return nil
		}
	}

	return fmt.Errorf("WiFi connection timeout")
}

// enableNAT configures iptables for NAT.
func (m *NetworkManager) enableNAT(upstreamIface string) error {
	// Clear existing NAT rules
	exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING").Run()

	// Enable masquerading
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", models.DefaultSubnet, "-o", upstreamIface, "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable NAT: %w", err)
	}

	// Allow forwarding from AP to upstream
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", APInterface, "-o", upstreamIface, "-j", "ACCEPT")
	cmd.Run()

	// Allow established connections back
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", upstreamIface, "-o", APInterface, "-m", "state",
		"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	cmd.Run()

	return nil
}

// disableNAT removes NAT configuration.
func (m *NetworkManager) disableNAT() error {
	// Flush NAT rules
	exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING").Run()

	// Disable IP forwarding
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)
}

// findWiFiClientInterface finds a USB WiFi dongle interface.
// Deprecated: Use GetPreferredClientInterface() instead.
func (m *NetworkManager) findWiFiClientInterface() string {
	return m.GetPreferredClientInterface()
}

// parseIWScan parses the output of 'iw scan'.
func (m *NetworkManager) parseIWScan(output string) []models.WiFiNetwork {
	var networks []models.WiFiNetwork
	var current *models.WiFiNetwork

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "BSS ") {
			if current != nil && current.SSID != "" {
				networks = append(networks, *current)
			}
			current = &models.WiFiNetwork{}
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				current.BSSID = strings.TrimSuffix(parts[1], "(")
			}
		} else if current != nil {
			if strings.HasPrefix(line, "SSID:") {
				current.SSID = strings.TrimPrefix(line, "SSID: ")
			} else if strings.HasPrefix(line, "signal:") {
				fmt.Sscanf(line, "signal: %d", &current.Signal)
			} else if strings.HasPrefix(line, "freq:") {
				fmt.Sscanf(line, "freq: %d", &current.Frequency)
				current.Channel = m.frequencyToChannel(current.Frequency)
			} else if strings.Contains(line, "WPA") || strings.Contains(line, "RSN") {
				current.Security = "WPA2"
			}
		}
	}

	if current != nil && current.SSID != "" {
		networks = append(networks, *current)
	}

	return networks
}

// frequencyToChannel converts WiFi frequency to channel number.
func (m *NetworkManager) frequencyToChannel(freq int) int {
	// 2.4 GHz band
	if freq >= 2412 && freq <= 2484 {
		return (freq-2412)/5 + 1
	}
	// 5 GHz band
	if freq >= 5180 && freq <= 5825 {
		return (freq-5180)/5 + 36
	}
	return 0
}

// ============================================================================
// Bandwidth Monitoring (from original file)
// ============================================================================

// InterfaceStats holds bandwidth statistics for an interface
type InterfaceStats struct {
	RxBytes   int64
	TxBytes   int64
	Timestamp time.Time
}

// BandwidthMonitor tracks bandwidth usage over time
type BandwidthMonitor struct {
	history     map[string][]InterfaceStats
	historyLock sync.RWMutex
	maxSamples  int
}

// NewBandwidthMonitor creates a new BandwidthMonitor
func NewBandwidthMonitor() *BandwidthMonitor {
	return &BandwidthMonitor{
		history:    make(map[string][]InterfaceStats),
		maxSamples: 300, // 5 minutes at 1 sample/second
	}
}

// Sample records current interface stats
func (b *BandwidthMonitor) Sample() {
	b.historyLock.Lock()
	defer b.historyLock.Unlock()

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return
	}

	now := time.Now()

	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}

		stats := InterfaceStats{Timestamp: now}

		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", name)); err == nil {
			stats.RxBytes, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", name)); err == nil {
			stats.TxBytes, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		}

		b.history[name] = append(b.history[name], stats)
		if len(b.history[name]) > b.maxSamples {
			b.history[name] = b.history[name][len(b.history[name])-b.maxSamples:]
		}
	}
}

// GetBandwidth returns bandwidth usage for an interface over a time period
func (b *BandwidthMonitor) GetBandwidth(iface string, seconds int) (rxBps, txBps float64) {
	b.historyLock.RLock()
	defer b.historyLock.RUnlock()

	history, ok := b.history[iface]
	if !ok || len(history) < 2 {
		return 0, 0
	}

	// Find samples within time range
	cutoff := time.Now().Add(-time.Duration(seconds) * time.Second)
	var oldest, newest InterfaceStats
	newest = history[len(history)-1]

	for _, sample := range history {
		if sample.Timestamp.After(cutoff) {
			oldest = sample
			break
		}
	}

	if oldest.Timestamp.IsZero() {
		oldest = history[0]
	}

	duration := newest.Timestamp.Sub(oldest.Timestamp).Seconds()
	if duration <= 0 {
		return 0, 0
	}

	rxBps = float64(newest.RxBytes-oldest.RxBytes) / duration
	txBps = float64(newest.TxBytes-oldest.TxBytes) / duration
	return
}

// ============================================================================
// Additional utility functions (preserved from original)
// ============================================================================

// GetRoutes returns the current routing table
func (m *NetworkManager) GetRoutes() []map[string]string {
	var routes []map[string]string

	cmd := exec.Command("ip", "route")
	output, err := cmd.Output()
	if err != nil {
		return routes
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		route := make(map[string]string)
		route["destination"] = parts[0]

		for i := 1; i < len(parts)-1; i++ {
			if parts[i] == "via" {
				route["gateway"] = parts[i+1]
			} else if parts[i] == "dev" {
				route["interface"] = parts[i+1]
			}
		}

		routes = append(routes, route)
	}

	return routes
}

// GetDNSServers returns configured DNS servers
func (m *NetworkManager) GetDNSServers() []string {
	var servers []string

	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return servers
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				servers = append(servers, parts[1])
			}
		}
	}

	return servers
}

// ============================================================================
// Missing methods required by handlers
// ============================================================================

// RestartDHCP restarts the DHCP server (dnsmasq via Pi-hole)
func (m *NetworkManager) RestartDHCP() error {
	// Pi-hole manages DHCP via dnsmasq
	cmd := exec.Command("pihole", "restartdns")
	if err := cmd.Run(); err != nil {
		// Fallback to systemctl
		cmd = exec.Command("systemctl", "restart", "pihole-FTL")
		return cmd.Run()
	}
	return nil
}

// GetWiFiQRCode generates a WiFi QR code string for the AP
func (m *NetworkManager) GetWiFiQRCode() *models.WiFiQRCode {
	cfg := m.GetAPConfig()
	if cfg == nil {
		return &models.WiFiQRCode{}
	}

	encryption := "WPA"
	if cfg.Password == "" {
		encryption = "nopass"
	}

	// WiFi QR code format: WIFI:T:WPA;S:ssid;P:password;;
	wifiString := fmt.Sprintf("WIFI:T:%s;S:%s;P:%s;;", encryption, cfg.SSID, cfg.Password)

	return &models.WiFiQRCode{
		WiFiString: wifiString,
		SSID:       cfg.SSID,
		Encryption: encryption,
	}
}

// TrafficStats holds traffic statistics for an interface
type TrafficStats struct {
	Interface string  `json:"interface"`
	RxBytes   uint64  `json:"rx_bytes"`
	TxBytes   uint64  `json:"tx_bytes"`
	RxRate    float64 `json:"rx_rate_bps"`
	TxRate    float64 `json:"tx_rate_bps"`
}

// GetTrafficStats returns current traffic statistics for all interfaces
func (m *NetworkManager) GetTrafficStats() []TrafficStats {
	var stats []TrafficStats

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return stats
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}

		stat := TrafficStats{Interface: name}

		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", name)); err == nil {
			stat.RxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
		if data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", name)); err == nil {
			stat.TxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		stats = append(stats, stat)
	}

	return stats
}

// TrafficHistoryPoint represents a point in traffic history
type TrafficHistoryPoint struct {
	Timestamp time.Time `json:"timestamp"`
	RxBytes   uint64    `json:"rx_bytes"`
	TxBytes   uint64    `json:"tx_bytes"`
}

// GetTrafficHistory returns traffic history for an interface (stub - returns empty)
func (m *NetworkManager) GetTrafficHistory(iface string, minutes int) []TrafficHistoryPoint {
	// TODO: Implement actual history tracking with BandwidthMonitor
	return []TrafficHistoryPoint{}
}

// ClientStats holds client statistics
type ClientStats struct {
	TotalConnected int `json:"total_connected"`
	TotalBlocked   int `json:"total_blocked"`
	TotalLeases    int `json:"total_leases"`
}

// GetClientStats returns WiFi client statistics
func (m *NetworkManager) GetClientStats() *ClientStats {
	clients := m.GetConnectedClients()
	leases := m.GetDHCPLeases()
	blocked := m.GetBlockedClients()

	return &ClientStats{
		TotalConnected: len(clients),
		TotalBlocked:   len(blocked),
		TotalLeases:    len(leases),
	}
}

// BlockClient blocks a MAC address from connecting
func (m *NetworkManager) BlockClient(mac string) error {
	// Use hostapd_cli to deny the client
	cmd := exec.Command("hostapd_cli", "-i", APInterface, "deny_acl", "ADD_MAC", mac)
	if err := cmd.Run(); err != nil {
		// Fallback: add to iptables
		cmd = exec.Command("iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP")
		return cmd.Run()
	}
	return nil
}

// UnblockClient removes a MAC address from the block list
func (m *NetworkManager) UnblockClient(mac string) error {
	// Use hostapd_cli to remove from deny list
	cmd := exec.Command("hostapd_cli", "-i", APInterface, "deny_acl", "DEL_MAC", mac)
	if err := cmd.Run(); err != nil {
		// Fallback: remove from iptables
		cmd = exec.Command("iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP")
		return cmd.Run()
	}
	return nil
}

// KickClient disconnects a client from the AP
func (m *NetworkManager) KickClient(mac string) error {
	// Use hostapd_cli to deauthenticate
	cmd := exec.Command("hostapd_cli", "-i", APInterface, "deauthenticate", mac)
	return cmd.Run()
}

// GetBlockedClients returns list of blocked MAC addresses
func (m *NetworkManager) GetBlockedClients() []string {
	var blocked []string

	// Try to get from hostapd deny list
	cmd := exec.Command("hostapd_cli", "-i", APInterface, "deny_acl", "SHOW")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// MAC address format check
			if len(line) == 17 && strings.Count(line, ":") == 5 {
				blocked = append(blocked, line)
			}
		}
	}

	return blocked
}

// Stub for json import (used elsewhere in original)
var _ = json.Marshal
var _ = sync.Mutex{}
