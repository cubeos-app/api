package managers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/models"
)

// NetworkManager handles network interfaces, WiFi AP, and DHCP
type NetworkManager struct {
	cfg *config.Config
}

// NewNetworkManager creates a new NetworkManager
func NewNetworkManager(cfg *config.Config) *NetworkManager {
	return &NetworkManager{cfg: cfg}
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
		fmt.Sprintf("interface=%s", m.cfg.APInterface),
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
		Interface: m.cfg.APInterface,
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
	cmd = exec.Command("ip", "link", "show", m.cfg.APInterface)
	if output, err := cmd.Output(); err == nil && strings.Contains(string(output), "state UP") {
		status.Status = "up"
	}

	// Get channel/frequency from iw
	cmd = exec.Command("iw", "dev", m.cfg.APInterface, "info")
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
	cmd := exec.Command("hostapd_cli", "-i", m.cfg.APInterface, "all_sta")
	if output, err := cmd.Output(); err == nil && len(output) > 10 {
		clients = m.parseHostapdClients(string(output))
		for _, c := range clients {
			macs[strings.ToLower(c.MACAddress)] = true
		}
	}

	// Fallback to iw if no clients found from hostapd
	if len(clients) == 0 {
		cmd = exec.Command("iw", "dev", m.cfg.APInterface, "station", "dump")
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
			continue
		}

		if currentClient != nil && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key, value := parts[0], parts[1]

			switch key {
			case "rx_bytes":
				currentClient.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			case "tx_bytes":
				currentClient.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			case "signal":
				dbm, _ := strconv.Atoi(value)
				currentClient.SignalDBM = &dbm
				pct := dbmToPercent(dbm)
				currentClient.SignalPercent = &pct
			case "connected_time":
				secs, _ := strconv.Atoi(value)
				currentClient.ConnectedTimeSeconds = &secs
				connectedSince := time.Now().Add(-time.Duration(secs) * time.Second)
				currentClient.ConnectedSince = &connectedSince
			case "inactive_msec":
				ms, _ := strconv.Atoi(value)
				currentClient.InactiveMs = &ms
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
		line := strings.TrimSpace(scanner.Text())

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
			continue
		}

		if currentClient != nil && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "rx bytes":
				currentClient.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			case "tx bytes":
				currentClient.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			case "signal":
				dbm, _ := strconv.Atoi(strings.Fields(value)[0])
				currentClient.SignalDBM = &dbm
				pct := dbmToPercent(dbm)
				currentClient.SignalPercent = &pct
			case "connected time":
				secs, _ := strconv.Atoi(strings.Fields(value)[0])
				currentClient.ConnectedTimeSeconds = &secs
			case "inactive time":
				ms, _ := strconv.Atoi(strings.Fields(value)[0])
				currentClient.InactiveMs = &ms
			}
		}
	}

	if currentClient != nil {
		clients = append(clients, *currentClient)
	}

	return clients
}

func dbmToPercent(dbm int) int {
	percent := 2 * (dbm + 100)
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

// CheckInternet checks internet connectivity
func (m *NetworkManager) CheckInternet() *models.InternetStatus {
	targets := []struct {
		IP   string
		Name string
	}{
		{"1.1.1.1", "Cloudflare DNS"},
		{"8.8.8.8", "Google DNS"},
	}

	for _, target := range targets {
		cmd := exec.Command("ping", "-c", "1", "-W", "3", target.IP)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		// Parse RTT
		var rtt float64
		if match := regexp.MustCompile(`time=(\d+\.?\d*)`).FindStringSubmatch(string(output)); len(match) > 1 {
			rtt, _ = strconv.ParseFloat(match[1], 64)
		}

		return &models.InternetStatus{
			Connected:  true,
			Target:     target.IP,
			TargetName: target.Name,
			RTTMs:      rtt,
		}
	}

	return &models.InternetStatus{Connected: false}
}

// RestartDHCP restarts the DHCP server
func (m *NetworkManager) RestartDHCP() error {
	cmd := exec.Command("systemctl", "restart", "dnsmasq")
	return cmd.Run()
}

// GetWiFiQRCode generates WiFi QR code data
func (m *NetworkManager) GetWiFiQRCode() *models.WiFiQRCode {
	cfg := m.GetAPConfig()

	encryption := "nopass"
	if cfg.Password != "" {
		encryption = "WPA"
	}

	// Escape special characters
	ssid := escapeWiFiString(cfg.SSID)
	password := escapeWiFiString(cfg.Password)

	var wifiString string
	if cfg.Password == "" {
		wifiString = fmt.Sprintf("WIFI:T:nopass;S:%s;;", ssid)
	} else {
		wifiString = fmt.Sprintf("WIFI:T:%s;S:%s;P:%s;;", encryption, ssid, password)
	}

	return &models.WiFiQRCode{
		WiFiString: wifiString,
		SSID:       cfg.SSID,
		Encryption: encryption,
	}
}

func escapeWiFiString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, ":", "\\:")
	return s
}

// BlockClient blocks a client by MAC address using iptables
func (m *NetworkManager) BlockClient(mac string) error {
	mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))

	// Add INPUT rule
	cmd := exec.Command("iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return err
	}

	// Add FORWARD rule
	cmd = exec.Command("iptables", "-A", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
	return cmd.Run()
}

// UnblockClient removes iptables rules blocking a client
func (m *NetworkManager) UnblockClient(mac string) error {
	mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))

	// Remove INPUT rule
	exec.Command("iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP").Run()

	// Remove FORWARD rule
	exec.Command("iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP").Run()

	return nil
}

// KickClient disconnects a client (they can reconnect)
func (m *NetworkManager) KickClient(mac string) error {
	mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
	cmd := exec.Command("hostapd_cli", "-i", m.cfg.APInterface, "deauthenticate", mac)
	return cmd.Run()
}

// GetBlockedClients returns list of blocked MAC addresses
func (m *NetworkManager) GetBlockedClients() []string {
	var blocked []string

	cmd := exec.Command("iptables", "-L", "INPUT", "-n", "-v")
	output, err := cmd.Output()
	if err != nil {
		return blocked
	}

	macRegex := regexp.MustCompile(`MAC\s+([0-9A-Fa-f:]{17})`)
	matches := macRegex.FindAllStringSubmatch(string(output), -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			mac := strings.ToLower(match[1])
			if !seen[mac] {
				seen[mac] = true
				blocked = append(blocked, mac)
			}
		}
	}

	return blocked
}

// GetClientStats returns statistics about connected clients
func (m *NetworkManager) GetClientStats() map[string]interface{} {
	clients := m.GetConnectedClients()
	leases := m.GetDHCPLeases()

	var totalRx, totalTx uint64
	signalRanges := map[string]int{
		"excellent": 0,
		"good":      0,
		"fair":      0,
		"weak":      0,
		"unknown":   0,
	}

	for _, client := range clients {
		totalRx += client.RxBytes
		totalTx += client.TxBytes

		if client.SignalDBM == nil {
			signalRanges["unknown"]++
		} else {
			dbm := *client.SignalDBM
			switch {
			case dbm >= -50:
				signalRanges["excellent"]++
			case dbm >= -60:
				signalRanges["good"]++
			case dbm >= -70:
				signalRanges["fair"]++
			default:
				signalRanges["weak"]++
			}
		}
	}

	return map[string]interface{}{
		"connected_count": len(clients),
		"lease_count":     len(leases),
		"total_rx_bytes":  totalRx,
		"total_tx_bytes":  totalTx,
		"signal_quality":  signalRanges,
	}
}

// InterfaceInfo holds network interface information
type InterfaceInfo struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	MAC       string `json:"mac_address"`
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
	Speed     string `json:"speed,omitempty"`
	MTU       int    `json:"mtu"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	Type      string `json:"type"` // ethernet, wifi, loopback, bridge
}

// GetInterfaces returns all network interfaces with their stats
func (m *NetworkManager) GetInterfaces() []InterfaceInfo {
	var interfaces []InterfaceInfo

	// Get interface list
	cmd := exec.Command("ip", "-j", "addr", "show")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to non-JSON parsing
		return m.getInterfacesFallback()
	}

	// Parse JSON output
	var ipData []struct {
		IfName    string `json:"ifname"`
		OperState string `json:"operstate"`
		Address   string `json:"address"`
		Mtu       int    `json:"mtu"`
		AddrInfo  []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
		} `json:"addr_info"`
	}

	if err := json.Unmarshal(output, &ipData); err != nil {
		return m.getInterfacesFallback()
	}

	for _, iface := range ipData {
		// Skip loopback
		if iface.IfName == "lo" {
			continue
		}

		info := InterfaceInfo{
			Name:  iface.IfName,
			State: iface.OperState,
			MAC:   iface.Address,
			MTU:   iface.Mtu,
			Type:  m.getInterfaceType(iface.IfName),
		}

		// Get IPs
		for _, addr := range iface.AddrInfo {
			if addr.Family == "inet" && info.IPv4 == "" {
				info.IPv4 = addr.Local
			} else if addr.Family == "inet6" && info.IPv6 == "" && !strings.HasPrefix(addr.Local, "fe80") {
				info.IPv6 = addr.Local
			}
		}

		// Get traffic stats from /sys
		info.RxBytes = m.readSysNetStat(iface.IfName, "rx_bytes")
		info.TxBytes = m.readSysNetStat(iface.IfName, "tx_bytes")
		info.RxPackets = m.readSysNetStat(iface.IfName, "rx_packets")
		info.TxPackets = m.readSysNetStat(iface.IfName, "tx_packets")
		info.RxErrors = m.readSysNetStat(iface.IfName, "rx_errors")
		info.TxErrors = m.readSysNetStat(iface.IfName, "tx_errors")

		// Get speed for ethernet
		if info.Type == "ethernet" {
			info.Speed = m.getEthernetSpeed(iface.IfName)
		}

		interfaces = append(interfaces, info)
	}

	return interfaces
}

func (m *NetworkManager) getInterfacesFallback() []InterfaceInfo {
	var interfaces []InterfaceInfo

	// Try host-mounted path first, then container path
	netPaths := []string{"/host/sys/class/net", "/sys/class/net"}
	var basePath string
	var entries []os.DirEntry
	var err error

	for _, path := range netPaths {
		entries, err = os.ReadDir(path)
		if err == nil {
			basePath = path
			break
		}
	}

	if basePath == "" || err != nil {
		return interfaces
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}

		info := InterfaceInfo{
			Name: name,
			Type: m.getInterfaceType(name),
		}

		// Get stats from basePath
		info.RxBytes = m.readSysNetStatPath(basePath, name, "rx_bytes")
		info.TxBytes = m.readSysNetStatPath(basePath, name, "tx_bytes")
		info.RxPackets = m.readSysNetStatPath(basePath, name, "rx_packets")
		info.TxPackets = m.readSysNetStatPath(basePath, name, "tx_packets")

		// Get state
		stateData, _ := os.ReadFile(fmt.Sprintf("%s/%s/operstate", basePath, name))
		info.State = strings.TrimSpace(string(stateData))
		if info.State == "" {
			info.State = "unknown"
		}

		// Get MAC
		macData, _ := os.ReadFile(fmt.Sprintf("%s/%s/address", basePath, name))
		info.MAC = strings.TrimSpace(string(macData))

		// Get MTU
		mtuData, _ := os.ReadFile(fmt.Sprintf("%s/%s/mtu", basePath, name))
		info.MTU, _ = strconv.Atoi(strings.TrimSpace(string(mtuData)))

		interfaces = append(interfaces, info)
	}

	return interfaces
}

func (m *NetworkManager) readSysNetStatPath(basePath, iface, stat string) uint64 {
	path := fmt.Sprintf("%s/%s/statistics/%s", basePath, iface, stat)
	data, err := os.ReadFile(path)
	if err == nil {
		val, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		return val
	}
	return 0
}

func (m *NetworkManager) getInterfaceType(name string) string {
	if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "en") {
		return "ethernet"
	}
	if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wl") {
		return "wifi"
	}
	if strings.HasPrefix(name, "br") || strings.HasPrefix(name, "docker") {
		return "bridge"
	}
	if strings.HasPrefix(name, "veth") {
		return "virtual"
	}
	return "unknown"
}

func (m *NetworkManager) readSysNetStat(iface, stat string) uint64 {
	paths := []string{
		fmt.Sprintf("/host/sys/class/net/%s/statistics/%s", iface, stat),
		fmt.Sprintf("/sys/class/net/%s/statistics/%s", iface, stat),
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			val, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
			return val
		}
	}
	return 0
}

func (m *NetworkManager) getEthernetSpeed(iface string) string {
	paths := []string{
		fmt.Sprintf("/host/sys/class/net/%s/speed", iface),
		fmt.Sprintf("/sys/class/net/%s/speed", iface),
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			speed := strings.TrimSpace(string(data))
			if speed != "" && speed != "-1" {
				return speed + " Mbps"
			}
		}
	}
	return ""
}

// TrafficStats holds per-interface traffic statistics
type TrafficStats struct {
	Interface string    `json:"interface"`
	RxBytes   uint64    `json:"rx_bytes"`
	TxBytes   uint64    `json:"tx_bytes"`
	RxRate    float64   `json:"rx_rate_bps"` // bytes per second
	TxRate    float64   `json:"tx_rate_bps"`
	Timestamp time.Time `json:"timestamp"`
}

// Traffic history storage (in-memory for now)
var trafficHistory = make(map[string][]TrafficStats)
var trafficMutex = &sync.Mutex{}
var lastTrafficSample = make(map[string]TrafficStats)

// GetTrafficStats returns current traffic stats with rate calculation
func (m *NetworkManager) GetTrafficStats() []TrafficStats {
	interfaces := m.GetInterfaces()
	now := time.Now()
	var stats []TrafficStats

	trafficMutex.Lock()
	defer trafficMutex.Unlock()

	for _, iface := range interfaces {
		current := TrafficStats{
			Interface: iface.Name,
			RxBytes:   iface.RxBytes,
			TxBytes:   iface.TxBytes,
			Timestamp: now,
		}

		// Calculate rate from last sample
		if last, ok := lastTrafficSample[iface.Name]; ok {
			elapsed := now.Sub(last.Timestamp).Seconds()
			if elapsed > 0 {
				current.RxRate = float64(current.RxBytes-last.RxBytes) / elapsed
				current.TxRate = float64(current.TxBytes-last.TxBytes) / elapsed
			}
		}

		// Store for next calculation
		lastTrafficSample[iface.Name] = current

		// Add to history (keep last hour)
		history := trafficHistory[iface.Name]
		history = append(history, current)
		if len(history) > 720 { // 5-second samples for 1 hour
			history = history[1:]
		}
		trafficHistory[iface.Name] = history

		stats = append(stats, current)
	}

	return stats
}

// GetTrafficHistory returns historical traffic data
func (m *NetworkManager) GetTrafficHistory(iface string, minutes int) []TrafficStats {
	trafficMutex.Lock()
	defer trafficMutex.Unlock()

	history := trafficHistory[iface]
	if minutes <= 0 || minutes > 60 {
		minutes = 60
	}

	// Filter to requested time range
	cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute)
	var filtered []TrafficStats
	for _, s := range history {
		if s.Timestamp.After(cutoff) {
			filtered = append(filtered, s)
		}
	}

	return filtered
}
