// Package hal provides a client for the CubeOS Hardware Abstraction Layer service.
// HAL runs as a privileged container with host network access, allowing the
// unprivileged API container to control hardware through HTTP calls.
//
// The HAL exposes 80+ endpoints across these categories:
// - System: temperature, throttle, EEPROM, boot config, services
// - Power: battery (X1202 UPS), RTC, watchdog
// - Network: interfaces, WiFi, Access Point
// - Firewall: rules, NAT, IP forwarding
// - VPN: WireGuard, OpenVPN, Tor
// - Storage: devices, SMART, usage, USB storage
// - Logs: kernel, journal, hardware
// - GPS: devices, status, position
// - Cellular: modems, signal, Android tethering
// - Meshtastic: LoRa mesh networking
// - Iridium: satellite communication (SBD)
// - Camera: Pi Camera, USB webcams
// - Sensors: 1-Wire (DS18B20), BME280
// - Audio: ALSA devices, volume control
// - GPIO: pin control
// - I2C: bus operations
// - Bluetooth: devices, pairing
// - Mounts: SMB/NFS network mounts
package hal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// DefaultHALURL is the default URL for the HAL service.
	// Uses Docker service hostname for DNS resolution through Swarm overlay network.
	// Override with HAL_URL environment variable if needed.
	DefaultHALURL = "http://cubeos-hal:6005"
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 30 * time.Second
)

// =============================================================================
// Client
// =============================================================================

// Client is a HAL API client
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new HAL client
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = os.Getenv("HAL_URL")
	}
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

// =============================================================================
// Response Types - System
// =============================================================================

// TemperatureResponse represents CPU temperature
type TemperatureResponse struct {
	Temperature float64 `json:"temperature"`
	Unit        string  `json:"unit"`
	Source      string  `json:"source"`
}

// ThrottleStatus represents CPU throttling status flags
type ThrottleStatus struct {
	UnderVoltageOccurred         bool   `json:"under_voltage_occurred"`
	ArmFrequencyCappedOccurred   bool   `json:"arm_frequency_capped_occurred"`
	CurrentlyThrottled           bool   `json:"currently_throttled"`
	SoftTemperatureLimitOccurred bool   `json:"soft_temperature_limit_occurred"`
	UnderVoltageNow              bool   `json:"under_voltage_now"`
	ArmFrequencyCappedNow        bool   `json:"arm_frequency_capped_now"`
	ThrottledNow                 bool   `json:"throttled_now"`
	SoftTemperatureLimitNow      bool   `json:"soft_temperature_limit_now"`
	RawHex                       string `json:"raw_hex"`
}

// EEPROMInfo represents Raspberry Pi EEPROM/firmware information
type EEPROMInfo struct {
	Version    string `json:"version"`
	Bootloader string `json:"bootloader,omitempty"`
	VL805      string `json:"vl805,omitempty"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Revision   string `json:"revision,omitempty"`
}

// BootConfig represents boot configuration from config.txt
type BootConfig struct {
	Config map[string]string `json:"config"`
	Raw    string            `json:"raw,omitempty"`
}

// UptimeInfo contains system uptime information
type UptimeInfo struct {
	Seconds     float64   `json:"seconds"`
	Formatted   string    `json:"formatted"`
	BootTime    string    `json:"boot_time"`
	LoadAverage []float64 `json:"load_average"`
}

// ServiceStatus represents a systemd service status
type ServiceStatus struct {
	Name        string `json:"name"`
	Active      bool   `json:"active"`
	Running     bool   `json:"running"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	MainPID     int    `json:"main_pid,omitempty"`
}

// =============================================================================
// Response Types - Power
// =============================================================================

// BatteryStatus represents current battery state from X1202 UPS
type BatteryStatus struct {
	Available           bool    `json:"available"`
	Voltage             float64 `json:"voltage"`
	VoltageRaw          uint16  `json:"voltage_raw,omitempty"`
	Percentage          float64 `json:"percentage"`
	PercentageEstimated float64 `json:"percentage_estimated,omitempty"`
	PercentageRaw       uint16  `json:"percentage_raw,omitempty"`
	IsCharging          bool    `json:"is_charging"`
	ChargingEnabled     bool    `json:"charging_enabled"`
	ACPresent           bool    `json:"ac_present"`
	IsLow               bool    `json:"is_low"`
	IsCritical          bool    `json:"is_critical"`
	LastUpdated         string  `json:"last_updated"`
}

// UPSInfo contains UPS hardware detection information
type UPSInfo struct {
	Model       string `json:"model"`
	Detected    bool   `json:"detected"`
	I2CAddress  string `json:"i2c_address"`
	I2CBus      int    `json:"i2c_bus"`
	FuelGauge   string `json:"fuel_gauge"`
	GPIOChip    string `json:"gpio_chip"`
	PiVersion   int    `json:"pi_version"`
	ChipVersion uint16 `json:"chip_version,omitempty"`
}

// PowerStatus combines all power-related information
type PowerStatus struct {
	UPS         UPSInfo       `json:"ups"`
	Battery     BatteryStatus `json:"battery"`
	Uptime      UptimeInfo    `json:"uptime"`
	RTC         RTCStatus     `json:"rtc"`
	Watchdog    WatchdogInfo  `json:"watchdog"`
	LastUpdated string        `json:"last_updated"`
}

// RTCStatus contains Real-Time Clock status
type RTCStatus struct {
	Available    bool   `json:"available"`
	Time         string `json:"time"`
	Synchronized bool   `json:"synchronized"`
	BatteryOK    bool   `json:"battery_ok"`
	Device       string `json:"device,omitempty"`
}

// WatchdogInfo contains hardware watchdog status
type WatchdogInfo struct {
	Device  string `json:"device"`
	Enabled bool   `json:"enabled"`
	Timeout int    `json:"timeout"`
}

// =============================================================================
// Response Types - Network
// =============================================================================

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

// APStatus represents Access Point status
type APStatus struct {
	Active    bool   `json:"active"`
	SSID      string `json:"ssid"`
	Channel   int    `json:"channel"`
	Interface string `json:"interface"`
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

// TrafficStats represents traffic statistics for interfaces
// HAL returns: {"interfaces": {"eth0": {...}, "wlan0": {...}}, "source": "..."}
type TrafficStats struct {
	Interfaces map[string]InterfaceTraffic `json:"interfaces"`
	Source     string                      `json:"source,omitempty"`
}

// InterfaceTraffic represents traffic for a single interface
type InterfaceTraffic struct {
	Name      string `json:"name,omitempty"` // Only set when converted to slice
	RXBytes   int64  `json:"rx_bytes"`
	TXBytes   int64  `json:"tx_bytes"`
	RXPackets int64  `json:"rx_packets"`
	TXPackets int64  `json:"tx_packets"`
	RXErrors  int64  `json:"rx_errors"`
	TXErrors  int64  `json:"tx_errors"`
	RXDropped int64  `json:"rx_dropped"`
	TXDropped int64  `json:"tx_dropped"`
}

// =============================================================================
// Response Types - VPN
// =============================================================================

// VPNStatus represents overall VPN status (adapter for manager compatibility)
type VPNStatus struct {
	WireGuard WireGuardStatus `json:"wireguard"`
	OpenVPN   OpenVPNStatus   `json:"openvpn"`
	Tor       TorStatus       `json:"tor"`
}

// WireGuardStatus represents WireGuard VPN status
type WireGuardStatus struct {
	Active     bool     `json:"active"`
	Interfaces []string `json:"interfaces"`
}

// OpenVPNStatus represents OpenVPN status
type OpenVPNStatus struct {
	Active bool `json:"active"`
}

// halVPNStatusResponse is the raw HAL response (internal)
type halVPNStatusResponse struct {
	WireGuard []VPNInterface `json:"wireguard"`
	OpenVPN   []VPNInterface `json:"openvpn"`
	Tor       TorStatus      `json:"tor"`
}

// VPNInterface represents a VPN interface
type VPNInterface struct {
	Name      string `json:"name"`
	Active    bool   `json:"active"`
	Type      string `json:"type"`
	Endpoint  string `json:"endpoint,omitempty"`
	LocalIP   string `json:"local_ip,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

// TorStatus represents Tor service status
type TorStatus struct {
	Running      bool   `json:"running"`
	Bootstrapped int    `json:"bootstrapped"`
	CircuitReady bool   `json:"circuit_ready"`
	SocksPort    int    `json:"socks_port"`
	ControlPort  int    `json:"control_port"`
	ExitIP       string `json:"exit_ip,omitempty"`
}

// TorConfig represents Tor configuration settings
type TorConfig struct {
	SocksPort   int               `json:"socks_port"`
	ControlPort int               `json:"control_port"`
	DataDir     string            `json:"data_dir"`
	Settings    map[string]string `json:"settings"`
}

// =============================================================================
// Response Types - Storage
// =============================================================================

// StorageDevice represents a storage device
type StorageDevice struct {
	Name       string          `json:"name"`
	Path       string          `json:"path"`
	Size       int64           `json:"size"`
	SizeHuman  string          `json:"size_human"`
	Type       string          `json:"type"`
	Model      string          `json:"model,omitempty"`
	Serial     string          `json:"serial,omitempty"`
	Vendor     string          `json:"vendor,omitempty"`
	Removable  bool            `json:"removable"`
	Partitions []StorageDevice `json:"partitions,omitempty"`
}

// StorageDevicesResponse represents storage devices list
type StorageDevicesResponse struct {
	Devices []StorageDevice `json:"devices"`
	Count   int             `json:"count"`
}

// FilesystemUsage represents filesystem usage
type FilesystemUsage struct {
	Mountpoint string `json:"mountpoint"`
	Filesystem string `json:"filesystem"`
	Size       int64  `json:"size"`
	Used       int64  `json:"used"`
	Available  int64  `json:"available"`
	UsePercent int    `json:"use_percent"`
	SizeHuman  string `json:"size_human"`
	UsedHuman  string `json:"used_human"`
	AvailHuman string `json:"avail_human"`
}

// StorageUsageResponse represents filesystem usage list
type StorageUsageResponse struct {
	Filesystems []FilesystemUsage `json:"filesystems"`
}

// SMARTInfo represents SMART health data
type SMARTInfo struct {
	Device       string                 `json:"device"`
	Type         string                 `json:"type"`
	Smart        string                 `json:"smart"`
	Health       string                 `json:"health"`
	Temperature  int                    `json:"temperature,omitempty"`
	PowerOnHours int                    `json:"power_on_hours,omitempty"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
}

// =============================================================================
// Response Types - USB
// =============================================================================

// USBDevice represents a USB device
type USBDevice struct {
	Bus      int    `json:"bus"`
	Device   int    `json:"device"`
	VendorID string `json:"vendor_id"`
	DeviceID string `json:"device_id"`
	Vendor   string `json:"vendor,omitempty"`
	Product  string `json:"product,omitempty"`
	Class    string `json:"class,omitempty"`
	Serial   string `json:"serial,omitempty"`
}

// USBDevicesResponse represents USB devices list
type USBDevicesResponse struct {
	Devices []USBDevice `json:"devices"`
	Count   int         `json:"count"`
}

// USBStorageDevice represents a USB storage device
type USBStorageDevice struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SizeHuman  string `json:"size_human"`
	Vendor     string `json:"vendor,omitempty"`
	Model      string `json:"model,omitempty"`
	Mounted    bool   `json:"mounted"`
	MountPoint string `json:"mount_point,omitempty"`
}

// =============================================================================
// Response Types - Logs
// =============================================================================

// LogsResponse represents log output
type LogsResponse struct {
	Lines []string `json:"lines"`
	Count int      `json:"count"`
}

// HardwareLogsResponse represents hardware-specific logs
type HardwareLogsResponse struct {
	Category string   `json:"category"`
	Entries  []string `json:"entries"`
	Count    int      `json:"count"`
}

// =============================================================================
// Response Types - GPS
// =============================================================================

// GPSDevice represents a GPS device
type GPSDevice struct {
	Port     string `json:"port"`
	Name     string `json:"name"`
	Vendor   string `json:"vendor,omitempty"`
	Product  string `json:"product,omitempty"`
	BaudRate int    `json:"baud_rate"`
	Active   bool   `json:"active"`
}

// GPSDevicesResponse represents GPS devices list
type GPSDevicesResponse struct {
	Count   int         `json:"count"`
	Devices []GPSDevice `json:"devices"`
}

// GPSStatus represents GPS status
type GPSStatus struct {
	Available  bool    `json:"available"`
	HasFix     bool    `json:"has_fix"`
	FixQuality string  `json:"fix_quality"`
	Satellites int     `json:"satellites"`
	HDOP       float64 `json:"hdop,omitempty"`
	LastUpdate string  `json:"last_update,omitempty"`
}

// GPSPosition represents GPS position data
type GPSPosition struct {
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
	Altitude   float64 `json:"altitude,omitempty"`
	Speed      float64 `json:"speed,omitempty"`
	Course     float64 `json:"course,omitempty"`
	Satellites int     `json:"satellites"`
	FixQuality int     `json:"fix_quality"`
	HDOP       float64 `json:"hdop,omitempty"`
	Timestamp  string  `json:"timestamp"`
	Valid      bool    `json:"valid"`
}

// =============================================================================
// Response Types - Cellular
// =============================================================================

// CellularModem represents a cellular modem
type CellularModem struct {
	Index         int    `json:"index"`
	Path          string `json:"path"`
	Manufacturer  string `json:"manufacturer"`
	Model         string `json:"model"`
	Revision      string `json:"revision,omitempty"`
	IMEI          string `json:"imei,omitempty"`
	State         string `json:"state"`
	PowerState    string `json:"power_state"`
	SignalQuality int    `json:"signal_quality"`
	AccessTech    string `json:"access_tech"`
	Operator      string `json:"operator,omitempty"`
	EquipmentID   string `json:"equipment_id,omitempty"`
}

// CellularStatus represents overall cellular status
type CellularStatus struct {
	Available   bool            `json:"available"`
	Connected   bool            `json:"connected"`
	Modems      []CellularModem `json:"modems"`
	ModemCount  int             `json:"modem_count"`
	ActiveModem string          `json:"active_modem,omitempty"`
}

// CellularModemsResponse represents cellular modems list
type CellularModemsResponse struct {
	Count  int             `json:"count"`
	Modems []CellularModem `json:"modems"`
}

// CellularSignal represents cellular signal info
type CellularSignal struct {
	Quality   int     `json:"quality"`
	RSSI      float64 `json:"rssi,omitempty"`
	RSRP      float64 `json:"rsrp,omitempty"`
	RSRQ      float64 `json:"rsrq,omitempty"`
	SNR       float64 `json:"snr,omitempty"`
	Bars      int     `json:"bars"`
	Tech      string  `json:"tech"`
	Band      string  `json:"band,omitempty"`
	Frequency int     `json:"frequency,omitempty"`
}

// AndroidTetheringStatus represents Android USB tethering status
type AndroidTetheringStatus struct {
	Available bool   `json:"available"`
	Connected bool   `json:"connected"`
	Interface string `json:"interface,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
}

// =============================================================================
// Response Types - Meshtastic
// =============================================================================

// MeshtasticDevice represents a Meshtastic LoRa device
type MeshtasticDevice struct {
	Port      string `json:"port"`
	Name      string `json:"name"`
	NodeID    string `json:"node_id,omitempty"`
	LongName  string `json:"long_name,omitempty"`
	ShortName string `json:"short_name,omitempty"`
	HWModel   string `json:"hw_model,omitempty"`
	Firmware  string `json:"firmware,omitempty"`
	Connected bool   `json:"connected"`
}

// MeshtasticStatus represents Meshtastic network status
type MeshtasticStatus struct {
	Available  bool              `json:"available"`
	Connected  bool              `json:"connected"`
	Device     *MeshtasticDevice `json:"device,omitempty"`
	NodeCount  int               `json:"node_count"`
	ChannelURL string            `json:"channel_url,omitempty"`
}

// MeshtasticNode represents a node in the mesh
type MeshtasticNode struct {
	NodeID       string  `json:"node_id"`
	LongName     string  `json:"long_name"`
	ShortName    string  `json:"short_name"`
	HWModel      string  `json:"hw_model,omitempty"`
	SNR          float64 `json:"snr,omitempty"`
	LastHeard    string  `json:"last_heard,omitempty"`
	Hops         int     `json:"hops,omitempty"`
	BatteryLevel int     `json:"battery_level,omitempty"`
	Latitude     float64 `json:"latitude,omitempty"`
	Longitude    float64 `json:"longitude,omitempty"`
	Altitude     float64 `json:"altitude,omitempty"`
}

// MeshtasticNodesResponse represents mesh nodes list
type MeshtasticNodesResponse struct {
	Count int              `json:"count"`
	Nodes []MeshtasticNode `json:"nodes"`
}

// MeshtasticDevicesResponse represents available Meshtastic devices
type MeshtasticDevicesResponse struct {
	Devices []MeshtasticDevice `json:"devices"`
}

// MeshtasticMessagesResponse represents Meshtastic message history
type MeshtasticMessagesResponse struct {
	Messages []MeshtasticMessage `json:"messages"`
}

// MeshtasticMessage represents a single Meshtastic message
type MeshtasticMessage struct {
	From      string  `json:"from"`
	To        string  `json:"to"`
	Text      string  `json:"text"`
	Channel   int     `json:"channel"`
	Timestamp int64   `json:"timestamp"`
	RxSNR     float64 `json:"rx_snr,omitempty"`
	RxRSSI    int     `json:"rx_rssi,omitempty"`
}

// MeshtasticPosition represents GPS position from a Meshtastic radio
type MeshtasticPosition struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Altitude  int     `json:"altitude"`
	Time      int64   `json:"time"`
}

// MeshtasticConnectRequest represents a Meshtastic connect request
type MeshtasticConnectRequest struct {
	Port      string `json:"port,omitempty"`
	Address   string `json:"address,omitempty"`
	Transport string `json:"transport,omitempty"` // "auto", "serial", "ble"
}

// MeshtasticChannelRequest represents a Meshtastic channel configuration request
type MeshtasticChannelRequest struct {
	Index           int    `json:"index"`
	Name            string `json:"name"`
	PSK             string `json:"psk,omitempty"`
	Role            string `json:"role"`
	UplinkEnabled   bool   `json:"uplink_enabled,omitempty"`
	DownlinkEnabled bool   `json:"downlink_enabled,omitempty"`
}

// MeshtasticRawRequest represents a raw Meshtastic packet send request
type MeshtasticRawRequest struct {
	To      string `json:"to,omitempty"`
	PortNum int    `json:"portnum"`
	Payload string `json:"payload"`
	Channel int    `json:"channel,omitempty"`
	WantAck bool   `json:"want_ack,omitempty"`
}

// =============================================================================
// Response Types - Iridium
// =============================================================================

// IridiumDevice represents an Iridium satellite modem
type IridiumDevice struct {
	Port       string `json:"port"`
	Name       string `json:"name"`
	IMEI       string `json:"imei,omitempty"`
	Model      string `json:"model,omitempty"`
	Connected  bool   `json:"connected"`
	Registered bool   `json:"registered"`
}

// IridiumStatus represents Iridium modem status
type IridiumStatus struct {
	Available     bool   `json:"available"`
	Connected     bool   `json:"connected"`
	SignalQuality int    `json:"signal_quality"`
	Registered    bool   `json:"registered"`
	NetworkTime   string `json:"network_time,omitempty"`
	MOQueue       int    `json:"mo_queue"`
	MTQueue       int    `json:"mt_queue"`
	LastContact   string `json:"last_contact,omitempty"`
	IMEI          string `json:"imei,omitempty"`
}

// IridiumSignal represents Iridium signal strength
type IridiumSignal struct {
	Quality int    `json:"quality"`
	Bars    int    `json:"bars"`
	Status  string `json:"status"`
}

// IridiumMessage represents a received SBD message
type IridiumMessage struct {
	MTMSN     int    `json:"mtmsn"`
	Data      string `json:"data"`
	Binary    bool   `json:"binary"`
	Timestamp string `json:"timestamp"`
	Length    int    `json:"length"`
}

// IridiumMessagesResponse represents Iridium messages list
type IridiumMessagesResponse struct {
	Count    int              `json:"count"`
	Messages []IridiumMessage `json:"messages"`
}

// IridiumDevicesResponse represents available Iridium devices
type IridiumDevicesResponse struct {
	Devices []IridiumDevice `json:"devices"`
}

// IridiumConnectRequest represents an Iridium connect request
type IridiumConnectRequest struct {
	Port string `json:"port,omitempty"`
}

// IridiumSendResponse represents the response from sending an SBD message
type IridiumSendResponse struct {
	Status     string `json:"status"`
	MOStatus   int    `json:"mo_status"`
	MOMSN      int    `json:"momsn"`
	MTReceived bool   `json:"mt_received"`
	MTQueued   int    `json:"mt_queued"`
}

// IridiumMailboxResponse represents the response from a mailbox check
type IridiumMailboxResponse struct {
	MTReceived bool    `json:"mt_received"`
	MTMessage  *string `json:"mt_message,omitempty"`
	MTQueued   int     `json:"mt_queued"`
}

// IridiumReceiveResponse represents a received Iridium message
type IridiumReceiveResponse struct {
	Data   string `json:"data,omitempty"`
	Length int    `json:"length"`
	Format string `json:"format"`
}

// IridiumClearRequest represents a request to clear Iridium buffers
type IridiumClearRequest struct {
	Buffer string `json:"buffer"` // "mo", "mt", or "both"
}

// =============================================================================
// Response Types - Infrastructure (HAL-backed)
// =============================================================================

// FirewallStatusResponse represents consolidated HAL firewall status
type FirewallStatusResponse struct {
	Active     bool `json:"active"`
	Rules      int  `json:"rules"`
	NAT        bool `json:"nat"`
	Forwarding bool `json:"forwarding"`
}

// PowerMonitorStatus represents UPS/power monitoring status
type PowerMonitorStatus struct {
	Running  bool   `json:"running"`
	UPSModel string `json:"ups_model"`
	Battery  int    `json:"battery_percent,omitempty"`
	Charging bool   `json:"charging,omitempty"`
	ACPower  bool   `json:"ac_power,omitempty"`
}

// =============================================================================
// Response Types - Camera
// =============================================================================

// CameraDevice represents a camera device
type CameraDevice struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Driver      string   `json:"driver,omitempty"`
	Resolutions []string `json:"resolutions,omitempty"`
}

// CameraDevicesResponse represents camera devices list
type CameraDevicesResponse struct {
	Count   int            `json:"count"`
	Cameras []CameraDevice `json:"cameras"`
}

// CameraInfo represents detailed camera information
type CameraInfo struct {
	Available bool   `json:"available"`
	Device    string `json:"device,omitempty"`
	Name      string `json:"name,omitempty"`
	Driver    string `json:"driver,omitempty"`
}

// StreamInfo represents camera stream status
type StreamInfo struct {
	Active    bool   `json:"active"`
	URL       string `json:"url,omitempty"`
	Port      int    `json:"port,omitempty"`
	Format    string `json:"format,omitempty"`
	Width     int    `json:"width,omitempty"`
	Height    int    `json:"height,omitempty"`
	Framerate int    `json:"framerate,omitempty"`
}

// =============================================================================
// Response Types - Sensors
// =============================================================================

// OneWireDevice represents a 1-Wire device
type OneWireDevice struct {
	ID          string  `json:"id"`
	Family      string  `json:"family"`
	Type        string  `json:"type"`
	Path        string  `json:"path"`
	Temperature float64 `json:"temperature,omitempty"`
	Unit        string  `json:"unit,omitempty"`
	Valid       bool    `json:"valid"`
}

// OneWireDevicesResponse represents 1-Wire devices list
type OneWireDevicesResponse struct {
	Count   int             `json:"count"`
	Devices []OneWireDevice `json:"devices"`
}

// BME280Reading represents BME280 sensor reading
type BME280Reading struct {
	Available   bool    `json:"available"`
	Temperature float64 `json:"temperature"`
	TempUnit    string  `json:"temp_unit"`
	Humidity    float64 `json:"humidity"`
	HumidUnit   string  `json:"humidity_unit"`
	Pressure    float64 `json:"pressure"`
	PressUnit   string  `json:"pressure_unit"`
	Altitude    float64 `json:"altitude,omitempty"`
	AltUnit     string  `json:"altitude_unit,omitempty"`
	Timestamp   string  `json:"timestamp"`
	I2CAddress  string  `json:"i2c_address"`
	I2CBus      int     `json:"i2c_bus"`
}

// SensorReading represents a generic sensor reading
type SensorReading struct {
	SensorID  string  `json:"sensor_id"`
	Type      string  `json:"type"`
	Value     float64 `json:"value"`
	Unit      string  `json:"unit"`
	Timestamp string  `json:"timestamp"`
	Valid     bool    `json:"valid"`
}

// AllSensorsResponse represents all sensor readings
type AllSensorsResponse struct {
	Timestamp string                 `json:"timestamp"`
	OneWire   []OneWireDevice        `json:"1wire,omitempty"`
	BME280    *BME280Reading         `json:"bme280,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// =============================================================================
// Response Types - Audio
// =============================================================================

// AudioDevice represents an audio device
type AudioDevice struct {
	Index    int    `json:"index"`
	Name     string `json:"name"`
	Card     int    `json:"card"`
	Device   int    `json:"device"`
	Type     string `json:"type"` // "playback" or "capture"
	Channels int    `json:"channels,omitempty"`
}

// AudioDevicesResponse represents audio devices list
type AudioDevicesResponse struct {
	Playback []AudioDevice `json:"playback"`
	Capture  []AudioDevice `json:"capture"`
}

// VolumeInfo represents volume information
type VolumeInfo struct {
	Volume int  `json:"volume"`
	Muted  bool `json:"muted"`
}

// =============================================================================
// Response Types - GPIO
// =============================================================================

// GPIOPin represents a GPIO pin
type GPIOPin struct {
	Pin    int    `json:"pin"`
	Mode   string `json:"mode"` // "in" or "out"
	Value  int    `json:"value"`
	Label  string `json:"label,omitempty"`
	Active bool   `json:"active"`
	Chip   string `json:"chip,omitempty"`
}

// GPIOPinsResponse represents GPIO pins status
type GPIOPinsResponse struct {
	Pins  []GPIOPin `json:"pins"`
	Count int       `json:"count"`
}

// =============================================================================
// Response Types - I2C
// =============================================================================

// I2CBus represents an I2C bus
type I2CBus struct {
	Bus    int    `json:"bus"`
	Path   string `json:"path"`
	Active bool   `json:"active"`
}

// I2CBusesResponse represents I2C buses list
type I2CBusesResponse struct {
	Buses []I2CBus `json:"buses"`
	Count int      `json:"count"`
}

// I2CScanResult represents I2C bus scan results
type I2CScanResult struct {
	Bus       int   `json:"bus"`
	Addresses []int `json:"addresses"`
	Count     int   `json:"count"`
}

// I2CDevice represents an I2C device
type I2CDevice struct {
	Bus     int    `json:"bus"`
	Address int    `json:"address"`
	Name    string `json:"name,omitempty"`
}

// =============================================================================
// Response Types - Bluetooth
// =============================================================================

// BluetoothDevice represents a Bluetooth device
type BluetoothDevice struct {
	Address   string `json:"address"`
	Name      string `json:"name"`
	Paired    bool   `json:"paired"`
	Connected bool   `json:"connected"`
	Trusted   bool   `json:"trusted"`
	Class     string `json:"class,omitempty"`
	RSSI      int    `json:"rssi,omitempty"`
}

// BluetoothDevicesResponse represents Bluetooth devices list
type BluetoothDevicesResponse struct {
	Paired    []BluetoothDevice `json:"paired"`
	Available []BluetoothDevice `json:"available,omitempty"`
}

// BluetoothStatus represents Bluetooth adapter status
type BluetoothStatus struct {
	Available    bool   `json:"available"`
	Powered      bool   `json:"powered"`
	Discoverable bool   `json:"discoverable"`
	Pairable     bool   `json:"pairable"`
	Name         string `json:"name"`
	Address      string `json:"address"`
	Alias        string `json:"alias,omitempty"`
}

// =============================================================================
// Response Types - Mounts
// =============================================================================

// MountInfo represents a network mount
type MountInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // "smb" or "nfs"
	RemotePath string `json:"remote_path"`
	LocalPath  string `json:"local_path"`
	Mounted    bool   `json:"mounted"`
	Error      string `json:"error,omitempty"`
}

// MountsResponse represents network mounts list
type MountsResponse struct {
	Mounts []MountInfo `json:"mounts"`
	Count  int         `json:"count"`
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

// =============================================================================
// Request Types
// =============================================================================

// ChargingRequest represents charging control request
type ChargingRequest struct {
	Enabled bool `json:"enabled"`
}

// WakeAlarmRequest represents wake alarm request
type WakeAlarmRequest struct {
	Time string `json:"time"` // RFC3339 format
}

// CellularConnectRequest represents cellular connection request
type CellularConnectRequest struct {
	ModemIndex int    `json:"modem_index"`
	APN        string `json:"apn"`
	User       string `json:"user,omitempty"`
	Password   string `json:"password,omitempty"`
	PIN        string `json:"pin,omitempty"`
}

// MeshtasticMessageRequest represents a Meshtastic message
type MeshtasticMessageRequest struct {
	Text    string `json:"text"`
	To      string `json:"to,omitempty"`
	Channel int    `json:"channel,omitempty"`
}

// IridiumSendRequest represents an SBD message to send
type IridiumSendRequest struct {
	Text   string `json:"text,omitempty"`
	Data   string `json:"data,omitempty"` // Base64 for binary
	Format string `json:"format"`         // "text" or "binary"
}

// CaptureRequest represents image capture request
type CaptureRequest struct {
	Device  string `json:"device,omitempty"`
	Width   int    `json:"width,omitempty"`
	Height  int    `json:"height,omitempty"`
	Quality int    `json:"quality,omitempty"`
	Format  string `json:"format,omitempty"` // "jpeg", "png"
}

// StreamRequest represents stream control request
type StreamRequest struct {
	Device    string `json:"device,omitempty"`
	Port      int    `json:"port,omitempty"`
	Width     int    `json:"width,omitempty"`
	Height    int    `json:"height,omitempty"`
	Framerate int    `json:"framerate,omitempty"`
}

// VolumeRequest represents volume control request
type VolumeRequest struct {
	Volume int `json:"volume"`
}

// MuteRequest represents mute control request
type MuteRequest struct {
	Muted bool `json:"muted"`
}

// GPIOPinRequest represents GPIO pin control request
type GPIOPinRequest struct {
	Pin   int `json:"pin"`
	Value int `json:"value"`
}

// GPIOModeRequest represents GPIO mode control request
type GPIOModeRequest struct {
	Pin  int    `json:"pin"`
	Mode string `json:"mode"` // "in" or "out"
}

// I2CWriteRequest represents I2C write request
type I2CWriteRequest struct {
	Bus      int    `json:"bus"`
	Address  int    `json:"address"`
	Register int    `json:"register"`
	Data     []byte `json:"data"`
}

// BluetoothConnectRequest represents Bluetooth connect request
type BluetoothConnectRequest struct {
	Address string `json:"address"`
}

// =============================================================================
// Generic Response Types
// =============================================================================

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ErrorResponse represents a generic error response
type ErrorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

// =============================================================================
// Helper Methods
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

func (c *Client) doGet(ctx context.Context, path string, result interface{}) error {
	body, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if result != nil {
		if err := json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
}

func (c *Client) doPost(ctx context.Context, path string, reqBody interface{}) error {
	_, err := c.doRequest(ctx, http.MethodPost, path, reqBody)
	return err
}

func (c *Client) doDelete(ctx context.Context, path string, reqBody interface{}) error {
	_, err := c.doRequest(ctx, http.MethodDelete, path, reqBody)
	return err
}

// doPostWithResult sends a POST and unmarshals the response into result
func (c *Client) doPostWithResult(ctx context.Context, path string, reqBody interface{}, result interface{}) error {
	body, err := c.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return err
	}
	if result != nil {
		if err := json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
}

// doGetRaw sends a GET and returns the raw response bytes (for binary downloads)
func (c *Client) doGetRaw(ctx context.Context, path string) ([]byte, error) {
	return c.doRequest(ctx, http.MethodGet, path, nil)
}

// doStreamRequest creates a raw HTTP request and returns the open *http.Response.
// The caller is responsible for closing the response body.
// Used for SSE event streams that need to be proxied to the API client.
func (c *Client) doStreamRequest(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	// Use a separate client with no timeout for long-lived SSE streams
	streamClient := &http.Client{}
	resp, err := streamClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stream request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("HAL error: %s", errResp.Error)
		}
		return nil, fmt.Errorf("HAL error: status %d", resp.StatusCode)
	}

	return resp, nil
}

// =============================================================================
// Health Check
// =============================================================================

// Health checks if HAL is running
func (c *Client) Health(ctx context.Context) error {
	_, err := c.doRequest(ctx, http.MethodGet, "/health", nil)
	return err
}

// =============================================================================
// System Operations
// =============================================================================

// GetTemperature returns CPU temperature
func (c *Client) GetTemperature(ctx context.Context) (*TemperatureResponse, error) {
	var result TemperatureResponse
	if err := c.doGet(ctx, "/system/temperature", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetThrottleStatus returns CPU throttling status
func (c *Client) GetThrottleStatus(ctx context.Context) (*ThrottleStatus, error) {
	var result ThrottleStatus
	if err := c.doGet(ctx, "/system/throttle", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetEEPROMInfo returns Raspberry Pi EEPROM/firmware information
func (c *Client) GetEEPROMInfo(ctx context.Context) (*EEPROMInfo, error) {
	var result EEPROMInfo
	if err := c.doGet(ctx, "/system/eeprom", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBootConfig returns boot configuration
func (c *Client) GetBootConfig(ctx context.Context) (*BootConfig, error) {
	var result BootConfig
	if err := c.doGet(ctx, "/system/bootconfig", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUptime returns system uptime information
func (c *Client) GetUptime(ctx context.Context) (*UptimeInfo, error) {
	var result UptimeInfo
	if err := c.doGet(ctx, "/system/uptime", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Reboot reboots the system
func (c *Client) Reboot(ctx context.Context) error {
	return c.doPost(ctx, "/system/reboot", nil)
}

// Shutdown shuts down the system
func (c *Client) Shutdown(ctx context.Context) error {
	return c.doPost(ctx, "/system/shutdown", nil)
}

// GetServiceStatus returns the status of a systemd service
func (c *Client) GetServiceStatus(ctx context.Context, name string) (*ServiceStatus, error) {
	var result ServiceStatus
	if err := c.doGet(ctx, "/system/service/"+url.PathEscape(name)+"/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StartService starts a systemd service
func (c *Client) StartService(ctx context.Context, name string) error {
	return c.doPost(ctx, "/system/service/"+url.PathEscape(name)+"/start", nil)
}

// StopService stops a systemd service
func (c *Client) StopService(ctx context.Context, name string) error {
	return c.doPost(ctx, "/system/service/"+url.PathEscape(name)+"/stop", nil)
}

// RestartService restarts a systemd service
func (c *Client) RestartService(ctx context.Context, name string) error {
	return c.doPost(ctx, "/system/service/"+url.PathEscape(name)+"/restart", nil)
}

// =============================================================================
// Power Operations
// =============================================================================

// GetPowerStatus returns complete power status
func (c *Client) GetPowerStatus(ctx context.Context) (*PowerStatus, error) {
	var result PowerStatus
	if err := c.doGet(ctx, "/power/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBatteryStatus returns battery status from X1202 UPS
func (c *Client) GetBatteryStatus(ctx context.Context) (*BatteryStatus, error) {
	var result BatteryStatus
	if err := c.doGet(ctx, "/power/battery", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUPSInfo returns UPS hardware information
func (c *Client) GetUPSInfo(ctx context.Context) (*UPSInfo, error) {
	var result UPSInfo
	if err := c.doGet(ctx, "/power/ups", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SetChargingEnabled controls battery charging
func (c *Client) SetChargingEnabled(ctx context.Context, enabled bool) error {
	return c.doPost(ctx, "/power/charging", ChargingRequest{Enabled: enabled})
}

// QuickStartBattery performs MAX17040 fuel gauge quick-start
func (c *Client) QuickStartBattery(ctx context.Context) error {
	return c.doPost(ctx, "/power/battery/quickstart", nil)
}

// StartPowerMonitor starts power monitoring
func (c *Client) StartPowerMonitor(ctx context.Context) error {
	return c.doPost(ctx, "/power/monitor/start", nil)
}

// StopPowerMonitor stops power monitoring
func (c *Client) StopPowerMonitor(ctx context.Context) error {
	return c.doPost(ctx, "/power/monitor/stop", nil)
}

// GetPowerMonitorStatus returns power monitoring status (battery, charging, UPS)
func (c *Client) GetPowerMonitorStatus(ctx context.Context) (*PowerMonitorStatus, error) {
	var result PowerMonitorStatus
	if err := c.doGet(ctx, "/power/monitor/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetHALFirewallStatus returns consolidated firewall status from HAL
func (c *Client) GetHALFirewallStatus(ctx context.Context) (*FirewallStatusResponse, error) {
	var result FirewallStatusResponse
	if err := c.doGet(ctx, "/firewall/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetSupportBundle downloads the support bundle zip from HAL
func (c *Client) GetSupportBundle(ctx context.Context) ([]byte, error) {
	return c.doGetRaw(ctx, "/support/bundle.zip")
}

// =============================================================================
// RTC Operations
// =============================================================================

// GetRTCStatus returns RTC status
func (c *Client) GetRTCStatus(ctx context.Context) (*RTCStatus, error) {
	var result RTCStatus
	if err := c.doGet(ctx, "/rtc/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SetRTCTime syncs system time to RTC
func (c *Client) SetRTCTime(ctx context.Context) error {
	return c.doPost(ctx, "/rtc/sync-to-rtc", nil)
}

// SyncTimeFromRTC syncs time from RTC to system
func (c *Client) SyncTimeFromRTC(ctx context.Context) error {
	return c.doPost(ctx, "/rtc/sync-from-rtc", nil)
}

// SetWakeAlarm sets the RTC wake alarm
func (c *Client) SetWakeAlarm(ctx context.Context, t time.Time) error {
	return c.doPost(ctx, "/rtc/wakealarm", WakeAlarmRequest{Time: t.Format(time.RFC3339)})
}

// ClearWakeAlarm clears the RTC wake alarm
func (c *Client) ClearWakeAlarm(ctx context.Context) error {
	return c.doDelete(ctx, "/rtc/wakealarm", nil)
}

// =============================================================================
// Watchdog Operations
// =============================================================================

// GetWatchdogStatus returns watchdog status
func (c *Client) GetWatchdogStatus(ctx context.Context) (*WatchdogInfo, error) {
	var result WatchdogInfo
	if err := c.doGet(ctx, "/watchdog/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PetWatchdog pets the watchdog
func (c *Client) PetWatchdog(ctx context.Context) error {
	return c.doPost(ctx, "/watchdog/pet", nil)
}

// EnableWatchdog enables the watchdog
func (c *Client) EnableWatchdog(ctx context.Context) error {
	return c.doPost(ctx, "/watchdog/enable", nil)
}

// =============================================================================
// Network Operations
// =============================================================================

// ListInterfaces returns all network interfaces
func (c *Client) ListInterfaces(ctx context.Context) ([]NetworkInterface, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/network/interfaces", nil)
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
	var result NetworkInterface
	if err := c.doGet(ctx, "/network/interface/"+url.PathEscape(name), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetInterfaceTraffic returns traffic statistics for an interface
func (c *Client) GetInterfaceTraffic(ctx context.Context, name string) (*InterfaceTraffic, error) {
	var result InterfaceTraffic
	if err := c.doGet(ctx, "/network/interface/"+url.PathEscape(name)+"/traffic", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TrafficHistoryPoint represents a point in traffic history
type TrafficHistoryPoint struct {
	Timestamp int64 `json:"timestamp"`
	RxBytes   int64 `json:"rx_bytes"`
	TxBytes   int64 `json:"tx_bytes"`
	RxRate    int64 `json:"rx_rate"`
	TxRate    int64 `json:"tx_rate"`
}

// GetTrafficHistory returns traffic history for an interface over a duration
func (c *Client) GetTrafficHistory(ctx context.Context, iface string, duration string) ([]TrafficHistoryPoint, error) {
	path := "/network/interface/" + url.PathEscape(iface) + "/traffic/history"
	if duration != "" {
		path += "?duration=" + url.QueryEscape(duration)
	}

	body, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp []TrafficHistoryPoint
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse traffic history: %w", err)
	}

	return resp, nil
}

// BringInterfaceUp brings a network interface up
func (c *Client) BringInterfaceUp(ctx context.Context, name string) error {
	return c.doPost(ctx, "/network/interface/"+url.PathEscape(name)+"/up", nil)
}

// BringInterfaceDown brings a network interface down
func (c *Client) BringInterfaceDown(ctx context.Context, name string) error {
	return c.doPost(ctx, "/network/interface/"+url.PathEscape(name)+"/down", nil)
}

// GetNetworkStatus returns overall network status
func (c *Client) GetNetworkStatus(ctx context.Context) (map[string]interface{}, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/network/status", nil)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp, nil
}

// ScanWiFi scans for WiFi networks on the specified interface
func (c *Client) ScanWiFi(ctx context.Context, iface string) ([]WiFiNetwork, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/network/wifi/scan/"+url.PathEscape(iface), nil)
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
	return c.doPost(ctx, "/network/wifi/connect", req)
}

// DisconnectWiFi disconnects from WiFi
func (c *Client) DisconnectWiFi(ctx context.Context, iface string) error {
	return c.doPost(ctx, "/network/wifi/disconnect/"+url.PathEscape(iface), nil)
}

// GetAPStatus returns Access Point status
func (c *Client) GetAPStatus(ctx context.Context) (*APStatus, error) {
	var result APStatus
	if err := c.doGet(ctx, "/network/ap/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetAPClients returns connected AP clients
func (c *Client) GetAPClients(ctx context.Context) (*APClientsResponse, error) {
	var result APClientsResponse
	if err := c.doGet(ctx, "/network/ap/clients", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DisconnectAPClient disconnects a client from the AP
func (c *Client) DisconnectAPClient(ctx context.Context, mac string) error {
	return c.doPost(ctx, "/network/ap/disconnect", map[string]string{"mac": mac})
}

// BlockAPClient blocks a MAC address from the AP
func (c *Client) BlockAPClient(ctx context.Context, mac string) error {
	return c.doPost(ctx, "/network/ap/block", map[string]string{"mac": mac})
}

// =============================================================================
// Firewall Operations
// =============================================================================

// AddFirewallRule adds a firewall rule
func (c *Client) AddFirewallRule(ctx context.Context, table, chain string, args []string) error {
	req := map[string]interface{}{
		"table": table,
		"chain": chain,
		"args":  args,
	}
	return c.doPost(ctx, "/firewall/rule", req)
}

// DeleteFirewallRule deletes a firewall rule
func (c *Client) DeleteFirewallRule(ctx context.Context, table, chain string, args []string) error {
	req := map[string]interface{}{
		"table": table,
		"chain": chain,
		"args":  args,
	}
	return c.doDelete(ctx, "/firewall/rule", req)
}

// EnableNAT enables NAT forwarding between interfaces
func (c *Client) EnableNAT(ctx context.Context, sourceInterface, destInterface string) error {
	req := map[string]string{
		"source_interface": sourceInterface,
		"dest_interface":   destInterface,
	}
	return c.doPost(ctx, "/firewall/nat/enable", req)
}

// DisableNAT disables NAT forwarding
func (c *Client) DisableNAT(ctx context.Context) error {
	return c.doPost(ctx, "/firewall/nat/disable", nil)
}

// EnableIPForward enables IP forwarding
func (c *Client) EnableIPForward(ctx context.Context) error {
	return c.doPost(ctx, "/firewall/forward/enable", nil)
}

// DisableIPForward disables IP forwarding
func (c *Client) DisableIPForward(ctx context.Context) error {
	return c.doPost(ctx, "/firewall/forward/disable", nil)
}

// SaveFirewallRules saves current iptables rules to persistent storage via HAL
func (c *Client) SaveFirewallRules(ctx context.Context) error {
	return c.doPost(ctx, "/firewall/save", nil)
}

// RestoreFirewallRules restores iptables rules from persistent storage via HAL
func (c *Client) RestoreFirewallRules(ctx context.Context) error {
	return c.doPost(ctx, "/firewall/restore", nil)
}

// ResetFirewall flushes all iptables rules and resets to default policy via HAL
func (c *Client) ResetFirewall(ctx context.Context) error {
	return c.doPost(ctx, "/firewall/reset", nil)
}

// =============================================================================
// VPN Operations
// =============================================================================

// GetVPNStatus returns overall VPN status
func (c *Client) GetVPNStatus(ctx context.Context) (*VPNStatus, error) {
	var halResp halVPNStatusResponse
	if err := c.doGet(ctx, "/vpn/status", &halResp); err != nil {
		return nil, err
	}

	// Convert HAL response to manager-expected structure
	result := &VPNStatus{
		Tor: halResp.Tor,
	}

	// Check if any WireGuard interface is active
	for _, iface := range halResp.WireGuard {
		if iface.Active {
			result.WireGuard.Active = true
		}
		result.WireGuard.Interfaces = append(result.WireGuard.Interfaces, iface.Name)
	}

	// Check if any OpenVPN connection is active
	for _, iface := range halResp.OpenVPN {
		if iface.Active {
			result.OpenVPN.Active = true
			break
		}
	}

	return result, nil
}

// WireGuardUp brings up a WireGuard interface
func (c *Client) WireGuardUp(ctx context.Context, name string) error {
	return c.doPost(ctx, "/vpn/wireguard/up/"+url.PathEscape(name), nil)
}

// WireGuardDown brings down a WireGuard interface
func (c *Client) WireGuardDown(ctx context.Context, name string) error {
	return c.doPost(ctx, "/vpn/wireguard/down/"+url.PathEscape(name), nil)
}

// OpenVPNUp starts OpenVPN with a config
func (c *Client) OpenVPNUp(ctx context.Context, name string) error {
	return c.doPost(ctx, "/vpn/openvpn/up/"+url.PathEscape(name), nil)
}

// OpenVPNDown stops OpenVPN
func (c *Client) OpenVPNDown(ctx context.Context, name string) error {
	return c.doPost(ctx, "/vpn/openvpn/down/"+url.PathEscape(name), nil)
}

// GetTorStatus returns Tor service status
func (c *Client) GetTorStatus(ctx context.Context) (*TorStatus, error) {
	var result TorStatus
	if err := c.doGet(ctx, "/vpn/tor/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTorConfig returns Tor configuration
func (c *Client) GetTorConfig(ctx context.Context) (*TorConfig, error) {
	var result TorConfig
	if err := c.doGet(ctx, "/vpn/tor/config", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StartTor starts the Tor service
func (c *Client) StartTor(ctx context.Context) error {
	return c.doPost(ctx, "/vpn/tor/start", nil)
}

// StopTor stops the Tor service
func (c *Client) StopTor(ctx context.Context) error {
	return c.doPost(ctx, "/vpn/tor/stop", nil)
}

// NewTorCircuit requests a new Tor circuit
func (c *Client) NewTorCircuit(ctx context.Context) error {
	return c.doPost(ctx, "/vpn/tor/newcircuit", nil)
}

// =============================================================================
// Storage Operations
// =============================================================================

// GetStorageDevices returns list of storage devices
func (c *Client) GetStorageDevices(ctx context.Context) (*StorageDevicesResponse, error) {
	var result StorageDevicesResponse
	if err := c.doGet(ctx, "/storage/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetStorageDevice returns info about a specific device
func (c *Client) GetStorageDevice(ctx context.Context, device string) (*StorageDevice, error) {
	var result StorageDevice
	if err := c.doGet(ctx, "/storage/device/"+url.PathEscape(device), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetSMARTInfo returns SMART health data for a device
func (c *Client) GetSMARTInfo(ctx context.Context, device string) (*SMARTInfo, error) {
	var result SMARTInfo
	if err := c.doGet(ctx, "/storage/smart/"+url.PathEscape(device), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetStorageUsage returns filesystem usage
func (c *Client) GetStorageUsage(ctx context.Context) (*StorageUsageResponse, error) {
	var result StorageUsageResponse
	if err := c.doGet(ctx, "/storage/usage", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUSBStorageDevices returns USB storage devices
func (c *Client) GetUSBStorageDevices(ctx context.Context) ([]USBStorageDevice, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/storage/usb", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Devices []USBStorageDevice `json:"devices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Devices, nil
}

// MountUSBStorage mounts a USB storage device
func (c *Client) MountUSBStorage(ctx context.Context, device string) (string, error) {
	body, err := c.doRequest(ctx, http.MethodPost, "/storage/usb/mount", map[string]string{"device": device})
	if err != nil {
		return "", err
	}

	var resp struct {
		MountPoint string `json:"mount_point"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.MountPoint, nil
}

// UnmountUSBStorage unmounts a USB storage device
func (c *Client) UnmountUSBStorage(ctx context.Context, device string) error {
	return c.doPost(ctx, "/storage/usb/unmount", map[string]string{"device": device})
}

// EjectUSBStorage safely ejects a USB storage device
func (c *Client) EjectUSBStorage(ctx context.Context, device string) error {
	return c.doPost(ctx, "/storage/usb/eject", map[string]string{"device": device})
}

// =============================================================================
// USB Operations
// =============================================================================

// GetUSBDevices returns list of USB devices
func (c *Client) GetUSBDevices(ctx context.Context) (*USBDevicesResponse, error) {
	var result USBDevicesResponse
	if err := c.doGet(ctx, "/usb/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUSBTree returns USB devices in tree format
func (c *Client) GetUSBTree(ctx context.Context) (map[string]interface{}, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/usb/tree", nil)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp, nil
}

// GetUSBDevicesByClass returns USB devices filtered by class
func (c *Client) GetUSBDevicesByClass(ctx context.Context, class string) ([]USBDevice, error) {
	path := "/usb/class"
	if class != "" {
		path += "?class=" + url.QueryEscape(class)
	}

	body, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Devices []USBDevice `json:"devices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Devices, nil
}

// ResetUSBDevice resets a USB device
func (c *Client) ResetUSBDevice(ctx context.Context, bus, device int) error {
	return c.doPost(ctx, "/usb/reset", map[string]int{"bus": bus, "device": device})
}

// RescanUSB rescans all USB buses
func (c *Client) RescanUSB(ctx context.Context) error {
	return c.doPost(ctx, "/usb/rescan", nil)
}

// =============================================================================
// Logs Operations
// =============================================================================

// GetKernelLogs returns kernel logs
func (c *Client) GetKernelLogs(ctx context.Context, lines int, level string) (*LogsResponse, error) {
	path := "/logs/kernel?lines=" + strconv.Itoa(lines)
	if level != "" {
		path += "&level=" + url.QueryEscape(level)
	}

	var result LogsResponse
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetJournalLogs returns systemd journal logs
func (c *Client) GetJournalLogs(ctx context.Context, lines int, unit, since string, priority int) (*LogsResponse, error) {
	path := "/logs/journal?lines=" + strconv.Itoa(lines)
	if unit != "" {
		path += "&unit=" + url.QueryEscape(unit)
	}
	if since != "" {
		path += "&since=" + url.QueryEscape(since)
	}
	if priority >= 0 {
		path += "&priority=" + strconv.Itoa(priority)
	}

	var result LogsResponse
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetHardwareLogs returns hardware-specific logs
func (c *Client) GetHardwareLogs(ctx context.Context, category string) (*HardwareLogsResponse, error) {
	path := "/logs/hardware"
	if category != "" {
		path += "?category=" + url.QueryEscape(category)
	}

	var result HardwareLogsResponse
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// =============================================================================
// GPS Operations
// =============================================================================

// GetGPSDevices returns list of GPS devices
func (c *Client) GetGPSDevices(ctx context.Context) (*GPSDevicesResponse, error) {
	var result GPSDevicesResponse
	if err := c.doGet(ctx, "/gps/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetGPSStatus returns GPS status
func (c *Client) GetGPSStatus(ctx context.Context, port string) (*GPSStatus, error) {
	path := "/gps/status"
	if port != "" {
		path += "?port=" + url.QueryEscape(port)
	}

	var result GPSStatus
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetGPSPosition returns current GPS position
func (c *Client) GetGPSPosition(ctx context.Context, port string, timeout int) (*GPSPosition, error) {
	path := "/gps/position"
	if port != "" {
		path += "?port=" + url.QueryEscape(port)
	}
	if timeout > 0 {
		if port != "" {
			path += "&"
		} else {
			path += "?"
		}
		path += "timeout=" + strconv.Itoa(timeout)
	}

	var result GPSPosition
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// =============================================================================
// Cellular Operations
// =============================================================================

// GetCellularModems returns list of cellular modems
func (c *Client) GetCellularModems(ctx context.Context) (*CellularModemsResponse, error) {
	var result CellularModemsResponse
	if err := c.doGet(ctx, "/cellular/modems", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCellularStatus returns cellular status
func (c *Client) GetCellularStatus(ctx context.Context) (*CellularStatus, error) {
	var result CellularStatus
	if err := c.doGet(ctx, "/cellular/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCellularSignal returns cellular signal info
func (c *Client) GetCellularSignal(ctx context.Context, modemIndex int) (*CellularSignal, error) {
	path := "/cellular/signal"
	if modemIndex >= 0 {
		path += "?modem=" + strconv.Itoa(modemIndex)
	}

	var result CellularSignal
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ConnectCellular connects a cellular modem
func (c *Client) ConnectCellular(ctx context.Context, modemIndex int, apn, user, password string) error {
	req := CellularConnectRequest{
		ModemIndex: modemIndex,
		APN:        apn,
		User:       user,
		Password:   password,
	}
	return c.doPost(ctx, "/cellular/connect/"+strconv.Itoa(modemIndex), req)
}

// DisconnectCellular disconnects a cellular modem
func (c *Client) DisconnectCellular(ctx context.Context, modemIndex int) error {
	return c.doPost(ctx, "/cellular/disconnect/"+strconv.Itoa(modemIndex), nil)
}

// GetAndroidTetheringStatus returns Android USB tethering status
func (c *Client) GetAndroidTetheringStatus(ctx context.Context) (*AndroidTetheringStatus, error) {
	var result AndroidTetheringStatus
	if err := c.doGet(ctx, "/cellular/android/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EnableAndroidTethering enables Android USB tethering
func (c *Client) EnableAndroidTethering(ctx context.Context) error {
	return c.doPost(ctx, "/cellular/android/enable", nil)
}

// DisableAndroidTethering disables Android USB tethering
func (c *Client) DisableAndroidTethering(ctx context.Context) error {
	return c.doPost(ctx, "/cellular/android/disable", nil)
}

// =============================================================================
// Meshtastic Operations
// =============================================================================

// GetMeshtasticDevices returns available Meshtastic devices
func (c *Client) GetMeshtasticDevices(ctx context.Context) (*MeshtasticDevicesResponse, error) {
	var result MeshtasticDevicesResponse
	if err := c.doGet(ctx, "/meshtastic/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ConnectMeshtastic connects to a Meshtastic device
func (c *Client) ConnectMeshtastic(ctx context.Context, req *MeshtasticConnectRequest) error {
	return c.doPost(ctx, "/meshtastic/connect", req)
}

// DisconnectMeshtastic disconnects from the Meshtastic device
func (c *Client) DisconnectMeshtastic(ctx context.Context) error {
	return c.doPost(ctx, "/meshtastic/disconnect", nil)
}

// GetMeshtasticStatus returns Meshtastic status
func (c *Client) GetMeshtasticStatus(ctx context.Context) (*MeshtasticStatus, error) {
	var result MeshtasticStatus
	if err := c.doGet(ctx, "/meshtastic/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetMeshtasticNodes returns mesh nodes
func (c *Client) GetMeshtasticNodes(ctx context.Context) (*MeshtasticNodesResponse, error) {
	var result MeshtasticNodesResponse
	if err := c.doGet(ctx, "/meshtastic/nodes", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetMeshtasticPosition returns GPS position from the connected Meshtastic radio
func (c *Client) GetMeshtasticPosition(ctx context.Context) (*MeshtasticPosition, error) {
	var result MeshtasticPosition
	if err := c.doGet(ctx, "/meshtastic/position", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetMeshtasticMessages returns Meshtastic message history
func (c *Client) GetMeshtasticMessages(ctx context.Context) (*MeshtasticMessagesResponse, error) {
	var result MeshtasticMessagesResponse
	if err := c.doGet(ctx, "/meshtastic/messages", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SendMeshtasticMessage sends a message via Meshtastic
func (c *Client) SendMeshtasticMessage(ctx context.Context, req *MeshtasticMessageRequest) error {
	return c.doPost(ctx, "/meshtastic/messages/send", req)
}

// SendMeshtasticRaw sends a raw protobuf packet via Meshtastic
func (c *Client) SendMeshtasticRaw(ctx context.Context, req *MeshtasticRawRequest) error {
	return c.doPost(ctx, "/meshtastic/messages/send_raw", req)
}

// GetMeshtasticConfig returns the Meshtastic radio configuration
func (c *Client) GetMeshtasticConfig(ctx context.Context) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.doGet(ctx, "/meshtastic/config", &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SetMeshtasticChannel configures a Meshtastic channel
func (c *Client) SetMeshtasticChannel(ctx context.Context, req *MeshtasticChannelRequest) error {
	return c.doPost(ctx, "/meshtastic/channel", req)
}

// StreamMeshtasticEvents returns an open SSE stream for Meshtastic events.
// The caller is responsible for closing the response body.
func (c *Client) StreamMeshtasticEvents(ctx context.Context) (*http.Response, error) {
	return c.doStreamRequest(ctx, "/meshtastic/events")
}

// =============================================================================
// Iridium Operations
// =============================================================================

// GetIridiumDevices returns available Iridium devices
func (c *Client) GetIridiumDevices(ctx context.Context) (*IridiumDevicesResponse, error) {
	var result IridiumDevicesResponse
	if err := c.doGet(ctx, "/iridium/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ConnectIridium connects to an Iridium device.
// Port is optional — if empty, HAL auto-detects.
func (c *Client) ConnectIridium(ctx context.Context, port string) error {
	path := "/iridium/connect"
	if port != "" {
		path += "?port=" + url.QueryEscape(port)
	}
	return c.doPost(ctx, path, nil)
}

// DisconnectIridium disconnects from the Iridium device
func (c *Client) DisconnectIridium(ctx context.Context) error {
	return c.doPost(ctx, "/iridium/disconnect", nil)
}

// GetIridiumStatus returns Iridium status
func (c *Client) GetIridiumStatus(ctx context.Context) (*IridiumStatus, error) {
	var result IridiumStatus
	if err := c.doGet(ctx, "/iridium/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetIridiumSignal returns Iridium signal strength
func (c *Client) GetIridiumSignal(ctx context.Context) (*IridiumSignal, error) {
	var result IridiumSignal
	if err := c.doGet(ctx, "/iridium/signal", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SendIridiumSBD sends an SBD message via Iridium
func (c *Client) SendIridiumSBD(ctx context.Context, req *IridiumSendRequest) (*IridiumSendResponse, error) {
	var result IridiumSendResponse
	if err := c.doPostWithResult(ctx, "/iridium/send", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetIridiumMessages retrieves Iridium messages (alias for receive)
func (c *Client) GetIridiumMessages(ctx context.Context) (*IridiumMessagesResponse, error) {
	var result IridiumMessagesResponse
	if err := c.doGet(ctx, "/iridium/messages", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CheckIridiumMailbox checks the Iridium mailbox
func (c *Client) CheckIridiumMailbox(ctx context.Context) (*IridiumMailboxResponse, error) {
	var result IridiumMailboxResponse
	if err := c.doPostWithResult(ctx, "/iridium/mailbox_check", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ReceiveIridiumMessage receives a pending Iridium message
func (c *Client) ReceiveIridiumMessage(ctx context.Context) (*IridiumReceiveResponse, error) {
	var result IridiumReceiveResponse
	if err := c.doGet(ctx, "/iridium/receive", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClearIridiumBuffers clears Iridium MO/MT buffers
func (c *Client) ClearIridiumBuffers(ctx context.Context, buffer string) error {
	req := IridiumClearRequest{Buffer: buffer}
	return c.doPost(ctx, "/iridium/clear", req)
}

// StreamIridiumEvents returns an open SSE stream for Iridium events.
// The caller is responsible for closing the response body.
func (c *Client) StreamIridiumEvents(ctx context.Context) (*http.Response, error) {
	return c.doStreamRequest(ctx, "/iridium/events")
}

// =============================================================================
// Camera Operations
// =============================================================================

// GetCameras returns list of camera devices
func (c *Client) GetCameras(ctx context.Context) (*CameraDevicesResponse, error) {
	var result CameraDevicesResponse
	if err := c.doGet(ctx, "/camera/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCameraInfo returns camera information
func (c *Client) GetCameraInfo(ctx context.Context) (*CameraInfo, error) {
	var result CameraInfo
	if err := c.doGet(ctx, "/camera/info", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CaptureImage captures an image from the camera
func (c *Client) CaptureImage(ctx context.Context, device string, width, height, quality int, format string) error {
	req := CaptureRequest{
		Device:  device,
		Width:   width,
		Height:  height,
		Quality: quality,
		Format:  format,
	}
	return c.doPost(ctx, "/camera/capture", req)
}

// GetCapturedImage retrieves the last captured image
func (c *Client) GetCapturedImage(ctx context.Context) ([]byte, error) {
	return c.doRequest(ctx, http.MethodGet, "/camera/image", nil)
}

// GetStreamInfo returns camera stream status
func (c *Client) GetStreamInfo(ctx context.Context) (*StreamInfo, error) {
	var result StreamInfo
	if err := c.doGet(ctx, "/camera/stream/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StartStream starts camera streaming
func (c *Client) StartStream(ctx context.Context, device string, port, width, height, framerate int) error {
	req := StreamRequest{
		Device:    device,
		Port:      port,
		Width:     width,
		Height:    height,
		Framerate: framerate,
	}
	return c.doPost(ctx, "/camera/stream/start", req)
}

// StopStream stops camera streaming
func (c *Client) StopStream(ctx context.Context) error {
	return c.doPost(ctx, "/camera/stream/stop", nil)
}

// =============================================================================
// Sensors Operations
// =============================================================================

// GetAllSensors returns all sensor readings
func (c *Client) GetAllSensors(ctx context.Context) (*AllSensorsResponse, error) {
	var result AllSensorsResponse
	if err := c.doGet(ctx, "/sensors/all", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Get1WireDevices returns list of 1-Wire devices
func (c *Client) Get1WireDevices(ctx context.Context) (*OneWireDevicesResponse, error) {
	var result OneWireDevicesResponse
	if err := c.doGet(ctx, "/sensors/1wire/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Read1WireDevice reads a specific 1-Wire device
func (c *Client) Read1WireDevice(ctx context.Context, deviceID string) (*OneWireDevice, error) {
	var result OneWireDevice
	if err := c.doGet(ctx, "/sensors/1wire/device/"+url.PathEscape(deviceID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Read1WireTemperatures reads all 1-Wire temperature sensors
func (c *Client) Read1WireTemperatures(ctx context.Context) ([]SensorReading, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/sensors/1wire/temperatures", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Readings []SensorReading `json:"readings"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Readings, nil
}

// ReadBME280 reads the BME280 sensor
func (c *Client) ReadBME280(ctx context.Context, bus int, address string) (*BME280Reading, error) {
	path := "/sensors/bme280"
	if address != "" {
		path += "?address=" + url.QueryEscape(address)
	}
	if bus > 0 {
		if address != "" {
			path += "&"
		} else {
			path += "?"
		}
		path += "bus=" + strconv.Itoa(bus)
	}

	var result BME280Reading
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DetectBME280 detects BME280 sensors on I2C bus
func (c *Client) DetectBME280(ctx context.Context, bus int) ([]map[string]interface{}, error) {
	path := "/sensors/bme280/detect"
	if bus > 0 {
		path += "?bus=" + strconv.Itoa(bus)
	}

	body, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Sensors []map[string]interface{} `json:"sensors"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Sensors, nil
}

// =============================================================================
// Audio Operations
// =============================================================================

// GetAudioDevices returns list of audio devices
func (c *Client) GetAudioDevices(ctx context.Context) (*AudioDevicesResponse, error) {
	var result AudioDevicesResponse
	if err := c.doGet(ctx, "/audio/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPlaybackDevices returns playback audio devices
func (c *Client) GetPlaybackDevices(ctx context.Context) ([]AudioDevice, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/audio/playback", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Devices []AudioDevice `json:"devices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Devices, nil
}

// GetCaptureDevices returns capture audio devices
func (c *Client) GetCaptureDevices(ctx context.Context) ([]AudioDevice, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/audio/capture", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Devices []AudioDevice `json:"devices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Devices, nil
}

// GetVolume returns current volume
func (c *Client) GetVolume(ctx context.Context) (*VolumeInfo, error) {
	var result VolumeInfo
	if err := c.doGet(ctx, "/audio/volume", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SetVolume sets the volume
func (c *Client) SetVolume(ctx context.Context, volume int) error {
	return c.doPost(ctx, "/audio/volume", VolumeRequest{Volume: volume})
}

// SetMute sets the mute state
func (c *Client) SetMute(ctx context.Context, muted bool) error {
	return c.doPost(ctx, "/audio/mute", MuteRequest{Muted: muted})
}

// PlayTestTone plays a test tone
func (c *Client) PlayTestTone(ctx context.Context) error {
	return c.doPost(ctx, "/audio/test", nil)
}

// =============================================================================
// GPIO Operations
// =============================================================================

// GetGPIOPins returns GPIO pins status
func (c *Client) GetGPIOPins(ctx context.Context) (*GPIOPinsResponse, error) {
	var result GPIOPinsResponse
	if err := c.doGet(ctx, "/gpio/pins", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetGPIOPin returns a specific GPIO pin status
func (c *Client) GetGPIOPin(ctx context.Context, pin int) (*GPIOPin, error) {
	var result GPIOPin
	if err := c.doGet(ctx, "/gpio/pin/"+strconv.Itoa(pin), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SetGPIOPin sets a GPIO pin value
func (c *Client) SetGPIOPin(ctx context.Context, pin, value int) error {
	return c.doPost(ctx, "/gpio/pin", GPIOPinRequest{Pin: pin, Value: value})
}

// SetGPIOMode sets a GPIO pin mode
func (c *Client) SetGPIOMode(ctx context.Context, pin int, mode string) error {
	return c.doPost(ctx, "/gpio/mode", GPIOModeRequest{Pin: pin, Mode: mode})
}

// ExportGPIOPin exports a GPIO pin
func (c *Client) ExportGPIOPin(ctx context.Context, pin int) error {
	return c.doPost(ctx, "/gpio/export/"+strconv.Itoa(pin), nil)
}

// UnexportGPIOPin unexports a GPIO pin
func (c *Client) UnexportGPIOPin(ctx context.Context, pin int) error {
	return c.doPost(ctx, "/gpio/unexport/"+strconv.Itoa(pin), nil)
}

// =============================================================================
// I2C Operations
// =============================================================================

// ListI2CBuses returns list of I2C buses
func (c *Client) ListI2CBuses(ctx context.Context) (*I2CBusesResponse, error) {
	var result I2CBusesResponse
	if err := c.doGet(ctx, "/i2c/buses", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ScanI2CBus scans an I2C bus for devices
func (c *Client) ScanI2CBus(ctx context.Context, bus int) (*I2CScanResult, error) {
	path := "/i2c/scan"
	if bus >= 0 {
		path += "?bus=" + strconv.Itoa(bus)
	}

	var result I2CScanResult
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetI2CDevice returns info about an I2C device
func (c *Client) GetI2CDevice(ctx context.Context, bus, address int) (*I2CDevice, error) {
	var result I2CDevice
	path := fmt.Sprintf("/i2c/bus/%d/device/0x%02x", bus, address)
	if err := c.doGet(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ReadI2CRegister reads an I2C register
func (c *Client) ReadI2CRegister(ctx context.Context, bus, address, register int) ([]byte, error) {
	path := fmt.Sprintf("/i2c/read?bus=%d&address=%d&register=%d", bus, address, register)
	return c.doRequest(ctx, http.MethodGet, path, nil)
}

// WriteI2CRegister writes to an I2C register
func (c *Client) WriteI2CRegister(ctx context.Context, bus, address, register int, data []byte) error {
	req := I2CWriteRequest{
		Bus:      bus,
		Address:  address,
		Register: register,
		Data:     data,
	}
	return c.doPost(ctx, "/i2c/write", req)
}

// =============================================================================
// Bluetooth Operations
// =============================================================================

// GetBluetoothStatus returns Bluetooth adapter status
func (c *Client) GetBluetoothStatus(ctx context.Context) (*BluetoothStatus, error) {
	var result BluetoothStatus
	if err := c.doGet(ctx, "/bluetooth/status", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PowerOnBluetooth powers on Bluetooth
func (c *Client) PowerOnBluetooth(ctx context.Context) error {
	return c.doPost(ctx, "/bluetooth/power/on", nil)
}

// PowerOffBluetooth powers off Bluetooth
func (c *Client) PowerOffBluetooth(ctx context.Context) error {
	return c.doPost(ctx, "/bluetooth/power/off", nil)
}

// GetBluetoothDevices returns list of Bluetooth devices
func (c *Client) GetBluetoothDevices(ctx context.Context) (*BluetoothDevicesResponse, error) {
	var result BluetoothDevicesResponse
	if err := c.doGet(ctx, "/bluetooth/devices", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ScanBluetoothDevices initiates Bluetooth scan
func (c *Client) ScanBluetoothDevices(ctx context.Context, duration int) error {
	path := "/bluetooth/scan"
	if duration > 0 {
		path += "?duration=" + strconv.Itoa(duration)
	}
	return c.doPost(ctx, path, nil)
}

// PairBluetoothDevice pairs with a Bluetooth device
func (c *Client) PairBluetoothDevice(ctx context.Context, address string) error {
	return c.doPost(ctx, "/bluetooth/pair", BluetoothConnectRequest{Address: address})
}

// ConnectBluetoothDevice connects to a Bluetooth device
func (c *Client) ConnectBluetoothDevice(ctx context.Context, address string) error {
	return c.doPost(ctx, "/bluetooth/connect/"+url.PathEscape(address), nil)
}

// DisconnectBluetoothDevice disconnects from a Bluetooth device
func (c *Client) DisconnectBluetoothDevice(ctx context.Context, address string) error {
	return c.doPost(ctx, "/bluetooth/disconnect/"+url.PathEscape(address), nil)
}

// RemoveBluetoothDevice removes a paired Bluetooth device
func (c *Client) RemoveBluetoothDevice(ctx context.Context, address string) error {
	return c.doDelete(ctx, "/bluetooth/remove/"+url.PathEscape(address), nil)
}

// =============================================================================
// Network Mounts Operations
// =============================================================================

// GetNetworkMounts returns list of network mounts
func (c *Client) GetNetworkMounts(ctx context.Context) (*MountsResponse, error) {
	var result MountsResponse
	if err := c.doGet(ctx, "/mounts/", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// MountSMB mounts an SMB/CIFS share
func (c *Client) MountSMB(ctx context.Context, req *MountRequest) (*MountResponse, error) {
	req.Type = "smb"
	body, err := c.doRequest(ctx, http.MethodPost, "/mounts/smb", req)
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
	body, err := c.doRequest(ctx, http.MethodPost, "/mounts/nfs", req)
	if err != nil {
		return nil, err
	}

	var resp MountResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// UnmountNetwork unmounts a network mount
func (c *Client) UnmountNetwork(ctx context.Context, path string) error {
	return c.doPost(ctx, "/mounts/unmount", map[string]string{"path": path})
}

// CheckSMBServer checks SMB server connectivity
func (c *Client) CheckSMBServer(ctx context.Context, server string) error {
	path := "/mounts/smb/check"
	if server != "" {
		path += "?server=" + url.QueryEscape(server)
	}
	return c.doGet(ctx, path, nil)
}

// CheckNFSServer checks NFS server connectivity
func (c *Client) CheckNFSServer(ctx context.Context, server string) error {
	path := "/mounts/nfs/check"
	if server != "" {
		path += "?server=" + url.QueryEscape(server)
	}
	return c.doGet(ctx, path, nil)
}

// =============================================================================
// Aliases for backwards compatibility
// =============================================================================

// StartWireGuard starts a WireGuard interface (alias for WireGuardUp)
func (c *Client) StartWireGuard(ctx context.Context, name string) error {
	return c.WireGuardUp(ctx, name)
}

// StopWireGuard stops a WireGuard interface (alias for WireGuardDown)
func (c *Client) StopWireGuard(ctx context.Context, name string) error {
	return c.WireGuardDown(ctx, name)
}

// StartOpenVPN starts OpenVPN (alias for OpenVPNUp)
func (c *Client) StartOpenVPN(ctx context.Context, name string) error {
	return c.OpenVPNUp(ctx, name)
}

// StopOpenVPN stops OpenVPN (alias for OpenVPNDown)
func (c *Client) StopOpenVPN(ctx context.Context, name string) error {
	return c.OpenVPNDown(ctx, name)
}

// ListUSBDevices lists USB devices (alias for GetUSBDevices)
func (c *Client) ListUSBDevices(ctx context.Context) (*USBDevicesResponse, error) {
	return c.GetUSBDevices(ctx)
}

// ListMounts returns list of active mounts (alias for GetNetworkMounts)
func (c *Client) ListMounts(ctx context.Context) (*MountsResponse, error) {
	return c.GetNetworkMounts(ctx)
}

// UnmountPath unmounts a path (alias for UnmountNetwork)
func (c *Client) UnmountPath(ctx context.Context, path string) error {
	return c.UnmountNetwork(ctx, path)
}

// GetTrafficStats returns current traffic statistics for all interfaces
func (c *Client) GetTrafficStats(ctx context.Context) (*TrafficStats, error) {
	var result TrafficStats
	if err := c.doGet(ctx, "/network/traffic", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetForwardingStatus returns whether IP forwarding is enabled
func (c *Client) GetForwardingStatus(ctx context.Context) (bool, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/firewall/forwarding", nil)
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

// KickAPClient disconnects a client from the AP (alias for DisconnectAPClient)
func (c *Client) KickAPClient(ctx context.Context, mac string) error {
	return c.DisconnectAPClient(ctx, mac)
}

// BlockAPClientLegacy blocks a MAC address from the AP
func (c *Client) BlockAPClientLegacy(ctx context.Context, mac string) error {
	return c.BlockAPClient(ctx, mac)
}

// UnblockAPClient removes a MAC address from the AP blocklist
func (c *Client) UnblockAPClient(ctx context.Context, mac string) error {
	return c.doPost(ctx, "/network/wifi/ap/unblock/"+url.PathEscape(mac), nil)
}

// StartAP starts the WiFi access point
func (c *Client) StartAP(ctx context.Context, iface string) error {
	return c.StartService(ctx, "hostapd")
}

// StopAP stops the WiFi access point
func (c *Client) StopAP(ctx context.Context, iface string) error {
	return c.StopService(ctx, "hostapd")
}

// MountUSB mounts a USB device (legacy compatibility)
func (c *Client) MountUSB(ctx context.Context, device string) (string, error) {
	return c.MountUSBStorage(ctx, device)
}

// UnmountUSB unmounts a USB device (legacy compatibility)
func (c *Client) UnmountUSB(ctx context.Context, device string) error {
	return c.UnmountUSBStorage(ctx, device)
}

// RequestDHCP requests a DHCP lease on an interface
func (c *Client) RequestDHCP(ctx context.Context, iface string) error {
	req := map[string]string{"interface": iface}
	return c.doPost(ctx, "/network/dhcp/request", req)
}

// SetStaticIP sets a static IP address on an interface
func (c *Client) SetStaticIP(ctx context.Context, iface, ip, gateway string) error {
	req := map[string]string{
		"interface": iface,
		"ip":        ip,
		"gateway":   gateway,
	}
	return c.doPost(ctx, "/network/ip/static", req)
}

// TestMountConnection tests connectivity to a remote share
func (c *Client) TestMountConnection(ctx context.Context, mountType, remotePath, username, password string) error {
	req := map[string]string{
		"type":        mountType,
		"remote_path": remotePath,
		"username":    username,
		"password":    password,
	}
	return c.doPost(ctx, "/mounts/test", req)
}

// IsMounted checks if a path is currently mounted
func (c *Client) IsMounted(ctx context.Context, path string) (bool, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/mounts/check?path="+url.QueryEscape(path), nil)
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
// Firewall Rules Response (HAL actual format)
// =============================================================================

// FirewallRule represents a single iptables rule from HAL
type FirewallRule struct {
	Chain       string `json:"chain"`
	Destination string `json:"destination"`
	Prot        string `json:"prot"`
	Source      string `json:"source"`
	Target      string `json:"target"`
}

// FirewallRulesResponse represents firewall rules from HAL
// HAL returns: {"filter": [{rule}, {rule}], "nat": [{rule}, {rule}]}
type FirewallRulesResponse struct {
	Filter []FirewallRule `json:"filter,omitempty"`
	NAT    []FirewallRule `json:"nat,omitempty"`
	Mangle []FirewallRule `json:"mangle,omitempty"`
	Raw    []FirewallRule `json:"raw,omitempty"`
}

// GetFirewallRulesDetailed returns current iptables rules from HAL
func (c *Client) GetFirewallRulesDetailed(ctx context.Context) (*FirewallRulesResponse, error) {
	body, err := c.doRequest(ctx, http.MethodGet, "/firewall/rules", nil)
	if err != nil {
		return nil, err
	}

	var resp FirewallRulesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// =============================================================================
// WiFi Saved Networks (HAL proxy methods)
// =============================================================================

// SavedWiFiNetwork represents a saved WiFi network from HAL
type SavedWiFiNetwork struct {
	SSID     string `json:"ssid"`
	Security string `json:"security,omitempty"`
	AutoJoin bool   `json:"auto_join"`
}

// SavedWiFiNetworksResponse is the HAL response for saved networks
type SavedWiFiNetworksResponse struct {
	Networks []SavedWiFiNetwork `json:"networks"`
	Count    int                `json:"count"`
}

// GetSavedWiFiNetworks returns saved WiFi networks via HAL
func (c *Client) GetSavedWiFiNetworks(ctx context.Context, iface string) (*SavedWiFiNetworksResponse, error) {
	path := "/network/wifi/saved"
	if iface != "" {
		path += "?interface=" + url.QueryEscape(iface)
	}

	body, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp SavedWiFiNetworksResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// ForgetWiFiNetwork removes a saved WiFi network via HAL
func (c *Client) ForgetWiFiNetwork(ctx context.Context, ssid, iface string) error {
	path := "/network/wifi/saved/" + url.PathEscape(ssid)
	if iface != "" {
		path += "?interface=" + url.QueryEscape(iface)
	}

	return c.doDelete(ctx, path, nil)
}

// =============================================================================
// Storage SMART via HAL
// =============================================================================

// GetStorageDeviceSMART returns SMART data for a device via HAL endpoint
func (c *Client) GetStorageDeviceSMART(ctx context.Context, device string) (*SMARTInfo, error) {
	// Remove /dev/ prefix if present for the URL
	device = strings.TrimPrefix(device, "/dev/")

	var result SMARTInfo
	if err := c.doGet(ctx, "/storage/devices/"+url.PathEscape(device)+"/smart", &result); err != nil {
		return nil, err
	}
	return &result, nil
}
