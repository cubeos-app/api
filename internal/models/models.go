package models

import (
	"encoding/json"
	"time"
)

// =============================================================================
// Authentication
// =============================================================================

type User struct {
	ID           int64      `db:"id" json:"id"`
	Username     string     `db:"username" json:"username"`
	PasswordHash string     `db:"password_hash" json:"-"`
	Email        string     `db:"email" json:"email,omitempty"`
	Role         string     `db:"role" json:"role"`
	LastLogin    *time.Time `db:"last_login" json:"last_login,omitempty"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	User         struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// =============================================================================
// System
// =============================================================================

type SystemInfo struct {
	CubeOSVersion      string            `json:"cubeos_version"`
	Hostname           string            `json:"hostname"`
	OSName             string            `json:"os_name"`
	OSVersion          string            `json:"os_version"`
	Kernel             string            `json:"kernel"`
	Architecture       string            `json:"architecture"`
	PiModel            string            `json:"pi_model,omitempty"`
	PiSerial           string            `json:"pi_serial,omitempty"`
	PiRevision         string            `json:"pi_revision,omitempty"`
	CPUModel           string            `json:"cpu_model,omitempty"`
	CPUCores           int               `json:"cpu_cores"`
	UptimeSeconds      int64             `json:"uptime_seconds"`
	UptimeHuman        string            `json:"uptime_human"`
	BootTime           time.Time         `json:"boot_time"`
	MACAddresses       map[string]string `json:"mac_addresses"`
	IPAddresses        map[string]string `json:"ip_addresses"`
	DefaultCredentials bool              `json:"default_credentials"`
}

type SystemStats struct {
	CPUPercent      float64   `json:"cpu_percent"`
	MemoryPercent   float64   `json:"memory_percent"`
	MemoryTotal     uint64    `json:"memory_total"`
	MemoryUsed      uint64    `json:"memory_used"`
	MemoryAvailable uint64    `json:"memory_available"`
	SwapTotal       uint64    `json:"swap_total"`
	SwapUsed        uint64    `json:"swap_used"`
	SwapPercent     float64   `json:"swap_percent"`
	DiskPercent     float64   `json:"disk_percent"`
	DiskTotal       uint64    `json:"disk_total"`
	DiskUsed        uint64    `json:"disk_used"`
	DiskFree        uint64    `json:"disk_free"`
	TemperatureCPU  float64   `json:"temperature_cpu"`
	Timestamp       time.Time `json:"timestamp"`
}

type Temperature struct {
	CPUTempC        float64 `json:"cpu_temp_c"`
	Temperature     float64 `json:"temperature"` // Alias for cpu_temp_c for API compatibility
	GPUTempC        float64 `json:"gpu_temp_c,omitempty"`
	Throttled       bool    `json:"throttled"`
	ThrottleFlags   string  `json:"throttle_flags"`
	SoftTempLimit   bool    `json:"soft_temp_limit"`
	UnderVoltage    bool    `json:"under_voltage"`
	FrequencyCapped bool    `json:"frequency_capped"`
	Status          string  `json:"status"` // normal, warm, hot, throttled
}

type PowerAction struct {
	Status        string     `json:"status"` // initiated, scheduled, cancelled, error
	Action        string     `json:"action"` // reboot, shutdown
	ScheduledTime *time.Time `json:"scheduled_time,omitempty"`
	Message       string     `json:"message"`
}

type ServiceStatus struct {
	Service  string `json:"service"`
	Active   bool   `json:"active"`
	State    string `json:"state"`
	SubState string `json:"sub_state"`
	PID      *int   `json:"pid,omitempty"`
}

// =============================================================================
// Battery/UPS (Geekworm X1202 support)
// =============================================================================

type BatteryStatus struct {
	Available     bool      `json:"available"`
	Voltage       float64   `json:"voltage,omitempty"`
	Percent       float64   `json:"percent,omitempty"`
	Charging      bool      `json:"charging,omitempty"`
	OnBattery     bool      `json:"on_battery,omitempty"`     // True when running on battery
	PowerGood     bool      `json:"power_good,omitempty"`     // True when AC present
	CellCount     int       `json:"cell_count,omitempty"`     // Number of cells (4 for X1202)
	EstimatedMins int       `json:"estimated_mins,omitempty"` // Estimated runtime
	TimeRemaining string    `json:"time_remaining,omitempty"`
	Status        string    `json:"status,omitempty"` // charging, discharging, full, critical, low
	LastUpdated   time.Time `json:"last_updated,omitempty"`
	Message       string    `json:"message,omitempty"`
}

// =============================================================================
// Network
// =============================================================================

type NetworkInterface struct {
	Name          string   `json:"name"`
	MACAddress    string   `json:"mac_address,omitempty"`
	IPv4Addresses []string `json:"ipv4_addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
	IsUp          bool     `json:"is_up"`
	IsLoopback    bool     `json:"is_loopback"`
	IsWireless    bool     `json:"is_wireless"`
	SpeedMbps     *int     `json:"speed_mbps,omitempty"`
	MTU           int      `json:"mtu"`
	RxBytes       uint64   `json:"rx_bytes"`
	TxBytes       uint64   `json:"tx_bytes"`
	RxPackets     uint64   `json:"rx_packets"`
	TxPackets     uint64   `json:"tx_packets"`
	RxErrors      uint64   `json:"rx_errors"`
	TxErrors      uint64   `json:"tx_errors"`
}

type WiFiAPStatus struct {
	Enabled          bool   `json:"enabled"`
	SSID             string `json:"ssid"`
	Password         string `json:"password,omitempty"`
	Channel          int    `json:"channel"`
	Frequency        string `json:"frequency"` // 2.4GHz, 5GHz
	Hidden           bool   `json:"hidden"`
	Interface        string `json:"interface"`
	ClientsConnected int    `json:"clients_connected"`
	Status           string `json:"status"` // up, down
}

type WiFiAPConfig struct {
	SSID        string `json:"ssid"`
	Password    string `json:"password,omitempty"`
	Channel     int    `json:"channel"`
	Hidden      bool   `json:"hidden"`
	HWMode      string `json:"hw_mode"`
	CountryCode string `json:"country_code"`
}

type WiFiClient struct {
	MACAddress           string     `json:"mac_address"`
	IPAddress            string     `json:"ip_address,omitempty"`
	Hostname             string     `json:"hostname,omitempty"`
	SignalDBM            *int       `json:"signal_dbm,omitempty"`
	SignalPercent        *int       `json:"signal_percent,omitempty"`
	RxBytes              uint64     `json:"rx_bytes"`
	TxBytes              uint64     `json:"tx_bytes"`
	ConnectedTimeSeconds *int       `json:"connected_time_seconds,omitempty"`
	ConnectedSince       *time.Time `json:"connected_since,omitempty"`
	InactiveMs           *int       `json:"inactive_ms,omitempty"`
}

type WiFiClientsResponse struct {
	TotalCount int          `json:"total_count"`
	Clients    []WiFiClient `json:"clients"`
	Timestamp  time.Time    `json:"timestamp"`
}

type DHCPLease struct {
	MACAddress  string     `json:"mac_address"`
	IPAddress   string     `json:"ip_address"`
	Hostname    string     `json:"hostname,omitempty"`
	LeaseExpiry *time.Time `json:"lease_expiry,omitempty"`
}

type InternetStatus struct {
	Connected  bool    `json:"connected"`
	Target     string  `json:"target,omitempty"`
	TargetName string  `json:"target_name,omitempty"`
	RTTMs      float64 `json:"rtt_ms,omitempty"`
}

type WiFiQRCode struct {
	WiFiString string `json:"wifi_string"`
	SSID       string `json:"ssid"`
	Encryption string `json:"encryption"`
}

// =============================================================================
// Storage
// =============================================================================

type DiskInfo struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	FSType      string  `json:"fstype"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	PercentUsed float64 `json:"percent_used"`
	TotalHuman  string  `json:"total_human"`
	UsedHuman   string  `json:"used_human"`
	FreeHuman   string  `json:"free_human"`
}

type DockerDiskUsage struct {
	ImagesSize     uint64 `json:"images_size"`
	ContainersSize uint64 `json:"containers_size"`
	VolumesSize    uint64 `json:"volumes_size"`
	BuildCacheSize uint64 `json:"build_cache_size"`
	TotalSize      uint64 `json:"total_size"`
	TotalHuman     string `json:"total_human"`
}

type StorageOverview struct {
	Disks         []DiskInfo       `json:"disks"`
	Docker        *DockerDiskUsage `json:"docker,omitempty"`
	TotalCapacity uint64           `json:"total_capacity"`
	TotalUsed     uint64           `json:"total_used"`
	TotalFree     uint64           `json:"total_free"`
}

// =============================================================================
// Docker Services
// =============================================================================

type ContainerInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Image       string            `json:"image"`
	State       string            `json:"state"`  // running, exited, paused, etc
	Status      string            `json:"status"` // human readable status
	Health      string            `json:"health"` // healthy, unhealthy, starting, none
	IsCore      bool              `json:"is_core"`
	Category    string            `json:"category,omitempty"`
	Ports       []PortBinding     `json:"ports,omitempty"`
	Created     time.Time         `json:"created"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type PortBinding struct {
	PrivatePort int    `json:"private_port"`
	PublicPort  int    `json:"public_port,omitempty"`
	Type        string `json:"type"` // tcp, udp
	IP          string `json:"ip,omitempty"`
}

type ServicesResponse struct {
	Services []ContainerInfo `json:"services"`
	Total    int             `json:"total"`
	Running  int             `json:"running"`
}

type ServiceAction struct {
	Success    bool   `json:"success"`
	Service    string `json:"service"`
	Action     string `json:"action"` // start, stop, restart, enable, disable
	Status     string `json:"status"`
	Message    string `json:"message"`
	RAMFreedMB int    `json:"ram_freed_mb,omitempty"`
}

type ContainerStats struct {
	MemoryMB      float64 `json:"memory_mb"`
	MemoryLimitMB float64 `json:"memory_limit_mb"`
	CPUPercent    float64 `json:"cpu_percent"`
}

// =============================================================================
// Generic
// =============================================================================

type ErrorResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
	Code   int    `json:"code,omitempty"`
}

type SuccessResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type HealthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Uptime    float64   `json:"uptime_seconds"`
}

// =============================================================================
// Extended System Stats (for managers)
// =============================================================================

type ExtendedStats struct {
	CPUPercent     float64 `json:"cpu_percent"`
	CPUCores       int     `json:"cpu_cores"`
	MemoryPercent  float64 `json:"memory_percent"`
	MemoryTotal    uint64  `json:"memory_total"`
	MemoryUsed     uint64  `json:"memory_used"`
	DiskPercent    float64 `json:"disk_percent"`
	DiskTotal      uint64  `json:"disk_total"`
	DiskUsed       uint64  `json:"disk_used"`
	TemperatureCPU float64 `json:"temperature_cpu"`
	Throttled      bool    `json:"throttled"`
	UnderVoltage   bool    `json:"under_voltage"`
}

// =============================================================================
// Logs
// =============================================================================

type LogEntry struct {
	Timestamp *time.Time `json:"timestamp,omitempty"`
	Unit      string     `json:"unit,omitempty"`
	Priority  string     `json:"priority"`
	Message   string     `json:"message"`
	PID       *int       `json:"pid,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
}

type LogsResponse struct {
	Entries []LogEntry `json:"entries"`
	Count   int        `json:"count"`
}

type LogUnitsResponse struct {
	Units []string `json:"units"`
	Count int      `json:"count"`
}

type ContainerLogsResponse struct {
	Container string   `json:"container"`
	Entries   []string `json:"entries"`
	Count     int      `json:"count"`
}

// =============================================================================
// Firewall
// =============================================================================

type FirewallRule struct {
	Chain        string `json:"chain"`
	Target       string `json:"target,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Source       string `json:"source,omitempty"`
	Destination  string `json:"destination,omitempty"`
	Port         int    `json:"port,omitempty"`
	InterfaceIn  string `json:"interface_in,omitempty"`
	InterfaceOut string `json:"interface_out,omitempty"`
}

type FirewallStatus struct {
	FilterRules []FirewallRule `json:"filter_rules"`
	NATRules    []FirewallRule `json:"nat_rules"`
	NATEnabled  bool           `json:"nat_enabled"`
	IPForward   bool           `json:"ip_forward"`
}

type PortRequest struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Comment  string `json:"comment,omitempty"`
}

// =============================================================================
// Backup
// =============================================================================

type BackupInfo struct {
	ID          string   `json:"id"`
	Filename    string   `json:"filename"`
	Type        string   `json:"type"`
	SizeBytes   int64    `json:"size_bytes"`
	SizeHuman   string   `json:"size_human"`
	CreatedAt   string   `json:"created_at"`
	Description string   `json:"description,omitempty"`
	Includes    []string `json:"includes,omitempty"`
	Compressed  bool     `json:"compressed"`
}

type BackupListResponse struct {
	Backups        []BackupInfo `json:"backups"`
	TotalCount     int          `json:"total_count"`
	TotalSizeBytes int64        `json:"total_size_bytes"`
}

type BackupCreateRequest struct {
	Type                 string `json:"type"`
	Description          string `json:"description,omitempty"`
	IncludeDockerVolumes bool   `json:"include_docker_volumes"`
	Compress             bool   `json:"compress"`
}

// =============================================================================
// Processes
// =============================================================================

type ProcessInfo struct {
	PID           int     `json:"pid"`
	Name          string  `json:"name"`
	Username      string  `json:"username"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryRSS     int64   `json:"memory_rss"`
	Status        string  `json:"status"`
	Cmdline       string  `json:"cmdline,omitempty"`
	NumThreads    int     `json:"num_threads"`
}

type ProcessListResponse struct {
	Processes  []ProcessInfo `json:"processes"`
	TotalCount int           `json:"total_count"`
	SortBy     string        `json:"sort_by"`
}

type ProcessStatsResponse struct {
	TotalProcesses int            `json:"total_processes"`
	ByStatus       map[string]int `json:"by_status"`
}

// =============================================================================
// Wizard
// =============================================================================

type WizardProfile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Services    []string `json:"services"`
	RAMEstimate int      `json:"ram_estimate_mb"`
	Categories  []string `json:"categories,omitempty"`
}

type WizardService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	RAMEstimate int    `json:"ram_estimate_mb"`
	Icon        string `json:"icon"`
	Enabled     bool   `json:"enabled"`
}

type WizardCategory struct {
	ID          string          `json:"category_id"`
	Name        string          `json:"category_name"`
	Description string          `json:"description"`
	Icon        string          `json:"icon"`
	Services    []WizardService `json:"services"`
}

type WizardServicesResponse struct {
	Categories    []WizardCategory `json:"categories"`
	TotalServices int              `json:"total_services"`
}

// =============================================================================
// Monitoring
// =============================================================================

type StatsSnapshot struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	Temperature   float64   `json:"temperature"`
}

type Alert struct {
	Type     string  `json:"type"`
	Message  string  `json:"message"`
	Severity string  `json:"severity"`
	Value    float64 `json:"value,omitempty"`
}

type AlertsResponse struct {
	Alerts     []Alert `json:"alerts"`
	AlertCount int     `json:"alert_count"`
	Timestamp  string  `json:"timestamp"`
}

type StatsHistoryResponse struct {
	History []StatsSnapshot `json:"history"`
	Count   int             `json:"count"`
}

// =============================================================================
// Preferences
// =============================================================================

// DashboardLayoutConfig holds all settings for a single UI mode (Standard or Advanced).
// Every field uses a pointer or omitempty so partial updates don't wipe sibling fields.
type DashboardLayoutConfig struct {
	// Widget visibility
	ShowClock        *bool `json:"show_clock,omitempty"`
	ShowSearch       *bool `json:"show_search,omitempty"`
	ShowStatusPill   *bool `json:"show_status_pill,omitempty"`
	ShowSystemVitals *bool `json:"show_system_vitals,omitempty"`
	ShowNetwork      *bool `json:"show_network_widget,omitempty"`
	ShowDisk         *bool `json:"show_disk_widget,omitempty"`
	ShowSignals      *bool `json:"show_signals_widget,omitempty"`
	ShowQuickActions *bool `json:"show_quick_actions,omitempty"`
	ShowFavorites    *bool `json:"show_favorites,omitempty"`
	ShowRecent       *bool `json:"show_recent,omitempty"`
	ShowMyApps       *bool `json:"show_my_apps,omitempty"`
	ShowAlerts       *bool `json:"show_alerts,omitempty"`

	// Extended visibility (Sessions 7-9: decomposed widgets + cross-mode)
	ShowUptimeLoad        *bool `json:"show_uptime_load,omitempty"`
	ShowNetworkThroughput *bool `json:"show_network_throughput,omitempty"`
	ShowRecentLogs        *bool `json:"show_recent_logs,omitempty"`
	ShowBattery           *bool `json:"show_battery,omitempty"`
	ShowCpuGauge          *bool `json:"show_cpu_gauge,omitempty"`
	ShowMemoryGauge       *bool `json:"show_memory_gauge,omitempty"`
	ShowDiskGauge         *bool `json:"show_disk_gauge,omitempty"`
	ShowTempGauge         *bool `json:"show_temp_gauge,omitempty"`

	// Clock settings
	ClockFormat  string `json:"clock_format,omitempty"` // "12h" | "24h"
	DateFormat   string `json:"date_format,omitempty"`  // "long" | "medium" | "short" | "iso" | "us" | "eu"
	ShowSeconds  *bool  `json:"show_seconds,omitempty"`
	ShowGreeting *bool  `json:"show_greeting,omitempty"`

	// Layout settings
	MyAppsRows   int      `json:"my_apps_rows,omitempty"`  // 1-5, 0 = show all
	FavoriteCols int      `json:"favorite_cols,omitempty"` // 2-6
	QuickActions []string `json:"quick_actions,omitempty"` // ordered list of action IDs

	// Widget order (legacy flat list, replaced by grid_layout)
	WidgetOrder []string `json:"widget_order,omitempty"` // e.g. ["clock","search","status","vitals","network","actions","launcher"]

	// Grid layout — row-based layout, each row holds 1-2 widget IDs.
	// Uses json.RawMessage to pass through arbitrary JSON structures from the frontend.
	GridLayout json.RawMessage `json:"grid_layout,omitempty"` // e.g. [{"row":["clock"]},{"row":["vitals","network"]}]

	// Per-widget opacity map (0=transparent, 100=opaque)
	WidgetOpacity json.RawMessage `json:"widget_opacity,omitempty"` // e.g. {"clock":0,"vitals":100}

	// Per-widget dimensions (width: 'half'|'full', height: 'auto'|'collapsed'|number)
	WidgetDimensions json.RawMessage `json:"widget_dimensions,omitempty"` // e.g. {"vitals":{"width":"full","height":"auto"}}

	// Per-widget refresh intervals in seconds (Session 5)
	WidgetRefreshIntervals json.RawMessage `json:"widget_refresh_intervals,omitempty"` // e.g. {"vitals":2,"disk":10}

	// Advanced mode section ordering (deprecated — Session 8 migrates to grid_layout)
	AdvancedSectionOrder json.RawMessage `json:"advanced_section_order,omitempty"` // e.g. ["gauges","infobar","disk-signals",...]

	// Advanced-specific section visibility
	ShowInfoBar      *bool `json:"show_info_bar,omitempty"`
	ShowSwarm        *bool `json:"show_swarm,omitempty"`
	ShowCoreServices *bool `json:"show_core_services,omitempty"`

	// Layout lock (Session 6) — prevents entering edit mode
	LayoutLocked *bool `json:"layout_locked,omitempty"`
}

// DashboardConfig holds per-mode dashboard customization.
// Each UI mode (Standard, Advanced) has its own independent layout config.
// UserPresets stores user-created layout presets as a JSON array.
type DashboardConfig struct {
	Standard    *DashboardLayoutConfig `json:"standard,omitempty"`
	Advanced    *DashboardLayoutConfig `json:"advanced,omitempty"`
	UserPresets json.RawMessage        `json:"user_presets,omitempty"` // Session 10: user-created presets
}

type Preferences struct {
	SetupComplete       bool             `json:"setupComplete"`
	TourComplete        bool             `json:"tourComplete"`
	Favorites           []string         `json:"favorites"`
	RecentServices      []string         `json:"recentServices"`
	Theme               string           `json:"theme"`
	CollapsedCategories []string         `json:"collapsedCategories"`
	AdminExpanded       bool             `json:"adminExpanded"`
	UIMode              string           `json:"ui_mode"`
	Wallpaper           *WallpaperPref   `json:"wallpaper,omitempty"`
	Dashboard           *DashboardConfig `json:"dashboard,omitempty"`
}

// WallpaperPref stores wallpaper configuration for Standard mode.
// Type is one of: "preset", "custom", "none".
// Value holds the preset ID (e.g. "topo-dark") or the serve URL for custom.
type WallpaperPref struct {
	Type  string `json:"type"`            // "preset" | "custom" | "none"
	Value string `json:"value,omitempty"` // preset ID or URL, empty for "none"
}

type PreferencesUpdate struct {
	SetupComplete       *bool            `json:"setupComplete,omitempty"`
	TourComplete        *bool            `json:"tourComplete,omitempty"`
	Favorites           []string         `json:"favorites,omitempty"`
	RecentServices      []string         `json:"recentServices,omitempty"`
	Theme               *string          `json:"theme,omitempty"`
	CollapsedCategories []string         `json:"collapsedCategories,omitempty"`
	AdminExpanded       *bool            `json:"adminExpanded,omitempty"`
	UIMode              *string          `json:"ui_mode,omitempty"`
	Wallpaper           *WallpaperPref   `json:"wallpaper,omitempty"`
	Dashboard           *DashboardConfig `json:"dashboard,omitempty"`
}

// =============================================================================
// Services (Extended)
// =============================================================================

type ServiceInfo struct {
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name"`
	Description   string   `json:"description"`
	Category      string   `json:"category"`
	IsCore        bool     `json:"is_core"`
	Enabled       bool     `json:"enabled"`
	Running       bool     `json:"running"`
	Status        string   `json:"status"`
	Health        string   `json:"health"`
	RAMEstimateMB int      `json:"ram_estimate_mb"`
	Icon          string   `json:"icon"`
	URL           string   `json:"url,omitempty"`
	Ports         []int    `json:"ports,omitempty"`
	Dependencies  []string `json:"dependencies,omitempty"`
}

// =============================================================================
// WebSocket Messages
// =============================================================================

type WSMessage struct {
	Type      string      `json:"type"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data"`
}

type WSStatsMessage struct {
	Type      string                 `json:"type"`
	Timestamp string                 `json:"timestamp"`
	System    map[string]interface{} `json:"system"`
	Network   map[string]interface{} `json:"network"`
}
