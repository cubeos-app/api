package models

// ConfigSnapshot is the P0-seed format for Cisco-style config export.
// Phase 4 writes a simplified version into every backup. Phase 6 extends
// this to the full Config Export/Import system.
//
// Design constraint: this format MUST be forward-compatible. Phase 6 adds
// fields; Phase 4 backups with fewer fields must still be importable.
type ConfigSnapshot struct {
	ConfigVersion int               `json:"cubeos_config_version"` // Always 1
	Metadata      ConfigMetadata    `json:"metadata"`
	System        ConfigSystem      `json:"system"`
	Network       ConfigNetwork     `json:"network"`
	Users         []ConfigUser      `json:"users"`
	Apps          []ConfigApp       `json:"apps"`
	Profiles      []ConfigProfile   `json:"profiles"`
	Preferences   map[string]string `json:"preferences"`
	VPNConfigs    []ConfigVPN       `json:"vpn_configs,omitempty"`
	Mounts        []ConfigMount     `json:"mounts,omitempty"`
}

// ConfigMetadata holds export context for a config snapshot.
type ConfigMetadata struct {
	ExportedAt     string `json:"exported_at"`
	CubeOSVersion  string `json:"cubeos_version"`
	SchemaVersion  int    `json:"schema_version"`
	SourceDevice   string `json:"source_device,omitempty"`
	SourceHardware string `json:"source_hardware,omitempty"`
	Description    string `json:"description,omitempty"`
}

// ConfigSystem holds system-level settings.
type ConfigSystem struct {
	Timezone    string `json:"timezone"`
	Domain      string `json:"domain"`
	GatewayIP   string `json:"gateway_ip"`
	Subnet      string `json:"subnet"`
	CountryCode string `json:"country_code"`
	Hostname    string `json:"hostname,omitempty"`
}

// ConfigNetwork holds network mode and AP settings.
type ConfigNetwork struct {
	Mode        string `json:"mode"`
	WiFiAPSSID  string `json:"wifi_ap_ssid,omitempty"`
	WiFiAPPass  string `json:"wifi_ap_password,omitempty"`
	WiFiChannel int    `json:"wifi_channel,omitempty"`
}

// ConfigUser holds a user account entry.
type ConfigUser struct {
	Username     string `json:"username"`
	Role         string `json:"role"`
	PasswordHash string `json:"password_hash"`
}

// ConfigApp holds an installed app entry.
type ConfigApp struct {
	Name        string `json:"name"`
	Source      string `json:"source"`
	StoreID     string `json:"store_id,omitempty"`
	Port        int    `json:"port"`
	FQDN        string `json:"fqdn"`
	Enabled     bool   `json:"enabled"`
	MemoryLimit string `json:"memory_limit,omitempty"`
}

// ConfigProfile holds a service profile entry.
type ConfigProfile struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	IsActive    bool     `json:"is_active"`
	Apps        []string `json:"apps"`
}

// ConfigVPN holds a VPN configuration entry.
type ConfigVPN struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	AutoConnect bool   `json:"auto_connect"`
}

// ConfigMount holds a mount configuration entry.
type ConfigMount struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	RemotePath string `json:"remote_path"`
	AutoMount  bool   `json:"auto_mount"`
}

// ConfigSnapshotRecord represents a stored config snapshot (DB row).
type ConfigSnapshotRecord struct {
	ID            int    `json:"id"`
	Trigger       string `json:"trigger"`
	Description   string `json:"description"`
	CubeOSVersion string `json:"cubeos_version"`
	SchemaVersion int    `json:"schema_version"`
	CreatedAt     string `json:"created_at"`
}
