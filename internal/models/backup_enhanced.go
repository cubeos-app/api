package models

import "encoding/json"

// BackupScope defines what's included in a backup.
// @Description Backup scope tier determining included content.
type BackupScope string

const (
	BackupScopeTier1 BackupScope = "tier1" // DB + config files
	BackupScopeTier2 BackupScope = "tier2" // + network config + app configs
	BackupScopeTier3 BackupScope = "tier3" // + Docker volumes
)

// BackupDestination defines where backups are stored.
// @Description Backup storage destination type.
type BackupDestination string

const (
	BackupDestLocal BackupDestination = "local"
	BackupDestUSB   BackupDestination = "usb"
	BackupDestNFS   BackupDestination = "nfs"
	BackupDestSMB   BackupDestination = "smb"
)

// BackupCreateEnhancedRequest extends the existing backup creation.
// @Description Enhanced backup creation request with scope and destination.
type BackupCreateEnhancedRequest struct {
	Scope       BackupScope       `json:"scope"`
	Destination BackupDestination `json:"destination"`
	DestConfig  json.RawMessage   `json:"dest_config,omitempty"` // destination-specific config
	Encrypt     bool              `json:"encrypt,omitempty"`
	Passphrase  string            `json:"passphrase,omitempty"` // P0-aligned: portable encryption passphrase
	Description string            `json:"description,omitempty"`
}

// BackupManifest describes backup contents for verification.
// @Description Manifest of backup contents used for integrity verification.
type BackupManifest struct {
	Version       string            `json:"version"` // CubeOS version at backup time
	Scope         BackupScope       `json:"scope"`
	CreatedAt     string            `json:"created_at"`
	SchemaVer     int               `json:"schema_version"`
	Files         []BackupFileEntry `json:"files"`
	Checksum      string            `json:"checksum"` // SHA256 of the archive
	Encrypted     bool              `json:"encrypted"`
	Apps          []string          `json:"apps"` // installed app names
	NetworkMode   string            `json:"network_mode"`
	EncryptMode   string            `json:"encrypt_mode"`        // "device" or "portable" (P0-aligned)
	HasConfigSnap bool              `json:"has_config_snapshot"` // true if config snapshot embedded
}

// BackupFileEntry describes one file in the backup.
// @Description Single file entry within a backup manifest.
type BackupFileEntry struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Checksum string `json:"checksum"` // SHA256
	Category string `json:"category"` // "config", "database", "app_data", "coreapp_data", "registry" (P3-aligned)
}

// BackupSchedule defines a backup schedule.
// @Description Scheduled backup configuration with cron expression and retention.
type BackupSchedule struct {
	ID             int               `json:"id"`
	Name           string            `json:"name"`
	Enabled        bool              `json:"enabled"`
	CronExpr       string            `json:"cron_expr"`
	Scope          BackupScope       `json:"scope"`
	Destination    BackupDestination `json:"destination"`
	DestConfig     json.RawMessage   `json:"dest_config,omitempty"`
	Encryption     bool              `json:"encryption"`
	RetentionCount int               `json:"retention_count"`
	LastRunAt      string            `json:"last_run_at,omitempty"`
	LastStatus     string            `json:"last_status,omitempty"`
	NextRunAt      string            `json:"next_run_at,omitempty"`
}

// BackupDestinationInfo describes an available backup destination.
// @Description Information about an available backup destination.
type BackupDestinationInfo struct {
	Type        string            `json:"type"`             // "local", "usb", "nfs", "smb"
	Name        string            `json:"name"`             // human-readable name
	Description string            `json:"description"`      // description of the destination
	Available   bool              `json:"available"`        // whether the destination is currently usable
	Config      map[string]string `json:"config,omitempty"` // pre-populated config for USB devices
}

// BackupDestinationsResponse is the response for listing backup destinations.
// @Description List of available backup destinations.
type BackupDestinationsResponse struct {
	Destinations []BackupDestinationInfo `json:"destinations"`
}

// BackupDestinationTestRequest is the request to test a backup destination.
// @Description Request to test connectivity and write access to a backup destination.
type BackupDestinationTestRequest struct {
	Destination string          `json:"destination"` // "local", "usb", "nfs", "smb"
	Config      json.RawMessage `json:"config"`      // destination-specific configuration
}

// BackupDestinationTestResponse is the response from testing a backup destination.
// @Description Result of testing a backup destination.
type BackupDestinationTestResponse struct {
	Destination    string `json:"destination"`
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	AvailableSpace int64  `json:"available_space,omitempty"` // bytes, -1 or 0 if unknown
}
