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
	Description string            `json:"description,omitempty"`
}

// BackupManifest describes backup contents for verification.
// @Description Manifest of backup contents used for integrity verification.
type BackupManifest struct {
	Version     string            `json:"version"` // CubeOS version at backup time
	Scope       BackupScope       `json:"scope"`
	CreatedAt   string            `json:"created_at"`
	SchemaVer   int               `json:"schema_version"`
	Files       []BackupFileEntry `json:"files"`
	Checksum    string            `json:"checksum"` // SHA256 of the archive
	Encrypted   bool              `json:"encrypted"`
	Apps        []string          `json:"apps"` // installed app names
	NetworkMode string            `json:"network_mode"`
}

// BackupFileEntry describes one file in the backup.
// @Description Single file entry within a backup manifest.
type BackupFileEntry struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Checksum string `json:"checksum"` // SHA256
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
