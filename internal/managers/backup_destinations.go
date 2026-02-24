package managers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"cubeos-api/internal/hal"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// BackupDestinationAdapter abstracts backup storage targets.
// Each adapter knows how to write/read/list/delete backup files at its destination.
type BackupDestinationAdapter interface {
	// Type returns the destination type identifier.
	Type() models.BackupDestination

	// Validate checks if the destination is accessible and writable.
	Validate(ctx context.Context, config json.RawMessage) error

	// AvailableSpace returns bytes available at the destination (-1 if unknown).
	AvailableSpace(ctx context.Context, config json.RawMessage) (int64, error)

	// Write copies a local file to the destination. Returns the remote path.
	Write(ctx context.Context, config json.RawMessage, localPath, filename string) (string, error)

	// Read copies a file from the destination to a local path.
	Read(ctx context.Context, config json.RawMessage, filename, localPath string) error

	// List returns backup files at the destination.
	List(ctx context.Context, config json.RawMessage) ([]string, error)

	// Delete removes a backup file from the destination.
	Delete(ctx context.Context, config json.RawMessage, filename string) error
}

// BackupDestinationRegistry maps destination types to adapters.
type BackupDestinationRegistry struct {
	adapters map[models.BackupDestination]BackupDestinationAdapter
}

// NewBackupDestinationRegistry creates a registry with all available adapters.
func NewBackupDestinationRegistry(halClient *hal.Client) *BackupDestinationRegistry {
	return &BackupDestinationRegistry{
		adapters: map[models.BackupDestination]BackupDestinationAdapter{
			models.BackupDestLocal: &LocalAdapter{},
			models.BackupDestUSB:   &USBAdapter{halClient: halClient},
			models.BackupDestNFS:   &NFSAdapter{halClient: halClient},
			models.BackupDestSMB:   &SMBAdapter{halClient: halClient},
		},
	}
}

// Get returns the adapter for the given destination type.
func (r *BackupDestinationRegistry) Get(dest models.BackupDestination) (BackupDestinationAdapter, error) {
	adapter, ok := r.adapters[dest]
	if !ok {
		return nil, fmt.Errorf("unsupported backup destination: %s", dest)
	}
	return adapter, nil
}

// AvailableTypes returns all registered destination types.
func (r *BackupDestinationRegistry) AvailableTypes() []models.BackupDestination {
	types := make([]models.BackupDestination, 0, len(r.adapters))
	for t := range r.adapters {
		types = append(types, t)
	}
	return types
}

// =============================================================================
// LocalAdapter — stores backups in /cubeos/data/backups/ (default behavior)
// =============================================================================

// LocalAdapter stores backups on the local filesystem.
type LocalAdapter struct{}

// localConfig is the configuration for LocalAdapter.
type localConfig struct {
	Path string `json:"path"`
}

func (a *LocalAdapter) parseConfig(config json.RawMessage) localConfig {
	var cfg localConfig
	if len(config) > 0 {
		json.Unmarshal(config, &cfg)
	}
	if cfg.Path == "" {
		cfg.Path = "/cubeos/data/backups"
	}
	return cfg
}

// Type returns the destination type.
func (a *LocalAdapter) Type() models.BackupDestination {
	return models.BackupDestLocal
}

// Validate checks if the local path is writable.
func (a *LocalAdapter) Validate(ctx context.Context, config json.RawMessage) error {
	cfg := a.parseConfig(config)
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return fmt.Errorf("local destination not writable: %w", err)
	}
	return nil
}

// AvailableSpace returns free bytes at the local path.
func (a *LocalAdapter) AvailableSpace(ctx context.Context, config json.RawMessage) (int64, error) {
	cfg := a.parseConfig(config)
	var stat syscall.Statfs_t
	checkPath := cfg.Path
	if _, err := os.Stat(checkPath); os.IsNotExist(err) {
		checkPath = filepath.Dir(checkPath)
	}
	if err := syscall.Statfs(checkPath, &stat); err != nil {
		return -1, fmt.Errorf("statfs failed: %w", err)
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

// Write copies a local file to the local backup directory.
func (a *LocalAdapter) Write(ctx context.Context, config json.RawMessage, localPath, filename string) (string, error) {
	cfg := a.parseConfig(config)
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	destPath := filepath.Join(cfg.Path, filename)

	// Try rename first (same filesystem)
	if err := os.Rename(localPath, destPath); err != nil {
		// Cross-filesystem: copy + remove
		if err := copyFileLocal(localPath, destPath); err != nil {
			return "", fmt.Errorf("failed to copy backup: %w", err)
		}
		os.Remove(localPath)
	}

	return destPath, nil
}

// Read copies a backup from local storage to a target path.
func (a *LocalAdapter) Read(ctx context.Context, config json.RawMessage, filename, localPath string) error {
	cfg := a.parseConfig(config)
	srcPath := filepath.Join(cfg.Path, filename)
	return copyFileLocal(srcPath, localPath)
}

// List returns backup files at the local destination.
func (a *LocalAdapter) List(ctx context.Context, config json.RawMessage) ([]string, error) {
	cfg := a.parseConfig(config)
	entries, err := os.ReadDir(cfg.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tar.gz") {
			files = append(files, e.Name())
		}
	}
	return files, nil
}

// Delete removes a backup from local storage.
func (a *LocalAdapter) Delete(ctx context.Context, config json.RawMessage, filename string) error {
	cfg := a.parseConfig(config)
	target := filepath.Join(cfg.Path, filename)
	// Prevent path traversal
	if filepath.Dir(target) != cfg.Path {
		return fmt.Errorf("invalid filename")
	}
	return os.Remove(target)
}

// =============================================================================
// USBAdapter — stores backups on USB drives via HAL mount operations
// =============================================================================

// USBAdapter stores backups on a USB drive, using HAL for mount operations.
type USBAdapter struct {
	halClient *hal.Client
}

// usbConfig is the configuration for USBAdapter.
type usbConfig struct {
	Device     string `json:"device"`     // e.g., "/dev/sda1"
	Mountpoint string `json:"mountpoint"` // defaults to "/cubeos/mnt/usb"
}

func (a *USBAdapter) parseConfig(config json.RawMessage) (usbConfig, error) {
	var cfg usbConfig
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid USB config: %w", err)
		}
	}
	if cfg.Device == "" {
		return cfg, fmt.Errorf("USB device is required (e.g., /dev/sda1)")
	}
	if cfg.Mountpoint == "" {
		cfg.Mountpoint = "/cubeos/mnt/usb"
	}
	return cfg, nil
}

// Type returns the destination type.
func (a *USBAdapter) Type() models.BackupDestination {
	return models.BackupDestUSB
}

// Validate checks if the USB device exists and is accessible.
func (a *USBAdapter) Validate(ctx context.Context, config json.RawMessage) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	// Verify device exists via HAL
	devices, err := a.halClient.GetUSBStorageDevices(ctx)
	if err != nil {
		return fmt.Errorf("failed to list USB devices: %w", err)
	}

	found := false
	for _, d := range devices {
		if d.Path == cfg.Device || d.Name == filepath.Base(cfg.Device) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("USB device %s not found", cfg.Device)
	}

	// Ensure mounted
	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	// Verify writable
	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("USB destination not writable: %w", err)
	}

	return nil
}

// AvailableSpace returns free bytes on the USB mount.
func (a *USBAdapter) AvailableSpace(ctx context.Context, config json.RawMessage) (int64, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return -1, err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return -1, err
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(cfg.Mountpoint, &stat); err != nil {
		return -1, fmt.Errorf("statfs failed on USB: %w", err)
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

// Write copies a backup to the USB drive.
func (a *USBAdapter) Write(ctx context.Context, config json.RawMessage, localPath, filename string) (string, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return "", err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return "", err
	}

	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup dir on USB: %w", err)
	}

	destPath := filepath.Join(backupDir, filename)
	if err := copyFileLocal(localPath, destPath); err != nil {
		return "", fmt.Errorf("failed to write backup to USB: %w", err)
	}

	log.Info().Str("dest", destPath).Msg("backup: written to USB")
	return destPath, nil
}

// Read copies a backup from the USB drive to a local path.
func (a *USBAdapter) Read(ctx context.Context, config json.RawMessage, filename, localPath string) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	srcPath := filepath.Join(cfg.Mountpoint, "backups", filename)
	return copyFileLocal(srcPath, localPath)
}

// List returns backup files on the USB drive.
func (a *USBAdapter) List(ctx context.Context, config json.RawMessage) ([]string, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return nil, err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return nil, err
	}

	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	return listBackupFiles(backupDir)
}

// Delete removes a backup from the USB drive.
func (a *USBAdapter) Delete(ctx context.Context, config json.RawMessage, filename string) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	target := filepath.Join(cfg.Mountpoint, "backups", filename)
	return os.Remove(target)
}

// ensureMounted mounts the USB device via HAL if not already mounted.
func (a *USBAdapter) ensureMounted(ctx context.Context, cfg usbConfig) error {
	// Check if already mounted at our expected path
	mounted, err := a.halClient.IsMounted(ctx, cfg.Mountpoint)
	if err != nil {
		log.Warn().Err(err).Msg("backup: could not check USB mount status")
	}
	if mounted {
		return nil
	}

	// Mount via HAL
	_, err = a.halClient.MountUSBStorage(ctx, cfg.Device)
	if err != nil {
		return fmt.Errorf("failed to mount USB device %s: %w", cfg.Device, err)
	}

	log.Info().Str("device", cfg.Device).Str("mountpoint", cfg.Mountpoint).Msg("backup: USB device mounted")
	return nil
}

// =============================================================================
// NFSAdapter — stores backups on NFS shares via HAL mount operations
// =============================================================================

// NFSAdapter stores backups on an NFS share, using HAL for mount operations.
type NFSAdapter struct {
	halClient *hal.Client
}

// nfsConfig is the configuration for NFSAdapter.
type nfsConfig struct {
	Server     string `json:"server"`     // e.g., "192.168.1.100"
	Share      string `json:"share"`      // e.g., "/backups"
	Mountpoint string `json:"mountpoint"` // defaults to "/cubeos/mnt/nfs"
	Options    string `json:"options,omitempty"`
}

func (a *NFSAdapter) parseConfig(config json.RawMessage) (nfsConfig, error) {
	var cfg nfsConfig
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid NFS config: %w", err)
		}
	}
	if cfg.Server == "" || cfg.Share == "" {
		return cfg, fmt.Errorf("NFS server and share are required")
	}
	if cfg.Mountpoint == "" {
		cfg.Mountpoint = "/cubeos/mnt/nfs"
	}
	return cfg, nil
}

// Type returns the destination type.
func (a *NFSAdapter) Type() models.BackupDestination {
	return models.BackupDestNFS
}

// Validate checks NFS connectivity and mount accessibility.
func (a *NFSAdapter) Validate(ctx context.Context, config json.RawMessage) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	// Test NFS server connectivity via HAL
	if err := a.halClient.CheckNFSServer(ctx, cfg.Server); err != nil {
		return fmt.Errorf("NFS server %s not reachable: %w", cfg.Server, err)
	}

	// Ensure mounted
	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	// Verify writable
	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("NFS destination not writable: %w", err)
	}

	return nil
}

// AvailableSpace returns free bytes on the NFS mount.
func (a *NFSAdapter) AvailableSpace(ctx context.Context, config json.RawMessage) (int64, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return -1, err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return -1, err
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(cfg.Mountpoint, &stat); err != nil {
		return -1, fmt.Errorf("statfs failed on NFS: %w", err)
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

// Write copies a backup to the NFS share.
func (a *NFSAdapter) Write(ctx context.Context, config json.RawMessage, localPath, filename string) (string, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return "", err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return "", err
	}

	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup dir on NFS: %w", err)
	}

	destPath := filepath.Join(backupDir, filename)
	if err := copyFileLocal(localPath, destPath); err != nil {
		return "", fmt.Errorf("failed to write backup to NFS: %w", err)
	}

	log.Info().Str("dest", destPath).Msg("backup: written to NFS")
	return destPath, nil
}

// Read copies a backup from the NFS share to a local path.
func (a *NFSAdapter) Read(ctx context.Context, config json.RawMessage, filename, localPath string) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	srcPath := filepath.Join(cfg.Mountpoint, "backups", filename)
	return copyFileLocal(srcPath, localPath)
}

// List returns backup files on the NFS share.
func (a *NFSAdapter) List(ctx context.Context, config json.RawMessage) ([]string, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return nil, err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return nil, err
	}

	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	return listBackupFiles(backupDir)
}

// Delete removes a backup from the NFS share.
func (a *NFSAdapter) Delete(ctx context.Context, config json.RawMessage, filename string) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	target := filepath.Join(cfg.Mountpoint, "backups", filename)
	return os.Remove(target)
}

// ensureMounted mounts the NFS share via HAL if not already mounted.
func (a *NFSAdapter) ensureMounted(ctx context.Context, cfg nfsConfig) error {
	mounted, err := a.halClient.IsMounted(ctx, cfg.Mountpoint)
	if err != nil {
		log.Warn().Err(err).Msg("backup: could not check NFS mount status")
	}
	if mounted {
		return nil
	}

	remotePath := cfg.Server + ":" + cfg.Share
	_, err = a.halClient.MountNFS(ctx, &hal.MountRequest{
		Name:       "backup-nfs",
		Type:       "nfs",
		RemotePath: remotePath,
		LocalPath:  cfg.Mountpoint,
		Options:    cfg.Options,
	})
	if err != nil {
		return fmt.Errorf("failed to mount NFS %s:%s: %w", cfg.Server, cfg.Share, err)
	}

	log.Info().Str("server", cfg.Server).Str("share", cfg.Share).Msg("backup: NFS share mounted")
	return nil
}

// =============================================================================
// SMBAdapter — stores backups on SMB shares via HAL mount operations
// =============================================================================

// SMBAdapter stores backups on an SMB share, using HAL for mount operations.
type SMBAdapter struct {
	halClient *hal.Client
}

// smbConfig is the configuration for SMBAdapter.
type smbConfig struct {
	Server     string `json:"server"`             // e.g., "192.168.1.100"
	Share      string `json:"share"`              // e.g., "backups"
	Username   string `json:"username,omitempty"` // SMB username
	Password   string `json:"password,omitempty"` // SMB password
	Mountpoint string `json:"mountpoint"`         // defaults to "/cubeos/mnt/smb"
	Options    string `json:"options,omitempty"`  // e.g., "domain=WORKGROUP,vers=3.0"
}

func (a *SMBAdapter) parseConfig(config json.RawMessage) (smbConfig, error) {
	var cfg smbConfig
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid SMB config: %w", err)
		}
	}
	if cfg.Server == "" || cfg.Share == "" {
		return cfg, fmt.Errorf("SMB server and share are required")
	}
	if cfg.Mountpoint == "" {
		cfg.Mountpoint = "/cubeos/mnt/smb"
	}
	return cfg, nil
}

// Type returns the destination type.
func (a *SMBAdapter) Type() models.BackupDestination {
	return models.BackupDestSMB
}

// Validate checks SMB connectivity and mount accessibility.
func (a *SMBAdapter) Validate(ctx context.Context, config json.RawMessage) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	// Test SMB server connectivity via HAL
	if err := a.halClient.CheckSMBServer(ctx, cfg.Server); err != nil {
		return fmt.Errorf("SMB server %s not reachable: %w", cfg.Server, err)
	}

	// Ensure mounted
	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	// Verify writable
	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("SMB destination not writable: %w", err)
	}

	return nil
}

// AvailableSpace returns free bytes on the SMB mount.
func (a *SMBAdapter) AvailableSpace(ctx context.Context, config json.RawMessage) (int64, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return -1, err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return -1, err
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(cfg.Mountpoint, &stat); err != nil {
		return -1, fmt.Errorf("statfs failed on SMB: %w", err)
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

// Write copies a backup to the SMB share.
func (a *SMBAdapter) Write(ctx context.Context, config json.RawMessage, localPath, filename string) (string, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return "", err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return "", err
	}

	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup dir on SMB: %w", err)
	}

	destPath := filepath.Join(backupDir, filename)
	if err := copyFileLocal(localPath, destPath); err != nil {
		return "", fmt.Errorf("failed to write backup to SMB: %w", err)
	}

	log.Info().Str("dest", destPath).Msg("backup: written to SMB")
	return destPath, nil
}

// Read copies a backup from the SMB share to a local path.
func (a *SMBAdapter) Read(ctx context.Context, config json.RawMessage, filename, localPath string) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	srcPath := filepath.Join(cfg.Mountpoint, "backups", filename)
	return copyFileLocal(srcPath, localPath)
}

// List returns backup files on the SMB share.
func (a *SMBAdapter) List(ctx context.Context, config json.RawMessage) ([]string, error) {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return nil, err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return nil, err
	}

	backupDir := filepath.Join(cfg.Mountpoint, "backups")
	return listBackupFiles(backupDir)
}

// Delete removes a backup from the SMB share.
func (a *SMBAdapter) Delete(ctx context.Context, config json.RawMessage, filename string) error {
	cfg, err := a.parseConfig(config)
	if err != nil {
		return err
	}

	if err := a.ensureMounted(ctx, cfg); err != nil {
		return err
	}

	target := filepath.Join(cfg.Mountpoint, "backups", filename)
	return os.Remove(target)
}

// ensureMounted mounts the SMB share via HAL if not already mounted.
func (a *SMBAdapter) ensureMounted(ctx context.Context, cfg smbConfig) error {
	mounted, err := a.halClient.IsMounted(ctx, cfg.Mountpoint)
	if err != nil {
		log.Warn().Err(err).Msg("backup: could not check SMB mount status")
	}
	if mounted {
		return nil
	}

	remotePath := "//" + cfg.Server + "/" + cfg.Share
	_, err = a.halClient.MountSMB(ctx, &hal.MountRequest{
		Name:       "backup-smb",
		Type:       "smb",
		RemotePath: remotePath,
		LocalPath:  cfg.Mountpoint,
		Username:   cfg.Username,
		Password:   cfg.Password,
		Options:    cfg.Options,
	})
	if err != nil {
		return fmt.Errorf("failed to mount SMB //%s/%s: %w", cfg.Server, cfg.Share, err)
	}

	log.Info().Str("server", cfg.Server).Str("share", cfg.Share).Msg("backup: SMB share mounted")
	return nil
}

// =============================================================================
// Shared helpers
// =============================================================================

// copyFileLocal copies a file from src to dst.
func copyFileLocal(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// listBackupFiles lists .tar.gz files in a directory.
func listBackupFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tar.gz") {
			files = append(files, e.Name())
		}
	}
	return files, nil
}
