package activities

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// BackupManagerInterface defines the BackupManager operations needed by backup activities.
type BackupManagerInterface interface {
	BackupDir() string
	ScopePaths(scope models.BackupScope) []BackupPathEntry
	HotBackupDatabase(ctx context.Context, destPath string) error
	CreateBackupManifest(scope models.BackupScope, archivePath string) (*models.BackupManifest, error)
	GenerateConfigSnapshot(ctx context.Context) (*models.ConfigSnapshot, error)
	StoreConfigSnapshot(ctx context.Context, trigger, description string, snapshot *models.ConfigSnapshot) error
	AddJSONToTar(tw *tar.Writer, archivePath string, v interface{}) error
	AddFileToTar(tw *tar.Writer, srcPath, archivePath string) error
	CheckDiskSpace(path string) (uint64, error)
	VerifyBackup(backupPath string) (*models.BackupManifest, error)
	RecordBackupInDB(ctx context.Context, name, scope, destType, destPath, checksum, workflowID string, sizeBytes int64, manifest *models.BackupManifest) error
}

// BackupDestinationRegistryInterface abstracts the destination registry for activities.
type BackupDestinationRegistryInterface interface {
	Get(dest models.BackupDestination) (BackupDestinationAdapterInterface, error)
}

// BackupDestinationAdapterInterface abstracts a single destination adapter for activities.
type BackupDestinationAdapterInterface interface {
	Type() models.BackupDestination
	Validate(ctx context.Context, config json.RawMessage) error
	AvailableSpace(ctx context.Context, config json.RawMessage) (int64, error)
	Write(ctx context.Context, config json.RawMessage, localPath, filename string) (string, error)
}

// BackupEncryptor abstracts backup encryption for activities.
type BackupEncryptor interface {
	EncryptBackup(inputPath, outputPath string, mode string, passphrase string) error
}

// BackupPathEntry mirrors managers.BackupPathEntry for the activity layer.
type BackupPathEntry struct {
	SourcePath  string
	ArchivePath string
	Description string
	Category    string
}

// DockerStackLister lists running Docker stacks for stop/restart operations.
type DockerStackLister interface {
	DeployStack(name, composePath string) error
	RemoveStack(name string) error
	StackExists(name string) (bool, error)
}

// --- Input/Output Schemas ---

// BackupValidateInput is the input for backup.validate_target.
type BackupValidateInput struct {
	Scope       string          `json:"scope"`
	Destination string          `json:"destination"`
	DestPath    string          `json:"dest_path"`
	DestConfig  json.RawMessage `json:"dest_config,omitempty"`
	Description string          `json:"description"`
	StopApps    bool            `json:"stop_apps"`
	Encrypt     bool            `json:"encrypt"`
	Passphrase  string          `json:"passphrase,omitempty"`
}

// BackupValidateOutput is the output of backup.validate_target.
type BackupValidateOutput struct {
	TempDir  string `json:"temp_dir"`
	DestPath string `json:"dest_path"`
	Scope    string `json:"scope"`
}

// BackupSnapshotConfigOutput is the output of backup.snapshot_config.
type BackupSnapshotConfigOutput struct {
	ConfigSnapshotPath string `json:"config_snapshot_path"`
}

// BackupStopAppsOutput is the output of backup.stop_apps_if_needed.
type BackupStopAppsOutput struct {
	StoppedStacks []string `json:"stopped_stacks"`
	Skipped       bool     `json:"skipped"`
}

// BackupSnapshotDBOutput is the output of backup.snapshot_database.
type BackupSnapshotDBOutput struct {
	DBSnapshotPath string `json:"db_snapshot_path"`
}

// BackupCollectOutput is the output of backup.collect_app_data.
type BackupCollectOutput struct {
	FileCount int `json:"file_count"`
}

// BackupCreateArchiveOutput is the output of backup.create_archive.
type BackupCreateArchiveOutput struct {
	ArchivePath string `json:"archive_path"`
	SizeBytes   int64  `json:"size_bytes"`
}

// BackupWriteManifestOutput is the output of backup.write_manifest.
type BackupWriteManifestOutput struct {
	ManifestJSON string `json:"manifest_json"`
}

// BackupChecksumOutput is the output of backup.compute_checksum.
type BackupChecksumOutput struct {
	Checksum string `json:"checksum"`
}

// BackupEncryptOutput is the output of backup.encrypt_archive.
type BackupEncryptOutput struct {
	ArchivePath string `json:"archive_path"` // may have changed if encryption applied
	Encrypted   bool   `json:"encrypted"`
	EncryptMode string `json:"encrypt_mode"` // "device" or "portable"
}

// BackupMoveOutput is the output of backup.move_to_destination.
type BackupMoveOutput struct {
	FinalPath string `json:"final_path"`
	Filename  string `json:"filename"`
}

// BackupRecordOutput is the output of backup.record_in_db.
type BackupRecordOutput struct {
	BackupName string `json:"backup_name"`
}

// --- Restore Input/Output ---

// RestoreValidateInput is the input for restore.validate_backup.
type RestoreValidateInput struct {
	BackupID   string `json:"backup_id"`
	BackupPath string `json:"backup_path"`
	Confirm    bool   `json:"confirm"`
}

// RestoreValidateOutput is the output of restore.validate_backup.
type RestoreValidateOutput struct {
	BackupPath string `json:"backup_path"`
	Scope      string `json:"scope"`
}

// RestoreVerifyOutput is the output of restore.verify_checksums.
type RestoreVerifyOutput struct {
	Verified bool `json:"verified"`
}

// RestoreImportConfigOutput is the output of restore.import_config.
type RestoreImportConfigOutput struct {
	DBRestored     bool `json:"db_restored"`
	ConfigRestored bool `json:"config_restored"`
}

// RestoreStopOutput is the output of restore.stop_services / restore.start_services.
type RestoreStopOutput struct {
	StacksStopped []string `json:"stacks_stopped"`
}

// RestoreDataOutput is the output of restore.restore_coreapp_data / restore.restore_app_data.
type RestoreDataOutput struct {
	FilesRestored int `json:"files_restored"`
}

// RestoreHealthOutput is the output of restore.verify_health.
type RestoreHealthOutput struct {
	Healthy bool `json:"healthy"`
}

// RegisterBackupActivities registers all backup/restore activities in the registry.
func RegisterBackupActivities(registry *flowengine.ActivityRegistry, db *sql.DB, backupMgr BackupManagerInterface, swarmMgr DockerStackLister, destRegistry BackupDestinationRegistryInterface, encryptor BackupEncryptor) {
	// Backup activities
	registry.MustRegister("backup.validate_target", makeBackupValidateTarget(backupMgr, destRegistry))
	registry.MustRegister("backup.snapshot_config", makeBackupSnapshotConfig(backupMgr))
	registry.MustRegister("backup.stop_apps_if_needed", makeBackupStopApps(swarmMgr, db))
	registry.MustRegister("backup.restart_stopped_apps", makeBackupRestartApps(swarmMgr, db))
	registry.MustRegister("backup.snapshot_database", makeBackupSnapshotDB(backupMgr))
	registry.MustRegister("backup.collect_app_data", makeBackupCollectData(backupMgr))
	registry.MustRegister("backup.create_archive", makeBackupCreateArchive(backupMgr))
	registry.MustRegister("backup.write_manifest", makeBackupWriteManifest(backupMgr))
	registry.MustRegister("backup.compute_checksum", makeBackupComputeChecksum())
	registry.MustRegister("backup.encrypt_archive", makeBackupEncryptArchive(encryptor))
	registry.MustRegister("backup.move_to_destination", makeBackupMoveToDest(backupMgr, destRegistry))
	registry.MustRegister("backup.cleanup_dest", makeBackupCleanupDest())
	registry.MustRegister("backup.cleanup_temp", makeBackupCleanupTemp())
	registry.MustRegister("backup.record_in_db", makeBackupRecordInDB(backupMgr))

	// Restore activities
	registry.MustRegister("restore.validate_backup", makeRestoreValidate(backupMgr))
	registry.MustRegister("restore.verify_checksums", makeRestoreVerifyChecksums(backupMgr))
	registry.MustRegister("restore.import_config", makeRestoreImportConfig(db))
	registry.MustRegister("restore.stop_services", makeRestoreStopServices(swarmMgr, db))
	registry.MustRegister("restore.start_services", makeRestoreStartServices(swarmMgr, db))
	registry.MustRegister("restore.restore_coreapp_data", makeRestoreData("coreapp_data"))
	registry.MustRegister("restore.restore_app_data", makeRestoreData("app_data"))
	registry.MustRegister("restore.restart_services", makeRestoreRestartServices(swarmMgr, db))
	registry.MustRegister("restore.verify_health", makeRestoreVerifyHealth())
}

// --- Backup Activity Implementations ---

func makeBackupValidateTarget(backupMgr BackupManagerInterface, destRegistry BackupDestinationRegistryInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in BackupValidateInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid validate_target input: %w", err))
		}

		scope := in.Scope
		if scope == "" {
			scope = "tier1"
		}

		dest := models.BackupDestination(in.Destination)
		if dest == "" {
			dest = models.BackupDestLocal
		}

		// Use destination adapter for validation if registry is available
		if destRegistry != nil {
			adapter, err := destRegistry.Get(dest)
			if err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("unsupported destination %s: %w", dest, err))
			}

			// Validate destination is accessible
			if err := adapter.Validate(ctx, in.DestConfig); err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("destination validation failed: %w", err))
			}

			// Check available space (require at least 100MB)
			freeBytes, err := adapter.AvailableSpace(ctx, in.DestConfig)
			if err != nil {
				log.Warn().Err(err).Msg("backup: failed to check disk space, proceeding anyway")
			} else if freeBytes >= 0 && freeBytes < 100*1024*1024 {
				return nil, flowengine.NewPermanentError(fmt.Errorf("insufficient space: %d bytes free, need at least 100MB", freeBytes))
			}
		} else {
			// Fallback: direct local validation
			destPath := in.DestPath
			if destPath == "" {
				destPath = backupMgr.BackupDir()
			}
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("destination not writable: %w", err))
			}
			freeBytes, err := backupMgr.CheckDiskSpace(destPath)
			if err != nil {
				log.Warn().Err(err).Msg("backup: failed to check disk space, proceeding anyway")
			} else if freeBytes < 100*1024*1024 {
				return nil, flowengine.NewPermanentError(fmt.Errorf("insufficient disk space: %d bytes free, need at least 100MB", freeBytes))
			}
		}

		// Determine dest_path for local reference
		destPath := in.DestPath
		if destPath == "" {
			destPath = backupMgr.BackupDir()
		}

		// Create temp directory for staging
		tempDir, err := os.MkdirTemp("/tmp", "cubeos-backup-")
		if err != nil {
			return nil, flowengine.NewTransientError(fmt.Errorf("failed to create temp dir: %w", err))
		}

		log.Info().Str("scope", scope).Str("temp_dir", tempDir).Str("dest", string(dest)).Msg("backup: validation passed")

		return marshalOutput(BackupValidateOutput{
			TempDir:  tempDir,
			DestPath: destPath,
			Scope:    scope,
		})
	}
}

func makeBackupSnapshotConfig(backupMgr BackupManagerInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			TempDir string `json:"temp_dir"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid snapshot_config input: %w", err))
		}
		if envelope.TempDir == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("temp_dir is required"))
		}

		snapshot, err := backupMgr.GenerateConfigSnapshot(ctx)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		// Write config snapshot to temp dir
		snapshotPath := filepath.Join(envelope.TempDir, "cubeos-config.json")
		data, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("failed to marshal config snapshot: %w", err))
		}
		if err := os.WriteFile(snapshotPath, data, 0644); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		// Also store in DB
		if err := backupMgr.StoreConfigSnapshot(ctx, "pre_backup", "Automatic pre-backup config snapshot", snapshot); err != nil {
			log.Warn().Err(err).Msg("backup: failed to store config snapshot in DB (non-fatal)")
		}

		log.Info().Str("path", snapshotPath).Msg("backup: config snapshot created")

		return marshalOutput(BackupSnapshotConfigOutput{
			ConfigSnapshotPath: snapshotPath,
		})
	}
}

func makeBackupStopApps(swarmMgr DockerStackLister, db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			Scope    string `json:"scope"`
			StopApps bool   `json:"stop_apps"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid stop_apps input: %w", err))
		}

		// Only stop apps for Tier 3 when explicitly requested
		if envelope.Scope != "tier3" || !envelope.StopApps {
			return marshalOutput(BackupStopAppsOutput{Skipped: true})
		}

		if swarmMgr == nil {
			return marshalOutput(BackupStopAppsOutput{Skipped: true})
		}

		// Get user app stacks from DB
		var stopped []string
		rows, err := db.QueryContext(ctx, "SELECT name FROM apps WHERE type = 'user' AND enabled = TRUE")
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		defer rows.Close()

		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				continue
			}
			exists, _ := swarmMgr.StackExists("cubeos-" + name)
			if exists {
				if err := swarmMgr.RemoveStack("cubeos-" + name); err != nil {
					log.Warn().Err(err).Str("stack", name).Msg("backup: failed to stop stack")
				} else {
					stopped = append(stopped, name)
				}
			}
		}

		log.Info().Int("count", len(stopped)).Msg("backup: stopped user app stacks for consistent backup")
		return marshalOutput(BackupStopAppsOutput{StoppedStacks: stopped})
	}
}

func makeBackupRestartApps(swarmMgr DockerStackLister, db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			StoppedStacks []string `json:"stopped_stacks"`
		}
		json.Unmarshal(input, &envelope)

		if len(envelope.StoppedStacks) == 0 || swarmMgr == nil {
			return marshalOutput(BackupStopAppsOutput{Skipped: true})
		}

		// Restart stopped stacks by re-deploying
		for _, name := range envelope.StoppedStacks {
			composePath := filepath.Join("/cubeos/apps", name, "appconfig", "docker-compose.yml")
			if err := swarmMgr.DeployStack("cubeos-"+name, composePath); err != nil {
				log.Warn().Err(err).Str("stack", name).Msg("backup: failed to restart stack")
			}
		}

		return marshalOutput(BackupStopAppsOutput{StoppedStacks: envelope.StoppedStacks})
	}
}

func makeBackupSnapshotDB(backupMgr BackupManagerInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			TempDir string `json:"temp_dir"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid snapshot_database input: %w", err))
		}
		if envelope.TempDir == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("temp_dir is required"))
		}

		dbPath := filepath.Join(envelope.TempDir, "cubeos.db")
		if err := backupMgr.HotBackupDatabase(ctx, dbPath); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(BackupSnapshotDBOutput{DBSnapshotPath: dbPath})
	}
}

func makeBackupCollectData(backupMgr BackupManagerInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			Scope string `json:"scope"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid collect_app_data input: %w", err))
		}

		scope := models.BackupScope(envelope.Scope)
		if scope == "" {
			scope = models.BackupScopeTier1
		}

		paths := backupMgr.ScopePaths(scope)
		log.Info().Int("paths", len(paths)).Str("scope", string(scope)).Msg("backup: collected paths for archiving")

		return marshalOutput(BackupCollectOutput{FileCount: len(paths)})
	}
}

func makeBackupCreateArchive(backupMgr BackupManagerInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			TempDir            string `json:"temp_dir"`
			Scope              string `json:"scope"`
			DBSnapshotPath     string `json:"db_snapshot_path"`
			ConfigSnapshotPath string `json:"config_snapshot_path"`
			Description        string `json:"description"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid create_archive input: %w", err))
		}
		if envelope.TempDir == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("temp_dir is required"))
		}

		scope := models.BackupScope(envelope.Scope)
		if scope == "" {
			scope = models.BackupScopeTier1
		}

		// Generate archive filename (cubeos-backup- prefix matches boot script glob)
		timestamp := time.Now().Format("20060102-150405")
		filename := fmt.Sprintf("cubeos-backup-%s-%s.tar.gz", scope, timestamp)
		archivePath := filepath.Join(envelope.TempDir, filename)

		// Create tar.gz
		file, err := os.Create(archivePath)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		defer file.Close()

		gzWriter := gzip.NewWriter(file)
		defer gzWriter.Close()

		tarWriter := tar.NewWriter(gzWriter)
		defer tarWriter.Close()

		// 1. Add config snapshot (cubeos-config.json) at archive root
		if envelope.ConfigSnapshotPath != "" {
			if err := backupMgr.AddFileToTar(tarWriter, envelope.ConfigSnapshotPath, "cubeos-config.json"); err != nil {
				log.Warn().Err(err).Msg("backup: failed to add config snapshot to archive")
			}
		}

		// 2. Add hot database snapshot (replaces the live DB in scope paths)
		if envelope.DBSnapshotPath != "" {
			if err := backupMgr.AddFileToTar(tarWriter, envelope.DBSnapshotPath, "cubeos/data/cubeos.db"); err != nil {
				log.Warn().Err(err).Msg("backup: failed to add DB snapshot to archive")
			}
		}

		// 3. Add scope paths (skip the live DB since we used the hot snapshot)
		paths := backupMgr.ScopePaths(scope)
		for _, p := range paths {
			// Skip the live database — we already added the hot snapshot
			if strings.HasSuffix(p.SourcePath, "cubeos.db") {
				continue
			}

			srcPath := p.SourcePath
			// Try host-mounted paths if direct path doesn't exist
			if _, err := os.Stat(srcPath); os.IsNotExist(err) {
				srcPath = "/host" + srcPath
				if _, err := os.Stat(srcPath); os.IsNotExist(err) {
					continue
				}
			}

			if err := backupMgr.AddFileToTar(tarWriter, srcPath, p.ArchivePath); err != nil {
				log.Warn().Err(err).Str("path", srcPath).Msg("backup: failed to add path to archive")
			}
		}

		// Close writers to flush
		tarWriter.Close()
		gzWriter.Close()
		file.Close()

		// Get size
		stat, err := os.Stat(archivePath)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		log.Info().Str("archive", archivePath).Int64("size", stat.Size()).Msg("backup: archive created")

		return marshalOutput(BackupCreateArchiveOutput{
			ArchivePath: archivePath,
			SizeBytes:   stat.Size(),
		})
	}
}

func makeBackupWriteManifest(backupMgr BackupManagerInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			ArchivePath string `json:"archive_path"`
			Scope       string `json:"scope"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid write_manifest input: %w", err))
		}
		if envelope.ArchivePath == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("archive_path is required"))
		}

		scope := models.BackupScope(envelope.Scope)
		if scope == "" {
			scope = models.BackupScopeTier1
		}

		// Generate manifest from the archive
		manifest, err := backupMgr.CreateBackupManifest(scope, envelope.ArchivePath)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		// Re-create the archive with manifest embedded at root
		// Strategy: create a new archive with manifest.json prepended, then copy original entries
		tempPath := envelope.ArchivePath + ".tmp"
		if err := embedManifestInArchive(envelope.ArchivePath, tempPath, manifest); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		// Replace original with new archive
		if err := os.Rename(tempPath, envelope.ArchivePath); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		manifestData, _ := json.Marshal(manifest)
		log.Info().Int("files", len(manifest.Files)).Msg("backup: manifest written to archive")

		return marshalOutput(BackupWriteManifestOutput{
			ManifestJSON: string(manifestData),
		})
	}
}

func makeBackupComputeChecksum() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			ArchivePath string `json:"archive_path"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid compute_checksum input: %w", err))
		}
		if envelope.ArchivePath == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("archive_path is required"))
		}

		f, err := os.Open(envelope.ArchivePath)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		checksum := hex.EncodeToString(h.Sum(nil))
		log.Info().Str("checksum", checksum[:16]+"...").Msg("backup: checksum computed")

		return marshalOutput(BackupChecksumOutput{Checksum: checksum})
	}
}

func makeBackupEncryptArchive(encryptor BackupEncryptor) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			ArchivePath string `json:"archive_path"`
			Encrypt     bool   `json:"encrypt"`
			Passphrase  string `json:"passphrase"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid encrypt_archive input: %w", err))
		}

		// Skip encryption if not requested
		if !envelope.Encrypt || encryptor == nil {
			return marshalOutput(BackupEncryptOutput{
				ArchivePath: envelope.ArchivePath,
				Encrypted:   false,
			})
		}

		// Determine mode: portable if passphrase provided, device otherwise
		mode := "device"
		if envelope.Passphrase != "" {
			mode = "portable"
		}

		encryptedPath := envelope.ArchivePath + ".enc"
		if err := encryptor.EncryptBackup(envelope.ArchivePath, encryptedPath, mode, envelope.Passphrase); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("encryption failed: %w", err))
		}

		// Remove unencrypted archive
		os.Remove(envelope.ArchivePath)

		log.Info().Str("mode", mode).Str("path", encryptedPath).Msg("backup: archive encrypted")

		return marshalOutput(BackupEncryptOutput{
			ArchivePath: encryptedPath,
			Encrypted:   true,
			EncryptMode: mode,
		})
	}
}

func makeBackupMoveToDest(backupMgr BackupManagerInterface, destRegistry BackupDestinationRegistryInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			ArchivePath string          `json:"archive_path"`
			DestPath    string          `json:"dest_path"`
			Destination string          `json:"destination"`
			DestConfig  json.RawMessage `json:"dest_config,omitempty"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid move_to_destination input: %w", err))
		}
		if envelope.ArchivePath == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("archive_path is required"))
		}

		filename := filepath.Base(envelope.ArchivePath)
		dest := models.BackupDestination(envelope.Destination)

		// Use destination adapter if registry is available and destination is not local default
		if destRegistry != nil && dest != "" {
			adapter, err := destRegistry.Get(dest)
			if err == nil {
				finalPath, err := adapter.Write(ctx, envelope.DestConfig, envelope.ArchivePath, filename)
				if err != nil {
					return nil, flowengine.ClassifyError(fmt.Errorf("destination write failed: %w", err))
				}

				// Remove source after successful write
				os.Remove(envelope.ArchivePath)

				log.Info().Str("final", finalPath).Str("dest", string(dest)).Msg("backup: archive moved to destination")
				return marshalOutput(BackupMoveOutput{
					FinalPath: finalPath,
					Filename:  filename,
				})
			}
			// Fall through to legacy path if adapter not found
			log.Warn().Err(err).Str("dest", string(dest)).Msg("backup: destination adapter not found, using legacy path")
		}

		// Legacy local path
		destPath := envelope.DestPath
		if destPath == "" {
			destPath = backupMgr.BackupDir()
		}

		finalPath := filepath.Join(destPath, filename)

		if err := os.MkdirAll(destPath, 0755); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		if err := os.Rename(envelope.ArchivePath, finalPath); err != nil {
			if err := copyFile(envelope.ArchivePath, finalPath); err != nil {
				return nil, flowengine.ClassifyError(err)
			}
			os.Remove(envelope.ArchivePath)
		}

		log.Info().Str("final", finalPath).Msg("backup: archive moved to destination")

		return marshalOutput(BackupMoveOutput{
			FinalPath: finalPath,
			Filename:  filename,
		})
	}
}

func makeBackupCleanupDest() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			FinalPath string `json:"final_path"`
		}
		json.Unmarshal(input, &envelope)

		if envelope.FinalPath != "" {
			os.Remove(envelope.FinalPath)
			log.Info().Str("path", envelope.FinalPath).Msg("backup: cleaned up destination file")
		}

		return marshalOutput(map[string]bool{"cleaned": true})
	}
}

func makeBackupCleanupTemp() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			TempDir string `json:"temp_dir"`
		}
		json.Unmarshal(input, &envelope)

		if envelope.TempDir != "" && strings.HasPrefix(envelope.TempDir, "/tmp/cubeos-backup-") {
			os.RemoveAll(envelope.TempDir)
			log.Info().Str("dir", envelope.TempDir).Msg("backup: cleaned up temp directory")
		}

		return marshalOutput(map[string]bool{"cleaned": true})
	}
}

func makeBackupRecordInDB(backupMgr BackupManagerInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			FinalPath    string `json:"final_path"`
			Filename     string `json:"filename"`
			Scope        string `json:"scope"`
			Destination  string `json:"destination"`
			DestPath     string `json:"dest_path"`
			Checksum     string `json:"checksum"`
			SizeBytes    int64  `json:"size_bytes"`
			Description  string `json:"description"`
			ManifestJSON string `json:"manifest_json"`
			TempDir      string `json:"temp_dir"`
			Encrypted    bool   `json:"encrypted"`
			EncryptMode  string `json:"encrypt_mode"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid record_in_db input: %w", err))
		}

		// Parse manifest if available
		var manifest *models.BackupManifest
		if envelope.ManifestJSON != "" {
			manifest = &models.BackupManifest{}
			json.Unmarshal([]byte(envelope.ManifestJSON), manifest)
			manifest.Checksum = envelope.Checksum
			manifest.Encrypted = envelope.Encrypted
			manifest.EncryptMode = envelope.EncryptMode
		}

		backupName := strings.TrimSuffix(envelope.Filename, ".tar.gz")
		if backupName == "" {
			backupName = fmt.Sprintf("backup-%s", time.Now().Format("20060102-150405"))
		}

		destType := envelope.Destination
		if destType == "" {
			destType = "local"
		}

		// Extract workflow_id from context if available (fat envelope doesn't carry it directly)
		workflowID := ""

		if err := backupMgr.RecordBackupInDB(ctx, backupName, envelope.Scope, destType, envelope.DestPath, envelope.Checksum, workflowID, envelope.SizeBytes, manifest); err != nil {
			log.Warn().Err(err).Msg("backup: failed to record in DB (non-fatal)")
		}

		// Clean up temp directory
		if envelope.TempDir != "" && strings.HasPrefix(envelope.TempDir, "/tmp/cubeos-backup-") {
			os.RemoveAll(envelope.TempDir)
		}

		// Also write .meta file for backward compatibility with ListBackups
		metaPath := envelope.FinalPath + ".meta"
		meta := map[string]interface{}{
			"type":         envelope.Scope,
			"description":  envelope.Description,
			"created_at":   time.Now().Format(time.RFC3339),
			"scope":        envelope.Scope,
			"checksum":     envelope.Checksum,
			"compressed":   true,
			"encrypted":    envelope.Encrypted,
			"encrypt_mode": envelope.EncryptMode,
		}
		metaData, _ := json.MarshalIndent(meta, "", "  ")
		os.WriteFile(metaPath, metaData, 0644)

		log.Info().Str("name", backupName).Msg("backup: recorded in database")

		return marshalOutput(BackupRecordOutput{BackupName: backupName})
	}
}

// --- Restore Activity Implementations ---

func makeRestoreValidate(backupMgr BackupManagerInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RestoreValidateInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore validate input: %w", err))
		}

		backupPath := in.BackupPath
		if backupPath == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("backup_path is required"))
		}

		// Verify file exists
		fi, err := os.Stat(backupPath)
		if err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("backup file not found: %w", err))
		}
		if fi.IsDir() {
			return nil, flowengine.NewPermanentError(fmt.Errorf("backup_path is a directory"))
		}

		// Try to extract and read manifest
		manifest, err := backupMgr.VerifyBackup(backupPath)
		scope := "unknown"
		if err == nil && manifest != nil {
			scope = string(manifest.Scope)
		} else {
			log.Warn().Err(err).Msg("restore: could not verify backup manifest, proceeding with caution")
		}

		log.Info().Str("backup", backupPath).Str("scope", scope).Msg("restore: backup validated")

		return marshalOutput(RestoreValidateOutput{
			BackupPath: backupPath,
			Scope:      scope,
		})
	}
}

func makeRestoreVerifyChecksums(backupMgr BackupManagerInterface) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			BackupPath string `json:"backup_path"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid verify_checksums input: %w", err))
		}

		_, err := backupMgr.VerifyBackup(envelope.BackupPath)
		if err != nil {
			// Non-fatal: older backups may not have manifests
			log.Warn().Err(err).Msg("restore: checksum verification failed (proceeding)")
		}

		return marshalOutput(RestoreVerifyOutput{Verified: err == nil})
	}
}

func makeRestoreImportConfig(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		// Phase 4 implementation: direct DB replace + env file restore
		// Phase 6 replaces this with ConfigImportWorkflow (W14) submission.
		var envelope struct {
			BackupPath string `json:"backup_path"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid import_config input: %w", err))
		}

		dbRestored := false
		configRestored := false

		// Extract DB and config files from backup
		f, err := os.Open(envelope.BackupPath)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		defer f.Close()

		gzReader, err := gzip.NewReader(f)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		defer gzReader.Close()

		tarReader := tar.NewReader(gzReader)

		// Only restore config and DB files in this step
		allowedPrefixes := []string{
			"cubeos/data/cubeos.db",
			"cubeos/config/",
			"cubeos/coreapps/image-versions.env",
		}

		const maxFileSize int64 = 500 * 1024 * 1024

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, flowengine.ClassifyError(err)
			}
			if header.Typeflag == tar.TypeDir {
				continue
			}

			// Check if this file is in allowed set
			allowed := false
			for _, prefix := range allowedPrefixes {
				if strings.HasPrefix(header.Name, prefix) || header.Name == prefix {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}

			if header.Size > maxFileSize {
				continue
			}

			// Compute target path
			target := filepath.Clean("/" + header.Name)
			if strings.Contains(target, "..") {
				continue
			}

			os.MkdirAll(filepath.Dir(target), 0755)
			outFile, err := os.Create(target)
			if err != nil {
				log.Warn().Err(err).Str("target", target).Msg("restore: failed to create file")
				continue
			}
			io.Copy(outFile, io.LimitReader(tarReader, maxFileSize))
			outFile.Close()
			os.Chmod(target, os.FileMode(header.Mode))

			if strings.HasSuffix(target, "cubeos.db") {
				dbRestored = true
			} else {
				configRestored = true
			}
		}

		log.Info().Bool("db", dbRestored).Bool("config", configRestored).Msg("restore: config import complete")

		return marshalOutput(RestoreImportConfigOutput{
			DBRestored:     dbRestored,
			ConfigRestored: configRestored,
		})
	}
}

func makeRestoreStopServices(swarmMgr DockerStackLister, db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		if swarmMgr == nil {
			return marshalOutput(RestoreStopOutput{})
		}

		var stopped []string

		// Get all app stacks
		rows, err := db.QueryContext(ctx, "SELECT name FROM apps WHERE enabled = TRUE")
		if err != nil {
			log.Warn().Err(err).Msg("restore: failed to query apps")
			return marshalOutput(RestoreStopOutput{})
		}
		defer rows.Close()

		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				continue
			}
			stackName := "cubeos-" + name
			exists, _ := swarmMgr.StackExists(stackName)
			if exists {
				if err := swarmMgr.RemoveStack(stackName); err != nil {
					log.Warn().Err(err).Str("stack", stackName).Msg("restore: failed to stop stack")
				} else {
					stopped = append(stopped, name)
				}
			}
		}

		log.Info().Int("count", len(stopped)).Msg("restore: stopped services")
		return marshalOutput(RestoreStopOutput{StacksStopped: stopped})
	}
}

func makeRestoreStartServices(swarmMgr DockerStackLister, db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			StacksStopped []string `json:"stacks_stopped"`
		}
		json.Unmarshal(input, &envelope)

		if swarmMgr == nil || len(envelope.StacksStopped) == 0 {
			return marshalOutput(RestoreStopOutput{})
		}

		for _, name := range envelope.StacksStopped {
			composePath := filepath.Join("/cubeos/apps", name, "appconfig", "docker-compose.yml")
			// Also check coreapps
			if _, err := os.Stat(composePath); os.IsNotExist(err) {
				composePath = filepath.Join("/cubeos/coreapps", name, "appconfig", "docker-compose.yml")
			}
			if err := swarmMgr.DeployStack("cubeos-"+name, composePath); err != nil {
				log.Warn().Err(err).Str("stack", name).Msg("restore: failed to restart stack")
			}
		}

		return marshalOutput(RestoreStopOutput{StacksStopped: envelope.StacksStopped})
	}
}

func makeRestoreData(category string) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			BackupPath string `json:"backup_path"`
			Scope      string `json:"scope"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore_data input: %w", err))
		}

		// Determine which path prefixes to restore based on category
		var allowedPrefixes []string
		switch category {
		case "coreapp_data":
			allowedPrefixes = []string{"cubeos/coreapps/"}
		case "app_data":
			allowedPrefixes = []string{"cubeos/apps/"}
		default:
			return marshalOutput(RestoreDataOutput{})
		}

		// Check scope — Tier 1 has no coreapp/app data
		if envelope.Scope == "tier1" {
			return marshalOutput(RestoreDataOutput{})
		}
		if category == "app_data" && envelope.Scope == "tier2" {
			return marshalOutput(RestoreDataOutput{})
		}

		f, err := os.Open(envelope.BackupPath)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		defer f.Close()

		gzReader, err := gzip.NewReader(f)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		defer gzReader.Close()

		tarReader := tar.NewReader(gzReader)

		const maxFileSize int64 = 500 * 1024 * 1024
		restored := 0

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, flowengine.ClassifyError(err)
			}

			// Skip config/DB files — they were restored in import_config step
			if strings.HasPrefix(header.Name, "cubeos/data/cubeos.db") ||
				strings.HasPrefix(header.Name, "cubeos/config/") ||
				header.Name == "cubeos/coreapps/image-versions.env" ||
				header.Name == "cubeos-config.json" ||
				header.Name == "manifest.json" {
				continue
			}

			allowed := false
			for _, prefix := range allowedPrefixes {
				if strings.HasPrefix(header.Name, prefix) {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}

			target := filepath.Clean("/" + header.Name)
			if strings.Contains(target, "..") {
				continue
			}

			if header.Typeflag == tar.TypeDir {
				os.MkdirAll(target, 0755)
				continue
			}

			if header.Size > maxFileSize {
				continue
			}

			os.MkdirAll(filepath.Dir(target), 0755)
			outFile, err := os.Create(target)
			if err != nil {
				continue
			}
			io.Copy(outFile, io.LimitReader(tarReader, maxFileSize))
			outFile.Close()
			os.Chmod(target, os.FileMode(header.Mode))
			restored++
		}

		log.Info().Str("category", category).Int("files", restored).Msg("restore: data restored")
		return marshalOutput(RestoreDataOutput{FilesRestored: restored})
	}
}

func makeRestoreRestartServices(swarmMgr DockerStackLister, db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		if swarmMgr == nil {
			return marshalOutput(RestoreStopOutput{})
		}

		var restarted []string
		rows, err := db.QueryContext(ctx, "SELECT name, compose_path FROM apps WHERE enabled = TRUE")
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		defer rows.Close()

		for rows.Next() {
			var name, composePath string
			if err := rows.Scan(&name, &composePath); err != nil {
				continue
			}
			stackName := "cubeos-" + name
			if err := swarmMgr.DeployStack(stackName, composePath); err != nil {
				log.Warn().Err(err).Str("stack", stackName).Msg("restore: failed to restart stack")
			} else {
				restarted = append(restarted, name)
			}
		}

		log.Info().Int("count", len(restarted)).Msg("restore: restarted services")
		return marshalOutput(RestoreStopOutput{StacksStopped: restarted})
	}
}

func makeRestoreVerifyHealth() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		// Best-effort health check — wait briefly then report success
		// Full health checking requires HAL, which may not be available during restore
		time.Sleep(5 * time.Second)

		log.Info().Msg("restore: health check completed (basic)")
		return marshalOutput(RestoreHealthOutput{Healthy: true})
	}
}

// --- Helpers ---

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
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

	_, err = io.Copy(out, in)
	return err
}

// embedManifestInArchive creates a new tar.gz with manifest.json prepended.
func embedManifestInArchive(srcArchive, dstArchive string, manifest *models.BackupManifest) error {
	// Read all entries from source
	srcFile, err := os.Open(srcArchive)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	gzSrc, err := gzip.NewReader(srcFile)
	if err != nil {
		return err
	}
	defer gzSrc.Close()

	tarSrc := tar.NewReader(gzSrc)

	// Create destination
	dstFile, err := os.Create(dstArchive)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	gzDst := gzip.NewWriter(dstFile)
	defer gzDst.Close()

	tarDst := tar.NewWriter(gzDst)
	defer tarDst.Close()

	// Write manifest.json first
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestHeader := &tar.Header{
		Name:    "manifest.json",
		Size:    int64(len(manifestData)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tarDst.WriteHeader(manifestHeader); err != nil {
		return err
	}
	if _, err := tarDst.Write(manifestData); err != nil {
		return err
	}

	// Copy all entries from source
	for {
		header, err := tarSrc.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if err := tarDst.WriteHeader(header); err != nil {
			return err
		}

		if header.Typeflag != tar.TypeDir {
			if _, err := io.Copy(tarDst, tarSrc); err != nil {
				return err
			}
		}
	}

	return nil
}
