package managers

import (
	"archive/tar"
	"bufio"
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
	"sort"
	"strings"
	"syscall"
	"time"

	"cubeos-api/internal/database"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// BackupManager handles backup and restore operations
type BackupManager struct {
	backupDir string
	db        *sql.DB
}

// NewBackupManager creates a new BackupManager
func NewBackupManager() *BackupManager {
	backupDir := "/cubeos/data/backups"
	os.MkdirAll(backupDir, 0755)
	return &BackupManager{backupDir: backupDir}
}

// SetDB wires the database connection. Called from main.go after DB is open.
func (m *BackupManager) SetDB(db *sql.DB) {
	m.db = db
}

// BackupDir returns the backup directory path.
func (m *BackupManager) BackupDir() string {
	return m.backupDir
}

// BackupPaths defines what to backup for each type
var BackupPaths = map[string][]string{
	"full": {
		"/cubeos/data",
		"/etc/hostapd",
		"/etc/dnsmasq.conf",
		"/etc/netplan",
	},
	"config": {
		"/cubeos/data/cubeos.db",
		"/cubeos/data/state",
		"/etc/hostapd/hostapd.conf",
		"/etc/dnsmasq.conf",
	},
	"user_data": {
		"/cubeos/data",
	},
	"database": {
		"/cubeos/data/cubeos.db",
	},
}

// ListBackups returns all available backups
func (m *BackupManager) ListBackups() []models.BackupInfo {
	var backups []models.BackupInfo

	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		return backups
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}

		// Accept .tar.gz and .tar.gz.enc backup files
		var backupID string
		var encrypted bool
		switch {
		case strings.HasSuffix(name, ".tar.gz.enc"):
			backupID = strings.TrimSuffix(name, ".tar.gz.enc")
			encrypted = true
		case strings.HasSuffix(name, ".tar.gz"):
			backupID = strings.TrimSuffix(name, ".tar.gz")
		default:
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Parse backup metadata from filename or .meta file
		backup := models.BackupInfo{
			ID:        backupID,
			Filename:  name,
			SizeBytes: info.Size(),
			SizeHuman: m.humanSize(info.Size()),
			CreatedAt: info.ModTime().Format(time.RFC3339),
			Encrypted: encrypted,
		}

		// Try to read metadata file (stored as <filename>.meta)
		metaPath := filepath.Join(m.backupDir, name+".meta")
		if metaData, err := os.ReadFile(metaPath); err == nil {
			var meta map[string]interface{}
			if json.Unmarshal(metaData, &meta) == nil {
				if t, ok := meta["type"].(string); ok {
					backup.Type = t
				}
				if d, ok := meta["description"].(string); ok {
					backup.Description = d
				}
				if inc, ok := meta["includes"].([]interface{}); ok {
					for _, i := range inc {
						if s, ok := i.(string); ok {
							backup.Includes = append(backup.Includes, s)
						}
					}
				}
				if enc, ok := meta["encrypted"].(bool); ok {
					backup.Encrypted = enc
				}
				if mode, ok := meta["encrypt_mode"].(string); ok {
					backup.EncryptMode = mode
				}
			}
		}

		// Infer type from filename if not in metadata
		if backup.Type == "" {
			if strings.Contains(name, "full") {
				backup.Type = "full"
			} else if strings.Contains(name, "config") {
				backup.Type = "config"
			} else if strings.Contains(name, "database") {
				backup.Type = "database"
			} else {
				backup.Type = "unknown"
			}
		}

		backups = append(backups, backup)
	}

	// Sort by creation time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt > backups[j].CreatedAt
	})

	return backups
}

// GetBackup returns details of a specific backup
func (m *BackupManager) GetBackup(backupID string) *models.BackupInfo {
	backups := m.ListBackups()
	for _, b := range backups {
		if b.ID == backupID {
			return &b
		}
	}
	return nil
}

// GetTotalSize returns total size of all backups
func (m *BackupManager) GetTotalSize() int64 {
	var total int64
	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if info, err := entry.Info(); err == nil {
			total += info.Size()
		}
	}
	return total
}

// CreateBackup creates a new backup
func (m *BackupManager) CreateBackup(backupType, description string, includeDockerVolumes, compress bool) (*models.SuccessResponse, error) {
	paths, ok := BackupPaths[backupType]
	if !ok {
		return &models.SuccessResponse{Status: "error", Message: "Invalid backup type"}, nil
	}

	// Generate backup ID and filename
	timestamp := time.Now().Format("20060102-150405")
	backupID := fmt.Sprintf("%s-%s", backupType, timestamp)
	filename := backupID + ".tar.gz"
	filepath := filepath.Join(m.backupDir, filename)

	// Create tarball
	file, err := os.Create(filepath)
	if err != nil {
		return &models.SuccessResponse{Status: "error", Message: err.Error()}, err
	}
	defer file.Close()

	var writer io.WriteCloser = file
	if compress {
		gzWriter := gzip.NewWriter(file)
		defer gzWriter.Close()
		writer = gzWriter
	}

	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()

	// Add files to tarball
	var includedPaths []string
	for _, path := range paths {
		// Try host-mounted paths if direct path doesn't exist
		actualPath := path
		if _, err := os.Stat(path); os.IsNotExist(err) {
			actualPath = "/host" + path
			if _, err := os.Stat(actualPath); os.IsNotExist(err) {
				continue
			}
		}

		err := m.addToTar(tarWriter, actualPath, path)
		if err == nil {
			includedPaths = append(includedPaths, path)
		}
	}

	// Write metadata file
	meta := map[string]interface{}{
		"type":        backupType,
		"description": description,
		"created_at":  time.Now().Format(time.RFC3339),
		"includes":    includedPaths,
		"compressed":  compress,
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(filepath+".meta", metaData, 0644)

	// Get file size
	if stat, err := os.Stat(filepath); err == nil {
		return &models.SuccessResponse{
			Status:  "success",
			Message: fmt.Sprintf("Backup created: %s (%s)", filename, m.humanSize(stat.Size())),
		}, nil
	}

	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("Backup created: %s", filename),
	}, nil
}

func (m *BackupManager) addToTar(tw *tar.Writer, srcPath, destPath string) error {
	return filepath.Walk(srcPath, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create header
		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}

		// Adjust the name to use destPath as base
		relPath, _ := filepath.Rel(srcPath, file)
		header.Name = filepath.Join(destPath, relPath)

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Write file content
		if !fi.IsDir() {
			f, err := os.Open(file)
			if err != nil {
				return err
			}
			defer f.Close()

			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
		}

		return nil
	})
}

// RestoreBackup restores from a backup
func (m *BackupManager) RestoreBackup(backupID string, restartServices bool) (*models.SuccessResponse, error) {
	backup := m.GetBackup(backupID)
	if backup == nil {
		return &models.SuccessResponse{Status: "error", Message: "Backup not found"}, nil
	}

	backupPath := filepath.Join(m.backupDir, backup.Filename)

	// Open tarball
	file, err := os.Open(backupPath)
	if err != nil {
		return &models.SuccessResponse{Status: "error", Message: err.Error()}, err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return &models.SuccessResponse{Status: "error", Message: err.Error()}, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	// Allowed restore target prefixes
	allowedRestorePrefixes := []string{"/cubeos/", "/etc/hostapd/", "/etc/dnsmasq.conf", "/etc/netplan/"}

	// Maximum single file size during restore: 500MB
	const maxRestoreFileSize int64 = 500 * 1024 * 1024

	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &models.SuccessResponse{Status: "error", Message: err.Error()}, err
		}

		// Security: clean the path and validate against allowed prefixes
		target := filepath.Clean("/" + header.Name)

		// Reject any path that still contains ".." after cleaning
		if strings.Contains(target, "..") {
			continue
		}

		// Validate target is within allowed restore paths
		allowed := false
		for _, prefix := range allowedRestorePrefixes {
			if strings.HasPrefix(target, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}

		if header.Typeflag == tar.TypeDir {
			os.MkdirAll(target, 0755)
			continue
		}

		// Skip excessively large files
		if header.Size > maxRestoreFileSize {
			continue
		}

		// Create parent directory
		os.MkdirAll(filepath.Dir(target), 0755)

		// Extract file with size-limited copy
		outFile, err := os.Create(target)
		if err != nil {
			continue
		}

		if _, err := io.Copy(outFile, io.LimitReader(tarReader, maxRestoreFileSize)); err != nil {
			outFile.Close()
			continue
		}
		outFile.Close()
		os.Chmod(target, os.FileMode(header.Mode))
	}

	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("Restored from backup: %s", backup.Filename),
	}, nil
}

// DeleteBackup deletes a backup
func (m *BackupManager) DeleteBackup(backupID string) *models.SuccessResponse {
	backup := m.GetBackup(backupID)
	if backup == nil {
		return &models.SuccessResponse{Status: "error", Message: "Backup not found"}
	}

	filepath := filepath.Join(m.backupDir, backup.Filename)
	metaPath := filepath + ".meta"

	os.Remove(filepath)
	os.Remove(metaPath)

	return &models.SuccessResponse{
		Status:  "success",
		Message: fmt.Sprintf("Deleted backup: %s", backup.Filename),
	}
}

// GetBackupFilePath returns the full path to a backup file
func (m *BackupManager) GetBackupFilePath(backupID string) string {
	backup := m.GetBackup(backupID)
	if backup == nil {
		return ""
	}
	return filepath.Join(m.backupDir, backup.Filename)
}

// GetStats returns backup statistics
func (m *BackupManager) GetStats() map[string]interface{} {
	backups := m.ListBackups()
	totalSize := m.GetTotalSize()

	byType := make(map[string]map[string]interface{})
	for _, backup := range backups {
		if _, ok := byType[backup.Type]; !ok {
			byType[backup.Type] = map[string]interface{}{
				"count": 0,
				"size":  int64(0),
			}
		}
		byType[backup.Type]["count"] = byType[backup.Type]["count"].(int) + 1
		byType[backup.Type]["size"] = byType[backup.Type]["size"].(int64) + backup.SizeBytes
	}

	return map[string]interface{}{
		"total_backups":    len(backups),
		"total_size_bytes": totalSize,
		"total_size_human": m.humanSize(totalSize),
		"by_type":          byType,
	}
}

// Checksum calculates SHA256 checksum of a backup
func (m *BackupManager) Checksum(backupID string) (string, error) {
	filepath := m.GetBackupFilePath(backupID)
	if filepath == "" {
		return "", fmt.Errorf("backup not found")
	}

	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (m *BackupManager) humanSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// =============================================================================
// Phase 4: Scope Tiers, Hot Backup, Manifest, Config Snapshot
// =============================================================================

// BackupPathEntry describes a single path to include in a backup.
type BackupPathEntry struct {
	SourcePath  string // Absolute path on disk
	ArchivePath string // Path inside the tar archive
	Description string // Human-readable description
	Category    string // P3 category: config, database, coreapp_data, app_data, config_snapshot
}

// ScopePaths returns the list of paths to include for a given backup scope.
// Tier 1 always included, Tier 2 adds to it, Tier 3 adds to Tier 2.
func (m *BackupManager) ScopePaths(scope models.BackupScope) []BackupPathEntry {
	var entries []BackupPathEntry

	// Tier 1: DB + Config (~2 MB typical)
	entries = append(entries,
		BackupPathEntry{
			SourcePath:  "/cubeos/data/cubeos.db",
			ArchivePath: "cubeos/data/cubeos.db",
			Description: "SQLite database",
			Category:    "database",
		},
		BackupPathEntry{
			SourcePath:  "/cubeos/config/",
			ArchivePath: "cubeos/config/",
			Description: "System config files (defaults.env, secrets.env)",
			Category:    "config",
		},
		BackupPathEntry{
			SourcePath:  "/cubeos/coreapps/image-versions.env",
			ArchivePath: "cubeos/coreapps/image-versions.env",
			Description: "Container image version pins",
			Category:    "config",
		},
	)

	if scope == models.BackupScopeTier1 {
		return entries
	}

	// Tier 2: Tier 1 + Network + App Configs (~5-20 MB typical)
	entries = append(entries,
		BackupPathEntry{
			SourcePath:  "/cubeos/coreapps/pihole/appdata/etc-pihole/pihole.toml",
			ArchivePath: "cubeos/coreapps/pihole/appdata/etc-pihole/pihole.toml",
			Description: "Pi-hole configuration",
			Category:    "coreapp_data",
		},
		BackupPathEntry{
			SourcePath:  "/cubeos/coreapps/npm/appdata/data/database.sqlite",
			ArchivePath: "cubeos/coreapps/npm/appdata/data/database.sqlite",
			Description: "NPM database",
			Category:    "coreapp_data",
		},
		BackupPathEntry{
			SourcePath:  "/cubeos/coreapps/pihole/appdata/etc-dnsmasq/",
			ArchivePath: "cubeos/coreapps/pihole/appdata/etc-dnsmasq/",
			Description: "DNS masq configuration",
			Category:    "coreapp_data",
		},
	)

	// Add each coreapp's appconfig directory
	m.addCoreappConfigs(&entries)

	if scope == models.BackupScopeTier2 {
		return entries
	}

	// Tier 3: Tier 2 + Docker Volumes (~100 MB - 10 GB)
	m.addCoreappData(&entries)
	m.addUserAppData(&entries)

	return entries
}

// addCoreappConfigs adds /cubeos/coreapps/*/appconfig/ directories.
func (m *BackupManager) addCoreappConfigs(entries *[]BackupPathEntry) {
	coreappsDir := "/cubeos/coreapps"
	dirEntries, err := os.ReadDir(coreappsDir)
	if err != nil {
		return
	}
	for _, d := range dirEntries {
		if !d.IsDir() {
			continue
		}
		configDir := filepath.Join(coreappsDir, d.Name(), "appconfig")
		if fi, err := os.Stat(configDir); err == nil && fi.IsDir() {
			*entries = append(*entries, BackupPathEntry{
				SourcePath:  configDir + "/",
				ArchivePath: filepath.Join("cubeos/coreapps", d.Name(), "appconfig") + "/",
				Description: fmt.Sprintf("Coreapp %s compose config", d.Name()),
				Category:    "coreapp_data",
			})
		}
	}
}

// addCoreappData adds /cubeos/coreapps/*/appdata/ directories (Tier 3).
func (m *BackupManager) addCoreappData(entries *[]BackupPathEntry) {
	coreappsDir := "/cubeos/coreapps"
	dirEntries, err := os.ReadDir(coreappsDir)
	if err != nil {
		return
	}
	for _, d := range dirEntries {
		if !d.IsDir() {
			continue
		}
		dataDir := filepath.Join(coreappsDir, d.Name(), "appdata")
		if fi, err := os.Stat(dataDir); err == nil && fi.IsDir() {
			*entries = append(*entries, BackupPathEntry{
				SourcePath:  dataDir + "/",
				ArchivePath: filepath.Join("cubeos/coreapps", d.Name(), "appdata") + "/",
				Description: fmt.Sprintf("Coreapp %s data volumes", d.Name()),
				Category:    "coreapp_data",
			})
		}
	}
}

// addUserAppData adds /cubeos/apps/*/ directories (Tier 3).
func (m *BackupManager) addUserAppData(entries *[]BackupPathEntry) {
	appsDir := "/cubeos/apps"
	dirEntries, err := os.ReadDir(appsDir)
	if err != nil {
		return
	}
	for _, d := range dirEntries {
		if !d.IsDir() {
			continue
		}
		appDir := filepath.Join(appsDir, d.Name())
		*entries = append(*entries, BackupPathEntry{
			SourcePath:  appDir + "/",
			ArchivePath: filepath.Join("cubeos/apps", d.Name()) + "/",
			Description: fmt.Sprintf("User app %s data", d.Name()),
			Category:    "app_data",
		})
	}
}

// HotBackupDatabase creates a consistent snapshot of the SQLite database
// using VACUUM INTO. This is safe to call while the database is being written
// to — it creates a point-in-time consistent copy without blocking readers.
func (m *BackupManager) HotBackupDatabase(ctx context.Context, destPath string) error {
	if m.db == nil {
		return fmt.Errorf("database not wired — call SetDB first")
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Remove any existing file at destPath (VACUUM INTO fails if file exists)
	os.Remove(destPath)

	log.Info().Str("dest", destPath).Msg("backup: creating hot database snapshot via VACUUM INTO")
	_, err := m.db.ExecContext(ctx, "VACUUM INTO ?", destPath)
	if err != nil {
		return fmt.Errorf("VACUUM INTO failed: %w", err)
	}

	log.Info().Str("dest", destPath).Msg("backup: database snapshot created successfully")
	return nil
}

// CreateBackupManifest generates a manifest describing the backup contents.
func (m *BackupManager) CreateBackupManifest(scope models.BackupScope, archivePath string) (*models.BackupManifest, error) {
	manifest := &models.BackupManifest{
		Version:       os.Getenv("CUBEOS_VERSION"),
		Scope:         scope,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		SchemaVer:     database.CurrentSchemaVersion,
		Encrypted:     false,
		NetworkMode:   m.getCurrentNetworkMode(),
		Apps:          m.getInstalledAppNames(),
		HasConfigSnap: true,
	}

	// Walk the archive and compute per-file SHA256
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive for manifest: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read error: %w", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}

		h := sha256.New()
		n, _ := io.Copy(h, tarReader)

		manifest.Files = append(manifest.Files, models.BackupFileEntry{
			Path:     header.Name,
			Size:     n,
			Checksum: hex.EncodeToString(h.Sum(nil)),
			Category: categorizeArchivePath(header.Name),
		})
	}

	return manifest, nil
}

// VerifyBackup reads a backup archive and verifies integrity against its manifest.
func (m *BackupManager) VerifyBackup(backupPath string) (*models.BackupManifest, error) {
	// Extract manifest.json from archive
	manifest, err := m.extractManifest(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract manifest: %w", err)
	}

	// Build checksum lookup from manifest
	expectedChecksums := make(map[string]string, len(manifest.Files))
	for _, f := range manifest.Files {
		expectedChecksums[f.Path] = f.Checksum
	}

	// Walk archive and verify checksums
	file, err := os.Open(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open backup: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	verified := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read error: %w", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}

		expected, inManifest := expectedChecksums[header.Name]
		if !inManifest {
			continue // file not tracked in manifest (e.g. manifest.json itself)
		}

		h := sha256.New()
		io.Copy(h, tarReader)
		actual := hex.EncodeToString(h.Sum(nil))

		if actual != expected {
			return manifest, fmt.Errorf("checksum mismatch for %s: expected %s, got %s", header.Name, expected, actual)
		}
		verified++
	}

	log.Info().Int("verified", verified).Int("total", len(manifest.Files)).Msg("backup: verification complete")
	return manifest, nil
}

// extractManifest reads manifest.json from a backup archive.
func (m *BackupManager) extractManifest(backupPath string) (*models.BackupManifest, error) {
	file, err := os.Open(backupPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("manifest.json not found in archive")
		}
		if err != nil {
			return nil, err
		}

		if filepath.Base(header.Name) == "manifest.json" {
			var manifest models.BackupManifest
			if err := json.NewDecoder(tarReader).Decode(&manifest); err != nil {
				return nil, fmt.Errorf("failed to decode manifest.json: %w", err)
			}
			return &manifest, nil
		}
	}
}

// GenerateConfigSnapshot reads the current system state and produces
// a P0-compatible config snapshot.
func (m *BackupManager) GenerateConfigSnapshot(ctx context.Context) (*models.ConfigSnapshot, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not wired — call SetDB first")
	}

	snapshot := &models.ConfigSnapshot{
		ConfigVersion: 1,
		Metadata: models.ConfigMetadata{
			ExportedAt:    time.Now().UTC().Format(time.RFC3339),
			CubeOSVersion: os.Getenv("CUBEOS_VERSION"),
			SchemaVersion: database.CurrentSchemaVersion,
		},
	}

	snapshot.System = m.readSystemConfig()
	snapshot.Network = m.readNetworkConfig(ctx)
	snapshot.Users = m.readUsers(ctx)
	snapshot.Apps = m.readApps(ctx)
	snapshot.Profiles = m.readProfiles(ctx)
	snapshot.Preferences = m.readPreferences(ctx)
	snapshot.VPNConfigs = m.readVPNConfigs(ctx)
	snapshot.Mounts = m.readMounts(ctx)

	return snapshot, nil
}

// StoreConfigSnapshot saves a config snapshot to the config_snapshots table.
func (m *BackupManager) StoreConfigSnapshot(ctx context.Context, trigger, description string, snapshot *models.ConfigSnapshot) error {
	if m.db == nil {
		return fmt.Errorf("database not wired")
	}

	configJSON, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal config snapshot: %w", err)
	}

	_, err = m.db.ExecContext(ctx,
		`INSERT INTO config_snapshots (trigger, description, config_json, cubeos_version, schema_version)
		 VALUES (?, ?, ?, ?, ?)`,
		trigger, description, string(configJSON),
		os.Getenv("CUBEOS_VERSION"), database.CurrentSchemaVersion,
	)
	return err
}

// AddJSONToTar writes a JSON-encoded value as a file inside a tar archive.
func (m *BackupManager) AddJSONToTar(tw *tar.Writer, archivePath string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON for %s: %w", archivePath, err)
	}
	header := &tar.Header{
		Name:    archivePath,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

// AddFileToTar adds a single file to a tar archive.
func (m *BackupManager) AddFileToTar(tw *tar.Writer, srcPath, archivePath string) error {
	fi, err := os.Stat(srcPath)
	if err != nil {
		return err
	}

	if fi.IsDir() {
		return m.addToTar(tw, srcPath, archivePath)
	}

	header, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	header.Name = archivePath

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(tw, f)
	return err
}

// CheckDiskSpace returns free bytes on the filesystem containing the given path.
func (m *BackupManager) CheckDiskSpace(path string) (uint64, error) {
	// Use /proc/mounts or df approach — but for simplicity, stat the filesystem
	fi, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	// If path doesn't exist, check parent
	checkPath := path
	if os.IsNotExist(err) {
		checkPath = filepath.Dir(path)
	}
	_ = fi

	// Read from /proc/mounts to find the mount point, then use syscall.Statfs
	var stat syscall.Statfs_t
	if err := syscall.Statfs(checkPath, &stat); err != nil {
		return 0, fmt.Errorf("statfs failed: %w", err)
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

// --- Private helpers for config snapshot ---

func (m *BackupManager) getCurrentNetworkMode() string {
	if m.db == nil {
		return "unknown"
	}
	var mode string
	err := m.db.QueryRow("SELECT mode FROM network_config WHERE id = 1").Scan(&mode)
	if err != nil {
		return "unknown"
	}
	return mode
}

func (m *BackupManager) getInstalledAppNames() []string {
	if m.db == nil {
		return nil
	}
	rows, err := m.db.Query("SELECT name FROM apps ORDER BY name")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			names = append(names, name)
		}
	}
	return names
}

func (m *BackupManager) readSystemConfig() models.ConfigSystem {
	sys := models.ConfigSystem{}
	// Read from defaults.env
	envPath := "/cubeos/config/defaults.env"
	envMap := m.parseEnvFile(envPath)
	sys.Timezone = envMap["TZ"]
	sys.Domain = envMap["DOMAIN"]
	sys.GatewayIP = envMap["GATEWAY_IP"]
	sys.Subnet = envMap["SUBNET"]
	sys.CountryCode = envMap["COUNTRY_CODE"]
	hostname, _ := os.Hostname()
	sys.Hostname = hostname
	return sys
}

func (m *BackupManager) readNetworkConfig(ctx context.Context) models.ConfigNetwork {
	net := models.ConfigNetwork{}
	if m.db == nil {
		return net
	}
	row := m.db.QueryRowContext(ctx, "SELECT mode, ap_ssid, ap_password, ap_channel FROM network_config WHERE id = 1")
	var apChannel int
	row.Scan(&net.Mode, &net.WiFiAPSSID, &net.WiFiAPPass, &apChannel)
	net.WiFiChannel = apChannel
	return net
}

func (m *BackupManager) readUsers(ctx context.Context) []models.ConfigUser {
	if m.db == nil {
		return nil
	}
	rows, err := m.db.QueryContext(ctx, "SELECT username, role, password_hash FROM users")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var users []models.ConfigUser
	for rows.Next() {
		var u models.ConfigUser
		if err := rows.Scan(&u.Username, &u.Role, &u.PasswordHash); err == nil {
			users = append(users, u)
		}
	}
	return users
}

func (m *BackupManager) readApps(ctx context.Context) []models.ConfigApp {
	if m.db == nil {
		return nil
	}
	rows, err := m.db.QueryContext(ctx,
		`SELECT a.name, a.source, COALESCE(a.store_id, ''), COALESCE(p.port, 0), COALESCE(f.fqdn, ''), a.enabled
		 FROM apps a
		 LEFT JOIN port_allocations p ON p.app_id = a.id AND p.is_primary = TRUE
		 LEFT JOIN fqdns f ON f.app_id = a.id
		 ORDER BY a.name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var apps []models.ConfigApp
	for rows.Next() {
		var a models.ConfigApp
		if err := rows.Scan(&a.Name, &a.Source, &a.StoreID, &a.Port, &a.FQDN, &a.Enabled); err == nil {
			apps = append(apps, a)
		}
	}
	return apps
}

func (m *BackupManager) readProfiles(ctx context.Context) []models.ConfigProfile {
	if m.db == nil {
		return nil
	}
	rows, err := m.db.QueryContext(ctx, "SELECT id, name, display_name, is_active FROM profiles")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var profiles []models.ConfigProfile
	for rows.Next() {
		var id int
		var p models.ConfigProfile
		if err := rows.Scan(&id, &p.Name, &p.DisplayName, &p.IsActive); err == nil {
			// Get apps for this profile
			appRows, err := m.db.QueryContext(ctx,
				"SELECT a.name FROM profile_apps pa JOIN apps a ON a.id = pa.app_id WHERE pa.profile_id = ? AND pa.enabled = TRUE", id)
			if err == nil {
				for appRows.Next() {
					var appName string
					if appRows.Scan(&appName) == nil {
						p.Apps = append(p.Apps, appName)
					}
				}
				appRows.Close()
			}
			profiles = append(profiles, p)
		}
	}
	return profiles
}

func (m *BackupManager) readPreferences(ctx context.Context) map[string]string {
	prefs := make(map[string]string)
	if m.db == nil {
		return prefs
	}
	rows, err := m.db.QueryContext(ctx, "SELECT key, value FROM preferences")
	if err != nil {
		return prefs
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			prefs[k] = v
		}
	}
	return prefs
}

func (m *BackupManager) readVPNConfigs(ctx context.Context) []models.ConfigVPN {
	if m.db == nil {
		return nil
	}
	rows, err := m.db.QueryContext(ctx, "SELECT name, type, auto_connect FROM vpn_configs")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var vpns []models.ConfigVPN
	for rows.Next() {
		var v models.ConfigVPN
		if err := rows.Scan(&v.Name, &v.Type, &v.AutoConnect); err == nil {
			vpns = append(vpns, v)
		}
	}
	return vpns
}

func (m *BackupManager) readMounts(ctx context.Context) []models.ConfigMount {
	if m.db == nil {
		return nil
	}
	rows, err := m.db.QueryContext(ctx, "SELECT name, type, remote_path, auto_mount FROM mounts")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var mounts []models.ConfigMount
	for rows.Next() {
		var mt models.ConfigMount
		if err := rows.Scan(&mt.Name, &mt.Type, &mt.RemotePath, &mt.AutoMount); err == nil {
			mounts = append(mounts, mt)
		}
	}
	return mounts
}

// parseEnvFile reads a KEY=VALUE env file into a map.
func (m *BackupManager) parseEnvFile(path string) map[string]string {
	result := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			result[key] = val
		}
	}
	return result
}

// categorizeArchivePath determines the P3 category for a file in the backup archive.
func categorizeArchivePath(archivePath string) string {
	switch {
	case strings.Contains(archivePath, "cubeos-config.json"):
		return "config_snapshot"
	case strings.Contains(archivePath, "cubeos.db"):
		return "database"
	case strings.HasPrefix(archivePath, "cubeos/config/"):
		return "config"
	case strings.Contains(archivePath, "image-versions.env"):
		return "config"
	case strings.HasPrefix(archivePath, "cubeos/apps/"):
		return "app_data"
	case strings.HasPrefix(archivePath, "cubeos/coreapps/"):
		return "coreapp_data"
	default:
		return "config"
	}
}

// RecordBackupInDB inserts or updates a backup record in the backups table.
func (m *BackupManager) RecordBackupInDB(ctx context.Context, name, scope, destType, destPath, checksum, workflowID string, sizeBytes int64, manifest *models.BackupManifest) error {
	if m.db == nil {
		return fmt.Errorf("database not wired")
	}

	manifestJSON := ""
	if manifest != nil {
		data, err := json.Marshal(manifest)
		if err == nil {
			manifestJSON = string(data)
		}
	}

	_, err := m.db.ExecContext(ctx,
		`INSERT INTO backups (name, destination, scope, destination_type, destination_path, checksum, workflow_id, size_bytes, manifest_json, last_run, last_status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'completed')`,
		name, destPath, scope, destType, destPath, checksum, workflowID, sizeBytes, manifestJSON,
	)
	return err
}
