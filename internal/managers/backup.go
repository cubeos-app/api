package managers

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cubeos-api/internal/models"
)

// BackupManager handles backup and restore operations
type BackupManager struct {
	backupDir string
}

// NewBackupManager creates a new BackupManager
func NewBackupManager() *BackupManager {
	backupDir := "/cubeos/data/backups"
	os.MkdirAll(backupDir, 0755)
	return &BackupManager{backupDir: backupDir}
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
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Parse backup metadata from filename or .meta file
		backup := models.BackupInfo{
			ID:        strings.TrimSuffix(entry.Name(), ".tar.gz"),
			Filename:  entry.Name(),
			SizeBytes: info.Size(),
			SizeHuman: m.humanSize(info.Size()),
			CreatedAt: info.ModTime().Format(time.RFC3339),
		}

		// Try to read metadata file
		metaPath := filepath.Join(m.backupDir, backup.ID+".meta")
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
			}
		}

		// Infer type from filename if not in metadata
		if backup.Type == "" {
			if strings.Contains(entry.Name(), "full") {
				backup.Type = "full"
			} else if strings.Contains(entry.Name(), "config") {
				backup.Type = "config"
			} else if strings.Contains(entry.Name(), "database") {
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

	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &models.SuccessResponse{Status: "error", Message: err.Error()}, err
		}

		// Security: don't extract outside expected paths
		if strings.Contains(header.Name, "..") {
			continue
		}

		// Create directories
		target := "/" + header.Name
		if header.Typeflag == tar.TypeDir {
			os.MkdirAll(target, 0755)
			continue
		}

		// Create parent directory
		os.MkdirAll(filepath.Dir(target), 0755)

		// Extract file
		outFile, err := os.Create(target)
		if err != nil {
			continue
		}

		io.Copy(outFile, tarReader)
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
