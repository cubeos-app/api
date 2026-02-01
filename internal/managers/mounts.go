// Package managers provides SMB/NFS mount management for CubeOS.
package managers

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/config"
)

// MountType represents the type of network mount
type MountType string

const (
	MountTypeSMB MountType = "smb"
	MountTypeNFS MountType = "nfs"
)

// Mount represents a network mount configuration
type Mount struct {
	ID         int64     `json:"id" db:"id"`
	Name       string    `json:"name" db:"name"`
	Type       MountType `json:"type" db:"type"`
	RemotePath string    `json:"remote_path" db:"remote_path"`
	LocalPath  string    `json:"local_path" db:"local_path"`
	Username   string    `json:"username,omitempty" db:"username"`
	Password   string    `json:"-" db:"password"` // Never expose password
	Options    string    `json:"options,omitempty" db:"options"`
	AutoMount  bool      `json:"auto_mount" db:"auto_mount"`
	IsMounted  bool      `json:"is_mounted" db:"is_mounted"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// MountRequest represents a request to create a mount
type MountRequest struct {
	Name       string    `json:"name"`
	Type       MountType `json:"type"`
	RemotePath string    `json:"remote_path"`
	Username   string    `json:"username,omitempty"`
	Password   string    `json:"password,omitempty"`
	Options    string    `json:"options,omitempty"`
	AutoMount  bool      `json:"auto_mount"`
}

// MountStatus represents the status of a mount point
type MountStatus struct {
	Name       string `json:"name"`
	IsMounted  bool   `json:"is_mounted"`
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
	Type       string `json:"type"`
	UsedBytes  int64  `json:"used_bytes,omitempty"`
	TotalBytes int64  `json:"total_bytes,omitempty"`
	FreeBytes  int64  `json:"free_bytes,omitempty"`
}

// MountsManager handles network mount operations
type MountsManager struct {
	cfg        *config.Config
	mountsDir  string
	configFile string
}

// NewMountsManager creates a new mounts manager
func NewMountsManager(cfg *config.Config) *MountsManager {
	return &MountsManager{
		cfg:        cfg,
		mountsDir:  "/cubeos/mounts",
		configFile: "/cubeos/config/mounts.conf",
	}
}

// ListMounts returns all configured mounts
func (m *MountsManager) ListMounts(ctx context.Context) ([]*Mount, error) {
	mounts, err := m.loadMounts()
	if err != nil {
		return nil, err
	}

	// Check mount status for each
	for _, mount := range mounts {
		mount.IsMounted = m.isMounted(mount.LocalPath)
	}

	return mounts, nil
}

// GetMount returns a specific mount by name
func (m *MountsManager) GetMount(ctx context.Context, name string) (*Mount, error) {
	mounts, err := m.ListMounts(ctx)
	if err != nil {
		return nil, err
	}

	for _, mount := range mounts {
		if mount.Name == name {
			return mount, nil
		}
	}

	return nil, fmt.Errorf("mount not found: %s", name)
}

// AddMount creates a new mount configuration
func (m *MountsManager) AddMount(ctx context.Context, req *MountRequest) (*Mount, error) {
	// Validate request
	if req.Name == "" {
		return nil, fmt.Errorf("mount name is required")
	}
	if strings.ContainsAny(req.Name, "/\\. ") {
		return nil, fmt.Errorf("mount name contains invalid characters")
	}
	if req.Type == "" {
		return nil, fmt.Errorf("mount type is required (smb or nfs)")
	}
	if req.RemotePath == "" {
		return nil, fmt.Errorf("remote path is required")
	}

	// Validate remote path format
	switch req.Type {
	case MountTypeSMB:
		if !strings.HasPrefix(req.RemotePath, "//") {
			return nil, fmt.Errorf("SMB remote path must start with // (e.g., //server/share)")
		}
	case MountTypeNFS:
		if !strings.Contains(req.RemotePath, ":") {
			return nil, fmt.Errorf("NFS remote path must contain : (e.g., server:/path)")
		}
	default:
		return nil, fmt.Errorf("unsupported mount type: %s", req.Type)
	}

	// Check for duplicate
	existing, _ := m.GetMount(ctx, req.Name)
	if existing != nil {
		return nil, fmt.Errorf("mount already exists: %s", req.Name)
	}

	// Create local mount point directory
	localPath := filepath.Join(m.mountsDir, req.Name)
	if err := os.MkdirAll(localPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create mount point: %w", err)
	}

	mount := &Mount{
		ID:         time.Now().UnixNano(),
		Name:       req.Name,
		Type:       req.Type,
		RemotePath: req.RemotePath,
		LocalPath:  localPath,
		Username:   req.Username,
		Password:   req.Password,
		Options:    req.Options,
		AutoMount:  req.AutoMount,
		IsMounted:  false,
		CreatedAt:  time.Now(),
	}

	// Save to config file
	if err := m.saveMount(mount); err != nil {
		return nil, fmt.Errorf("failed to save mount configuration: %w", err)
	}

	// Create credentials file for SMB if needed
	if mount.Type == MountTypeSMB && mount.Username != "" {
		if err := m.createCredentialsFile(mount); err != nil {
			return nil, fmt.Errorf("failed to create credentials file: %w", err)
		}
	}

	// Add to fstab if auto_mount is enabled
	if mount.AutoMount {
		if err := m.addToFstab(mount); err != nil {
			// Non-fatal, just log
			fmt.Printf("Warning: failed to add to fstab: %v\n", err)
		}
	}

	return mount, nil
}

// DeleteMount removes a mount configuration
func (m *MountsManager) DeleteMount(ctx context.Context, name string) error {
	mount, err := m.GetMount(ctx, name)
	if err != nil {
		return err
	}

	// Unmount if mounted
	if mount.IsMounted {
		if err := m.Unmount(ctx, name); err != nil {
			return fmt.Errorf("failed to unmount before deletion: %w", err)
		}
	}

	// Remove from fstab
	m.removeFromFstab(mount)

	// Remove credentials file if exists
	credsFile := filepath.Join("/cubeos/config", fmt.Sprintf(".%s.creds", name))
	os.Remove(credsFile)

	// Remove mount point directory (only if empty)
	os.Remove(mount.LocalPath)

	// Remove from config
	return m.removeMountConfig(name)
}

// Mount mounts a configured share
func (m *MountsManager) Mount(ctx context.Context, name string) error {
	mount, err := m.GetMount(ctx, name)
	if err != nil {
		return err
	}

	if mount.IsMounted {
		return nil // Already mounted
	}

	var cmd *exec.Cmd
	switch mount.Type {
	case MountTypeSMB:
		cmd = m.buildSMBMountCommand(mount)
	case MountTypeNFS:
		cmd = m.buildNFSMountCommand(mount)
	default:
		return fmt.Errorf("unsupported mount type: %s", mount.Type)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount failed: %s: %w", string(output), err)
	}

	return nil
}

// Unmount unmounts a share
func (m *MountsManager) Unmount(ctx context.Context, name string) error {
	mount, err := m.GetMount(ctx, name)
	if err != nil {
		return err
	}

	if !mount.IsMounted {
		return nil // Already unmounted
	}

	cmd := exec.Command("umount", mount.LocalPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try lazy unmount
		cmd = exec.Command("umount", "-l", mount.LocalPath)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("unmount failed: %s: %w", string(output), err)
		}
	}

	return nil
}

// GetMountStatus returns detailed status of a mount
func (m *MountsManager) GetMountStatus(ctx context.Context, name string) (*MountStatus, error) {
	mount, err := m.GetMount(ctx, name)
	if err != nil {
		return nil, err
	}

	status := &MountStatus{
		Name:       mount.Name,
		IsMounted:  mount.IsMounted,
		LocalPath:  mount.LocalPath,
		RemotePath: mount.RemotePath,
		Type:       string(mount.Type),
	}

	// Get disk usage if mounted
	if mount.IsMounted {
		cmd := exec.Command("df", "-B1", mount.LocalPath)
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) >= 2 {
				fields := strings.Fields(lines[1])
				if len(fields) >= 4 {
					fmt.Sscanf(fields[1], "%d", &status.TotalBytes)
					fmt.Sscanf(fields[2], "%d", &status.UsedBytes)
					fmt.Sscanf(fields[3], "%d", &status.FreeBytes)
				}
			}
		}
	}

	return status, nil
}

// Helper methods

func (m *MountsManager) isMounted(path string) bool {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == path {
			return true
		}
	}

	return false
}

func (m *MountsManager) loadMounts() ([]*Mount, error) {
	var mounts []*Mount

	file, err := os.Open(m.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return mounts, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var id int64 = 1
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: name|type|remote_path|local_path|username|options|auto_mount
		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			continue
		}

		mount := &Mount{
			ID:         id,
			Name:       parts[0],
			Type:       MountType(parts[1]),
			RemotePath: parts[2],
			LocalPath:  parts[3],
		}
		id++

		if len(parts) > 4 {
			mount.Username = parts[4]
		}
		if len(parts) > 5 {
			mount.Options = parts[5]
		}
		if len(parts) > 6 {
			mount.AutoMount = parts[6] == "true"
		}

		mounts = append(mounts, mount)
	}

	return mounts, scanner.Err()
}

func (m *MountsManager) saveMount(mount *Mount) error {
	// Ensure config directory exists
	if err := os.MkdirAll(filepath.Dir(m.configFile), 0755); err != nil {
		return err
	}

	// Append to config file
	f, err := os.OpenFile(m.configFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	autoMount := "false"
	if mount.AutoMount {
		autoMount = "true"
	}

	line := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s\n",
		mount.Name, mount.Type, mount.RemotePath, mount.LocalPath,
		mount.Username, mount.Options, autoMount)

	_, err = f.WriteString(line)
	return err
}

func (m *MountsManager) removeMountConfig(name string) error {
	mounts, err := m.loadMounts()
	if err != nil {
		return err
	}

	// Rewrite config without the deleted mount
	f, err := os.Create(m.configFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, mount := range mounts {
		if mount.Name == name {
			continue
		}

		autoMount := "false"
		if mount.AutoMount {
			autoMount = "true"
		}

		line := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s\n",
			mount.Name, mount.Type, mount.RemotePath, mount.LocalPath,
			mount.Username, mount.Options, autoMount)
		f.WriteString(line)
	}

	return nil
}

func (m *MountsManager) createCredentialsFile(mount *Mount) error {
	credsFile := filepath.Join("/cubeos/config", fmt.Sprintf(".%s.creds", mount.Name))

	content := fmt.Sprintf("username=%s\npassword=%s\n", mount.Username, mount.Password)
	return os.WriteFile(credsFile, []byte(content), 0600)
}

func (m *MountsManager) buildSMBMountCommand(mount *Mount) *exec.Cmd {
	options := []string{"-t", "cifs"}

	// Build mount options
	mountOpts := []string{"vers=3.0"}

	if mount.Username != "" {
		credsFile := filepath.Join("/cubeos/config", fmt.Sprintf(".%s.creds", mount.Name))
		mountOpts = append(mountOpts, fmt.Sprintf("credentials=%s", credsFile))
	} else {
		mountOpts = append(mountOpts, "guest")
	}

	if mount.Options != "" {
		mountOpts = append(mountOpts, mount.Options)
	}

	options = append(options, "-o", strings.Join(mountOpts, ","))
	options = append(options, mount.RemotePath, mount.LocalPath)

	return exec.Command("mount", options...)
}

func (m *MountsManager) buildNFSMountCommand(mount *Mount) *exec.Cmd {
	options := []string{"-t", "nfs"}

	mountOpts := []string{"rw", "soft", "intr"}
	if mount.Options != "" {
		mountOpts = append(mountOpts, mount.Options)
	}

	options = append(options, "-o", strings.Join(mountOpts, ","))
	options = append(options, mount.RemotePath, mount.LocalPath)

	return exec.Command("mount", options...)
}

func (m *MountsManager) addToFstab(mount *Mount) error {
	// Read current fstab
	content, err := os.ReadFile("/etc/fstab")
	if err != nil {
		return err
	}

	// Check if already in fstab
	if strings.Contains(string(content), mount.LocalPath) {
		return nil
	}

	// Build fstab entry
	var entry string
	switch mount.Type {
	case MountTypeSMB:
		credsFile := filepath.Join("/cubeos/config", fmt.Sprintf(".%s.creds", mount.Name))
		if mount.Username != "" {
			entry = fmt.Sprintf("%s %s cifs credentials=%s,vers=3.0,noauto,x-systemd.automount 0 0\n",
				mount.RemotePath, mount.LocalPath, credsFile)
		} else {
			entry = fmt.Sprintf("%s %s cifs guest,vers=3.0,noauto,x-systemd.automount 0 0\n",
				mount.RemotePath, mount.LocalPath)
		}
	case MountTypeNFS:
		entry = fmt.Sprintf("%s %s nfs rw,soft,intr,noauto,x-systemd.automount 0 0\n",
			mount.RemotePath, mount.LocalPath)
	}

	// Append to fstab
	f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(entry)
	return err
}

func (m *MountsManager) removeFromFstab(mount *Mount) error {
	content, err := os.ReadFile("/etc/fstab")
	if err != nil {
		return err
	}

	// Filter out the mount entry
	var lines []string
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.Contains(line, mount.LocalPath) {
			lines = append(lines, line)
		}
	}

	return os.WriteFile("/etc/fstab", []byte(strings.Join(lines, "\n")), 0644)
}

// TestConnection tests connectivity to a remote share without mounting
func (m *MountsManager) TestConnection(ctx context.Context, mountType MountType, remotePath, username, password string) error {
	switch mountType {
	case MountTypeSMB:
		// Use smbclient to test
		args := []string{"-L", strings.Split(remotePath, "/")[2], "-N"}
		if username != "" {
			args = []string{"-L", strings.Split(remotePath, "/")[2], "-U", fmt.Sprintf("%s%%%s", username, password)}
		}
		cmd := exec.Command("smbclient", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("SMB connection test failed: %s", string(output))
		}
		return nil

	case MountTypeNFS:
		// Use showmount to test
		parts := strings.SplitN(remotePath, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid NFS path format")
		}
		cmd := exec.Command("showmount", "-e", parts[0])
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("NFS connection test failed: %s", string(output))
		}
		return nil

	default:
		return fmt.Errorf("unsupported mount type: %s", mountType)
	}
}
