// Package managers provides mount management for CubeOS.
// This version uses the HAL (Hardware Abstraction Layer) service for
// mount operations since the API runs in a Swarm container without
// direct access to mount/umount commands.
package managers

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/hal"
)

// MountsManager handles SMB/NFS mount operations via HAL
type MountsManager struct {
	cfg *config.Config
	db  *sql.DB
	hal *hal.Client
}

// NewMountsManager creates a new mounts manager
func NewMountsManager(cfg *config.Config, halClient *hal.Client) *MountsManager {
	if halClient == nil {
		halClient = hal.NewClient("")
	}
	return &MountsManager{
		cfg: cfg,
		hal: halClient,
	}
}

// SetDB sets the database connection (called from main after orchestrator init)
func (m *MountsManager) SetDB(db *sql.DB) {
	m.db = db
}

// Mount represents a configured mount
type Mount struct {
	ID         int64     `json:"id" db:"id"`
	Name       string    `json:"name" db:"name"`
	Type       string    `json:"type" db:"type"` // "smb" or "nfs"
	RemotePath string    `json:"remote_path" db:"remote_path"`
	LocalPath  string    `json:"local_path" db:"local_path"`
	Username   string    `json:"username,omitempty" db:"username"`
	Password   string    `json:"-" db:"password"` // Never expose in JSON
	Options    string    `json:"options,omitempty" db:"options"`
	AutoMount  bool      `json:"auto_mount" db:"auto_mount"`
	IsMounted  bool      `json:"is_mounted" db:"is_mounted"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// CreateMountRequest is the request to create a new mount
type CreateMountRequest struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // "smb" or "nfs"
	RemotePath string `json:"remote_path"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Options    string `json:"options,omitempty"`
	AutoMount  bool   `json:"auto_mount"`
}

// ListMounts returns all configured mounts
func (m *MountsManager) ListMounts(ctx context.Context) ([]Mount, error) {
	if m.db == nil {
		return []Mount{}, nil
	}

	rows, err := m.db.QueryContext(ctx, `
		SELECT id, name, type, remote_path, local_path, username, password, options, auto_mount, is_mounted, created_at
		FROM mounts ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query mounts: %w", err)
	}
	defer rows.Close()

	var mounts []Mount
	for rows.Next() {
		var mount Mount
		if err := rows.Scan(&mount.ID, &mount.Name, &mount.Type, &mount.RemotePath, &mount.LocalPath,
			&mount.Username, &mount.Password, &mount.Options, &mount.AutoMount, &mount.IsMounted, &mount.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan mount: %w", err)
		}

		// Check actual mount status from /proc/mounts (readable from container)
		mount.IsMounted = m.checkMountStatus(mount.LocalPath)
		mounts = append(mounts, mount)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate mounts: %w", err)
	}

	return mounts, nil
}

// GetMount returns a single mount by ID
func (m *MountsManager) GetMount(ctx context.Context, id int64) (*Mount, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var mount Mount
	err := m.db.QueryRowContext(ctx, `
		SELECT id, name, type, remote_path, local_path, username, password, options, auto_mount, is_mounted, created_at
		FROM mounts WHERE id = ?
	`, id).Scan(&mount.ID, &mount.Name, &mount.Type, &mount.RemotePath, &mount.LocalPath,
		&mount.Username, &mount.Password, &mount.Options, &mount.AutoMount, &mount.IsMounted, &mount.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("mount not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mount: %w", err)
	}

	// Check actual mount status
	mount.IsMounted = m.checkMountStatus(mount.LocalPath)
	return &mount, nil
}

// CreateMount creates a new mount configuration
func (m *MountsManager) CreateMount(ctx context.Context, req *CreateMountRequest) (*Mount, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// Validate request
	if req.Name == "" {
		return nil, fmt.Errorf("mount name is required")
	}
	if req.Type != "smb" && req.Type != "nfs" {
		return nil, fmt.Errorf("mount type must be 'smb' or 'nfs'")
	}
	if req.RemotePath == "" {
		return nil, fmt.Errorf("remote path is required")
	}

	// Create local path
	localPath := fmt.Sprintf("/cubeos/mounts/%s", req.Name)

	// Insert into database
	result, err := m.db.ExecContext(ctx, `
		INSERT INTO mounts (name, type, remote_path, local_path, username, password, options, auto_mount, is_mounted, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.Type, req.RemotePath, localPath, req.Username, req.Password, req.Options, req.AutoMount, false, time.Now())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return nil, fmt.Errorf("mount with name '%s' already exists", req.Name)
		}
		return nil, fmt.Errorf("failed to create mount: %w", err)
	}

	id, _ := result.LastInsertId()
	return m.GetMount(ctx, id)
}

// DeleteMount removes a mount configuration
func (m *MountsManager) DeleteMount(ctx context.Context, id int64) error {
	if m.db == nil {
		return fmt.Errorf("database not initialized")
	}

	mount, err := m.GetMount(ctx, id)
	if err != nil {
		return err
	}

	// Unmount if mounted
	if mount.IsMounted {
		_ = m.UnmountPath(ctx, id) // Ignore error, continue with deletion
	}

	_, err = m.db.ExecContext(ctx, "DELETE FROM mounts WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete mount: %w", err)
	}

	return nil
}

// MountPath mounts a configured mount via HAL
func (m *MountsManager) MountPath(ctx context.Context, id int64) error {
	mount, err := m.GetMount(ctx, id)
	if err != nil {
		return err
	}

	if mount.IsMounted {
		return fmt.Errorf("already mounted")
	}

	// Create HAL mount request
	req := &hal.MountRequest{
		Name:       mount.Name,
		Type:       mount.Type,
		RemotePath: mount.RemotePath,
		LocalPath:  mount.LocalPath,
		Username:   mount.Username,
		Password:   mount.Password,
		Options:    mount.Options,
	}

	// Call HAL to mount
	var resp *hal.MountResponse
	if mount.Type == "smb" {
		resp, err = m.hal.MountSMB(ctx, req)
	} else {
		resp, err = m.hal.MountNFS(ctx, req)
	}

	if err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("mount failed: %s", resp.Message)
	}

	// Update database
	if m.db != nil {
		_, _ = m.db.ExecContext(ctx, "UPDATE mounts SET is_mounted = ? WHERE id = ?", true, id)
	}

	return nil
}

// UnmountPath unmounts a configured mount via HAL
func (m *MountsManager) UnmountPath(ctx context.Context, id int64) error {
	mount, err := m.GetMount(ctx, id)
	if err != nil {
		return err
	}

	if !mount.IsMounted {
		return fmt.Errorf("not mounted")
	}

	// Call HAL to unmount
	if err := m.hal.UnmountPath(ctx, mount.LocalPath); err != nil {
		return fmt.Errorf("unmount failed: %w", err)
	}

	// Update database
	if m.db != nil {
		_, _ = m.db.ExecContext(ctx, "UPDATE mounts SET is_mounted = ? WHERE id = ?", false, id)
	}

	return nil
}

// TestConnection tests connectivity to a remote share via HAL
func (m *MountsManager) TestConnection(ctx context.Context, mountType, remotePath, username, password string) error {
	return m.hal.TestMountConnection(ctx, mountType, remotePath, username, password)
}

// checkMountStatus checks if a path is mounted by reading /proc/mounts
// This works from inside the container since /proc is readable
func (m *MountsManager) checkMountStatus(localPath string) bool {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == localPath {
			return true
		}
	}
	return false
}

// MountAutoMounts mounts all mounts configured with auto_mount=true
func (m *MountsManager) MountAutoMounts(ctx context.Context) error {
	mounts, err := m.ListMounts(ctx)
	if err != nil {
		return err
	}

	var lastErr error
	for _, mount := range mounts {
		if mount.AutoMount && !mount.IsMounted {
			if err := m.MountPath(ctx, mount.ID); err != nil {
				lastErr = err
				// Continue with other mounts
			}
		}
	}
	return lastErr
}

// GetMountByName returns a mount by its name
func (m *MountsManager) GetMountByName(ctx context.Context, name string) (*Mount, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var mount Mount
	err := m.db.QueryRowContext(ctx, `
		SELECT id, name, type, remote_path, local_path, username, password, options, auto_mount, is_mounted, created_at
		FROM mounts WHERE name = ?
	`, name).Scan(&mount.ID, &mount.Name, &mount.Type, &mount.RemotePath, &mount.LocalPath,
		&mount.Username, &mount.Password, &mount.Options, &mount.AutoMount, &mount.IsMounted, &mount.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("mount not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mount: %w", err)
	}

	mount.IsMounted = m.checkMountStatus(mount.LocalPath)
	return &mount, nil
}
