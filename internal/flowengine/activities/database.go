package activities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/flowengine"

	"github.com/rs/zerolog/log"
)

// AppDatabase defines the database operations needed by DB activities.
// Satisfied by *sql.DB (with appropriate query methods).
type AppDatabase interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// PortAllocator defines the port allocation operations needed by DB activities.
// Satisfied by *managers.PortManager.
type PortAllocator interface {
	AllocateUserPort() (int, error)
	ReleasePort(port int) error
}

// --- Input/Output Schemas ---

// InsertAppInput is the input for the db.insert_app activity.
type InsertAppInput struct {
	Name        string `json:"name"`
	Port        int    `json:"port"`
	FQDN        string `json:"fqdn"`
	Source      string `json:"source"`       // "casaos", "registry", "custom"
	Image       string `json:"image"`        // Docker image reference
	ComposePath string `json:"compose_path"` // path to docker-compose.yml
	DataPath    string `json:"data_path"`    // path to app data directory
	StoreID     string `json:"store_id,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// InsertAppOutput is the output of the db.insert_app activity.
type InsertAppOutput struct {
	AppID   int64  `json:"app_id"`
	Name    string `json:"name"`
	Created bool   `json:"created"`
	Skipped bool   `json:"skipped"` // true if app already existed
}

// DeleteAppInput is the input for the db.delete_app activity.
type DeleteAppInput struct {
	AppID   int64  `json:"app_id,omitempty"`
	AppName string `json:"app_name,omitempty"` // fallback if ID not known
}

// DeleteAppOutput is the output of the db.delete_app activity.
type DeleteAppOutput struct {
	AppName string `json:"app_name"`
	Deleted bool   `json:"deleted"`
}

// AllocatePortInput is the input for the db.allocate_port activity.
type AllocatePortInput struct {
	AppName string `json:"app_name"`
	Port    int    `json:"port,omitempty"` // if non-zero, use this specific port
}

// AllocatePortOutput is the output of the db.allocate_port activity.
type AllocatePortOutput struct {
	AppName string `json:"app_name"`
	Port    int    `json:"port"`
	Skipped bool   `json:"skipped"` // true if port was already allocated for this app
}

// ReleasePortInput is the input for the db.release_port activity.
type ReleasePortInput struct {
	Port    int    `json:"port"`
	AppName string `json:"app_name,omitempty"` // informational
}

// ReleasePortOutput is the output of the db.release_port activity.
type ReleasePortOutput struct {
	Port     int  `json:"port"`
	Released bool `json:"released"`
}

// CleanupFilesInput is the input for the db.cleanup_files activity.
type CleanupFilesInput struct {
	AppName  string `json:"app_name"`
	DataPath string `json:"data_path"`
	KeepData bool   `json:"keep_data"`
}

// CleanupFilesOutput is the output of the db.cleanup_files activity.
type CleanupFilesOutput struct {
	AppName  string `json:"app_name"`
	Cleaned  bool   `json:"cleaned"`
	KeepData bool   `json:"keep_data"`
}

// RegisterDatabaseActivities registers all database-related activities in the registry.
// Activities: db.insert_app, db.delete_app, db.allocate_port, db.release_port, db.cleanup_files.
func RegisterDatabaseActivities(registry *flowengine.ActivityRegistry, db AppDatabase, portMgr PortAllocator) {
	registry.MustRegister("db.insert_app", makeInsertApp(db))
	registry.MustRegister("db.delete_app", makeDeleteApp(db))
	registry.MustRegister("db.allocate_port", makeAllocatePort(db, portMgr))
	registry.MustRegister("db.release_port", makeReleasePort(db, portMgr))
	registry.MustRegister("db.cleanup_files", makeCleanupFiles())
}

// makeInsertApp creates the db.insert_app activity.
// Idempotent: if an app with the same name already exists, returns skipped=true.
func makeInsertApp(db AppDatabase) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in InsertAppInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid insert_app input: %w", err))
		}
		if in.Name == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("name is required"))
		}

		// Idempotency check: does an app with this name already exist?
		var existingID int64
		err := db.QueryRowContext(ctx, "SELECT id FROM apps WHERE name = ?", in.Name).Scan(&existingID)
		if err == nil && existingID > 0 {
			log.Info().Str("app", in.Name).Int64("id", existingID).Msg("insert_app: app already exists, skipping")
			return marshalOutput(InsertAppOutput{AppID: existingID, Name: in.Name, Created: true, Skipped: true})
		}

		now := time.Now().UTC()
		enabled := 1
		if !in.Enabled {
			enabled = 0
		}

		result, err := db.ExecContext(ctx, `
			INSERT INTO apps (name, port, fqdn, source, image, compose_path, data_path, store_id, enabled, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, in.Name, in.Port, in.FQDN, in.Source, in.Image, in.ComposePath, in.DataPath, in.StoreID, enabled, now, now)
		if err != nil {
			// Unique constraint violation → permanent (duplicate)
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				return nil, flowengine.NewPermanentError(fmt.Errorf("app %s already exists: %w", in.Name, err))
			}
			return nil, flowengine.ClassifyError(err)
		}

		appID, _ := result.LastInsertId()
		log.Info().Str("app", in.Name).Int64("id", appID).Msg("insert_app: app record created")

		// Also create the FQDN record if FQDN is set
		if in.FQDN != "" {
			_, err = db.ExecContext(ctx, `
				INSERT OR IGNORE INTO fqdns (app_id, fqdn, created_at)
				VALUES (?, ?, ?)
			`, appID, in.FQDN, now)
			if err != nil {
				log.Warn().Err(err).Str("fqdn", in.FQDN).Msg("insert_app: failed to create FQDN record (non-fatal)")
			}
		}

		// Create port allocation record
		if in.Port > 0 {
			_, err = db.ExecContext(ctx, `
				INSERT OR IGNORE INTO port_allocations (app_id, port, created_at)
				VALUES (?, ?, ?)
			`, appID, in.Port, now)
			if err != nil {
				log.Warn().Err(err).Int("port", in.Port).Msg("insert_app: failed to create port allocation record (non-fatal)")
			}
		}

		return marshalOutput(InsertAppOutput{AppID: appID, Name: in.Name, Created: true, Skipped: false})
	}
}

// makeDeleteApp creates the db.delete_app activity.
// Idempotent: if the app doesn't exist, returns success with deleted=false.
// FK cascades delete port_allocations and fqdns records.
func makeDeleteApp(db AppDatabase) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DeleteAppInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid delete_app input: %w", err))
		}
		if in.AppID == 0 && in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_id or app_name is required"))
		}

		var result sql.Result
		var err error
		var name string

		if in.AppID > 0 {
			// Get name for logging before deletion
			_ = db.QueryRowContext(ctx, "SELECT name FROM apps WHERE id = ?", in.AppID).Scan(&name)
			result, err = db.ExecContext(ctx, "DELETE FROM apps WHERE id = ?", in.AppID)
		} else {
			name = in.AppName
			result, err = db.ExecContext(ctx, "DELETE FROM apps WHERE name = ?", in.AppName)
		}

		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		rows, _ := result.RowsAffected()
		if rows == 0 {
			log.Info().Str("app", name).Msg("delete_app: app not found, nothing to delete")
			return marshalOutput(DeleteAppOutput{AppName: name, Deleted: false})
		}

		log.Info().Str("app", name).Msg("delete_app: app record deleted (cascaded to ports/fqdns)")
		return marshalOutput(DeleteAppOutput{AppName: name, Deleted: true})
	}
}

// makeAllocatePort creates the db.allocate_port activity.
// Idempotent: if a port is already allocated for this app, returns the existing port.
func makeAllocatePort(db AppDatabase, portMgr PortAllocator) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in AllocatePortInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid allocate_port input: %w", err))
		}
		if in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_name is required"))
		}

		// Idempotency check: is there already a port allocated for this app?
		// Check by looking at port_allocations joined with apps
		var existingPort int
		err := db.QueryRowContext(ctx,
			"SELECT pa.port FROM port_allocations pa JOIN apps a ON pa.app_id = a.id WHERE a.name = ?",
			in.AppName,
		).Scan(&existingPort)
		if err == nil && existingPort > 0 {
			log.Info().Str("app", in.AppName).Int("port", existingPort).Msg("allocate_port: port already allocated, skipping")
			return marshalOutput(AllocatePortOutput{AppName: in.AppName, Port: existingPort, Skipped: true})
		}

		// Allocate a new port
		var port int
		if in.Port > 0 {
			port = in.Port
		} else {
			port, err = portMgr.AllocateUserPort()
			if err != nil {
				return nil, flowengine.NewPermanentError(fmt.Errorf("no available ports: %w", err))
			}
		}

		log.Info().Str("app", in.AppName).Int("port", port).Msg("allocate_port: port allocated")
		return marshalOutput(AllocatePortOutput{AppName: in.AppName, Port: port, Skipped: false})
	}
}

// makeReleasePort creates the db.release_port activity.
// This is the explicit compensation for db.allocate_port — fixes the existing port leak bug.
// Idempotent: if the port isn't allocated, returns success with released=false.
func makeReleasePort(db AppDatabase, portMgr PortAllocator) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ReleasePortInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid release_port input: %w", err))
		}
		if in.Port == 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("port is required"))
		}

		log.Info().Int("port", in.Port).Str("app", in.AppName).Msg("release_port: releasing port")

		if err := portMgr.ReleasePort(in.Port); err != nil {
			if isNotFoundError(err) {
				return marshalOutput(ReleasePortOutput{Port: in.Port, Released: false})
			}
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(ReleasePortOutput{Port: in.Port, Released: true})
	}
}

// makeCleanupFiles creates the db.cleanup_files activity.
// Removes app directories. Not idempotent in reverse (no compensation).
// Best-effort: failure doesn't block workflow completion.
func makeCleanupFiles() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in CleanupFilesInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid cleanup_files input: %w", err))
		}

		if in.KeepData {
			log.Info().Str("app", in.AppName).Msg("cleanup_files: keep_data=true, skipping file cleanup")
			return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: false, KeepData: true})
		}

		if in.DataPath == "" {
			return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: false})
		}

		// Safety check: only remove paths under /cubeos/apps/
		absPath, err := filepath.Abs(in.DataPath)
		if err != nil || !strings.HasPrefix(absPath, "/cubeos/apps/") {
			log.Warn().Str("path", in.DataPath).Msg("cleanup_files: refusing to remove path outside /cubeos/apps/")
			return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: false})
		}

		log.Info().Str("app", in.AppName).Str("path", absPath).Msg("cleanup_files: removing app directory")
		if err := os.RemoveAll(absPath); err != nil {
			log.Warn().Err(err).Str("path", absPath).Msg("cleanup_files: failed to remove directory (non-fatal)")
			// Non-fatal: return success anyway — files can be cleaned up manually
			return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: false})
		}

		return marshalOutput(CleanupFilesOutput{AppName: in.AppName, Cleaned: true})
	}
}
