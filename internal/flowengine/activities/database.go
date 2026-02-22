package activities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/flowengine"
)

// RegisterDatabaseActivities registers database-related activities with the registry.
// Called once at engine startup from main.go.
func RegisterDatabaseActivities(reg *flowengine.ActivityRegistry, db *sql.DB) {
	reg.MustRegister("db.delete_app", makeDeleteAppActivity(db))
	reg.MustRegister("db.cleanup_files", makeCleanupFilesActivity())

	// Stubs for Batch 2.4 (AppInstall workflows)
	reg.MustRegister("db.insert_app", makeInsertAppStub())
	reg.MustRegister("db.allocate_port", makeAllocatePortStub())
	reg.MustRegister("db.release_port", makeReleasePortStub())
}

// DeleteAppInput is the input for the db.delete_app activity.
type DeleteAppInput struct {
	AppID   int64  `json:"app_id"`
	AppName string `json:"app_name"`
}

// DeleteAppOutput is the output of the db.delete_app activity.
type DeleteAppOutput struct {
	AppID   int64  `json:"app_id"`
	Deleted bool   `json:"deleted"`
	AppName string `json:"app_name"`
}

// makeDeleteAppActivity creates an idempotent app deletion activity.
// Deletes the app row from the database. Foreign key cascades handle ports and fqdns.
// Idempotent: returns success if the app doesn't exist (already deleted).
func makeDeleteAppActivity(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DeleteAppInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("unmarshal input: %w", err))
		}

		if in.AppID == 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_id is required"))
		}

		log.Info().
			Int64("app_id", in.AppID).
			Str("app_name", in.AppName).
			Msg("Activity: deleting app from database")

		result, err := db.ExecContext(ctx, "DELETE FROM apps WHERE id = ?", in.AppID)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		rows, _ := result.RowsAffected()
		if rows == 0 {
			// Already deleted — idempotent
			log.Debug().Int64("app_id", in.AppID).Msg("App already deleted (idempotent)")
			return marshalOutput(DeleteAppOutput{AppID: in.AppID, AppName: in.AppName, Deleted: false})
		}

		return marshalOutput(DeleteAppOutput{AppID: in.AppID, AppName: in.AppName, Deleted: true})
	}
}

// CleanupFilesInput is the input for the db.cleanup_files activity.
type CleanupFilesInput struct {
	ComposePath string `json:"compose_path,omitempty"`
	DataPath    string `json:"data_path,omitempty"`
	KeepData    bool   `json:"keep_data"`
}

// makeCleanupFilesActivity creates an activity that removes app directories.
// Removes compose config directory always, data directory only if !keepData.
// Idempotent: returns success if directories don't exist.
func makeCleanupFilesActivity() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in CleanupFilesInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("unmarshal input: %w", err))
		}

		log.Info().
			Str("compose_path", in.ComposePath).
			Str("data_path", in.DataPath).
			Bool("keep_data", in.KeepData).
			Msg("Activity: cleaning up app files")

		// Remove compose config directory
		if in.ComposePath != "" {
			removePathBestEffort(in.ComposePath)
		}

		// Optionally remove data directory
		if !in.KeepData && in.DataPath != "" {
			removePathBestEffort(in.DataPath)
		}

		return marshalOutput(map[string]string{"status": "cleaned"})
	}
}

// removePathBestEffort removes a path, logging but not failing on error.
// File cleanup failures should not block the workflow — the files can be
// cleaned up manually or on next boot.
func removePathBestEffort(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Best-effort file cleanup failed")
		return
	}

	// Try to clean up empty parent directory
	parentDir := filepath.Dir(path)
	if entries, err := os.ReadDir(parentDir); err == nil && len(entries) == 0 {
		os.Remove(parentDir)
	}
}

// Stubs for Batch 2.4

func makeInsertAppStub() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("db.insert_app not yet implemented (Batch 2.4)"))
	}
}

func makeAllocatePortStub() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("db.allocate_port not yet implemented (Batch 2.4)"))
	}
}

func makeReleasePortStub() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("db.release_port not yet implemented (Batch 2.4)"))
	}
}
