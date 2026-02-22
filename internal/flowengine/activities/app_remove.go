package activities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/flowengine"
)

// RegisterAppRemoveActivities registers activities specific to the AppRemoveWorkflow.
// These are thin activities that transform workflow input into step-specific inputs,
// acting as the "glue" between the generic workflow input and typed activity inputs.
func RegisterAppRemoveActivities(reg *flowengine.ActivityRegistry, db *sql.DB) {
	reg.MustRegister("app_remove.validate", makeAppRemoveValidateActivity(db))
}

// AppRemoveValidateInput mirrors the workflow-level input.
type AppRemoveValidateInput struct {
	AppID       int64  `json:"app_id"`
	AppName     string `json:"app_name"`
	FQDN        string `json:"fqdn"`
	ComposePath string `json:"compose_path,omitempty"`
	DataPath    string `json:"data_path,omitempty"`
	KeepData    bool   `json:"keep_data"`
	UsesSwarm   bool   `json:"uses_swarm"`
}

// AppRemoveValidateOutput is the validated output that subsequent steps consume.
// It carries forward all the data needed by downstream steps.
type AppRemoveValidateOutput struct {
	AppID       int64  `json:"app_id"`
	AppName     string `json:"app_name"`
	StackName   string `json:"stack_name"`
	FQDN        string `json:"fqdn"`
	ComposePath string `json:"compose_path,omitempty"`
	DataPath    string `json:"data_path,omitempty"`
	KeepData    bool   `json:"keep_data"`
	UsesSwarm   bool   `json:"uses_swarm"`
}

// makeAppRemoveValidateActivity creates a validation activity that:
// 1. Verifies the app exists in the database
// 2. Verifies it's not a protected system app
// 3. Outputs validated data for downstream steps
func makeAppRemoveValidateActivity(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in AppRemoveValidateInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("unmarshal input: %w", err))
		}

		if in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_name is required"))
		}

		log.Info().
			Str("app_name", in.AppName).
			Int64("app_id", in.AppID).
			Msg("Activity: validating app removal")

		// Verify app exists
		var exists int
		err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM apps WHERE id = ?", in.AppID).Scan(&exists)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		if exists == 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app not found: %s (id=%d)", in.AppName, in.AppID))
		}

		// Check if app is protected (type = 'system' or category = 'system')
		var appType, category string
		err = db.QueryRowContext(ctx,
			"SELECT COALESCE(type, ''), COALESCE(category, '') FROM apps WHERE id = ?",
			in.AppID).Scan(&appType, &category)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		if appType == "system" || category == "system" {
			return nil, flowengine.NewPermanentError(
				fmt.Errorf("cannot uninstall protected system app: %s", in.AppName))
		}

		out := AppRemoveValidateOutput{
			AppID:       in.AppID,
			AppName:     in.AppName,
			StackName:   in.AppName, // Stack name = app name in CubeOS
			FQDN:        in.FQDN,
			ComposePath: in.ComposePath,
			DataPath:    in.DataPath,
			KeepData:    in.KeepData,
			UsesSwarm:   in.UsesSwarm,
		}

		return marshalOutput(out)
	}
}
