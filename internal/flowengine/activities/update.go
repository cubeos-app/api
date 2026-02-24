package activities

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cubeos-api/internal/database"
	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// UpdateValidator validates whether an update can be applied.
// Satisfied by *managers.UpdateManager.
type UpdateValidator interface {
	ValidateUpdate(manifest *models.ReleaseManifest) error
	GetLatestRelease() *models.ReleaseManifest
}

// UpdateStack represents a deployed Swarm stack for update operations.
type UpdateStack struct {
	Name     string
	Services int
}

// UpdateSwarmManager defines the Swarm operations needed by update activities.
// Satisfied by *managers.SwarmManager via an adapter.
type UpdateSwarmManager interface {
	DeployStack(name, composePath string) error
	ListUpdateStacks() ([]UpdateStack, error)
	WaitForServiceConvergence(ctx context.Context, stackName string, timeout time.Duration) error
}

// --- Input/Output Schemas ---

// UpdateValidateInput is the input for the update.validate activity.
type UpdateValidateInput struct {
	Version  string                  `json:"version"`
	Force    bool                    `json:"force"`
	Manifest *models.ReleaseManifest `json:"manifest"`
}

// UpdateValidateOutput is the output of the update.validate activity.
type UpdateValidateOutput struct {
	Version     string `json:"version"`
	Validated   bool   `json:"validated"`
	HasBreaking bool   `json:"has_breaking"`
}

// SnapshotConfigInput is the input for the update.snapshot_config activity.
type SnapshotConfigInput struct {
	Version string `json:"version"`
}

// SnapshotConfigOutput is the output of the update.snapshot_config activity.
type SnapshotConfigOutput struct {
	SnapshotID int `json:"snapshot_id"`
}

// SnapshotStateInput is the input for the update.snapshot_state activity.
type SnapshotStateInput struct {
	Version string `json:"version"`
}

// SnapshotStateOutput is the output of the update.snapshot_state activity.
type SnapshotStateOutput struct {
	OriginalVersions map[string]string `json:"original_versions"`
	SchemaVersion    int               `json:"schema_version"`
}

// RecordStartInput is the input for the update.record_start activity.
type RecordStartInput struct {
	Version  string                  `json:"version"`
	Manifest *models.ReleaseManifest `json:"manifest"`
}

// RecordStartOutput is the output of the update.record_start activity.
type RecordStartOutput struct {
	HistoryID int64 `json:"history_id"`
}

// PullImagesInput is the input for the update.pull_images activity.
type PullImagesInput struct {
	Manifest *models.ReleaseManifest `json:"manifest"`
}

// PullImagesOutput is the output of the update.pull_images activity.
type PullImagesOutput struct {
	PulledCount  int `json:"pulled_count"`
	SkippedCount int `json:"skipped_count"`
}

// WriteVersionsInput is the input for the update.write_versions activity.
type WriteVersionsInput struct {
	Manifest *models.ReleaseManifest `json:"manifest"`
}

// WriteVersionsOutput is the output of the update.write_versions activity.
type WriteVersionsOutput struct {
	Written bool `json:"written"`
}

// RedeployStacksInput is the input for the update.redeploy_stacks activity.
type RedeployStacksInput struct {
	Manifest *models.ReleaseManifest `json:"manifest"`
}

// RedeployStacksOutput is the output of the update.redeploy_stacks activity.
type RedeployStacksOutput struct {
	DeployedStacks []string `json:"deployed_stacks"`
}

// WaitHealthyInput is the input for the update.wait_healthy activity.
type WaitHealthyInput struct {
	DeployedStacks []string `json:"deployed_stacks"`
}

// WaitHealthyOutput is the output of the update.wait_healthy activity.
type WaitHealthyOutput struct {
	AllHealthy bool `json:"all_healthy"`
}

// RecordCompleteInput is the input for the update.record_complete activity.
type RecordCompleteInput struct {
	HistoryID int64  `json:"history_id"`
	Version   string `json:"version"`
}

// RecordCompleteOutput is the output of the update.record_complete activity.
type RecordCompleteOutput struct {
	Completed bool `json:"completed"`
}

// RegisterUpdateActivities registers all update-related activities in the registry.
func RegisterUpdateActivities(registry *flowengine.ActivityRegistry, db *sql.DB, swarmMgr UpdateSwarmManager, updateMgr UpdateValidator) {
	versionsPath := os.Getenv("CUBEOS_VERSIONS_PATH")
	if versionsPath == "" {
		versionsPath = "/cubeos/coreapps/image-versions.env"
	}

	coreappsPath := os.Getenv("CUBEOS_COREAPPS_PATH")
	if coreappsPath == "" {
		coreappsPath = "/cubeos/coreapps"
	}

	registryHost := os.Getenv("REGISTRY_HOST")
	if registryHost == "" {
		registryHost = "localhost:5000"
	}

	registry.MustRegister("update.validate", makeUpdateValidate(db, updateMgr))
	registry.MustRegister("update.snapshot_config", makeSnapshotConfig(db))
	registry.MustRegister("update.snapshot_state", makeSnapshotState(db, versionsPath))
	registry.MustRegister("update.record_start", makeRecordStart(db))
	registry.MustRegister("update.pull_images", makePullImages(registryHost))
	registry.MustRegister("update.write_versions", makeWriteVersions(versionsPath))
	registry.MustRegister("update.restore_versions", makeRestoreVersions(versionsPath))
	registry.MustRegister("update.redeploy_stacks", makeRedeployStacks(swarmMgr, coreappsPath))
	registry.MustRegister("update.rollback_stacks", makeRollbackStacks(swarmMgr, coreappsPath))
	registry.MustRegister("update.wait_healthy", makeWaitHealthy(swarmMgr))
	registry.MustRegister("update.record_complete", makeRecordComplete(db))
	registry.MustRegister("update.record_failed", makeRecordFailed(db))
}

// makeUpdateValidate creates the update.validate activity.
// Checks that the target version exists and is compatible with the current system.
func makeUpdateValidate(db *sql.DB, updateMgr UpdateValidator) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in UpdateValidateInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid validate input: %w", err))
		}
		if in.Version == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("version is required"))
		}
		if in.Manifest == nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("manifest is required"))
		}

		// Check no in-flight updates
		var count int
		err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM update_history WHERE status = 'applying'").Scan(&count)
		if err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("check in-flight updates: %w", err))
		}
		if count > 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("another update is already in progress"))
		}

		// Validate compatibility
		if err := updateMgr.ValidateUpdate(in.Manifest); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("validation failed: %w", err))
		}

		// Check breaking changes — if not forced, reject
		hasBreaking := len(in.Manifest.Breaking) > 0
		if hasBreaking && !in.Force {
			return nil, flowengine.NewPermanentError(fmt.Errorf("update contains breaking changes — use force=true to proceed"))
		}

		log.Info().Str("version", in.Version).Bool("has_breaking", hasBreaking).Msg("update.validate: passed")

		return marshalOutput(UpdateValidateOutput{
			Version:     in.Version,
			Validated:   true,
			HasBreaking: hasBreaking,
		})
	}
}

// makeSnapshotConfig creates the update.snapshot_config activity.
// P0 auto-snapshot: reads system state from DB and stores a ConfigSnapshot.
func makeSnapshotConfig(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in SnapshotConfigInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid snapshot_config input: %w", err))
		}

		// Build a ConfigSnapshot from current system state
		snapshot := models.ConfigSnapshot{
			ConfigVersion: 1,
			Metadata: models.ConfigMetadata{
				ExportedAt:    time.Now().Format(time.RFC3339),
				CubeOSVersion: os.Getenv("CUBEOS_VERSION"),
				Description:   fmt.Sprintf("Auto-snapshot before update to %s", in.Version),
			},
		}

		// Read schema version
		schemaVer, err := database.GetSchemaVersion(db)
		if err == nil {
			snapshot.Metadata.SchemaVersion = schemaVer
		}

		// Read system config
		rows, err := db.QueryContext(ctx, "SELECT key, value FROM system_config")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var key, val string
				if rows.Scan(&key, &val) == nil {
					switch key {
					case "timezone":
						snapshot.System.Timezone = val
					case "domain":
						snapshot.System.Domain = val
					case "gateway_ip":
						snapshot.System.GatewayIP = val
					case "country_code":
						snapshot.System.CountryCode = val
					}
				}
			}
		}

		// Read network mode
		var mode string
		if db.QueryRowContext(ctx, "SELECT mode FROM network_config WHERE id = 1").Scan(&mode) == nil {
			snapshot.Network.Mode = mode
		}

		// Read users
		userRows, err := db.QueryContext(ctx, "SELECT username, role, password_hash FROM users")
		if err == nil {
			defer userRows.Close()
			for userRows.Next() {
				var u models.ConfigUser
				if userRows.Scan(&u.Username, &u.Role, &u.PasswordHash) == nil {
					snapshot.Users = append(snapshot.Users, u)
				}
			}
		}

		// Read installed apps
		appRows, err := db.QueryContext(ctx,
			"SELECT name, COALESCE(source,''), COALESCE(store_id,''), COALESCE(port,0), COALESCE(fqdn,''), COALESCE(enabled,1) FROM apps WHERE type IN ('user','ai')")
		if err == nil {
			defer appRows.Close()
			for appRows.Next() {
				var a models.ConfigApp
				if appRows.Scan(&a.Name, &a.Source, &a.StoreID, &a.Port, &a.FQDN, &a.Enabled) == nil {
					snapshot.Apps = append(snapshot.Apps, a)
				}
			}
		}

		// Read preferences
		snapshot.Preferences = make(map[string]string)
		prefRows, err := db.QueryContext(ctx, "SELECT key, value FROM preferences")
		if err == nil {
			defer prefRows.Close()
			for prefRows.Next() {
				var k, v string
				if prefRows.Scan(&k, &v) == nil {
					snapshot.Preferences[k] = v
				}
			}
		}

		// Serialize and store
		configJSON, err := json.Marshal(snapshot)
		if err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("marshal config snapshot: %w", err))
		}

		result, err := db.ExecContext(ctx,
			`INSERT INTO config_snapshots (trigger, description, config_json, cubeos_version, schema_version)
			 VALUES ('pre_update', ?, ?, ?, ?)`,
			snapshot.Metadata.Description,
			string(configJSON),
			snapshot.Metadata.CubeOSVersion,
			snapshot.Metadata.SchemaVersion,
		)
		if err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("insert config snapshot: %w", err))
		}

		snapshotID, _ := result.LastInsertId()
		log.Info().Int64("snapshot_id", snapshotID).Msg("update.snapshot_config: P0 config snapshot stored")

		return marshalOutput(SnapshotConfigOutput{SnapshotID: int(snapshotID)})
	}
}

// makeSnapshotState creates the update.snapshot_state activity.
// Reads current image-versions.env and schema version for rollback.
func makeSnapshotState(db *sql.DB, versionsPath string) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		versions, err := readVersionsEnv(versionsPath)
		if err != nil {
			// If the file doesn't exist yet, that's okay — empty map
			if !os.IsNotExist(err) {
				return nil, flowengine.ClassifyError(fmt.Errorf("read image-versions.env: %w", err))
			}
			versions = make(map[string]string)
		}

		schemaVer, _ := database.GetSchemaVersion(db)

		log.Info().Int("images", len(versions)).Int("schema", schemaVer).Msg("update.snapshot_state: captured current state")

		return marshalOutput(SnapshotStateOutput{
			OriginalVersions: versions,
			SchemaVersion:    schemaVer,
		})
	}
}

// makeRecordStart creates the update.record_start activity.
// Inserts an update_history row with status=applying.
func makeRecordStart(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RecordStartInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid record_start input: %w", err))
		}

		currentVersion := os.Getenv("CUBEOS_VERSION")
		if currentVersion == "" {
			currentVersion = "0.0.0"
		}

		manifestJSON, _ := json.Marshal(in.Manifest)

		result, err := db.ExecContext(ctx,
			`INSERT INTO update_history (from_version, to_version, status, manifest_json)
			 VALUES (?, ?, 'applying', ?)`,
			currentVersion, in.Version, string(manifestJSON),
		)
		if err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("insert update_history: %w", err))
		}

		historyID, _ := result.LastInsertId()
		log.Info().Int64("history_id", historyID).Str("version", in.Version).Msg("update.record_start: update history recorded")

		return marshalOutput(RecordStartOutput{HistoryID: historyID})
	}
}

// makePullImages creates the update.pull_images activity.
// Pulls each image from upstream and pushes to the local registry.
func makePullImages(registryHost string) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in PullImagesInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid pull_images input: %w", err))
		}
		if in.Manifest == nil || len(in.Manifest.Images) == 0 {
			log.Info().Msg("update.pull_images: no images to pull")
			return marshalOutput(PullImagesOutput{PulledCount: 0, SkippedCount: 0})
		}

		pulled := 0
		skipped := 0

		for service, imageTag := range in.Manifest.Images {
			localRef := fmt.Sprintf("%s/%s", registryHost, imageTag)

			// Check if image already exists in local registry
			checkCmd := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", localRef)
			if checkCmd.Run() == nil {
				log.Info().Str("service", service).Str("image", localRef).Msg("update.pull_images: already in local registry, skipping")
				skipped++
				continue
			}

			// Pull from upstream
			log.Info().Str("service", service).Str("image", imageTag).Msg("update.pull_images: pulling from upstream")
			pullCmd := exec.CommandContext(ctx, "docker", "pull", imageTag)
			if output, err := pullCmd.CombinedOutput(); err != nil {
				return nil, flowengine.ClassifyError(fmt.Errorf("pull %s: %w\n%s", imageTag, err, string(output)))
			}

			// Tag for local registry
			tagCmd := exec.CommandContext(ctx, "docker", "tag", imageTag, localRef)
			if output, err := tagCmd.CombinedOutput(); err != nil {
				return nil, flowengine.ClassifyError(fmt.Errorf("tag %s → %s: %w\n%s", imageTag, localRef, err, string(output)))
			}

			// Push to local registry
			pushCmd := exec.CommandContext(ctx, "docker", "push", localRef)
			if output, err := pushCmd.CombinedOutput(); err != nil {
				return nil, flowengine.ClassifyError(fmt.Errorf("push %s: %w\n%s", localRef, err, string(output)))
			}

			pulled++
			log.Info().Str("service", service).Str("image", localRef).Msg("update.pull_images: cached in local registry")
		}

		return marshalOutput(PullImagesOutput{PulledCount: pulled, SkippedCount: skipped})
	}
}

// makeWriteVersions creates the update.write_versions activity.
// Writes new image tags to image-versions.env atomically.
func makeWriteVersions(versionsPath string) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in WriteVersionsInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid write_versions input: %w", err))
		}
		if in.Manifest == nil || len(in.Manifest.Images) == 0 {
			return marshalOutput(WriteVersionsOutput{Written: true})
		}

		// Read existing versions
		existing, err := readVersionsEnv(versionsPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, flowengine.ClassifyError(fmt.Errorf("read versions: %w", err))
		}
		if existing == nil {
			existing = make(map[string]string)
		}

		// Merge new versions
		for service, imageTag := range in.Manifest.Images {
			key := serviceToEnvKey(service)
			existing[key] = imageTag
		}

		// Write atomically
		if err := writeVersionsEnv(versionsPath, existing); err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("write versions: %w", err))
		}

		log.Info().Int("updated", len(in.Manifest.Images)).Msg("update.write_versions: image-versions.env updated")
		return marshalOutput(WriteVersionsOutput{Written: true})
	}
}

// makeRestoreVersions creates the update.restore_versions compensation activity.
// Restores the original image-versions.env from the snapshot.
func makeRestoreVersions(versionsPath string) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			OriginalVersions map[string]string `json:"original_versions"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid restore_versions input: %w", err))
		}

		if len(envelope.OriginalVersions) == 0 {
			log.Warn().Msg("update.restore_versions: no original versions to restore")
			return marshalOutput(WriteVersionsOutput{Written: true})
		}

		if err := writeVersionsEnv(versionsPath, envelope.OriginalVersions); err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("restore versions: %w", err))
		}

		log.Info().Int("restored", len(envelope.OriginalVersions)).Msg("update.restore_versions: image-versions.env restored")
		return marshalOutput(WriteVersionsOutput{Written: true})
	}
}

// makeRedeployStacks creates the update.redeploy_stacks activity.
// Redeploys Swarm stacks for services that have changed images.
// Deploy order: infrastructure first, then platform, then user apps.
func makeRedeployStacks(swarmMgr UpdateSwarmManager, coreappsPath string) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RedeployStacksInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid redeploy_stacks input: %w", err))
		}
		if in.Manifest == nil || len(in.Manifest.Images) == 0 {
			return marshalOutput(RedeployStacksOutput{DeployedStacks: nil})
		}

		// Determine which stacks need redeploying based on changed services
		changedServices := make(map[string]bool)
		for service := range in.Manifest.Images {
			changedServices[service] = true
		}

		// List current stacks
		stacks, err := swarmMgr.ListUpdateStacks()
		if err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("list stacks: %w", err))
		}

		// Categorize stacks by priority for ordered deployment
		var infraStacks, platformStacks, otherStacks []string
		infraNames := map[string]bool{"cubeos-pihole": true, "cubeos-npm": true}
		platformNames := map[string]bool{"cubeos-api": true, "cubeos-hal": true, "cubeos-dashboard": true}

		for _, stack := range stacks {
			// Check if any service in this stack has a changed image
			stackRelevant := false
			for service := range changedServices {
				if strings.Contains(stack.Name, service) || strings.HasPrefix(stack.Name, "cubeos-") {
					stackRelevant = true
					break
				}
			}
			if !stackRelevant {
				continue
			}

			if infraNames[stack.Name] {
				infraStacks = append(infraStacks, stack.Name)
			} else if platformNames[stack.Name] {
				platformStacks = append(platformStacks, stack.Name)
			} else {
				otherStacks = append(otherStacks, stack.Name)
			}
		}

		// Deploy in priority order
		var deployed []string
		allStacks := append(append(infraStacks, platformStacks...), otherStacks...)

		for _, stackName := range allStacks {
			composePath := filepath.Join(coreappsPath, stackName, "docker-compose.yml")
			if _, err := os.Stat(composePath); os.IsNotExist(err) {
				// Try without the cubeos- prefix
				shortName := strings.TrimPrefix(stackName, "cubeos-")
				composePath = filepath.Join(coreappsPath, shortName, "docker-compose.yml")
				if _, err := os.Stat(composePath); os.IsNotExist(err) {
					log.Warn().Str("stack", stackName).Msg("update.redeploy_stacks: compose file not found, skipping")
					continue
				}
			}

			log.Info().Str("stack", stackName).Str("compose", composePath).Msg("update.redeploy_stacks: deploying")
			if err := swarmMgr.DeployStack(stackName, composePath); err != nil {
				return nil, flowengine.ClassifyError(fmt.Errorf("deploy stack %s: %w", stackName, err))
			}
			deployed = append(deployed, stackName)
		}

		log.Info().Strs("deployed", deployed).Msg("update.redeploy_stacks: all stacks redeployed")
		return marshalOutput(RedeployStacksOutput{DeployedStacks: deployed})
	}
}

// makeRollbackStacks creates the update.rollback_stacks compensation activity.
// Re-deploys stacks with original image tags.
func makeRollbackStacks(swarmMgr UpdateSwarmManager, coreappsPath string) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			DeployedStacks []string `json:"deployed_stacks"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid rollback_stacks input: %w", err))
		}

		if len(envelope.DeployedStacks) == 0 {
			log.Info().Msg("update.rollback_stacks: no stacks to rollback")
			return marshalOutput(RedeployStacksOutput{DeployedStacks: nil})
		}

		// Re-deploy stacks (image-versions.env should already be restored by restore_versions)
		var rolledBack []string
		for _, stackName := range envelope.DeployedStacks {
			composePath := filepath.Join(coreappsPath, stackName, "docker-compose.yml")
			if _, err := os.Stat(composePath); os.IsNotExist(err) {
				shortName := strings.TrimPrefix(stackName, "cubeos-")
				composePath = filepath.Join(coreappsPath, shortName, "docker-compose.yml")
				if _, err := os.Stat(composePath); os.IsNotExist(err) {
					continue
				}
			}

			log.Info().Str("stack", stackName).Msg("update.rollback_stacks: re-deploying with original tags")
			if err := swarmMgr.DeployStack(stackName, composePath); err != nil {
				log.Error().Err(err).Str("stack", stackName).Msg("update.rollback_stacks: failed to rollback stack")
				continue // best-effort
			}
			rolledBack = append(rolledBack, stackName)
		}

		log.Info().Strs("rolled_back", rolledBack).Msg("update.rollback_stacks: rollback complete")
		return marshalOutput(RedeployStacksOutput{DeployedStacks: rolledBack})
	}
}

// makeWaitHealthy creates the update.wait_healthy activity.
// Waits for all deployed stacks to converge (90s timeout per stack).
func makeWaitHealthy(swarmMgr UpdateSwarmManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in WaitHealthyInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid wait_healthy input: %w", err))
		}

		if len(in.DeployedStacks) == 0 {
			return marshalOutput(WaitHealthyOutput{AllHealthy: true})
		}

		timeout := 90 * time.Second
		for _, stackName := range in.DeployedStacks {
			log.Info().Str("stack", stackName).Dur("timeout", timeout).Msg("update.wait_healthy: waiting for convergence")
			if err := swarmMgr.WaitForServiceConvergence(ctx, stackName, timeout); err != nil {
				return nil, flowengine.NewTransientError(fmt.Errorf("convergence timeout for %s: %w", stackName, err))
			}
		}

		log.Info().Int("stacks", len(in.DeployedStacks)).Msg("update.wait_healthy: all services converged")
		return marshalOutput(WaitHealthyOutput{AllHealthy: true})
	}
}

// makeRecordComplete creates the update.record_complete activity.
// Updates update_history status to completed.
func makeRecordComplete(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RecordCompleteInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid record_complete input: %w", err))
		}

		_, err := db.ExecContext(ctx,
			"UPDATE update_history SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
			in.HistoryID,
		)
		if err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("update history status: %w", err))
		}

		log.Info().Int64("history_id", in.HistoryID).Msg("update.record_complete: update marked completed")
		return marshalOutput(RecordCompleteOutput{Completed: true})
	}
}

// makeRecordFailed creates the update.record_failed compensation activity.
// Updates update_history status to rolled_back with error message.
func makeRecordFailed(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var envelope struct {
			HistoryID int64  `json:"history_id"`
			Version   string `json:"version"`
		}
		if err := json.Unmarshal(input, &envelope); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid record_failed input: %w", err))
		}

		_, err := db.ExecContext(ctx,
			`UPDATE update_history
			 SET status = 'rolled_back', completed_at = CURRENT_TIMESTAMP,
			     error_message = 'Update rolled back due to failure during apply'
			 WHERE id = ?`,
			envelope.HistoryID,
		)
		if err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("update history to rolled_back: %w", err))
		}

		log.Info().Int64("history_id", envelope.HistoryID).Msg("update.record_failed: update marked rolled_back")
		return marshalOutput(RecordCompleteOutput{Completed: false})
	}
}

// --- Helpers ---

// readVersionsEnv reads a KEY=VALUE env file into a map.
func readVersionsEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	versions := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			versions[key] = val
		}
	}
	return versions, scanner.Err()
}

// writeVersionsEnv writes a map as KEY=VALUE env file atomically.
func writeVersionsEnv(path string, versions map[string]string) error {
	// Sort keys for deterministic output
	keys := make([]string, 0, len(versions))
	for k := range versions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# CubeOS image version pins — managed by UpdateManager\n")
	b.WriteString(fmt.Sprintf("# Updated: %s\n", time.Now().Format(time.RFC3339)))
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("%s=%s\n", k, versions[k]))
	}

	// Write to temp file, then rename (atomic on same filesystem)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp to final: %w", err)
	}
	return nil
}

// serviceToEnvKey converts a service name to an env variable key.
// e.g., "cubeos-api" → "CUBEOS_API_IMAGE"
func serviceToEnvKey(service string) string {
	key := strings.ReplaceAll(strings.ToUpper(service), "-", "_")
	if !strings.HasSuffix(key, "_IMAGE") {
		key += "_IMAGE"
	}
	return key
}
