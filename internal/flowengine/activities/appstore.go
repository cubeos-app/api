package activities

import (
	"context"
	"encoding/json"
	"fmt"

	"cubeos-api/internal/flowengine"

	"github.com/rs/zerolog/log"
)

// AppStoreManifestReader reads and processes CasaOS app store manifests.
// Satisfied by *managers.AppStoreManager (subset of methods).
type AppStoreManifestReader interface {
	// ReadManifest fetches the raw manifest for a store app.
	ReadManifest(ctx context.Context, storeID, appName string) (json.RawMessage, error)
	// ProcessManifest transforms a raw manifest into a compose-ready config.
	ProcessManifest(ctx context.Context, manifest json.RawMessage) (*ProcessedManifest, error)
	// RemapVolumes adjusts volume paths for the CubeOS directory structure.
	RemapVolumes(ctx context.Context, compose string, appName string) (string, error)
	// DetectWebUIType determines the app's web UI access type.
	DetectWebUIType(ctx context.Context, manifest json.RawMessage) (string, error)
}

// ProcessedManifest holds the result of manifest processing.
type ProcessedManifest struct {
	ComposeYAML   string `json:"compose_yaml"`
	Image         string `json:"image"`
	ContainerPort int    `json:"container_port"` // detected EXPOSE port
	WebUIType     string `json:"webui_type"`     // "http", "https", "none"
	Title         string `json:"title"`
	Description   string `json:"description"`
}

// --- Input/Output Schemas ---

// AppStoreValidateInput is the input for the appstore.validate activity.
type AppStoreValidateInput struct {
	StoreID string `json:"store_id"` // e.g. "casaos-official"
	AppName string `json:"app_name"` // e.g. "nextcloud"
}

// AppStoreValidateOutput is the output of the appstore.validate activity.
type AppStoreValidateOutput struct {
	StoreID string `json:"store_id"`
	AppName string `json:"app_name"`
	Valid   bool   `json:"valid"`
}

// ReadManifestInput is the input for the appstore.read_manifest activity.
type ReadManifestInput struct {
	StoreID string `json:"store_id"`
	AppName string `json:"app_name"`
}

// ReadManifestOutput is the output of the appstore.read_manifest activity.
type ReadManifestOutput struct {
	StoreID  string          `json:"store_id"`
	AppName  string          `json:"app_name"`
	Manifest json.RawMessage `json:"manifest"` // raw manifest JSON
}

// ProcessManifestInput is the input for the appstore.process_manifest activity.
type ProcessManifestInput struct {
	AppName  string          `json:"app_name"`
	Manifest json.RawMessage `json:"manifest"`
}

// ProcessManifestOutput is the output of the appstore.process_manifest activity.
type ProcessManifestOutput struct {
	AppName       string `json:"app_name"`
	ComposeYAML   string `json:"compose_yaml"`
	Image         string `json:"image"`
	ContainerPort int    `json:"container_port"`
	WebUIType     string `json:"webui_type"`
	Title         string `json:"title"`
	Description   string `json:"description"`
}

// RemapVolumesInput is the input for the appstore.remap_volumes activity.
type RemapVolumesInput struct {
	AppName     string `json:"app_name"`
	ComposeYAML string `json:"compose_yaml"`
}

// RemapVolumesOutput is the output of the appstore.remap_volumes activity.
type RemapVolumesOutput struct {
	AppName     string `json:"app_name"`
	ComposeYAML string `json:"compose_yaml"` // remapped compose
}

// RegisterAppStoreActivities registers all AppStore-specific activities in the registry.
// Activities: appstore.validate, appstore.read_manifest, appstore.process_manifest, appstore.remap_volumes.
func RegisterAppStoreActivities(registry *flowengine.ActivityRegistry, storeMgr AppStoreManifestReader, checker AppConflictChecker) {
	registry.MustRegister("appstore.validate", makeAppStoreValidate(checker))
	registry.MustRegister("appstore.read_manifest", makeReadManifest(storeMgr))
	registry.MustRegister("appstore.process_manifest", makeProcessManifest(storeMgr))
	registry.MustRegister("appstore.remap_volumes", makeRemapVolumes(storeMgr))
}

// makeAppStoreValidate creates the appstore.validate activity.
func makeAppStoreValidate(checker AppConflictChecker) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in AppStoreValidateInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid appstore validate input: %w", err))
		}
		if in.StoreID == "" || in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("store_id and app_name are required"))
		}

		// Check app doesn't already exist
		exists, err := checker.AppExists(ctx, in.AppName)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		if exists {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app %s already exists", in.AppName))
		}

		log.Info().Str("store", in.StoreID).Str("app", in.AppName).Msg("appstore.validate: validation passed")
		return marshalOutput(AppStoreValidateOutput{StoreID: in.StoreID, AppName: in.AppName, Valid: true})
	}
}

// makeReadManifest creates the appstore.read_manifest activity.
// Reads the app manifest from the store (cached or remote).
func makeReadManifest(storeMgr AppStoreManifestReader) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ReadManifestInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid read_manifest input: %w", err))
		}
		if in.StoreID == "" || in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("store_id and app_name are required"))
		}

		log.Info().Str("store", in.StoreID).Str("app", in.AppName).Msg("read_manifest: reading manifest")
		manifest, err := storeMgr.ReadManifest(ctx, in.StoreID, in.AppName)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(ReadManifestOutput{
			StoreID:  in.StoreID,
			AppName:  in.AppName,
			Manifest: manifest,
		})
	}
}

// makeProcessManifest creates the appstore.process_manifest activity.
// Transforms the raw CasaOS manifest into a Swarm-ready compose configuration.
func makeProcessManifest(storeMgr AppStoreManifestReader) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in ProcessManifestInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid process_manifest input: %w", err))
		}
		if len(in.Manifest) == 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("manifest is required"))
		}

		log.Info().Str("app", in.AppName).Msg("process_manifest: processing manifest")
		processed, err := storeMgr.ProcessManifest(ctx, in.Manifest)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		if processed == nil || processed.ComposeYAML == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("manifest processing produced empty compose for %s", in.AppName))
		}

		return marshalOutput(ProcessManifestOutput{
			AppName:       in.AppName,
			ComposeYAML:   processed.ComposeYAML,
			Image:         processed.Image,
			ContainerPort: processed.ContainerPort,
			WebUIType:     processed.WebUIType,
			Title:         processed.Title,
			Description:   processed.Description,
		})
	}
}

// makeRemapVolumes creates the appstore.remap_volumes activity.
// Adjusts volume paths to match CubeOS directory conventions.
func makeRemapVolumes(storeMgr AppStoreManifestReader) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RemapVolumesInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid remap_volumes input: %w", err))
		}
		if in.ComposeYAML == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("compose_yaml is required"))
		}

		log.Info().Str("app", in.AppName).Msg("remap_volumes: remapping volume paths")
		remapped, err := storeMgr.RemapVolumes(ctx, in.ComposeYAML, in.AppName)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(RemapVolumesOutput{AppName: in.AppName, ComposeYAML: remapped})
	}
}
