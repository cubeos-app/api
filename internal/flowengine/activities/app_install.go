package activities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cubeos-api/internal/flowengine"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// --- Input/Output Schemas for App Install Activities ---

// AppInstallValidateInput is the input for the app_install.validate activity.
type AppInstallValidateInput struct {
	Name        string `json:"name"`
	Source      string `json:"source"`       // "registry", "custom", "casaos"
	Image       string `json:"image"`        // for registry source
	Tag         string `json:"tag"`          // for registry source
	ComposePath string `json:"compose_path"` // for custom source
	ComposeYAML string `json:"compose_yaml"` // inline compose content
}

// AppInstallValidateOutput is the output of the app_install.validate activity.
type AppInstallValidateOutput struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Valid  bool   `json:"valid"`
}

// CreateDirsInput is the input for the app.create_dirs activity.
type CreateDirsInput struct {
	AppName   string `json:"app_name"`
	BasePath  string `json:"base_path"`  // e.g. "/cubeos/apps/nextcloud"
	ConfigDir string `json:"config_dir"` // e.g. "appconfig"
	DataDir   string `json:"data_dir"`   // e.g. "appdata"
}

// CreateDirsOutput is the output of the app.create_dirs activity.
type CreateDirsOutput struct {
	AppName    string `json:"app_name"`
	BasePath   string `json:"base_path"`
	ConfigPath string `json:"config_path"`
	DataPath   string `json:"data_path"`
	Created    bool   `json:"created"`
	Skipped    bool   `json:"skipped"` // true if dirs already existed
}

// WriteComposeInput is the input for the app.write_compose activity.
type WriteComposeInput struct {
	AppName     string `json:"app_name"`
	ComposePath string `json:"compose_path"` // full path to write to
	Content     string `json:"content"`      // compose YAML content
}

// WriteComposeOutput is the output of the app.write_compose activity.
type WriteComposeOutput struct {
	AppName     string `json:"app_name"`
	ComposePath string `json:"compose_path"`
	Written     bool   `json:"written"`
}

// RemoveDirsInput is the input for the app.remove_dirs activity (compensation for create_dirs).
type RemoveDirsInput struct {
	AppName  string `json:"app_name"`
	BasePath string `json:"base_path"`
}

// RemoveDirsOutput is the output of the app.remove_dirs activity.
type RemoveDirsOutput struct {
	AppName string `json:"app_name"`
	Removed bool   `json:"removed"`
}

// AppConflictChecker checks for name/port/FQDN conflicts.
// Satisfied by the Orchestrator or a thin wrapper.
type AppConflictChecker interface {
	AppExists(ctx context.Context, name string) (bool, error)
}

// RegisterAppInstallActivities registers activities specific to app installation.
// Activities: app_install.validate, app.create_dirs, app.write_compose, app.remove_dirs.
func RegisterAppInstallActivities(registry *flowengine.ActivityRegistry, checker AppConflictChecker) {
	registry.MustRegister("app_install.validate", makeAppInstallValidate(checker))
	registry.MustRegister("app.create_dirs", makeCreateDirs())
	registry.MustRegister("app.write_compose", makeWriteCompose())
	registry.MustRegister("app.remove_dirs", makeRemoveDirs())
}

// makeAppInstallValidate creates the app_install.validate activity.
// Validates that the app name is valid and no conflicts exist.
func makeAppInstallValidate(checker AppConflictChecker) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in AppInstallValidateInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid validate input: %w", err))
		}

		// Name validation
		if in.Name == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app name is required"))
		}
		if len(in.Name) > 63 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app name too long (max 63 chars)"))
		}
		if strings.ContainsAny(in.Name, " \t\n/\\") {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app name contains invalid characters"))
		}

		// Source validation
		validSources := map[string]bool{"registry": true, "custom": true, "casaos": true}
		if !validSources[in.Source] {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid source: %s (must be registry, custom, or casaos)", in.Source))
		}

		// Source-specific validation
		switch in.Source {
		case "registry":
			if in.Image == "" {
				return nil, flowengine.NewPermanentError(fmt.Errorf("image is required for registry source"))
			}
		case "custom":
			if in.ComposePath == "" && in.ComposeYAML == "" {
				return nil, flowengine.NewPermanentError(fmt.Errorf("compose_path or compose_yaml is required for custom source"))
			}
		}

		// Conflict check
		exists, err := checker.AppExists(ctx, in.Name)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}
		if exists {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app %s already exists", in.Name))
		}

		log.Info().Str("app", in.Name).Str("source", in.Source).Msg("app_install.validate: validation passed")
		return marshalOutput(AppInstallValidateOutput{Name: in.Name, Source: in.Source, Valid: true})
	}
}

// makeCreateDirs creates the app.create_dirs activity.
// Creates the app base, config, and data directories.
// Idempotent: if directories already exist, returns skipped=true.
func makeCreateDirs() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in CreateDirsInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid create_dirs input: %w", err))
		}
		if in.AppName == "" || in.BasePath == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("app_name and base_path are required"))
		}

		// Safety check
		absPath, err := filepath.Abs(in.BasePath)
		if err != nil || !strings.HasPrefix(absPath, "/cubeos/apps/") {
			return nil, flowengine.NewPermanentError(fmt.Errorf("base_path must be under /cubeos/apps/"))
		}

		configDir := in.ConfigDir
		if configDir == "" {
			configDir = "appconfig"
		}
		dataDir := in.DataDir
		if dataDir == "" {
			dataDir = "appdata"
		}

		configPath := filepath.Join(absPath, configDir)
		dataPath := filepath.Join(absPath, dataDir)

		// Idempotency check: if both dirs exist, skip
		_, configErr := os.Stat(configPath)
		_, dataErr := os.Stat(dataPath)
		if configErr == nil && dataErr == nil {
			log.Info().Str("app", in.AppName).Msg("create_dirs: directories already exist, skipping")
			return marshalOutput(CreateDirsOutput{
				AppName: in.AppName, BasePath: absPath,
				ConfigPath: configPath, DataPath: dataPath,
				Created: true, Skipped: true,
			})
		}

		// Create directories
		if err := os.MkdirAll(configPath, 0755); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("failed to create config dir: %w", err))
		}
		if err := os.MkdirAll(dataPath, 0755); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("failed to create data dir: %w", err))
		}

		log.Info().Str("app", in.AppName).Str("base", absPath).Msg("create_dirs: directories created")
		return marshalOutput(CreateDirsOutput{
			AppName: in.AppName, BasePath: absPath,
			ConfigPath: configPath, DataPath: dataPath,
			Created: true, Skipped: false,
		})
	}
}

// makeWriteCompose creates the app.write_compose activity.
// Writes the Docker Compose YAML content to disk.
// Idempotent: overwrites if file exists (deploy_stack is itself idempotent).
func makeWriteCompose() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in WriteComposeInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid write_compose input: %w", err))
		}
		if in.ComposePath == "" || in.Content == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("compose_path and content are required"))
		}

		// Safety check
		absPath, err := filepath.Abs(in.ComposePath)
		if err != nil || !strings.HasPrefix(absPath, "/cubeos/apps/") {
			return nil, flowengine.NewPermanentError(fmt.Errorf("compose_path must be under /cubeos/apps/"))
		}

		// Ensure parent directory exists
		dir := filepath.Dir(absPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("failed to create compose directory: %w", err))
		}

		// Write compose file
		if err := os.WriteFile(absPath, []byte(in.Content), 0644); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("failed to write compose file: %w", err))
		}

		// Pre-create bind mount source directories (Swarm doesn't auto-create them)
		preCreateBindMounts(in.Content)

		log.Info().Str("app", in.AppName).Str("path", absPath).Msg("write_compose: compose file written")
		return marshalOutput(WriteComposeOutput{AppName: in.AppName, ComposePath: absPath, Written: true})
	}
}

// makeRemoveDirs creates the app.remove_dirs activity (compensation for create_dirs).
// Removes the app base directory and all contents.
func makeRemoveDirs() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RemoveDirsInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid remove_dirs input: %w", err))
		}
		if in.BasePath == "" {
			return marshalOutput(RemoveDirsOutput{AppName: in.AppName, Removed: false})
		}

		absPath, err := filepath.Abs(in.BasePath)
		if err != nil || !strings.HasPrefix(absPath, "/cubeos/apps/") {
			return marshalOutput(RemoveDirsOutput{AppName: in.AppName, Removed: false})
		}

		if err := os.RemoveAll(absPath); err != nil {
			log.Warn().Err(err).Str("path", absPath).Msg("remove_dirs: failed (non-fatal)")
			return marshalOutput(RemoveDirsOutput{AppName: in.AppName, Removed: false})
		}

		log.Info().Str("app", in.AppName).Str("path", absPath).Msg("remove_dirs: directory removed")
		return marshalOutput(RemoveDirsOutput{AppName: in.AppName, Removed: true})
	}
}

// preCreateBindMounts parses compose YAML and creates all bind mount source directories.
// Docker Swarm (unlike docker-compose) does NOT auto-create bind mount host paths.
// Without this, services fail to start with "invalid mount config" errors.
func preCreateBindMounts(composeContent string) {
	var compose struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(composeContent), &compose); err != nil {
		log.Warn().Err(err).Msg("preCreateBindMounts: failed to parse compose YAML")
		return
	}

	for svcName, svc := range compose.Services {
		for _, v := range svc.Volumes {
			parts := strings.SplitN(v, ":", 3)
			if len(parts) < 2 {
				continue
			}
			hostPath := parts[0]
			// Skip named volumes (no slash prefix)
			if !strings.HasPrefix(hostPath, "/") {
				continue
			}
			if err := os.MkdirAll(hostPath, 0777); err != nil {
				log.Warn().Err(err).Str("service", svcName).Str("path", hostPath).
					Msg("preCreateBindMounts: failed to create directory")
				continue
			}
			// Explicit chmod — MkdirAll may be affected by umask
			if err := os.Chmod(hostPath, 0777); err != nil {
				log.Warn().Err(err).Str("path", hostPath).Msg("preCreateBindMounts: failed to chmod")
			}
		}
	}
}
