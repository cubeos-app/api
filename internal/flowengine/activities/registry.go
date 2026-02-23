package activities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"cubeos-api/internal/flowengine"

	"github.com/rs/zerolog/log"
)

// --- Input/Output Schemas ---

// RetagImageInput is the input for the registry.retag_image activity.
type RetagImageInput struct {
	SourceImage  string `json:"source_image"`            // e.g. "linuxserver/prowlarr:latest"
	RegistryHost string `json:"registry_host,omitempty"` // e.g. "10.42.24.1:5000"
}

// RetagImageOutput is the output of the registry.retag_image activity.
type RetagImageOutput struct {
	SourceImage   string `json:"source_image"`
	LocalImage    string `json:"local_image"`    // e.g. "10.42.24.1:5000/linuxserver/prowlarr:latest"
	RegistryImage string `json:"registry_image"` // alias of LocalImage for store_cached_manifest
	Tagged        bool   `json:"tagged"`
	Skipped       bool   `json:"skipped"` // true if local image already existed or tagging failed (non-fatal)
}

// PushToRegistryInput is the input for the registry.push_to_registry activity.
type PushToRegistryInput struct {
	LocalImage string `json:"local_image"` // e.g. "10.42.24.1:5000/linuxserver/prowlarr:latest"
}

// PushToRegistryOutput is the output of the registry.push_to_registry activity.
type PushToRegistryOutput struct {
	LocalImage string `json:"local_image"`
	Pushed     bool   `json:"pushed"`
	Skipped    bool   `json:"skipped"` // true if push failed (non-fatal in auto-cache context)
}

// StoreCachedManifestInput is the input for the registry.store_cached_manifest activity.
type StoreCachedManifestInput struct {
	StoreID       string          `json:"store_id"`
	AppName       string          `json:"app_name"`
	Image         string          `json:"image"`
	RegistryImage string          `json:"registry_image"`
	Manifest      json.RawMessage `json:"manifest"`     // fat envelope passes JSON object from read_manifest
	ManifestRaw   string          `json:"manifest_raw"` // fallback for manifest (from process_manifest in auto-cache)
	Title         string          `json:"title"`
	Icon          string          `json:"icon"`
	Category      string          `json:"category"`
	Tagline       string          `json:"tagline"`
}

// StoreCachedManifestOutput is the output of the registry.store_cached_manifest activity.
type StoreCachedManifestOutput struct {
	AppName string `json:"app_name"`
	Stored  bool   `json:"stored"`
	Skipped bool   `json:"skipped"` // true if store failed (non-fatal in auto-cache context)
}

// DeleteCachedManifestInput is the input for the registry.delete_cached_manifest activity.
type DeleteCachedManifestInput struct {
	StoreID string `json:"store_id"`
	AppName string `json:"app_name"`
}

// DeleteCachedManifestOutput is the output of the registry.delete_cached_manifest activity.
type DeleteCachedManifestOutput struct {
	Deleted bool `json:"deleted"`
}

// RegisterRegistryActivities registers all registry-related activities in the registry.
// Activities: registry.retag_image, registry.push_to_registry,
// registry.store_cached_manifest, registry.delete_cached_manifest.
func RegisterRegistryActivities(registry *flowengine.ActivityRegistry, db *sql.DB) {
	registry.MustRegister("registry.retag_image", makeRetagImage())
	registry.MustRegister("registry.push_to_registry", makePushToRegistry())
	registry.MustRegister("registry.store_cached_manifest", makeStoreCachedManifest(db))
	registry.MustRegister("registry.delete_cached_manifest", makeDeleteCachedManifest(db))
}

// makeRetagImage creates the registry.retag_image activity.
// Tags a Docker image for the local registry.
// Idempotent: if local image already exists, returns tagged=true, skipped=true.
//
// Docker CLI commands (tag/push/pull) run on the host via the Docker socket.
// The host daemon trusts localhost:5000 implicitly but NOT the gateway IP
// (10.42.24.1:5000) unless configured as an insecure registry. So we use
// localhost:5000 for the docker tag/push target (LocalImage) and keep the
// gateway IP for RegistryImage (used in HTTP API calls from inside containers).
func makeRetagImage() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RetagImageInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid retag_image input: %w", err))
		}
		if in.SourceImage == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("source_image is required"))
		}

		// Resolve registry host from input, env, or default
		registryHost := in.RegistryHost
		if registryHost == "" {
			registryHost = os.Getenv("REGISTRY_HOST")
			if registryHost == "" {
				registryHost = "10.42.24.1:5000"
			}
		}

		// Derive local name: strip external registry host if present
		localName := in.SourceImage
		if parts := strings.SplitN(in.SourceImage, "/", 2); len(parts) == 2 && strings.Contains(parts[0], ".") {
			localName = parts[1]
		}

		// localhost:5000 for Docker CLI (host daemon trusts localhost implicitly)
		localImage := "localhost:5000/" + localName
		// Gateway IP for HTTP API calls from containers in overlay network
		registryImage := registryHost + "/" + localName

		// Idempotency check: does the local image already exist?
		checkCmd := exec.CommandContext(ctx, "docker", "image", "inspect", localImage)
		if err := checkCmd.Run(); err == nil {
			log.Info().Str("local_image", localImage).Msg("retag_image: local image already exists, skipping")
			return marshalOutput(RetagImageOutput{
				SourceImage:   in.SourceImage,
				LocalImage:    localImage,
				RegistryImage: registryImage,
				Tagged:        true,
				Skipped:       true,
			})
		}

		// Tag the image. Non-fatal: if tagging fails (e.g. source image not yet pulled),
		// return success with skipped=true so the saga doesn't compensate.
		log.Info().Str("source", in.SourceImage).Str("target", localImage).Msg("retag_image: tagging image")
		tagCmd := exec.CommandContext(ctx, "docker", "tag", in.SourceImage, localImage)
		if output, err := tagCmd.CombinedOutput(); err != nil {
			log.Warn().Str("image", in.SourceImage).Str("error", strings.TrimSpace(string(output))).Msg("retag_image: failed, skipping (non-fatal)")
			return marshalOutput(RetagImageOutput{
				SourceImage:   in.SourceImage,
				LocalImage:    localImage,
				RegistryImage: registryImage,
				Tagged:        false,
				Skipped:       true,
			})
		}

		return marshalOutput(RetagImageOutput{
			SourceImage:   in.SourceImage,
			LocalImage:    localImage,
			RegistryImage: registryImage,
			Tagged:        true,
			Skipped:       false,
		})
	}
}

// makePushToRegistry creates the registry.push_to_registry activity.
// Pushes a tagged image to the local registry.
// Idempotent: re-pushing same layers is a no-op.
func makePushToRegistry() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in PushToRegistryInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid push_to_registry input: %w", err))
		}
		if in.LocalImage == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("local_image is required"))
		}

		// Non-fatal: if push fails (e.g. registry down), return success with skipped=true
		// so the saga doesn't compensate. The install succeeds without caching.
		log.Info().Str("image", in.LocalImage).Msg("push_to_registry: pushing image")
		pushCmd := exec.CommandContext(ctx, "docker", "push", in.LocalImage)
		if output, err := pushCmd.CombinedOutput(); err != nil {
			errStr := strings.TrimSpace(string(output))
			log.Warn().Str("image", in.LocalImage).Str("error", errStr).Msg("push_to_registry: failed, skipping (non-fatal)")
			return marshalOutput(PushToRegistryOutput{
				LocalImage: in.LocalImage,
				Pushed:     false,
				Skipped:    true,
			})
		}

		return marshalOutput(PushToRegistryOutput{
			LocalImage: in.LocalImage,
			Pushed:     true,
			Skipped:    false,
		})
	}
}

// makeStoreCachedManifest creates the registry.store_cached_manifest activity.
// Stores app manifest metadata in the cached_manifests table.
// Idempotent: uses INSERT OR REPLACE (upsert on store_id + app_name).
func makeStoreCachedManifest(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in StoreCachedManifestInput
		if err := json.Unmarshal(input, &in); err != nil {
			// Non-fatal: log and return skipped so the saga doesn't compensate
			log.Warn().Err(err).Msg("store_cached_manifest: invalid input, skipping (non-fatal)")
			return marshalOutput(StoreCachedManifestOutput{
				AppName: "unknown",
				Stored:  false,
				Skipped: true,
			})
		}
		if in.StoreID == "" || in.AppName == "" {
			log.Warn().Msg("store_cached_manifest: missing store_id or app_name, skipping (non-fatal)")
			return marshalOutput(StoreCachedManifestOutput{
				AppName: in.AppName,
				Stored:  false,
				Skipped: true,
			})
		}

		// Use manifest from fat envelope (JSON object from read_manifest output).
		// Convert json.RawMessage to string; fall back to ManifestRaw if empty/null.
		manifest := string(in.Manifest)
		if manifest == "" || manifest == "null" {
			manifest = in.ManifestRaw
		}

		// Non-fatal: if the DB write fails, return success with skipped=true
		// so the saga doesn't compensate. The install succeeds without caching.
		log.Info().Str("store", in.StoreID).Str("app", in.AppName).Msg("store_cached_manifest: storing manifest")
		_, err := db.ExecContext(ctx, `
			INSERT INTO cached_manifests (store_id, app_name, image, registry_image, manifest, title, icon, category, tagline)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(store_id, app_name) DO UPDATE SET
				image = excluded.image,
				registry_image = excluded.registry_image,
				manifest = excluded.manifest,
				title = excluded.title,
				icon = excluded.icon,
				category = excluded.category,
				tagline = excluded.tagline,
				cached_at = CURRENT_TIMESTAMP
		`, in.StoreID, in.AppName, in.Image, in.RegistryImage, manifest, in.Title, in.Icon, in.Category, in.Tagline)
		if err != nil {
			log.Warn().Str("app", in.AppName).Err(err).Msg("store_cached_manifest: failed, skipping (non-fatal)")
			return marshalOutput(StoreCachedManifestOutput{
				AppName: in.AppName,
				Stored:  false,
				Skipped: true,
			})
		}

		return marshalOutput(StoreCachedManifestOutput{
			AppName: in.AppName,
			Stored:  true,
		})
	}
}

// makeDeleteCachedManifest creates the registry.delete_cached_manifest activity.
// Removes a cached manifest entry. Used as compensation for store_cached_manifest
// and also by the cleanup/uninstall flow.
// Idempotent: if not found, returns deleted=false (no error).
func makeDeleteCachedManifest(db *sql.DB) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DeleteCachedManifestInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid delete_cached_manifest input: %w", err))
		}
		if in.StoreID == "" || in.AppName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("store_id and app_name are required"))
		}

		log.Info().Str("store", in.StoreID).Str("app", in.AppName).Msg("delete_cached_manifest: deleting manifest")
		result, err := db.ExecContext(ctx, `DELETE FROM cached_manifests WHERE store_id = ? AND app_name = ?`,
			in.StoreID, in.AppName)
		if err != nil {
			return nil, flowengine.ClassifyError(fmt.Errorf("failed to delete cached manifest: %w", err))
		}

		rows, _ := result.RowsAffected()
		return marshalOutput(DeleteCachedManifestOutput{
			Deleted: rows > 0,
		})
	}
}
