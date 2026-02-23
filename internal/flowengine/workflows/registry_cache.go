package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

const (
	// RegistryCacheType is the workflow type for caching an app store app into the local registry.
	RegistryCacheType = "registry_cache"
	// RegistryCacheVersion is the current version of the workflow definition.
	RegistryCacheVersion = 1
)

// RegistryCacheWorkflow defines the step sequence for caching an app store app
// into the local Docker registry for offline use.
//
// When a user caches an app for offline use, this workflow:
//  1. Validates the store app exists and is not already installed
//  2. Reads the full CasaOS manifest from disk
//  3. Pulls the Docker image from upstream
//  4. Retags the image for the local registry (10.42.24.1:5000)
//  5. Pushes the retagged image to the local registry
//  6. Stores the manifest metadata in cached_manifests table
//
// After completion, the app appears in the "Offline Apps" view with full metadata,
// enabling proper install/uninstall when disconnected.
//
// Input shape (submitted by CacheApp handler):
//
//	{
//	  "store_id": "casa-store-abc",
//	  "app_name": "prowlarr",
//	  "image": "linuxserver/prowlarr:latest",
//	  "title": "Prowlarr",
//	  "icon": "https://...",
//	  "category": "Downloaders",
//	  "tagline": "Indexer manager/proxy"
//	}
type RegistryCacheWorkflow struct{}

func (w *RegistryCacheWorkflow) Type() string { return RegistryCacheType }
func (w *RegistryCacheWorkflow) Version() int { return RegistryCacheVersion }

func (w *RegistryCacheWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			// Step 0: Validate store ID and app name, check no conflicts
			Name:       "validate",
			Action:     "appstore.validate",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			// Step 1: Fetch app manifest from store (cached on disk)
			Name:       "read_manifest",
			Action:     "appstore.read_manifest",
			Compensate: "", // read-only
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    30 * time.Second,
		},
		{
			// Step 2: Pull Docker image from upstream registry
			// 300s timeout for large images (e.g. linuxserver images ~500MB) on Pi
			Name:       "pull_image",
			Action:     "docker.pull_image",
			Compensate: "", // keeping pulled image is fine
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 2 * time.Second, MaxInterval: 30 * time.Second},
			Timeout:    300 * time.Second,
		},
		{
			// Step 3: Tag image for local registry (10.42.24.1:5000/...)
			Name:       "retag_image",
			Action:     "registry.retag_image",
			Compensate: "", // best effort cleanup, not worth compensating
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    30 * time.Second,
		},
		{
			// Step 4: Push retagged image to local registry
			Name:       "push_to_registry",
			Action:     "registry.push_to_registry",
			Compensate: "", // image in registry is harmless
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 2 * time.Second, MaxInterval: 30 * time.Second},
			Timeout:    120 * time.Second,
		},
		{
			// Step 5: Store manifest metadata in cached_manifests table
			Name:       "store_manifest",
			Action:     "registry.store_cached_manifest",
			Compensate: "registry.delete_cached_manifest",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 500 * time.Millisecond},
			Timeout:    10 * time.Second,
		},
	}
}

// NewRegistryCacheWorkflow creates a new RegistryCacheWorkflow definition.
func NewRegistryCacheWorkflow() *RegistryCacheWorkflow {
	return &RegistryCacheWorkflow{}
}
