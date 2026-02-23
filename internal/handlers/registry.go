// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/flowengine/workflows"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

// RegistryHandler handles local Docker registry endpoints.
type RegistryHandler struct {
	registryURL  string
	registryPath string
	httpClient   *http.Client
	portManager  *managers.PortManager         // B108: triple-source port allocation
	orchestrator *managers.Orchestrator        // Unified install pipeline (Batch 1)
	db           *sql.DB                       // Settings persistence
	syncManager  *managers.RegistrySyncManager // Batch 5: background upstream sync
	appStoreMgr  *managers.AppStoreManager     // App store catalog access (offline registry)
	networkMgr   *managers.NetworkManager      // Network mode check (offline detection)
	flowEngine   *flowengine.WorkflowEngine    // FlowEngine for workflow submission
	feStore      *flowengine.WorkflowStore     // FlowEngine store for progress tracking
}

// NewRegistryHandler creates a new RegistryHandler instance.
// For Swarm containers, use the gateway IP (not localhost:5000)
// because containers in overlay network cannot reach localhost on the host.
func NewRegistryHandler(registryURL, registryPath string, portMgr *managers.PortManager, orchestrator *managers.Orchestrator, db *sql.DB, syncMgr *managers.RegistrySyncManager, appStoreMgr *managers.AppStoreManager, networkMgr *managers.NetworkManager, engine *flowengine.WorkflowEngine, store *flowengine.WorkflowStore) *RegistryHandler {
	if registryURL == "" {
		// Check env var first, then fall back to gateway IP (works from inside Swarm overlay)
		registryURL = os.Getenv("REGISTRY_URL")
		if registryURL == "" {
			registryURL = "http://" + models.DefaultGatewayIP + ":5000"
		}
	}
	if registryPath == "" {
		registryPath = "/cubeos/data/registry"
	}
	return &RegistryHandler{
		registryURL:  registryURL,
		registryPath: registryPath,
		portManager:  portMgr,
		orchestrator: orchestrator,
		db:           db,
		syncManager:  syncMgr,
		appStoreMgr:  appStoreMgr,
		networkMgr:   networkMgr,
		flowEngine:   engine,
		feStore:      store,
		httpClient: &http.Client{
			Timeout: 10 * time.Second, // Reduced timeout for faster failure detection
		},
	}
}

// Routes returns the router for registry endpoints.
func (h *RegistryHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/status", h.GetStatus)
	r.Post("/init", h.InitRegistry)
	r.Post("/cache", h.CacheImage)
	r.Get("/check", h.CheckImage)
	r.Get("/images", h.ListImages)
	r.Get("/images/{name}/tags", h.GetImageTags)
	r.Delete("/images/{name}/tags/{tag}", h.DeleteImageTag)
	r.Delete("/images/{name}", h.DeleteImage)
	r.Post("/cleanup", h.CleanupRegistry)
	r.Get("/disk-usage", h.GetDiskUsage)
	r.Post("/deploy", h.DeployImage)
	r.Get("/settings", h.GetRegistrySettings)
	r.Put("/settings", h.UpdateRegistrySettings)
	r.Post("/sync", h.TriggerSync)
	r.Get("/sync/status", h.GetSyncStatus)
	r.Get("/cached-apps", h.ListCachedApps)
	r.Post("/cache-app", h.CacheApp)

	return r
}

// RegistryStatus represents the registry status response.
type RegistryStatus struct {
	Online       bool   `json:"online"`
	URL          string `json:"url"`
	Version      string `json:"version,omitempty"`
	DiskUsage    int64  `json:"disk_usage_bytes"`
	DiskUsageStr string `json:"disk_usage"`
	ImageCount   int    `json:"image_count"`
	Error        string `json:"error,omitempty"`
}

// GetStatus godoc
// @Summary Get registry status
// @Description Returns the local Docker registry health status including online state, version, disk usage, and image count
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Success 200 {object} RegistryStatus "Registry status with online, url, version, disk_usage, image_count"
// @Router /registry/status [get]
func (h *RegistryHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := RegistryStatus{
		URL: h.registryURL,
	}

	// Check if registry is online
	resp, err := h.httpClient.Get(h.registryURL + "/v2/")
	if err != nil {
		status.Online = false
		status.Error = fmt.Sprintf("Cannot connect to registry: %v", err)
	} else {
		defer resp.Body.Close()
		status.Online = (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized)

		if !status.Online {
			status.Error = fmt.Sprintf("Registry returned HTTP %d", resp.StatusCode)
		}

		// Try to get version from headers
		if version := resp.Header.Get("Docker-Distribution-Api-Version"); version != "" {
			status.Version = version
		}
	}

	// Get image count (only if online to avoid additional errors)
	if status.Online {
		images, err := h.getImageList()
		if err == nil {
			status.ImageCount = len(images)
		}
	}

	// Get disk usage (may fail if path not accessible from container)
	status.DiskUsage = h.getDiskUsage()
	status.DiskUsageStr = registryFormatBytes(status.DiskUsage)

	registryWriteJSON(w, http.StatusOK, status)
}

// InitRegistryRequest is the optional request body for registry initialization.
type InitRegistryRequest struct {
	StoragePath string `json:"storage_path,omitempty"` // Override default storage path
}

// InitRegistry godoc
// @Summary Initialize local Docker registry
// @Description Starts the local Docker registry container if it is not already running. Creates the storage directory and deploys the registry service.
// @Tags Registry
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body InitRegistryRequest false "Optional initialization parameters"
// @Success 200 {object} map[string]interface{} "success: true, already_running or started, url"
// @Failure 500 {object} ErrorResponse "Failed to initialize registry"
// @Router /registry/init [post]
func (h *RegistryHandler) InitRegistry(w http.ResponseWriter, r *http.Request) {
	// Check if registry is already running
	resp, err := h.httpClient.Get(h.registryURL + "/v2/")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
			registryWriteJSON(w, http.StatusOK, map[string]interface{}{
				"success":         true,
				"already_running": true,
				"url":             h.registryURL,
				"message":         "Registry is already running",
			})
			return
		}
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(h.registryPath, 0755); err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to create registry storage directory: "+err.Error())
		return
	}

	// Start registry container using docker CLI
	// Use docker run with restart policy for resilience
	cmd := exec.CommandContext(r.Context(), "docker", "run", "-d",
		"--name", "cubeos-registry",
		"--restart", "unless-stopped",
		"-p", "5000:5000",
		"-v", h.registryPath+":/var/lib/registry",
		"-e", "REGISTRY_STORAGE_DELETE_ENABLED=true",
		"registry:2",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := strings.TrimSpace(string(output))
		// If container already exists but is stopped, try to start it
		if strings.Contains(outputStr, "already in use") {
			startCmd := exec.CommandContext(r.Context(), "docker", "start", "cubeos-registry")
			if startOut, startErr := startCmd.CombinedOutput(); startErr != nil {
				registryWriteError(w, http.StatusInternalServerError,
					fmt.Sprintf("Failed to start existing registry: %s", strings.TrimSpace(string(startOut))))
				return
			}
		} else {
			registryWriteError(w, http.StatusInternalServerError,
				fmt.Sprintf("Failed to start registry: %s", outputStr))
			return
		}
	}

	// Wait briefly for registry to become available
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		if checkResp, checkErr := h.httpClient.Get(h.registryURL + "/v2/"); checkErr == nil {
			checkResp.Body.Close()
			if checkResp.StatusCode == http.StatusOK || checkResp.StatusCode == http.StatusUnauthorized {
				break
			}
		}
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"started": true,
		"url":     h.registryURL,
		"message": "Registry started successfully",
	})
}

// CacheImageRequest is the request body for caching a remote image.
type CacheImageRequest struct {
	Image string `json:"image"` // Full image reference (e.g. "nginx:latest", "ghcr.io/org/repo:tag")
}

// CacheImage godoc
// @Summary Cache a remote image to local registry
// @Description Pulls a remote Docker image, retags it for the local registry, and pushes it. This enables offline installation of the image.
// @Tags Registry
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CacheImageRequest true "Image to cache"
// @Success 200 {object} map[string]interface{} "success: true, image, local_image, message"
// @Failure 400 {object} ErrorResponse "Missing image reference"
// @Failure 500 {object} ErrorResponse "Failed to pull, tag, or push image"
// @Router /registry/cache [post]
func (h *RegistryHandler) CacheImage(w http.ResponseWriter, r *http.Request) {
	var req CacheImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Image == "" {
		registryWriteError(w, http.StatusBadRequest, "Image reference is required (e.g. {\"image\": \"nginx:latest\"})")
		return
	}

	imageRef := req.Image

	// Derive local registry image name
	// e.g. "nginx:latest" -> "10.42.24.1:5000/nginx:latest"
	// e.g. "ghcr.io/org/repo:v1" -> "10.42.24.1:5000/org/repo:v1"
	registryHost := strings.TrimPrefix(h.registryURL, "http://")
	registryHost = strings.TrimPrefix(registryHost, "https://")

	// Strip the original registry host if present
	localName := imageRef
	if parts := strings.SplitN(imageRef, "/", 2); len(parts) == 2 && strings.Contains(parts[0], ".") {
		// Has a registry host prefix (e.g. ghcr.io/org/repo:tag)
		localName = parts[1]
	}
	localImage := registryHost + "/" + localName

	// Step 1: Pull the remote image
	pullCmd := exec.CommandContext(r.Context(), "docker", "pull", imageRef)
	if output, err := pullCmd.CombinedOutput(); err != nil {
		registryWriteError(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to pull image %s: %s", imageRef, strings.TrimSpace(string(output))))
		return
	}

	// Step 2: Tag for local registry
	tagCmd := exec.CommandContext(r.Context(), "docker", "tag", imageRef, localImage)
	if output, err := tagCmd.CombinedOutput(); err != nil {
		registryWriteError(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to tag image: %s", strings.TrimSpace(string(output))))
		return
	}

	// Step 3: Push to local registry
	pushCmd := exec.CommandContext(r.Context(), "docker", "push", localImage)
	if output, err := pushCmd.CombinedOutput(); err != nil {
		registryWriteError(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to push to local registry: %s", strings.TrimSpace(string(output))))
		return
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"image":       imageRef,
		"local_image": localImage,
		"message":     fmt.Sprintf("Image %s cached to local registry as %s", imageRef, localImage),
	})
}

// CheckImage godoc
// @Summary Check if an image exists in local registry
// @Description Checks whether a specific image:tag combination exists in the local Docker registry.
// @Description Uses query parameters to avoid URL encoding issues with multi-segment image names (e.g., kiwix/kiwix-serve).
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Param image query string true "Image name (e.g., nginx, kiwix/kiwix-serve, tsl0922/ttyd)"
// @Param tag query string false "Image tag (default: latest)"
// @Success 200 {object} map[string]interface{} "exists: bool, image: string, tag: string, digest: string (if exists)"
// @Failure 400 {object} ErrorResponse "Missing image parameter"
// @Failure 500 {object} ErrorResponse "Registry communication error"
// @Router /registry/check [get]
func (h *RegistryHandler) CheckImage(w http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	tag := r.URL.Query().Get("tag")

	if image == "" {
		registryWriteError(w, http.StatusBadRequest, "Missing required 'image' query parameter")
		return
	}
	if tag == "" {
		tag = "latest"
	}

	// Try to get the manifest digest — if it succeeds, the image exists
	digest, err := h.getManifestDigest(image, tag)
	if err != nil {
		registryWriteJSON(w, http.StatusOK, map[string]interface{}{
			"exists": false,
			"image":  image,
			"tag":    tag,
		})
		return
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"exists": true,
		"image":  image,
		"tag":    tag,
		"digest": digest,
	})
}

// DeleteImageTag godoc
// @Summary Delete a specific image tag
// @Description Deletes a specific tag of an image from the local registry. Requires garbage collection to reclaim disk space. System image tags cannot be deleted.
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Param name path string true "Image name (e.g., nginx or library/nginx)"
// @Param tag path string true "Tag to delete (e.g., latest, v1.0)"
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 403 {object} ErrorResponse "Cannot delete system image tag"
// @Failure 404 {object} ErrorResponse "Image or tag not found"
// @Failure 500 {object} ErrorResponse "Failed to delete tag"
// @Router /registry/images/{name}/tags/{tag} [delete]
func (h *RegistryHandler) DeleteImageTag(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tag := chi.URLParam(r, "tag")

	if name == "" || tag == "" {
		registryWriteError(w, http.StatusBadRequest, "Image name and tag are required")
		return
	}

	// Block deletion of system-managed image tags (Tier 1: all 10 protected)
	if isProtectedRegistryImage(name) {
		registryWriteError(w, http.StatusForbidden, fmt.Sprintf("Cannot delete system image tag %s:%s — it is required by CubeOS", name, tag))
		return
	}

	// Get manifest digest for this tag
	digest, err := h.getManifestDigest(name, tag)
	if err != nil {
		registryWriteError(w, http.StatusNotFound, "Image or tag not found: "+err.Error())
		return
	}

	// Delete by digest
	deleteURL := fmt.Sprintf("%s/v2/%s/manifests/%s", h.registryURL, url.PathEscape(name), url.PathEscape(digest))
	req2, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to create delete request: "+err.Error())
		return
	}

	resp, err := h.httpClient.Do(req2)
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to delete tag: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		registryWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Registry returned status %d", resp.StatusCode))
		return
	}

	// Clean up cached manifest if this image was cached for offline use
	if h.db != nil {
		h.db.Exec("DELETE FROM cached_manifests WHERE image LIKE ? OR registry_image LIKE ?",
			"%"+name+":%", "%"+name+":%")
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Deleted %s:%s", name, tag),
	})
}

// RegistryImage represents an image in the registry.
type RegistryImage struct {
	Name     string   `json:"name"`
	Tags     []string `json:"tags,omitempty"`
	TagCount int      `json:"tag_count"`
	FullName string   `json:"full_name,omitempty"`
	System   bool     `json:"system"`   // Tier 1: protected from registry deletion
	Critical bool     `json:"critical"` // Tier 2: hidden from App Store entirely
}

// isProtectedRegistryImage returns true for ALL system images that cannot
// be deleted from the local registry (9 coreapp images).
// NOTE: kiwix removed — it's a user app, not a system service.
// NOTE: registry image itself isn't stored IN the registry.
func isProtectedRegistryImage(name string) bool {
	protected := map[string]bool{
		"cubeos-app/api":              true,
		"cubeos-app/hal":              true,
		"cubeos-app/dashboard":        true,
		"cubeos-app/cubeos-docsindex": true,
		"pihole/pihole":               true,
		"jc21/nginx-proxy-manager":    true,
		"amir20/dozzle":               true,
		"sigoden/dufs":                true,
		"tsl0922/ttyd":                true,
	}
	return protected[name]
}

// isCriticalSystemImage returns true for images that must NEVER appear as
// installable apps in the App Store. All protected images are also critical
// (hidden from App Store). The previous Tier 2/Tier 3 distinction was removed
// because coreapps deployed via compose/swarm don't appear in the installed
// apps DB, so the "Installed" badge never shows.
func isCriticalSystemImage(name string) bool {
	return isProtectedRegistryImage(name)
}

// ListImages godoc
// @Summary List registry images
// @Description Returns all images stored in the local Docker registry with optional tag details
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Param include_tags query boolean false "Include full tag list for each image"
// @Success 200 {object} map[string]interface{} "images: array of RegistryImage, count, url"
// @Failure 503 {object} ErrorResponse "Failed to get image list (registry unavailable)"
// @Router /registry/images [get]
func (h *RegistryHandler) ListImages(w http.ResponseWriter, r *http.Request) {
	images, err := h.getImageList()
	if err != nil {
		registryWriteError(w, http.StatusServiceUnavailable, "Failed to get image list: "+err.Error())
		return
	}

	// Optionally get tags for each image
	includeTags := r.URL.Query().Get("include_tags") == "true"

	result := make([]RegistryImage, 0)
	for _, name := range images {
		img := RegistryImage{
			Name:     name,
			FullName: fmt.Sprintf("%s/%s", strings.TrimPrefix(h.registryURL, "http://"), name),
			System:   isProtectedRegistryImage(name),
			Critical: isCriticalSystemImage(name),
		}

		if includeTags {
			tags, _ := h.getImageTags(name)
			img.Tags = tags
			img.TagCount = len(tags)
		} else {
			// Just get count
			tags, _ := h.getImageTags(name)
			img.TagCount = len(tags)
		}

		result = append(result, img)
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"images": result,
		"count":  len(result),
		"url":    h.registryURL,
	})
}

// GetImageTags godoc
// @Summary Get image tags
// @Description Returns all tags for a specific image in the local registry. Supports nested image names (e.g., library/nginx).
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Param name path string true "Image name (e.g., nginx or library/nginx)"
// @Success 200 {object} map[string]interface{} "name: image name, tags: array of tag strings"
// @Failure 404 {object} ErrorResponse "Image not found or failed to get tags"
// @Router /registry/images/{name}/tags [get]
func (h *RegistryHandler) GetImageTags(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	// Handle nested names (e.g., library/nginx)
	if r.URL.Path != "" {
		// Extract everything after /images/
		pathParts := strings.SplitN(r.URL.Path, "/images/", 2)
		if len(pathParts) > 1 {
			name = strings.TrimSuffix(pathParts[1], "/tags")
		}
	}

	tags, err := h.getImageTags(name)
	if err != nil {
		registryWriteError(w, http.StatusNotFound, "Image not found or failed to get tags: "+err.Error())
		return
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"name": name,
		"tags": tags,
	})
}

// DeleteImage godoc
// @Summary Delete an image tag
// @Description Deletes a specific tag of an image from the local registry. Requires garbage collection to reclaim disk space. System images cannot be deleted.
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Param name path string true "Image name"
// @Param tag query string false "Tag to delete (defaults to 'latest')"
// @Success 200 {object} map[string]interface{} "success: true, message: deletion confirmation"
// @Failure 403 {object} ErrorResponse "Cannot delete system image"
// @Failure 404 {object} ErrorResponse "Image or tag not found"
// @Failure 500 {object} ErrorResponse "Failed to delete image"
// @Router /registry/images/{name} [delete]
func (h *RegistryHandler) DeleteImage(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		tag = "latest"
	}

	// Block deletion of system-managed images (Tier 1: all 10 protected)
	if isProtectedRegistryImage(name) {
		registryWriteError(w, http.StatusForbidden, fmt.Sprintf("Cannot delete system image %s — it is required by CubeOS", name))
		return
	}

	// Get manifest digest
	digest, err := h.getManifestDigest(name, tag)
	if err != nil {
		registryWriteError(w, http.StatusNotFound, "Image or tag not found: "+err.Error())
		return
	}

	// Delete by digest
	deleteURL := fmt.Sprintf("%s/v2/%s/manifests/%s", h.registryURL, url.PathEscape(name), url.PathEscape(digest))
	req, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to create delete request: "+err.Error())
		return
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to delete image: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		registryWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Registry returned status %d", resp.StatusCode))
		return
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Deleted %s:%s", name, tag),
	})
}

// CleanupRequest is the request body for cleanup operation.
type CleanupRequest struct {
	KeepTags      int  `json:"keep_tags"`       // Number of tags to keep per image
	OlderThanDays int  `json:"older_than_days"` // Delete tags older than N days
	DryRun        bool `json:"dry_run"`         // If true, only report what would be deleted
}

// CleanupRegistry godoc
// @Summary Cleanup old images
// @Description Identifies and optionally removes old/unused image tags. Use dry_run=true to preview. Requires running garbage-collect on the registry container to reclaim disk space.
// @Tags Registry
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CleanupRequest false "Cleanup options (defaults: keep_tags=2, dry_run=false)"
// @Success 200 {object} map[string]interface{} "success, dry_run, deleted_count, deleted_images, message with gc command"
// @Router /registry/cleanup [post]
func (h *RegistryHandler) CleanupRegistry(w http.ResponseWriter, r *http.Request) {
	var req CleanupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.KeepTags = 2
		req.DryRun = false
	}
	if req.KeepTags < 1 {
		req.KeepTags = 1
	}

	images, _ := h.getImageList()
	var totalDeleted int
	var deletedImages []string

	for _, name := range images {
		// Never clean up system images (Tier 1: all 10 protected)
		if isProtectedRegistryImage(name) {
			continue
		}
		tags, _ := h.getImageTags(name)
		if len(tags) <= req.KeepTags {
			continue
		}

		// Keep the last N tags (sorted alphabetically — "latest" typically sorts high)
		toDelete := tags[:len(tags)-req.KeepTags]

		for _, tag := range toDelete {
			if tag == "latest" {
				continue // Never delete "latest" tag
			}
			if !req.DryRun {
				digest, err := h.getManifestDigest(name, tag)
				if err != nil {
					continue
				}
				deleteURL := fmt.Sprintf("%s/v2/%s/manifests/%s", h.registryURL, url.PathEscape(name), url.PathEscape(digest))
				delReq, err := http.NewRequest("DELETE", deleteURL, nil)
				if err != nil {
					continue
				}
				resp, err := h.httpClient.Do(delReq)
				if err != nil {
					continue
				}
				resp.Body.Close()
				if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
					totalDeleted++
					deletedImages = append(deletedImages, fmt.Sprintf("%s:%s", name, tag))
				}
			} else {
				totalDeleted++
				deletedImages = append(deletedImages, fmt.Sprintf("%s:%s (dry-run)", name, tag))
			}
		}
	}

	// If we actually deleted tags, run GC
	gcMessage := ""
	if totalDeleted > 0 && !req.DryRun {
		gcCmd := exec.CommandContext(r.Context(), "docker", "exec", "registry",
			"bin/registry", "garbage-collect", "/etc/docker/registry/config.yml", "--delete-untagged")
		gcOut, err := gcCmd.CombinedOutput()
		if err != nil {
			gcMessage = fmt.Sprintf("GC failed: %s", strings.TrimSpace(string(gcOut)))
		} else {
			gcMessage = "GC completed successfully"
		}
	}

	result := map[string]interface{}{
		"success":        true,
		"dry_run":        req.DryRun,
		"deleted_count":  totalDeleted,
		"deleted_images": deletedImages,
	}
	if gcMessage != "" {
		result["gc_result"] = gcMessage
	}
	if req.DryRun {
		result["message"] = fmt.Sprintf("Would delete %d tags (dry-run mode)", totalDeleted)
	} else {
		result["message"] = fmt.Sprintf("Deleted %d tags", totalDeleted)
	}

	registryWriteJSON(w, http.StatusOK, result)
}

// GetDiskUsage godoc
// @Summary Get registry disk usage
// @Description Returns the disk space used by the local Docker registry storage
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "bytes: size in bytes, readable: human-readable size, path: storage path"
// @Router /registry/disk-usage [get]
func (h *RegistryHandler) GetDiskUsage(w http.ResponseWriter, r *http.Request) {
	totalBytes := h.getDiskUsage()

	result := map[string]interface{}{
		"bytes":    totalBytes,
		"readable": registryFormatBytes(totalBytes),
		"path":     h.registryPath,
	}

	// Add warning if we couldn't get disk usage
	if totalBytes == 0 {
		result["warning"] = "Could not access registry storage path from container"
	}

	registryWriteJSON(w, http.StatusOK, result)
}

// DeployImageRequest is the request body for deploying a cached registry image.
type DeployImageRequest struct {
	Image   string `json:"image"`    // Image name in registry (e.g., "kiwix-serve")
	Tag     string `json:"tag"`      // Image tag (default: "latest")
	AppName string `json:"app_name"` // App/stack name (default: derived from image)
}

// DeployImage godoc
// @Summary Deploy a cached registry image
// @Description Deploys an image from the local registry through the unified Orchestrator pipeline. Creates DB record, allocates port, sets up FQDN/DNS/NPM proxy, and deploys via Docker Swarm. The app appears in "My Apps" and can be managed/uninstalled normally. Internally delegates to POST /api/v1/apps with source="registry".
// @Tags Registry
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body DeployImageRequest true "Image to deploy"
// @Success 200 {object} map[string]interface{} "success, app_name, image, port, fqdn, web_ui"
// @Failure 400 {object} ErrorResponse "Missing image or invalid app name"
// @Failure 404 {object} ErrorResponse "Image not found in registry"
// @Failure 500 {object} ErrorResponse "Failed to deploy"
// @Router /registry/deploy [post]
func (h *RegistryHandler) DeployImage(w http.ResponseWriter, r *http.Request) {
	var req DeployImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Image == "" {
		registryWriteError(w, http.StatusBadRequest, "Image name is required")
		return
	}

	if req.Tag == "" {
		req.Tag = "latest"
	}

	// Derive app name from image if not provided
	appName := req.AppName
	if appName == "" {
		// Take last path segment: "library/nginx" → "nginx"
		parts := strings.Split(req.Image, "/")
		appName = parts[len(parts)-1]
	}
	// Sanitize: lowercase, alphanumeric + hyphens only
	appName = strings.ToLower(appName)
	appName = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, appName)
	appName = strings.Trim(appName, "-")
	if appName == "" {
		registryWriteError(w, http.StatusBadRequest, "Could not derive a valid app name from image")
		return
	}

	// Verify image exists in registry
	tags, err := h.getImageTags(req.Image)
	if err != nil || len(tags) == 0 {
		registryWriteError(w, http.StatusNotFound, fmt.Sprintf("Image %s not found in registry", req.Image))
		return
	}
	tagFound := false
	for _, t := range tags {
		if t == req.Tag {
			tagFound = true
			break
		}
	}
	if !tagFound {
		registryWriteError(w, http.StatusNotFound, fmt.Sprintf("Tag %s not found for image %s (available: %s)", req.Tag, req.Image, strings.Join(tags, ", ")))
		return
	}

	// Delegate to Orchestrator unified pipeline (Batch 1: ONE code path)
	app, err := h.orchestrator.InstallApp(r.Context(), models.InstallAppRequest{
		Name:   appName,
		Source: models.AppSourceRegistry,
		Image:  req.Image,
		Tag:    req.Tag,
	})
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	fqdn := app.GetPrimaryFQDN()
	webUI := fmt.Sprintf("http://%s", fqdn)

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"app_name": app.Name,
		"image":    req.Image + ":" + req.Tag,
		"fqdn":     fqdn,
		"web_ui":   webUI,
		"message":  fmt.Sprintf("Deployed %s — accessible at %s", app.Name, webUI),
	})
}

// Helper methods

func (h *RegistryHandler) getImageList() ([]string, error) {
	resp, err := h.httpClient.Get(h.registryURL + "/v2/_catalog")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return catalog.Repositories, nil
}

func (h *RegistryHandler) getImageTags(name string) ([]string, error) {
	tagURL := fmt.Sprintf("%s/v2/%s/tags/list", h.registryURL, url.PathEscape(name))
	resp, err := h.httpClient.Get(tagURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("image not found")
	}

	var tags struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil, err
	}

	return tags.Tags, nil
}

func (h *RegistryHandler) getManifestDigest(name, tag string) (string, error) {
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", h.registryURL, url.PathEscape(name), url.PathEscape(tag))
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("manifest not found")
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		// Fall back to parsing the manifest body
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
		if err != nil {
			return "", fmt.Errorf("failed to read manifest body: %w", err)
		}
		var manifest struct {
			Config struct {
				Digest string `json:"digest"`
			} `json:"config"`
		}
		if err := json.Unmarshal(body, &manifest); err != nil {
			return "", fmt.Errorf("failed to parse manifest: %w", err)
		}
		digest = manifest.Config.Digest
	}

	if digest == "" {
		return "", fmt.Errorf("no digest found for %s:%s", name, tag)
	}

	return digest, nil
}

func (h *RegistryHandler) getDiskUsage() int64 {
	var size int64
	err := filepath.Walk(h.registryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking even on errors
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0
	}
	return size
}

// Helper functions for JSON responses (local to avoid conflicts with other handlers)

func registryWriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func registryWriteError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func registryFormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// =========================================================================
// Registry Settings (T11)
// =========================================================================

// RegistrySettings represents configurable registry settings.
type RegistrySettings struct {
	AutoUpdate bool `json:"auto_update"`
}

// GetRegistrySettings godoc
// @Summary Get registry settings
// @Description Returns the current registry settings including auto-update toggle
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Success 200 {object} RegistrySettings "Current registry settings"
// @Router /registry/settings [get]
func (h *RegistryHandler) GetRegistrySettings(w http.ResponseWriter, r *http.Request) {
	val := h.getSetting("registry_auto_update")
	autoUpdate := val != "false" // default true

	registryWriteJSON(w, http.StatusOK, RegistrySettings{
		AutoUpdate: autoUpdate,
	})
}

// UpdateRegistrySettings godoc
// @Summary Update registry settings
// @Description Updates registry settings (e.g., auto-update toggle)
// @Tags Registry
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param settings body RegistrySettings true "Registry settings"
// @Success 200 {object} RegistrySettings "Updated registry settings"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Router /registry/settings [put]
func (h *RegistryHandler) UpdateRegistrySettings(w http.ResponseWriter, r *http.Request) {
	var req RegistrySettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		registryWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	val := "false"
	if req.AutoUpdate {
		val = "true"
	}
	h.setSetting("registry_auto_update", val)

	registryWriteJSON(w, http.StatusOK, RegistrySettings{
		AutoUpdate: req.AutoUpdate,
	})
}

// =========================================================================
// Registry Sync (T16)
// =========================================================================

// TriggerSync godoc
// @Summary Trigger registry sync
// @Description Triggers an immediate sync cycle that checks upstream registries for newer images and updates the local registry. Non-blocking — returns immediately, sync runs in background.
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 409 {object} ErrorResponse "Sync already in progress"
// @Failure 503 {object} ErrorResponse "Sync manager not initialized"
// @Router /registry/sync [post]
func (h *RegistryHandler) TriggerSync(w http.ResponseWriter, r *http.Request) {
	if h.syncManager == nil {
		registryWriteError(w, http.StatusServiceUnavailable, "Sync manager not initialized")
		return
	}

	if err := h.syncManager.TriggerSync(); err != nil {
		registryWriteError(w, http.StatusConflict, err.Error())
		return
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Sync triggered — check GET /api/v1/registry/sync/status for progress",
	})
}

// GetSyncStatus godoc
// @Summary Get sync status
// @Description Returns the current sync state (running/idle) and the result of the last sync cycle including which images were checked, updated, or failed.
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "running, last_result"
// @Failure 503 {object} ErrorResponse "Sync manager not initialized"
// @Router /registry/sync/status [get]
func (h *RegistryHandler) GetSyncStatus(w http.ResponseWriter, r *http.Request) {
	if h.syncManager == nil {
		registryWriteError(w, http.StatusServiceUnavailable, "Sync manager not initialized")
		return
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"running":     h.syncManager.IsRunning(),
		"last_result": h.syncManager.GetLastResult(),
	})
}

func (h *RegistryHandler) getSetting(key string) string {
	if h.db == nil {
		return ""
	}
	var val string
	err := h.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if err != nil {
		return ""
	}
	return val
}

func (h *RegistryHandler) setSetting(key, value string) {
	if h.db == nil {
		return
	}
	_, _ = h.db.Exec(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`, key, value)
}

// =========================================================================
// Offline Registry — Cached Apps (Batch 1)
// =========================================================================

// CachedApp represents an app cached in the registry for offline use.
type CachedApp struct {
	StoreID       string `json:"store_id"`
	AppName       string `json:"app_name"`
	Image         string `json:"image"`
	RegistryImage string `json:"registry_image"`
	Title         string `json:"title"`
	Icon          string `json:"icon"`
	Category      string `json:"category"`
	Tagline       string `json:"tagline"`
	CachedAt      string `json:"cached_at"`
	Installed     bool   `json:"installed"`
}

// ListCachedApps godoc
// @Summary List apps cached for offline use
// @Description Returns all apps that have been cached in the local registry with their full manifests, enabling offline install. Cross-references the apps table to set the installed flag.
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "cached_apps: []CachedApp, count: int"
// @Failure 500 {object} ErrorResponse "Database query failed"
// @Router /registry/cached-apps [get]
func (h *RegistryHandler) ListCachedApps(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT cm.store_id, cm.app_name, cm.image, cm.registry_image,
		       cm.title, cm.icon, cm.category, cm.tagline, cm.cached_at,
		       CASE WHEN a.id IS NOT NULL THEN 1 ELSE 0 END AS installed
		FROM cached_manifests cm
		LEFT JOIN apps a ON a.name = cm.app_name
		ORDER BY cm.cached_at DESC
	`)
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to query cached apps: "+err.Error())
		return
	}
	defer rows.Close()

	apps := make([]CachedApp, 0)
	for rows.Next() {
		var app CachedApp
		var installed int
		if err := rows.Scan(&app.StoreID, &app.AppName, &app.Image, &app.RegistryImage,
			&app.Title, &app.Icon, &app.Category, &app.Tagline, &app.CachedAt, &installed); err != nil {
			continue
		}
		app.Installed = installed == 1
		apps = append(apps, app)
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"cached_apps": apps,
		"count":       len(apps),
	})
}

// CacheAppRequest is the request body for caching a store app.
type CacheAppRequest struct {
	StoreID string `json:"store_id"`
	AppName string `json:"app_name"`
}

// CacheApp godoc
// @Summary Cache a store app for offline use
// @Description Caches a CasaOS app store app into the local Docker registry, storing the full manifest alongside the image. This enables offline installation with proper metadata. Returns a workflow ID for SSE progress tracking. Requires internet connectivity to pull images from upstream.
// @Tags Registry
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CacheAppRequest true "App to cache (store_id + app_name)"
// @Success 202 {object} map[string]interface{} "workflow_id: string, message: string"
// @Failure 400 {object} ErrorResponse "Missing store_id or app_name"
// @Failure 404 {object} ErrorResponse "App not found in store catalog"
// @Failure 503 {object} ErrorResponse "Cannot cache while offline or FlowEngine unavailable"
// @Router /registry/cache-app [post]
func (h *RegistryHandler) CacheApp(w http.ResponseWriter, r *http.Request) {
	// Check FlowEngine is available
	if h.flowEngine == nil {
		registryWriteError(w, http.StatusServiceUnavailable, "FlowEngine not available")
		return
	}

	// Check device is online (images must be pulled from upstream)
	if h.networkMgr != nil && h.networkMgr.GetCurrentMode().IsOffline() {
		registryWriteError(w, http.StatusServiceUnavailable,
			"Cannot cache apps while offline — images must be pulled from upstream")
		return
	}

	var req CacheAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		registryWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.StoreID == "" || req.AppName == "" {
		registryWriteError(w, http.StatusBadRequest, "store_id and app_name are required")
		return
	}

	// Check app store manager is available
	if h.appStoreMgr == nil {
		registryWriteError(w, http.StatusServiceUnavailable, "App store manager not available")
		return
	}

	// Fetch app from store catalog
	storeApp := h.appStoreMgr.GetApp(req.StoreID, req.AppName)
	if storeApp == nil {
		registryWriteError(w, http.StatusNotFound,
			fmt.Sprintf("App %s not found in store %s", req.AppName, req.StoreID))
		return
	}

	// Extract image reference from manifest YAML
	imageRef, err := h.extractImageFromManifest(storeApp.ManifestPath)
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to extract image from manifest: %v", err))
		return
	}

	// Resolve title and tagline from localized maps
	title := storeApp.Name
	if t, ok := storeApp.Title["en_us"]; ok && t != "" {
		title = t
	}
	tagline := ""
	if t, ok := storeApp.Tagline["en_us"]; ok {
		tagline = t
	}

	// Build workflow input
	inputData, err := json.Marshal(map[string]interface{}{
		"store_id":      req.StoreID,
		"app_name":      req.AppName,
		"image":         imageRef,
		"source_image":  imageRef,
		"title":         title,
		"icon":          storeApp.Icon,
		"category":      storeApp.Category,
		"tagline":       tagline,
		"registry_host": strings.TrimPrefix(strings.TrimPrefix(h.registryURL, "http://"), "https://"),
	})
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to marshal workflow input")
		return
	}

	// Submit workflow
	run, err := h.flowEngine.Submit(r.Context(), flowengine.SubmitParams{
		WorkflowType: workflows.RegistryCacheType,
		ExternalID:   req.AppName,
		Input:        json.RawMessage(inputData),
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "active workflow") {
			registryWriteError(w, http.StatusConflict,
				fmt.Sprintf("A cache workflow for %s is already in progress", req.AppName))
			return
		}
		registryWriteError(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to submit cache workflow: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"workflow_id": run.ID,
		"message":     fmt.Sprintf("Caching %s — workflow %s submitted", req.AppName, run.ID),
	})
}

// extractImageFromManifest parses a CasaOS docker-compose manifest YAML
// and returns the image reference of the first (or main) service.
func (h *RegistryHandler) extractImageFromManifest(manifestPath string) (string, error) {
	if manifestPath == "" {
		return "", fmt.Errorf("manifest path is empty")
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("failed to read manifest: %w", err)
	}

	// Parse as a docker-compose file to extract the image
	var compose struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return "", fmt.Errorf("failed to parse manifest YAML: %w", err)
	}

	// Return the first service's image
	for _, svc := range compose.Services {
		if svc.Image != "" {
			return svc.Image, nil
		}
	}

	return "", fmt.Errorf("no image found in manifest")
}

// =========================================================================
// System Images (T14)
// =========================================================================

// SystemImage represents an image in the registry with running context.
type SystemImage struct {
	Name        string   `json:"name"`                   // e.g. "pihole/pihole"
	Tags        []string `json:"tags"`                   // e.g. ["latest"]
	Type        string   `json:"type"`                   // "core", "curated", "user"
	Running     bool     `json:"running"`                // Is a Docker service/container using this image?
	ServiceName string   `json:"service_name,omitempty"` // e.g. "cubeos-pihole"
	Pinned      bool     `json:"pinned"`                 // Core/curated are always pinned
}

// ListSystemImages godoc
// @Summary List all system images with running status
// @Description Returns all images in the local registry enriched with running status, type classification (core/curated/user), and pinning state. Core and curated images are always pinned. User images are unpinned by default.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "images: []SystemImage, total: int"
// @Failure 500 {object} ErrorResponse "Failed to query registry or Docker"
// @Router /system/images [get]
func (h *RegistryHandler) ListSystemImages(w http.ResponseWriter, r *http.Request) {
	repos, err := h.getImageList()
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to query registry: "+err.Error())
		return
	}

	runningImages := h.getRunningImages()

	var images []SystemImage
	for _, repo := range repos {
		tags, _ := h.getImageTags(repo)
		if len(tags) == 0 {
			tags = []string{"unknown"}
		}

		imgType := classifyImage(repo)
		fullRef := fmt.Sprintf("localhost:5000/%s:%s", repo, tags[0])
		svcName, running := runningImages[fullRef]
		if !running {
			for _, tag := range tags {
				ref := fmt.Sprintf("%s:%s", repo, tag)
				if s, ok := runningImages[ref]; ok {
					svcName = s
					running = true
					break
				}
			}
		}

		images = append(images, SystemImage{
			Name:        repo,
			Tags:        tags,
			Type:        imgType,
			Running:     running,
			ServiceName: svcName,
			Pinned:      imgType == "core" || imgType == "curated",
		})
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"images": images,
		"total":  len(images),
	})
}

// classifyImage determines if a registry image is core, curated, or user-installed.
func classifyImage(repo string) string {
	coreImages := map[string]bool{
		"pihole/pihole":               true,
		"jc21/nginx-proxy-manager":    true,
		"cubeos-app/api":              true,
		"cubeos-app/hal":              true,
		"cubeos-app/dashboard":        true,
		"cubeos-app/cubeos-docsindex": true,
		"amir20/dozzle":               true,
		"sigoden/dufs":                true,
	}
	curatedImages := map[string]bool{
		"kiwix/kiwix-serve": true,
		"tsl0922/ttyd":      true,
	}
	if coreImages[repo] {
		return "core"
	}
	if curatedImages[repo] {
		return "curated"
	}
	return "user"
}

// getRunningImages returns a map of image reference -> service/container name
// for all currently running Docker containers and Swarm services.
func (h *RegistryHandler) getRunningImages() map[string]string {
	result := make(map[string]string)

	out, err := exec.Command("docker", "ps", "--format", "{{.Image}}|{{.Names}}").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 2)
			if len(parts) == 2 {
				result[parts[0]] = parts[1]
			}
		}
	}

	out, err = exec.Command("docker", "service", "ls", "--format", "{{.Image}}|{{.Name}}").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 2)
			if len(parts) == 2 {
				result[parts[0]] = parts[1]
			}
		}
	}

	return result
}
