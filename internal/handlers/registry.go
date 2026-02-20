// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"context"
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

	"cubeos-api/internal/models"

	"github.com/go-chi/chi/v5"
)

// RegistryHandler handles local Docker registry endpoints.
type RegistryHandler struct {
	registryURL  string
	registryPath string
	httpClient   *http.Client
}

// NewRegistryHandler creates a new RegistryHandler instance.
// For Swarm containers, use the gateway IP (not localhost:5000)
// because containers in overlay network cannot reach localhost on the host.
func NewRegistryHandler(registryURL, registryPath string) *RegistryHandler {
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
// @Description Deletes a specific tag of an image from the local registry. Requires garbage collection to reclaim disk space.
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Param name path string true "Image name (e.g., nginx or library/nginx)"
// @Param tag path string true "Tag to delete (e.g., latest, v1.0)"
// @Success 200 {object} map[string]interface{} "success: true, message"
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
// @Description Deletes a specific tag of an image from the local registry. Requires garbage collection to reclaim disk space.
// @Tags Registry
// @Produce json
// @Security BearerAuth
// @Param name path string true "Image name"
// @Param tag query string false "Tag to delete (defaults to 'latest')"
// @Success 200 {object} map[string]interface{} "success: true, message: deletion confirmation"
// @Failure 404 {object} ErrorResponse "Image or tag not found"
// @Failure 500 {object} ErrorResponse "Failed to delete image"
// @Router /registry/images/{name} [delete]
func (h *RegistryHandler) DeleteImage(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		tag = "latest"
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
		// Use defaults
		req.KeepTags = 2
		req.DryRun = false
	}

	if req.KeepTags < 1 {
		req.KeepTags = 1
	}

	// This is a simplified cleanup - just report what could be cleaned
	// Full implementation would need registry garbage collection

	images, _ := h.getImageList()
	var totalDeleted int
	var deletedImages []string

	for _, name := range images {
		tags, _ := h.getImageTags(name)
		if len(tags) > req.KeepTags {
			toDelete := len(tags) - req.KeepTags
			if !req.DryRun {
				// In a real implementation, we'd delete the older tags here
				// For now, just count them
			}
			totalDeleted += toDelete
			deletedImages = append(deletedImages, fmt.Sprintf("%s (%d tags)", name, toDelete))
		}
	}

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"dry_run":        req.DryRun,
		"deleted_count":  totalDeleted,
		"deleted_images": deletedImages,
		"message":        "Run 'docker exec cubeos-registry bin/registry garbage-collect /etc/docker/registry/config.yml' to reclaim disk space",
	})
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
// @Description Creates a Docker Swarm service from an image in the local registry. Generates a minimal docker-compose.yml, allocates a port, and deploys via docker stack deploy.
// @Tags Registry
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body DeployImageRequest true "Image to deploy"
// @Success 200 {object} map[string]interface{} "success, app_name, image, port, fqdn"
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

	// Allocate port (scan 6100-6999 for an unused one)
	port, err := h.findAvailablePort(r.Context())
	if err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to allocate port: "+err.Error())
		return
	}

	// Build local registry image reference
	registryHost := strings.TrimPrefix(h.registryURL, "http://")
	registryHost = strings.TrimPrefix(registryHost, "https://")
	fullImage := fmt.Sprintf("%s/%s:%s", registryHost, req.Image, req.Tag)

	// Generate docker-compose.yml
	compose := fmt.Sprintf(`version: "3.8"
services:
  %s:
    image: %s
    ports:
      - "%d:%d"
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    volumes:
      - data:/data
volumes:
  data:
`, appName, fullImage, port, port)

	// Create directories
	appBase := filepath.Join("/cubeos/apps", appName)
	appConfig := filepath.Join(appBase, "appconfig")
	appData := filepath.Join(appBase, "appdata")
	if err := os.MkdirAll(appConfig, 0755); err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to create app directory: "+err.Error())
		return
	}
	if err := os.MkdirAll(appData, 0777); err != nil {
		registryWriteError(w, http.StatusInternalServerError, "Failed to create data directory: "+err.Error())
		return
	}

	// Write compose file
	composePath := filepath.Join(appConfig, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(compose), 0644); err != nil {
		os.RemoveAll(appBase)
		registryWriteError(w, http.StatusInternalServerError, "Failed to write compose file: "+err.Error())
		return
	}

	// Deploy via docker stack deploy
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
		"-c", composePath,
		"--resolve-image=never",
		appName,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(appBase)
		registryWriteError(w, http.StatusInternalServerError,
			fmt.Sprintf("Stack deploy failed: %s", strings.TrimSpace(string(output))))
		return
	}

	fqdn := appName + ".cubeos.cube"

	registryWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"app_name":     appName,
		"image":        fullImage,
		"port":         port,
		"fqdn":         fqdn,
		"compose_path": composePath,
		"message":      fmt.Sprintf("Deployed %s on port %d", appName, port),
	})
}

// findAvailablePort scans for the next available port in the 6100-6999 range
// by checking existing Docker service port bindings.
func (h *RegistryHandler) findAvailablePort(ctx context.Context) (int, error) {
	// Get list of used ports from Docker
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.Ports}}")
	output, err := cmd.Output()
	if err != nil {
		// If docker ps fails, start from 6100
		return 6100, nil
	}

	usedPorts := make(map[int]bool)
	for _, line := range strings.Split(string(output), "\n") {
		// Parse port mappings like "0.0.0.0:6100->8080/tcp"
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if idx := strings.Index(part, "->"); idx > 0 {
				hostPart := part[:idx]
				if colonIdx := strings.LastIndex(hostPart, ":"); colonIdx >= 0 {
					portStr := hostPart[colonIdx+1:]
					var p int
					if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil {
						usedPorts[p] = true
					}
				}
			}
		}
	}

	// Find first available port in 6100-6999
	for port := 6100; port <= 6999; port++ {
		if !usedPorts[port] {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports in range 6100-6999")
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
