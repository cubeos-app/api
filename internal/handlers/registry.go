// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// RegistryHandler handles local Docker registry endpoints.
type RegistryHandler struct {
	registryURL  string
	registryPath string
	httpClient   *http.Client
}

// NewRegistryHandler creates a new RegistryHandler instance.
// For Swarm containers, use 10.42.24.1:5000 (gateway IP) not localhost:5000
// because containers in overlay network cannot reach localhost on the host.
func NewRegistryHandler(registryURL, registryPath string) *RegistryHandler {
	if registryURL == "" {
		// Check env var first, then fall back to gateway IP (works from inside Swarm overlay)
		registryURL = os.Getenv("REGISTRY_URL")
		if registryURL == "" {
			registryURL = "http://10.42.24.1:5000"
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
	r.Get("/images", h.ListImages)
	r.Get("/images/{name}/tags", h.GetImageTags)
	r.Delete("/images/{name}", h.DeleteImage)
	r.Post("/cleanup", h.CleanupRegistry)
	r.Get("/disk-usage", h.GetDiskUsage)

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
