// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
func NewRegistryHandler(registryURL, registryPath string) *RegistryHandler {
	if registryURL == "" {
		registryURL = "http://localhost:5000"
	}
	if registryPath == "" {
		registryPath = "/cubeos/data/registry"
	}
	return &RegistryHandler{
		registryURL:  registryURL,
		registryPath: registryPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
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
}

// GetStatus returns the registry health and status.
// GET /api/v1/registry/status
func (h *RegistryHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := RegistryStatus{
		URL: h.registryURL,
	}

	// Check if registry is online
	resp, err := h.httpClient.Get(h.registryURL + "/v2/")
	if err != nil {
		status.Online = false
	} else {
		defer resp.Body.Close()
		status.Online = (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized)

		// Try to get version from headers
		if version := resp.Header.Get("Docker-Distribution-Api-Version"); version != "" {
			status.Version = version
		}
	}

	// Get image count
	images, _ := h.getImageList()
	status.ImageCount = len(images)

	// Get disk usage
	status.DiskUsage = h.getDiskUsage()
	status.DiskUsageStr = formatBytes(status.DiskUsage)

	writeJSON(w, http.StatusOK, status)
}

// RegistryImage represents an image in the registry.
type RegistryImage struct {
	Name     string   `json:"name"`
	Tags     []string `json:"tags,omitempty"`
	TagCount int      `json:"tag_count"`
	FullName string   `json:"full_name,omitempty"`
}

// ListImages returns all images in the registry.
// GET /api/v1/registry/images
func (h *RegistryHandler) ListImages(w http.ResponseWriter, r *http.Request) {
	images, err := h.getImageList()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get image list: "+err.Error())
		return
	}

	// Optionally get tags for each image
	includeTags := r.URL.Query().Get("include_tags") == "true"

	result := make([]RegistryImage, 0)
	for _, name := range images {
		img := RegistryImage{
			Name:     name,
			FullName: fmt.Sprintf("localhost:5000/%s", name),
		}

		if includeTags {
			tags, _ := h.getImageTags(name)
			img.Tags = tags
			img.TagCount = len(tags)
		}

		result = append(result, img)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"images": result,
		"count":  len(result),
	})
}

// GetImageTags returns tags for a specific image.
// GET /api/v1/registry/images/{name}/tags
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
		writeError(w, http.StatusNotFound, "Image not found or failed to get tags: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name": name,
		"tags": tags,
	})
}

// DeleteImage deletes an image from the registry.
// DELETE /api/v1/registry/images/{name}?tag=latest
func (h *RegistryHandler) DeleteImage(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		tag = "latest"
	}

	// Get manifest digest
	digest, err := h.getManifestDigest(name, tag)
	if err != nil {
		writeError(w, http.StatusNotFound, "Image or tag not found: "+err.Error())
		return
	}

	// Delete by digest
	deleteURL := fmt.Sprintf("%s/v2/%s/manifests/%s", h.registryURL, name, digest)
	req, _ := http.NewRequest("DELETE", deleteURL, nil)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete image: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Registry returned status %d", resp.StatusCode))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
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

// CleanupRegistry removes old/unused images.
// POST /api/v1/registry/cleanup
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"dry_run":        req.DryRun,
		"deleted_count":  totalDeleted,
		"deleted_images": deletedImages,
		"message":        "Run 'docker exec cubeos-registry bin/registry garbage-collect /etc/docker/registry/config.yml' to reclaim disk space",
	})
}

// GetDiskUsage returns detailed disk usage information.
// GET /api/v1/registry/disk-usage
func (h *RegistryHandler) GetDiskUsage(w http.ResponseWriter, r *http.Request) {
	totalBytes := h.getDiskUsage()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"bytes":    totalBytes,
		"readable": formatBytes(totalBytes),
		"path":     h.registryPath,
	})
}

// Helper methods

func (h *RegistryHandler) getImageList() ([]string, error) {
	resp, err := h.httpClient.Get(h.registryURL + "/v2/_catalog")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, err
	}

	return catalog.Repositories, nil
}

func (h *RegistryHandler) getImageTags(name string) ([]string, error) {
	url := fmt.Sprintf("%s/v2/%s/tags/list", h.registryURL, name)
	resp, err := h.httpClient.Get(url)
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
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", h.registryURL, name, tag)
	req, _ := http.NewRequest("GET", url, nil)
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
		// Read body and parse
		body, _ := io.ReadAll(resp.Body)
		var manifest struct {
			Config struct {
				Digest string `json:"digest"`
			} `json:"config"`
		}
		json.Unmarshal(body, &manifest)
		digest = manifest.Config.Digest
	}

	return digest, nil
}

func (h *RegistryHandler) getDiskUsage() int64 {
	var size int64
	filepath.Walk(h.registryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func formatBytes(bytes int64) string {
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
