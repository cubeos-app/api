package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

// CasaOSHandler handles CasaOS import API requests
type CasaOSHandler struct {
	appStoreManager *managers.AppStoreManager
	appsPath        string
	gatewayIP       string
	baseDomain      string
}

// NewCasaOSHandler creates a new CasaOS handler
func NewCasaOSHandler(appStoreManager *managers.AppStoreManager, gatewayIP, baseDomain string) *CasaOSHandler {
	return &CasaOSHandler{
		appStoreManager: appStoreManager,
		appsPath:        "/cubeos/apps",
		gatewayIP:       gatewayIP,
		baseDomain:      baseDomain,
	}
}

// Routes returns the router for CasaOS endpoints
func (h *CasaOSHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/stores", h.GetStores)
	r.Post("/preview", h.PreviewManifest)
	r.Post("/import", h.ImportApp)

	return r
}

// CasaOSStoreInfo represents a CasaOS-compatible store
type CasaOSStoreInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	Author      string `json:"author,omitempty"`
	AppCount    int    `json:"app_count"`
	Format      string `json:"format"` // "github-zip" or "direct"
	Compatible  bool   `json:"compatible"`
}

// GetStores returns CasaOS-compatible store information
// GET /api/v1/casaos/stores
func (h *CasaOSHandler) GetStores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get all registered stores from the appstore manager
	stores := h.appStoreManager.GetStores()

	casaosStores := make([]CasaOSStoreInfo, 0, len(stores))
	for _, store := range stores {
		format := "github-zip"
		if strings.Contains(store.URL, ".json") {
			format = "direct"
		}

		casaosStores = append(casaosStores, CasaOSStoreInfo{
			ID:          store.ID,
			Name:        store.Name,
			URL:         store.URL,
			Description: store.Description,
			Author:      store.Author,
			AppCount:    store.AppCount,
			Format:      format,
			Compatible:  true, // All our stores are CasaOS-compatible
		})
	}

	// Add well-known CasaOS stores for reference
	wellKnownStores := []CasaOSStoreInfo{
		{
			ID:          "casaos-official",
			Name:        "CasaOS Official",
			URL:         "https://github.com/IceWhaleTech/CasaOS-AppStore",
			Description: "Official CasaOS App Store with 100+ apps",
			Author:      "IceWhaleTech",
			Format:      "github-zip",
			Compatible:  true,
		},
		{
			ID:          "big-bear",
			Name:        "Big Bear CasaOS",
			URL:         "https://github.com/bigbeartechworld/big-bear-casaos",
			Description: "Community app store with 200+ self-hosted apps",
			Author:      "BigBearTechWorld",
			Format:      "github-zip",
			Compatible:  true,
		},
		{
			ID:          "casaos-linuxserver",
			Name:        "LinuxServer.io Apps",
			URL:         "https://github.com/WisdomSky/CasaOS-LinuxServer-AppStore",
			Description: "LinuxServer.io images for CasaOS",
			Author:      "WisdomSky",
			Format:      "github-zip",
			Compatible:  true,
		},
	}

	// Merge - avoid duplicates based on ID
	existingIDs := make(map[string]bool)
	for _, store := range casaosStores {
		existingIDs[store.ID] = true
	}

	for _, store := range wellKnownStores {
		if !existingIDs[store.ID] {
			store.AppCount = 0 // Not synced yet
			casaosStores = append(casaosStores, store)
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"stores": casaosStores,
		"count":  len(casaosStores),
		"info": map[string]string{
			"format":  "CasaOS docker-compose.yml with x-casaos extensions",
			"doc_url": "https://github.com/IceWhaleTech/CasaOS-AppStore#app-structure",
		},
	})
}

// PreviewRequest represents a request to preview a CasaOS manifest
type PreviewRequest struct {
	Manifest string `json:"manifest"`      // YAML or JSON content
	URL      string `json:"url,omitempty"` // Optional: URL to fetch manifest from
	AppName  string `json:"app_name,omitempty"`
}

// PreviewResponse represents the parsed manifest preview
type PreviewResponse struct {
	Valid         bool                   `json:"valid"`
	AppName       string                 `json:"app_name"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Category      string                 `json:"category"`
	Author        string                 `json:"author"`
	Version       string                 `json:"version"`
	Icon          string                 `json:"icon"`
	MainService   string                 `json:"main_service"`
	Services      []ServicePreview       `json:"services"`
	Ports         []PortPreview          `json:"ports"`
	Volumes       []VolumePreview        `json:"volumes"`
	EnvVars       []EnvVarPreview        `json:"env_vars"`
	Architectures []string               `json:"architectures"`
	Compatible    bool                   `json:"compatible"`
	WebUIPort     string                 `json:"webui_port,omitempty"`
	WebUIPath     string                 `json:"webui_path,omitempty"`
	Warnings      []string               `json:"warnings,omitempty"`
	Errors        []string               `json:"errors,omitempty"`
	RawManifest   *models.CasaOSManifest `json:"raw_manifest,omitempty"`
}

// ServicePreview represents a service in the preview
type ServicePreview struct {
	Name        string `json:"name"`
	Image       string `json:"image"`
	IsMain      bool   `json:"is_main"`
	NetworkMode string `json:"network_mode,omitempty"`
	Privileged  bool   `json:"privileged,omitempty"`
}

// PortPreview represents a port mapping in the preview
type PortPreview struct {
	Host        string `json:"host"`
	Container   string `json:"container"`
	Protocol    string `json:"protocol"`
	Description string `json:"description,omitempty"`
}

// VolumePreview represents a volume mapping in the preview
type VolumePreview struct {
	Host        string `json:"host"`
	Container   string `json:"container"`
	Description string `json:"description,omitempty"`
}

// EnvVarPreview represents an environment variable in the preview
type EnvVarPreview struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// PreviewManifest parses and previews a CasaOS manifest
// POST /api/v1/casaos/preview
func (h *CasaOSHandler) PreviewManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req PreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	manifestContent := req.Manifest

	// If URL provided, fetch manifest
	if req.URL != "" && manifestContent == "" {
		resp, err := http.Get(req.URL)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("failed to fetch URL: %v", err)})
			return
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to read response"})
			return
		}
		manifestContent = string(bodyBytes)
	}

	if manifestContent == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "manifest content or url required"})
		return
	}

	// Parse the manifest
	preview := h.parseManifest(manifestContent, req.AppName)

	json.NewEncoder(w).Encode(preview)
}

// parseManifest parses a CasaOS manifest and returns a preview
func (h *CasaOSHandler) parseManifest(content string, suggestedName string) *PreviewResponse {
	preview := &PreviewResponse{
		Valid:    false,
		Warnings: []string{},
		Errors:   []string{},
	}

	var manifest models.CasaOSManifest
	if err := yaml.Unmarshal([]byte(content), &manifest); err != nil {
		preview.Errors = append(preview.Errors, fmt.Sprintf("YAML parse error: %v", err))
		return preview
	}

	// Validate required fields
	if len(manifest.Services) == 0 {
		preview.Errors = append(preview.Errors, "no services defined")
		return preview
	}

	if manifest.XCasaOS.Main == "" {
		preview.Warnings = append(preview.Warnings, "x-casaos.main not set, will use first service")
	}

	// Determine app name
	if manifest.Name != "" {
		preview.AppName = manifest.Name
	} else if suggestedName != "" {
		preview.AppName = suggestedName
	} else {
		preview.AppName = "imported-app"
	}

	// Extract metadata from x-casaos
	preview.Title = getLocalizedString(manifest.XCasaOS.Title)
	preview.Description = getLocalizedString(manifest.XCasaOS.Description)
	preview.Category = manifest.XCasaOS.Category
	preview.Author = manifest.XCasaOS.Author
	preview.Icon = manifest.XCasaOS.Icon
	preview.Architectures = manifest.XCasaOS.Architectures
	preview.MainService = manifest.XCasaOS.Main
	preview.WebUIPort = manifest.XCasaOS.PortMap
	preview.WebUIPath = manifest.XCasaOS.Index

	// Check architecture compatibility
	preview.Compatible = h.isCompatible(manifest.XCasaOS.Architectures)
	if !preview.Compatible && len(manifest.XCasaOS.Architectures) > 0 {
		preview.Warnings = append(preview.Warnings,
			fmt.Sprintf("app may not be compatible with ARM64 (supports: %v)", manifest.XCasaOS.Architectures))
	}

	// Parse services
	for name, svc := range manifest.Services {
		isMain := name == manifest.XCasaOS.Main
		if preview.MainService == "" && len(manifest.Services) == 1 {
			isMain = true
			preview.MainService = name
		}

		// Extract version from image tag
		if isMain {
			if parts := strings.Split(svc.Image, ":"); len(parts) > 1 {
				preview.Version = parts[1]
			}
		}

		preview.Services = append(preview.Services, ServicePreview{
			Name:        name,
			Image:       svc.Image,
			IsMain:      isMain,
			NetworkMode: svc.NetworkMode,
			Privileged:  svc.Privileged,
		})

		// Parse ports
		for _, p := range svc.Ports {
			port := parsePort(p)
			if port != nil {
				preview.Ports = append(preview.Ports, *port)
			}
		}

		// Parse volumes
		for _, v := range svc.Volumes {
			vol := parseVolume(v)
			if vol != nil {
				preview.Volumes = append(preview.Volumes, *vol)
			}
		}

		// Parse environment variables
		envs := parseEnvironment(svc.Environment)
		preview.EnvVars = append(preview.EnvVars, envs...)

		// Add descriptions from x-casaos service metadata
		for _, xPort := range svc.XCasaOS.Ports {
			for i := range preview.Ports {
				if preview.Ports[i].Container == xPort.Container {
					preview.Ports[i].Description = getLocalizedString(xPort.Description)
				}
			}
		}

		for _, xVol := range svc.XCasaOS.Volumes {
			for i := range preview.Volumes {
				if preview.Volumes[i].Container == xVol.Container {
					preview.Volumes[i].Description = getLocalizedString(xVol.Description)
				}
			}
		}

		for _, xEnv := range svc.XCasaOS.Envs {
			for i := range preview.EnvVars {
				if preview.EnvVars[i].Name == xEnv.Container {
					preview.EnvVars[i].Description = getLocalizedString(xEnv.Description)
				}
			}
		}
	}

	// Warnings for privileged/host network
	for _, svc := range preview.Services {
		if svc.Privileged {
			preview.Warnings = append(preview.Warnings,
				fmt.Sprintf("service '%s' requires privileged mode", svc.Name))
		}
		if svc.NetworkMode == "host" {
			preview.Warnings = append(preview.Warnings,
				fmt.Sprintf("service '%s' uses host network mode", svc.Name))
		}
	}

	preview.Valid = len(preview.Errors) == 0
	preview.RawManifest = &manifest

	return preview
}

// ImportRequest represents a request to import a CasaOS app
type ImportRequest struct {
	Manifest     string            `json:"manifest"`                // YAML content
	URL          string            `json:"url,omitempty"`           // Optional URL to fetch
	AppName      string            `json:"app_name"`                // Required app name
	Title        string            `json:"title,omitempty"`         // Custom title
	EnvOverrides map[string]string `json:"env_overrides,omitempty"` // Environment overrides
	AutoStart    bool              `json:"auto_start"`              // Start after import
}

// ImportResponse represents the result of an import
type ImportResponse struct {
	Success     bool     `json:"success"`
	AppID       string   `json:"app_id"`
	AppName     string   `json:"app_name"`
	Title       string   `json:"title"`
	Status      string   `json:"status"`
	ComposePath string   `json:"compose_path"`
	DataPath    string   `json:"data_path"`
	WebUI       string   `json:"webui,omitempty"`
	FQDN        string   `json:"fqdn,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// ImportApp imports and optionally starts a CasaOS app
// POST /api/v1/casaos/import
func (h *CasaOSHandler) ImportApp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ImportResponse{
			Success: false,
			Error:   "invalid request body",
		})
		return
	}

	manifestContent := req.Manifest

	// Fetch from URL if provided
	if req.URL != "" && manifestContent == "" {
		resp, err := http.Get(req.URL)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ImportResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to fetch URL: %v", err),
			})
			return
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ImportResponse{
				Success: false,
				Error:   "failed to read response",
			})
			return
		}
		manifestContent = string(bodyBytes)
	}

	if manifestContent == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ImportResponse{
			Success: false,
			Error:   "manifest content or url required",
		})
		return
	}

	if req.AppName == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ImportResponse{
			Success: false,
			Error:   "app_name is required",
		})
		return
	}

	// Sanitize app name
	appName := sanitizeAppName(req.AppName)
	if appName == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ImportResponse{
			Success: false,
			Error:   "invalid app_name (must be alphanumeric with dashes)",
		})
		return
	}

	// Check if app already exists
	appBase := filepath.Join(h.appsPath, appName)
	if _, err := os.Stat(appBase); err == nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ImportResponse{
			Success: false,
			Error:   fmt.Sprintf("app '%s' already exists", appName),
		})
		return
	}

	// Parse and validate manifest
	preview := h.parseManifest(manifestContent, appName)
	if !preview.Valid {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ImportResponse{
			Success:  false,
			Error:    "invalid manifest",
			Warnings: append(preview.Errors, preview.Warnings...),
		})
		return
	}

	// Process manifest with substitutions
	processedManifest := h.processManifest(manifestContent, appName, req.EnvOverrides)

	// Create directories
	appConfig := filepath.Join(appBase, "appconfig")
	appData := filepath.Join(appBase, "appdata")
	os.MkdirAll(appConfig, 0755)
	os.MkdirAll(appData, 0755)

	// Write docker-compose.yml
	composePath := filepath.Join(appConfig, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(processedManifest), 0644); err != nil {
		os.RemoveAll(appBase)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ImportResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to write compose file: %v", err),
		})
		return
	}

	// Write .env file with overrides
	if len(req.EnvOverrides) > 0 {
		var envContent strings.Builder
		envContent.WriteString("# CubeOS imported app environment\n")
		envContent.WriteString(fmt.Sprintf("# Imported: %s\n\n", time.Now().Format(time.RFC3339)))
		for k, v := range req.EnvOverrides {
			envContent.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		}
		envPath := filepath.Join(appConfig, ".env")
		os.WriteFile(envPath, []byte(envContent.String()), 0644)
	}

	response := ImportResponse{
		Success:     true,
		AppID:       appName,
		AppName:     appName,
		Title:       preview.Title,
		ComposePath: composePath,
		DataPath:    appData,
		Warnings:    preview.Warnings,
	}

	// Build WebUI URL
	if preview.WebUIPort != "" {
		scheme := "http"
		path := preview.WebUIPath
		if path == "" {
			path = "/"
		}
		response.WebUI = fmt.Sprintf("%s://%s:%s%s", scheme, h.gatewayIP, preview.WebUIPort, path)
		response.FQDN = fmt.Sprintf("%s.%s", appName, h.baseDomain)
	}

	// Auto-start if requested
	if req.AutoStart {
		// Pull images first
		pullCmd := exec.Command("docker", "compose", "-f", composePath, "pull")
		pullCmd.Dir = appConfig
		if _, err := pullCmd.CombinedOutput(); err != nil {
			response.Warnings = append(response.Warnings, "image pull may have failed, trying anyway")
		}

		// Start containers
		upCmd := exec.Command("docker", "compose", "-f", composePath, "up", "-d")
		upCmd.Dir = appConfig
		if output, err := upCmd.CombinedOutput(); err != nil {
			response.Status = "failed"
			response.Warnings = append(response.Warnings, fmt.Sprintf("startup failed: %s", string(output)))
		} else {
			response.Status = "running"
		}
	} else {
		response.Status = "imported"
	}

	if req.Title != "" {
		response.Title = req.Title
	}

	json.NewEncoder(w).Encode(response)
}

// processManifest processes a CasaOS manifest with variable substitution
func (h *CasaOSHandler) processManifest(manifest string, appName string, envOverrides map[string]string) string {
	// System variables
	puid := "1000"
	pgid := "1000"
	tz := os.Getenv("TZ")
	if tz == "" {
		tz = "UTC"
	}

	dataDir := filepath.Join(h.appsPath, appName, "appdata")

	// Variable substitutions
	replacements := map[string]string{
		"$PUID":                  puid,
		"${PUID}":                puid,
		"$PGID":                  pgid,
		"${PGID}":                pgid,
		"$TZ":                    tz,
		"${TZ}":                  tz,
		"$AppID":                 appName,
		"${AppID}":               appName,
		"/DATA/AppData/$AppID":   dataDir,
		"/DATA/AppData/${AppID}": dataDir,
		"/DATA/AppData":          filepath.Join(h.appsPath, appName),
	}

	result := manifest
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	// Apply env overrides
	for key, val := range envOverrides {
		result = strings.ReplaceAll(result, fmt.Sprintf("${%s}", key), val)
		result = strings.ReplaceAll(result, fmt.Sprintf("$%s", key), val)
	}

	return result
}

// Helper functions

func (h *CasaOSHandler) isCompatible(archs []string) bool {
	if len(archs) == 0 {
		return true // No arch specified = assume compatible
	}

	arm64Aliases := []string{"arm64", "aarch64", "arm64/v8"}
	for _, arch := range archs {
		archLower := strings.ToLower(arch)
		for _, alias := range arm64Aliases {
			if archLower == alias {
				return true
			}
		}
	}
	return false
}

func getLocalizedString(m map[string]string) string {
	if m == nil {
		return ""
	}
	// Prefer en_us, then en, then first available
	if v, ok := m["en_us"]; ok {
		return v
	}
	if v, ok := m["en"]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return ""
}

func parsePort(p interface{}) *PortPreview {
	switch v := p.(type) {
	case string:
		parts := strings.Split(v, ":")
		if len(parts) == 2 {
			// Check for protocol suffix
			containerParts := strings.Split(parts[1], "/")
			protocol := "tcp"
			if len(containerParts) > 1 {
				protocol = containerParts[1]
			}
			return &PortPreview{
				Host:      parts[0],
				Container: containerParts[0],
				Protocol:  protocol,
			}
		}
	case map[string]interface{}:
		port := &PortPreview{Protocol: "tcp"}
		if target, ok := v["target"]; ok {
			port.Container = fmt.Sprintf("%v", target)
		}
		if published, ok := v["published"]; ok {
			port.Host = fmt.Sprintf("%v", published)
		}
		if protocol, ok := v["protocol"]; ok {
			port.Protocol = fmt.Sprintf("%v", protocol)
		}
		if port.Container != "" {
			return port
		}
	}
	return nil
}

func parseVolume(v interface{}) *VolumePreview {
	switch val := v.(type) {
	case string:
		parts := strings.Split(val, ":")
		if len(parts) >= 2 {
			return &VolumePreview{
				Host:      parts[0],
				Container: parts[1],
			}
		}
	case map[string]interface{}:
		vol := &VolumePreview{}
		if source, ok := val["source"]; ok {
			vol.Host = fmt.Sprintf("%v", source)
		}
		if target, ok := val["target"]; ok {
			vol.Container = fmt.Sprintf("%v", target)
		}
		if vol.Container != "" {
			return vol
		}
	}
	return nil
}

func parseEnvironment(env interface{}) []EnvVarPreview {
	var result []EnvVarPreview

	switch v := env.(type) {
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok {
				parts := strings.SplitN(s, "=", 2)
				if len(parts) == 2 {
					result = append(result, EnvVarPreview{
						Name:  parts[0],
						Value: parts[1],
					})
				}
			}
		}
	case map[string]interface{}:
		for k, val := range v {
			result = append(result, EnvVarPreview{
				Name:  k,
				Value: fmt.Sprintf("%v", val),
			})
		}
	}

	return result
}

func sanitizeAppName(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)

	// Replace spaces and underscores with dashes
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "_", "-")

	// Keep only alphanumeric and dashes
	var result strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result.WriteRune(c)
		}
	}

	// Remove leading/trailing dashes
	return strings.Trim(result.String(), "-")
}
