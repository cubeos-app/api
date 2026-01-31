package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// AppManagerHandler handles AppManager API endpoints
type AppManagerHandler struct {
	mgr *managers.AppManager
}

// NewAppManagerHandler creates a new AppManagerHandler
func NewAppManagerHandler(mgr *managers.AppManager) *AppManagerHandler {
	return &AppManagerHandler{mgr: mgr}
}

// Routes returns the router for AppManager endpoints
func (h *AppManagerHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Apps
	r.Get("/apps", h.ListApps)
	r.Post("/apps", h.RegisterApp)
	r.Get("/apps/{name}", h.GetApp)
	r.Delete("/apps/{name}", h.UnregisterApp)
	r.Post("/apps/{name}/enable", h.EnableApp)
	r.Post("/apps/{name}/disable", h.DisableApp)
	r.Post("/apps/{name}/start", h.StartApp)
	r.Post("/apps/{name}/stop", h.StopApp)
	r.Post("/apps/{name}/restart", h.RestartApp)
	r.Get("/apps/{name}/status", h.GetAppStatus)
	r.Get("/apps/{name}/config", h.GetAppConfig)
	r.Put("/apps/{name}/config", h.SaveAppConfig)

	// Ports
	r.Get("/ports", h.ListPorts)
	r.Post("/ports", h.AllocatePort)
	r.Delete("/ports/{port}", h.ReleasePort)
	r.Get("/ports/available", h.GetAvailablePort)
	r.Get("/ports/listening", h.GetListeningPorts)
	r.Get("/ports/stats", h.GetPortStats)
	r.Post("/ports/sync", h.SyncPorts)

	// FQDNs / Domains
	r.Get("/fqdns", h.ListFQDNs)
	r.Post("/fqdns", h.RegisterFQDN)
	r.Delete("/fqdns/{fqdn}", h.DeregisterFQDN)
	r.Get("/domains", h.ListDomains)
	r.Post("/domains/sync", h.SyncDomains)

	// NPM (Nginx Proxy Manager)
	r.Get("/npm/status", h.GetNPMStatus)
	r.Get("/npm/hosts", h.ListNPMHosts)
	r.Post("/npm/init", h.InitNPM)

	// Profiles
	r.Get("/profiles", h.ListProfiles)
	r.Post("/profiles", h.CreateProfile)
	r.Get("/profiles/{id}", h.GetProfile)
	r.Delete("/profiles/{id}", h.DeleteProfile)
	r.Post("/profiles/{id}/activate", h.ActivateProfile)
	r.Put("/profiles/{id}/apps/{appId}", h.SetProfileApp)

	// Registry
	r.Get("/registry/status", h.GetRegistryStatus)
	r.Post("/registry/init", h.InitRegistry)
	r.Get("/registry/images", h.ListRegistryImages)
	r.Post("/registry/images/cache", h.CacheImage)
	r.Delete("/registry/images/{name}", h.DeleteRegistryImage)

	// CasaOS
	r.Post("/casaos/preview", h.PreviewCasaOSApp)
	r.Post("/casaos/import", h.ImportCasaOSApp)
	r.Get("/casaos/stores", h.FetchCasaOSStore)

	// Migration
	r.Post("/migrate", h.RunMigration)

	return r
}

// === Apps ===

func (h *AppManagerHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.mgr.ListApps()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if apps == nil {
		apps = []models.App{}
	}
	json.NewEncoder(w).Encode(models.AppsResponse{Apps: apps})
}

func (h *AppManagerHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	app, err := h.mgr.GetApp(name)
	if err != nil {
		http.Error(w, "App not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(app)
}

func (h *AppManagerHandler) RegisterApp(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	app, err := h.mgr.RegisterApp(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(app)
}

func (h *AppManagerHandler) UnregisterApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.mgr.UnregisterApp(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AppManagerHandler) EnableApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.mgr.EnableApp(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AppManagerHandler) DisableApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.mgr.DisableApp(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AppManagerHandler) StartApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.mgr.StartApp(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "starting"})
}

func (h *AppManagerHandler) StopApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.mgr.StopApp(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "stopping"})
}

func (h *AppManagerHandler) RestartApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.mgr.RestartApp(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "restarting"})
}

func (h *AppManagerHandler) GetAppStatus(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	status, err := h.mgr.GetAppStatus(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Set Running to true only when status is "running"
	running := status == "running"
	json.NewEncoder(w).Encode(models.AppStatusResponse{Name: name, Status: status, Running: running})
}

// === Ports ===

func (h *AppManagerHandler) ListPorts(w http.ResponseWriter, r *http.Request) {
	ports, err := h.mgr.ListPorts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ports == nil {
		ports = []models.PortAllocation{}
	}
	json.NewEncoder(w).Encode(models.PortsResponse{Ports: ports})
}

func (h *AppManagerHandler) AllocatePort(w http.ResponseWriter, r *http.Request) {
	var req models.AllocatePortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	port, err := h.mgr.AllocatePort(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(port)
}

func (h *AppManagerHandler) ReleasePort(w http.ResponseWriter, r *http.Request) {
	portStr := chi.URLParam(r, "port")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		http.Error(w, "Invalid port number", http.StatusBadRequest)
		return
	}

	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "tcp"
	}

	if err := h.mgr.ReleasePort(port, protocol); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AppManagerHandler) GetAvailablePort(w http.ResponseWriter, r *http.Request) {
	appType := r.URL.Query().Get("type")
	if appType == "" {
		appType = "user"
	}

	port, err := h.mgr.GetAvailablePort(appType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(models.AvailablePortResponse{Port: port})
}

// === FQDNs ===

func (h *AppManagerHandler) ListFQDNs(w http.ResponseWriter, r *http.Request) {
	fqdns, err := h.mgr.ListFQDNs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if fqdns == nil {
		fqdns = []models.FQDN{}
	}
	json.NewEncoder(w).Encode(models.FQDNsResponse{FQDNs: fqdns})
}

func (h *AppManagerHandler) RegisterFQDN(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterFQDNRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	fqdn, err := h.mgr.RegisterFQDN(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(fqdn)
}

func (h *AppManagerHandler) DeregisterFQDN(w http.ResponseWriter, r *http.Request) {
	fqdn := chi.URLParam(r, "fqdn")
	if err := h.mgr.DeregisterFQDN(fqdn); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// === Profiles ===

func (h *AppManagerHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.mgr.ListProfiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if profiles == nil {
		profiles = []models.Profile{}
	}
	json.NewEncoder(w).Encode(models.ProfilesResponse{Profiles: profiles})
}

func (h *AppManagerHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid profile ID", http.StatusBadRequest)
		return
	}

	profile, err := h.mgr.GetProfile(id)
	if err != nil {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(profile)
}

func (h *AppManagerHandler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	var req models.CreateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	profile, err := h.mgr.CreateProfile(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(profile)
}

func (h *AppManagerHandler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid profile ID", http.StatusBadRequest)
		return
	}

	if err := h.mgr.DeleteProfile(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AppManagerHandler) ActivateProfile(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid profile ID", http.StatusBadRequest)
		return
	}

	if err := h.mgr.ActivateProfile(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "activated"})
}

func (h *AppManagerHandler) SetProfileApp(w http.ResponseWriter, r *http.Request) {
	profileIDStr := chi.URLParam(r, "id")
	profileID, err := strconv.ParseInt(profileIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid profile ID", http.StatusBadRequest)
		return
	}

	appIDStr := chi.URLParam(r, "appId")
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid app ID", http.StatusBadRequest)
		return
	}

	var req models.SetProfileAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.mgr.SetProfileApp(profileID, appID, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// === Registry ===

func (h *AppManagerHandler) GetRegistryStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.mgr.GetRegistryStatus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(status)
}

func (h *AppManagerHandler) InitRegistry(w http.ResponseWriter, r *http.Request) {
	if err := h.mgr.InitRegistry(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "initialized"})
}

func (h *AppManagerHandler) ListRegistryImages(w http.ResponseWriter, r *http.Request) {
	images, err := h.mgr.ListRegistryImages()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if images == nil {
		images = []models.RegistryImage{}
	}
	json.NewEncoder(w).Encode(models.RegistryImagesResponse{Images: images})
}

func (h *AppManagerHandler) CacheImage(w http.ResponseWriter, r *http.Request) {
	var req models.CacheImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Run async
	go h.mgr.CacheImage(req.Image)
	json.NewEncoder(w).Encode(map[string]string{"status": "caching"})
}

func (h *AppManagerHandler) DeleteRegistryImage(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		tag = "latest"
	}

	if err := h.mgr.DeleteRegistryImage(name, tag); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// === CasaOS ===

func (h *AppManagerHandler) PreviewCasaOSApp(w http.ResponseWriter, r *http.Request) {
	var req models.CasaOSImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	app, err := h.mgr.ParseCasaOSApp(req.JSON)
	if err != nil {
		http.Error(w, "Invalid CasaOS JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	compose := h.mgr.ConvertCasaOSToCompose(app)
	json.NewEncoder(w).Encode(models.CasaOSPreviewResponse{App: *app, Compose: compose})
}

func (h *AppManagerHandler) ImportCasaOSApp(w http.ResponseWriter, r *http.Request) {
	var req models.CasaOSImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	app, err := h.mgr.ImportCasaOSApp(req.JSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(app)
}

func (h *AppManagerHandler) FetchCasaOSStore(w http.ResponseWriter, r *http.Request) {
	storeURL := r.URL.Query().Get("url")
	if storeURL == "" {
		http.Error(w, "Missing 'url' query parameter", http.StatusBadRequest)
		return
	}

	apps, err := h.mgr.FetchCasaOSStore(storeURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if apps == nil {
		apps = []models.CasaOSApp{}
	}
	json.NewEncoder(w).Encode(models.CasaOSStoreResponse{Apps: apps})
}

// === Config Editing ===

func (h *AppManagerHandler) GetAppConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	config, err := h.mgr.GetAppConfig(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(config)
}

func (h *AppManagerHandler) SaveAppConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req models.SaveConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.mgr.SaveAppConfig(name, req.Compose, req.Env, req.Recreate); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"recreated": req.Recreate,
	})
}

// === Enhanced Ports ===

func (h *AppManagerHandler) GetListeningPorts(w http.ResponseWriter, r *http.Request) {
	ports, err := h.mgr.GetListeningPorts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ports": ports,
	})
}

func (h *AppManagerHandler) GetPortStats(w http.ResponseWriter, r *http.Request) {
	stats := h.mgr.GetPortStats()
	json.NewEncoder(w).Encode(stats)
}

func (h *AppManagerHandler) SyncPorts(w http.ResponseWriter, r *http.Request) {
	if err := h.mgr.SyncPortsFromSystem(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "synced"})
}

// === Enhanced Domains ===

func (h *AppManagerHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.mgr.ListDomainsEnhanced()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domains": domains,
	})
}

func (h *AppManagerHandler) SyncDomains(w http.ResponseWriter, r *http.Request) {
	if err := h.mgr.SyncDomainsFromPihole(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "synced"})
}

// === NPM (Nginx Proxy Manager) ===

func (h *AppManagerHandler) GetNPMStatus(w http.ResponseWriter, r *http.Request) {
	status := h.mgr.GetNPMStatus()
	json.NewEncoder(w).Encode(status)
}

func (h *AppManagerHandler) ListNPMHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.mgr.ListNPMHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts": hosts,
	})
}

func (h *AppManagerHandler) InitNPM(w http.ResponseWriter, r *http.Request) {
	if err := h.mgr.InitNPM(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "initialized"})
}

// === Migration ===

func (h *AppManagerHandler) RunMigration(w http.ResponseWriter, r *http.Request) {
	result, err := h.mgr.RunMigration()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(result)
}
