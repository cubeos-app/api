package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cubeos-api/internal/flowengine"
	feworkflows "cubeos-api/internal/flowengine/workflows"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// SetupHandler handles setup wizard endpoints
type SetupHandler struct {
	manager    *managers.SetupManager
	engine     *flowengine.WorkflowEngine
	store      *flowengine.WorkflowStore
	halClient  *hal.Client
	networkMgr *managers.NetworkManager
	tlsMgr     *managers.TLSManager
}

// NewSetupHandler creates a new setup handler
func NewSetupHandler(manager *managers.SetupManager, engine *flowengine.WorkflowEngine, store *flowengine.WorkflowStore) *SetupHandler {
	return &SetupHandler{
		manager: manager,
		engine:  engine,
		store:   store,
	}
}

// SetHALClient sets the HAL client for Ethernet status checks.
func (h *SetupHandler) SetHALClient(c *hal.Client) {
	h.halClient = c
}

// SetNetworkManager sets the NetworkManager for AP teardown.
func (h *SetupHandler) SetNetworkManager(nm *managers.NetworkManager) {
	h.networkMgr = nm
}

// SetTLSManager sets the TLS manager for CA generation during wizard completion.
func (h *SetupHandler) SetTLSManager(tm *managers.TLSManager) {
	h.tlsMgr = tm
}

// Routes returns the router for setup endpoints
func (h *SetupHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Status and metadata
	r.Get("/status", h.GetSetupStatus)
	r.Get("/steps", h.GetWizardSteps)
	r.Get("/defaults", h.GetDefaultConfig)
	r.Get("/requirements", h.GetSystemRequirements)

	// Reference data
	r.Get("/timezones", h.GetTimezones)
	r.Get("/purposes", h.GetDeploymentPurposes)
	r.Get("/dns-providers", h.GetDNSProviders)

	// Validation and application
	r.Post("/validate", h.ValidateConfig)
	r.Post("/apply", h.ApplyConfig)

	// Recovery
	r.Post("/reset", h.ResetSetup)

	// Skip setup wizard
	r.Post("/skip", h.SkipSetup)

	// Mark setup as complete (lightweight alternative to /apply)
	r.Post("/complete", h.CompleteSetup)

	// Ethernet readiness check (for Standard profile gate)
	r.Get("/ethernet-status", h.GetEthernetStatus)

	// AP teardown (after Standard profile wizard completion)
	r.Post("/ap-teardown", h.APTeardown)

	// Pre-configuration (detected from Pi Imager, Armbian, custom.toml, LXC)
	r.Get("/preconfiguration", h.GetPreconfiguration)

	return r
}

// GetSetupStatus godoc
// @Summary Get setup wizard status
// @Description Returns current setup progress including completion status, current step, and configured components
// @Tags Setup
// @Produce json
// @Success 200 {object} models.SetupStatus "Setup status with completed flag, current step, and progress"
// @Router /setup/status [get]
func (h *SetupHandler) GetSetupStatus(w http.ResponseWriter, r *http.Request) {
	status := h.manager.GetSetupStatus()
	json.NewEncoder(w).Encode(status)
}

// GetWizardSteps godoc
// @Summary Get wizard step definitions
// @Description Returns all setup wizard steps with their order, titles, descriptions, and required fields
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "steps: array of step definitions, total: step count"
// @Router /setup/steps [get]
func (h *SetupHandler) GetWizardSteps(w http.ResponseWriter, r *http.Request) {
	steps := h.manager.GetWizardSteps()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"steps": steps,
		"total": len(steps),
	})
}

// GetDefaultConfig godoc
// @Summary Get default configuration
// @Description Returns default configuration values for the setup wizard based on detected hardware and environment
// @Tags Setup
// @Produce json
// @Success 200 {object} models.SetupConfig "Default configuration values"
// @Router /setup/defaults [get]
func (h *SetupHandler) GetDefaultConfig(w http.ResponseWriter, r *http.Request) {
	defaults := h.manager.GenerateDefaultConfig()
	json.NewEncoder(w).Encode(defaults)
}

// GetSystemRequirements godoc
// @Summary Get system requirements
// @Description Returns device capabilities and system requirements including available memory, storage, and detected hardware
// @Tags Setup
// @Produce json
// @Success 200 {object} models.SystemRequirements "System requirements and capabilities"
// @Router /setup/requirements [get]
func (h *SetupHandler) GetSystemRequirements(w http.ResponseWriter, r *http.Request) {
	req := h.manager.GetSystemRequirements()
	json.NewEncoder(w).Encode(req)
}

// GetTimezones godoc
// @Summary Get available timezones
// @Description Returns all available timezones grouped by region for timezone selection during setup
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "timezones: flat list, by_region: grouped by region, total: count"
// @Router /setup/timezones [get]
func (h *SetupHandler) GetTimezones(w http.ResponseWriter, r *http.Request) {
	timezones := h.manager.GetTimezones()

	// Group by region
	byRegion := make(map[string][]models.TimezoneInfo)
	for _, tz := range timezones {
		byRegion[tz.Region] = append(byRegion[tz.Region], tz)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"timezones": timezones,
		"by_region": byRegion,
		"total":     len(timezones),
	})
}

// GetDeploymentPurposes godoc
// @Summary Get deployment purposes
// @Description Returns available deployment purpose options (e.g., home server, expedition, emergency) with recommended configurations
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "purposes: array of purpose definitions, total: count"
// @Router /setup/purposes [get]
func (h *SetupHandler) GetDeploymentPurposes(w http.ResponseWriter, r *http.Request) {
	purposes := h.manager.GetDeploymentPurposes()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"purposes": purposes,
		"total":    len(purposes),
	})
}

// GetDNSProviders godoc
// @Summary Get DNS providers for Let's Encrypt
// @Description Returns available DNS providers for Let's Encrypt DNS-01 challenge with required configuration fields
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "providers: array of DNS provider definitions, total: count"
// @Router /setup/dns-providers [get]
func (h *SetupHandler) GetDNSProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.manager.GetDNSProviders()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": providers,
		"total":     len(providers),
	})
}

// ValidateConfig godoc
// @Summary Validate setup configuration
// @Description Validates a setup configuration without applying it. Returns validation errors and warnings.
// @Tags Setup
// @Accept json
// @Produce json
// @Param request body models.SetupConfig true "Setup configuration to validate"
// @Success 200 {object} models.SetupValidation "Validation result with valid flag, errors, and warnings"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Router /setup/validate [post]
func (h *SetupHandler) ValidateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg models.SetupConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	result := h.manager.ValidateSetupConfig(&cfg)
	json.NewEncoder(w).Encode(result)
}

// ApplyConfig godoc
// @Summary Apply setup configuration
// @Description Applies the complete setup configuration via FlowEngine workflow, configuring all system components with saga rollback protection. This is the main setup completion endpoint.
// @Tags Setup
// @Accept json
// @Produce json
// @Param request body models.SetupConfig true "Setup configuration to apply"
// @Success 200 {object} map[string]interface{} "success: true, message, status: updated setup status"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to apply configuration"
// @Router /setup/apply [post]
func (h *SetupHandler) ApplyConfig(w http.ResponseWriter, r *http.Request) {
	var cfg models.SetupConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	// Submit to FlowEngine
	input, err := json.Marshal(cfg)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to marshal config"})
		return
	}

	wf, err := h.engine.Submit(r.Context(), flowengine.SubmitParams{
		WorkflowType: feworkflows.FirstBootSetupType,
		ExternalID:   "first-boot",
		Input:        input,
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Synchronous wait (120s — SSL cert gen + hostapd restart on Pi)
	waitCtx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	if err := flowengine.WaitForCompletion(waitCtx, h.store, wf.ID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "setup failed: " + err.Error()})
		return
	}

	// Save access profile from wizard config (Phase 2)
	h.manager.SaveAccessProfileFromConfig(&cfg)

	// Phase 12: Generate self-signed CA if TLS mode requires it
	if cfg.TLSMode == "self_signed_ca" && h.tlsMgr != nil && !h.tlsMgr.IsCAGenerated() {
		if err := h.tlsMgr.GenerateCA(); err != nil {
			log.Warn().Err(err).Msg("CA generation failed during setup — can be retried from Settings")
		} else {
			log.Info().Msg("Self-signed CA generated during setup")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Setup completed successfully",
		"status":  h.manager.GetSetupStatus(),
	})
}

// ResetSetup godoc
// @Summary Reset setup wizard
// @Description Resets the setup wizard to initial state, allowing reconfiguration. Admin only in production.
// @Tags Setup
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 500 {object} ErrorResponse "Failed to reset setup"
// @Router /setup/reset [post]
func (h *SetupHandler) ResetSetup(w http.ResponseWriter, r *http.Request) {
	// This should be protected by admin auth in production
	if err := h.manager.ResetSetup(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Setup has been reset",
	})
}

// SkipSetup godoc
// @Summary Skip setup wizard
// @Description Skips the setup wizard by marking it complete with default configuration. Does NOT run the workflow — accepts current system state as-is.
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "success: true, message, skipped: true"
// @Failure 500 {object} ErrorResponse "Failed to skip setup"
// @Router /setup/skip [post]
func (h *SetupHandler) SkipSetup(w http.ResponseWriter, r *http.Request) {
	defaults := h.manager.GenerateDefaultConfig()
	if err := h.manager.MarkSetupComplete(defaults); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Setup skipped, using default configuration",
		"skipped": true,
	})
}

// CompleteSetup godoc
// @Summary Mark setup as complete
// @Description Marks the first-boot setup wizard as complete. This is a lightweight endpoint that the dashboard calls after the user finishes all wizard steps. Unlike /apply, it does not reconfigure system components — it simply flags setup as done.
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 500 {object} ErrorResponse "Failed to complete setup"
// @Router /setup/complete [post]
func (h *SetupHandler) CompleteSetup(w http.ResponseWriter, r *http.Request) {
	// If setup is already complete, return success idempotently
	if h.manager.IsSetupComplete() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":          true,
			"already_complete": true,
			"message":          "Setup was already complete",
		})
		return
	}

	// Mark setup as complete using current/default config
	defaults := h.manager.GenerateDefaultConfig()
	if err := h.manager.MarkSetupComplete(defaults); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Setup marked as complete",
	})
}

// GetEthernetStatus godoc
// @Summary Get Ethernet interface status
// @Description Returns Ethernet carrier state and assigned IP address. Used by the wizard to gate Standard profile on Ethernet readiness.
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "available: bool, carrier: bool, ip: string"
// @Router /setup/ethernet-status [get]
func (h *SetupHandler) GetEthernetStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.halClient == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available": false,
			"carrier":   false,
			"ip":        "",
		})
		return
	}

	iface, err := h.halClient.GetInterface(r.Context(), "eth0")
	if err != nil {
		// eth0 doesn't exist or HAL unreachable — no Ethernet available
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available": false,
			"carrier":   false,
			"ip":        "",
		})
		return
	}

	ip := ""
	if len(iface.IPv4Addresses) > 0 {
		ip = iface.IPv4Addresses[0]
		// Strip CIDR prefix (e.g., "192.168.1.42/24" → "192.168.1.42")
		if idx := strings.Index(ip, "/"); idx != -1 {
			ip = ip[:idx]
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"available": true,
		"carrier":   iface.IsUp,
		"ip":        ip,
	})
}

// APTeardown godoc
// @Summary Tear down Access Point
// @Description Switches network mode to eth_client, stopping the AP and disabling DHCP. Called by the wizard after Standard profile setup completes and the user has seen the Ethernet IP.
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "success: true, message"
// @Failure 500 {object} ErrorResponse "Failed to tear down AP"
// @Router /setup/ap-teardown [post]
func (h *SetupHandler) APTeardown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.networkMgr == nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "network manager not available"})
		return
	}

	log.Info().Msg("AP teardown: switching to eth_client mode (Standard profile)")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := h.networkMgr.SetEthClientModeInline(ctx, models.StaticIPConfig{}); err != nil {
		log.Error().Err(err).Msg("AP teardown failed")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "AP teardown failed: " + err.Error()})
		return
	}

	log.Info().Msg("AP teardown: completed — now in eth_client mode")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "AP teardown complete, switched to Ethernet-only mode",
	})
}

// SetupRequiredMiddleware blocks requests if setup is not complete.
// Allows: health check, setup endpoints, and login (so user can authenticate after setup).
func SetupRequiredMiddleware(setupMgr *managers.SetupManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Always allow setup endpoints, health check, login, and swagger docs
			if strings.HasPrefix(path, "/api/v1/setup") ||
				strings.HasPrefix(path, "/api/v1/swagger") ||
				path == "/health" ||
				path == "/api/v1/auth/login" ||
				path == "/api/v1/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if setup is complete
			if !setupMgr.IsSetupComplete() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionRequired)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":          "Setup required",
					"setup_required": true,
					"redirect":       "/setup",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetPreconfiguration godoc
// @Summary Get pre-configuration settings
// @Description Returns settings detected from Pi Imager, Armbian, custom.toml, or LXC during first boot. WiFi password is redacted.
// @Tags Setup
// @Produce json
// @Success 200 {object} models.Preconfiguration "Pre-configuration settings"
// @Failure 500 {object} models.ErrorResponse "Failed to read preconfiguration"
// @Router /setup/preconfiguration [get]
func (h *SetupHandler) GetPreconfiguration(w http.ResponseWriter, r *http.Request) {
	// Resolve preconfiguration.json path
	configDir := os.Getenv("CUBEOS_CONFIG_DIR")
	if configDir == "" {
		configDir = "/cubeos/config"
	}
	preconfigPath := filepath.Join(configDir, "preconfiguration.json")

	data, err := os.ReadFile(preconfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No preconfiguration file — return default "none" response
			writeJSON(w, http.StatusOK, models.Preconfiguration{
				Source:            "none",
				NetworkModeHint:   "wifi_router",
				AccessProfileHint: "standard",
				SSH:               models.PreconfigSSH{Enabled: true, PasswordAuth: true},
				Users:             []models.PreconfigUser{},
			})
			return
		}
		log.Error().Err(err).Str("path", preconfigPath).Msg("Failed to read preconfiguration.json")
		writeError(w, http.StatusInternalServerError, "Failed to read preconfiguration")
		return
	}

	// Parse into struct
	var preconfig models.Preconfiguration
	if err := json.Unmarshal(data, &preconfig); err != nil {
		log.Error().Err(err).Msg("Failed to parse preconfiguration.json")
		writeError(w, http.StatusInternalServerError, "Preconfiguration file is corrupt")
		return
	}

	// Redact WiFi password — dashboard doesn't need it (already applied by boot scripts)
	if preconfig.WiFi != nil {
		preconfig.WiFi.Password = "[redacted]"
	}

	// Ensure users slice is not nil (prevents null in JSON)
	if preconfig.Users == nil {
		preconfig.Users = []models.PreconfigUser{}
	}

	writeJSON(w, http.StatusOK, preconfig)
}
