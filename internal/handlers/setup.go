package handlers

import (
	"encoding/json"
	"net/http"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"

	"github.com/go-chi/chi/v5"
)

// SetupHandler handles setup wizard endpoints
type SetupHandler struct {
	manager *managers.SetupManager
}

// NewSetupHandler creates a new setup handler
func NewSetupHandler(manager *managers.SetupManager) *SetupHandler {
	return &SetupHandler{manager: manager}
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
// @Description Applies the complete setup configuration, configuring all system components. This is the main setup completion endpoint.
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

	if err := h.manager.ApplySetupConfig(&cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

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
// @Description Skips the setup wizard and marks setup as complete using default configuration values
// @Tags Setup
// @Produce json
// @Success 200 {object} map[string]interface{} "success: true, message, skipped: true"
// @Failure 500 {object} ErrorResponse "Failed to skip setup"
// @Router /setup/skip [post]
func (h *SetupHandler) SkipSetup(w http.ResponseWriter, r *http.Request) {
	// Apply default config to mark setup complete
	defaults := h.manager.GenerateDefaultConfig()
	if err := h.manager.MarkSetupComplete(defaults); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Setup skipped, using default configuration",
		"skipped": true,
	})
}

// SetupRequiredMiddleware blocks requests if setup is not complete
func SetupRequiredMiddleware(setupMgr *managers.SetupManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow setup endpoints
			if r.URL.Path == "/api/v1/setup" ||
				r.URL.Path == "/api/v1/setup/" ||
				len(r.URL.Path) > 13 && r.URL.Path[:14] == "/api/v1/setup/" {
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
