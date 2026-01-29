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

// GetSetupStatus returns current setup progress
func (h *SetupHandler) GetSetupStatus(w http.ResponseWriter, r *http.Request) {
	status := h.manager.GetSetupStatus()
	json.NewEncoder(w).Encode(status)
}

// GetWizardSteps returns all wizard step definitions
func (h *SetupHandler) GetWizardSteps(w http.ResponseWriter, r *http.Request) {
	steps := h.manager.GetWizardSteps()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"steps": steps,
		"total": len(steps),
	})
}

// GetDefaultConfig returns default configuration values
func (h *SetupHandler) GetDefaultConfig(w http.ResponseWriter, r *http.Request) {
	defaults := h.manager.GenerateDefaultConfig()
	json.NewEncoder(w).Encode(defaults)
}

// GetSystemRequirements returns device capabilities
func (h *SetupHandler) GetSystemRequirements(w http.ResponseWriter, r *http.Request) {
	req := h.manager.GetSystemRequirements()
	json.NewEncoder(w).Encode(req)
}

// GetTimezones returns available timezones
func (h *SetupHandler) GetTimezones(w http.ResponseWriter, r *http.Request) {
	timezones := h.manager.GetTimezones()
	
	// Group by region
	byRegion := make(map[string][]models.TimezoneInfo)
	for _, tz := range timezones {
		byRegion[tz.Region] = append(byRegion[tz.Region], tz)
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"timezones":  timezones,
		"by_region":  byRegion,
		"total":      len(timezones),
	})
}

// GetDeploymentPurposes returns available deployment purposes
func (h *SetupHandler) GetDeploymentPurposes(w http.ResponseWriter, r *http.Request) {
	purposes := h.manager.GetDeploymentPurposes()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"purposes": purposes,
		"total":    len(purposes),
	})
}

// GetDNSProviders returns available DNS providers for Let's Encrypt
func (h *SetupHandler) GetDNSProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.manager.GetDNSProviders()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": providers,
		"total":     len(providers),
	})
}

// ValidateConfig validates a setup configuration
func (h *SetupHandler) ValidateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg models.SetupConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	result := h.manager.ValidateSetupConfig(&cfg)
	json.NewEncoder(w).Encode(result)
}

// ApplyConfig applies the complete setup configuration
func (h *SetupHandler) ApplyConfig(w http.ResponseWriter, r *http.Request) {
	var cfg models.SetupConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if err := h.manager.ApplySetupConfig(&cfg); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Setup completed successfully",
		"status":  h.manager.GetSetupStatus(),
	})
}

// ResetSetup resets the setup wizard (admin only)
func (h *SetupHandler) ResetSetup(w http.ResponseWriter, r *http.Request) {
	// This should be protected by admin auth in production
	if err := h.manager.ResetSetup(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Setup has been reset",
	})
}

// SkipSetup skips the wizard and marks setup as complete with defaults
func (h *SetupHandler) SkipSetup(w http.ResponseWriter, r *http.Request) {
	// Apply default config to mark setup complete
	defaults := h.manager.GenerateDefaultConfig()
	if err := h.manager.MarkSetupComplete(defaults); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
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
