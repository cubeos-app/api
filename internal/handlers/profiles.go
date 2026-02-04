// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// ProfilesHandler handles profile management endpoints.
type ProfilesHandler struct {
	orchestrator *managers.Orchestrator
}

// NewProfilesHandler creates a new ProfilesHandler instance.
func NewProfilesHandler(orchestrator *managers.Orchestrator) *ProfilesHandler {
	return &ProfilesHandler{
		orchestrator: orchestrator,
	}
}

// Routes returns the router for profiles endpoints.
func (h *ProfilesHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListProfiles)
	r.Post("/", h.CreateProfile)
	r.Get("/{name}", h.GetProfile)
	r.Post("/{name}/apply", h.ApplyProfile)

	return r
}

// ListProfiles godoc
// @Summary List all profiles
// @Description Returns all available profiles (built-in and custom) along with the currently active profile name
// @Tags Profiles
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "profiles: array of profile objects, active_profile: current profile name"
// @Failure 500 {object} ErrorResponse "Failed to list profiles"
// @Router /profiles [get]
func (h *ProfilesHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, activeProfile, err := h.orchestrator.ListProfiles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profiles":       profiles,
		"active_profile": activeProfile,
	})
}

// GetProfile godoc
// @Summary Get a profile by name
// @Description Returns a single profile by name including its app configuration and resource limits
// @Tags Profiles
// @Produce json
// @Security BearerAuth
// @Param name path string true "Profile name"
// @Success 200 {object} models.Profile "Profile details"
// @Failure 404 {object} ErrorResponse "Profile not found"
// @Router /profiles/{name} [get]
func (h *ProfilesHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	profile, err := h.orchestrator.GetProfile(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

// CreateProfile godoc
// @Summary Create a custom profile
// @Description Creates a new custom profile with specified apps and configuration. Built-in profiles (minimal, standard, full) cannot be overwritten.
// @Tags Profiles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.CreateProfileRequest true "Profile creation request"
// @Success 201 {object} models.Profile "Created profile"
// @Failure 400 {object} ErrorResponse "Invalid request body or missing profile name"
// @Failure 500 {object} ErrorResponse "Failed to create profile"
// @Router /profiles [post]
func (h *ProfilesHandler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	var req models.CreateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Profile name is required")
		return
	}

	profile, err := h.orchestrator.CreateProfile(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, profile)
}

// ApplyProfile godoc
// @Summary Apply a profile
// @Description Applies a profile by starting apps defined in the profile and stopping apps not in the profile. Returns the list of started and stopped apps.
// @Tags Profiles
// @Produce json
// @Security BearerAuth
// @Param name path string true "Profile name to apply"
// @Success 200 {object} map[string]interface{} "started: apps started, stopped: apps stopped, profile: applied profile name"
// @Failure 404 {object} ErrorResponse "Profile not found"
// @Failure 500 {object} ErrorResponse "Failed to apply profile"
// @Router /profiles/{name}/apply [post]
func (h *ProfilesHandler) ApplyProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	// Check if profile exists first
	if _, err := h.orchestrator.GetProfile(r.Context(), name); err != nil {
		writeError(w, http.StatusNotFound, "Profile not found: "+name)
		return
	}

	result, err := h.orchestrator.ApplyProfile(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}
