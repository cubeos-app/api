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

// ListProfiles returns all profiles.
// GET /api/v1/profiles
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

// GetProfile returns a single profile by name.
// GET /api/v1/profiles/{name}
func (h *ProfilesHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	profile, err := h.orchestrator.GetProfile(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

// CreateProfile creates a new custom profile.
// POST /api/v1/profiles
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

// ApplyProfile applies a profile, starting/stopping apps as needed.
// POST /api/v1/profiles/{name}/apply
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
