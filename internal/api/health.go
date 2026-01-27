// Package api provides HTTP handlers for the CubeOS REST API.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"

	"github.com/nuclearlighters/cubeos/internal/config"
)

// HealthResponse is the JSON response for the /health endpoint.
type HealthResponse struct {
	Status          string `json:"status"`
	Version         string `json:"version"`
	DockerConnected bool   `json:"docker_connected"`
	// UptimeKumaConnected is included for MuleCube compatibility
	UptimeKumaConnected bool `json:"uptime_kuma_connected"`
}

// HealthHandler handles GET /health requests.
type HealthHandler struct {
	cfg          *config.Settings
	dockerClient *client.Client
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(cfg *config.Settings, dockerClient *client.Client) *HealthHandler {
	return &HealthHandler{
		cfg:          cfg,
		dockerClient: dockerClient,
	}
}

// ServeHTTP implements http.Handler for the health check endpoint.
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:              "healthy",
		Version:             h.cfg.Version,
		DockerConnected:     false,
		UptimeKumaConnected: false,
	}

	// Check Docker connectivity
	if h.dockerClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		_, err := h.dockerClient.Ping(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Docker ping failed")
			resp.Status = "degraded"
		} else {
			resp.DockerConnected = true
		}
	} else {
		resp.Status = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")

	if resp.Status == "degraded" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error().Err(err).Msg("Failed to encode health response")
	}
}
