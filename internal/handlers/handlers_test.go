package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/models"
)

// TestWriteJSON tests the JSON helper function
func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		data       interface{}
		wantStatus int
		wantType   string
	}{
		{
			name:       "success response",
			status:     http.StatusOK,
			data:       map[string]string{"message": "ok"},
			wantStatus: http.StatusOK,
			wantType:   "application/json",
		},
		{
			name:       "created response",
			status:     http.StatusCreated,
			data:       map[string]int{"id": 123},
			wantStatus: http.StatusCreated,
			wantType:   "application/json",
		},
		{
			name:       "empty data",
			status:     http.StatusNoContent,
			data:       nil,
			wantStatus: http.StatusNoContent,
			wantType:   "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeJSON(w, tt.status, tt.data)

			if w.Code != tt.wantStatus {
				t.Errorf("writeJSON() status = %v, want %v", w.Code, tt.wantStatus)
			}

			contentType := w.Header().Get("Content-Type")
			if contentType != tt.wantType {
				t.Errorf("writeJSON() Content-Type = %v, want %v", contentType, tt.wantType)
			}
		})
	}
}

// TestWriteError tests the error helper function
func TestWriteError(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		message    string
		wantStatus int
	}{
		{
			name:       "bad request",
			status:     http.StatusBadRequest,
			message:    "Invalid input",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unauthorized",
			status:     http.StatusUnauthorized,
			message:    "Invalid credentials",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "not found",
			status:     http.StatusNotFound,
			message:    "Resource not found",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "internal error",
			status:     http.StatusInternalServerError,
			message:    "Something went wrong",
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeError(w, tt.status, tt.message)

			if w.Code != tt.wantStatus {
				t.Errorf("writeError() status = %v, want %v", w.Code, tt.wantStatus)
			}

			var resp models.ErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if resp.Error != tt.message {
				t.Errorf("writeError() message = %v, want %v", resp.Error, tt.message)
			}

			if resp.Code != tt.status {
				t.Errorf("writeError() code = %v, want %v", resp.Code, tt.status)
			}
		})
	}
}

// TestHealth tests the health endpoint
func TestHealth(t *testing.T) {
	cfg := &config.Config{
		Version: "test-v1.0.0",
	}
	
	h := &Handlers{
		cfg:       cfg,
		startTime: time.Now().Add(-10 * time.Second), // Started 10 seconds ago
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Health() status = %v, want %v", w.Code, http.StatusOK)
	}

	var resp models.HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Health() status = %v, want healthy", resp.Status)
	}

	if resp.Version != "test-v1.0.0" {
		t.Errorf("Health() version = %v, want test-v1.0.0", resp.Version)
	}

	if resp.Uptime < 10 {
		t.Errorf("Health() uptime = %v, want >= 10", resp.Uptime)
	}
}

// TestLoginBadRequest tests login with invalid JSON
func TestLoginBadRequest(t *testing.T) {
	cfg := &config.Config{}
	h := &Handlers{cfg: cfg}

	// Invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()

	h.Login(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Login() with invalid JSON status = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

// TestGetMeUnauthorized tests /me endpoint without auth
func TestGetMeUnauthorized(t *testing.T) {
	cfg := &config.Config{}
	h := &Handlers{cfg: cfg}

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	w := httptest.NewRecorder()

	h.GetMe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("GetMe() without auth status = %v, want %v", w.Code, http.StatusUnauthorized)
	}
}

// TestRefreshTokenUnauthorized tests refresh without valid token
func TestRefreshTokenUnauthorized(t *testing.T) {
	cfg := &config.Config{}
	h := &Handlers{cfg: cfg}

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	w := httptest.NewRecorder()

	h.RefreshToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("RefreshToken() without auth status = %v, want %v", w.Code, http.StatusUnauthorized)
	}
}
