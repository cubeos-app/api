package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
)

// MediaHandler handles camera and audio HTTP requests via HAL.
type MediaHandler struct {
	halClient *hal.Client
}

// NewMediaHandler creates a new media handler.
func NewMediaHandler(halClient *hal.Client) *MediaHandler {
	return &MediaHandler{
		halClient: halClient,
	}
}

// Routes returns the media routes.
func (h *MediaHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Camera
	r.Get("/cameras", h.GetCameras)
	r.Get("/cameras/info", h.GetCameraInfo)
	r.Post("/cameras/capture", h.CaptureImage)
	r.Get("/cameras/capture", h.GetCapturedImage)
	r.Get("/cameras/stream", h.GetStreamInfo)
	r.Post("/cameras/stream/start", h.StartStream)
	r.Post("/cameras/stream/stop", h.StopStream)

	// Audio
	r.Get("/audio", h.GetAudioDevices)
	r.Get("/audio/playback", h.GetPlaybackDevices)
	r.Get("/audio/capture", h.GetCaptureDevices)
	r.Get("/audio/volume", h.GetVolume)
	r.Post("/audio/volume", h.SetVolume)
	r.Post("/audio/mute", h.SetMute)

	return r
}

// =============================================================================
// Camera Endpoints
// =============================================================================

// GetCameras godoc
// @Summary List cameras
// @Description Returns list of detected camera devices (USB, CSI)
// @Tags Media
// @Accept json
// @Produce json
// @Success 200 {object} hal.CameraDevicesResponse
// @Failure 500 {object} models.ErrorResponse "Failed to list cameras"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/cameras [get]
func (h *MediaHandler) GetCameras(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	cameras, err := h.halClient.GetCameras(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cameras: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, cameras)
}

// GetCameraInfo godoc
// @Summary Get camera info
// @Description Returns detailed information about the default camera
// @Tags Media
// @Accept json
// @Produce json
// @Success 200 {object} hal.CameraInfo
// @Failure 500 {object} models.ErrorResponse "Failed to get camera info"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/cameras/info [get]
func (h *MediaHandler) GetCameraInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	info, err := h.halClient.GetCameraInfo(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get camera info: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// CaptureImageRequest represents an image capture request
type CaptureImageRequest struct {
	Device  string `json:"device,omitempty"`  // Camera device (default: video0)
	Width   int    `json:"width,omitempty"`   // Image width (default: 1920)
	Height  int    `json:"height,omitempty"`  // Image height (default: 1080)
	Quality int    `json:"quality,omitempty"` // JPEG quality 1-100 (default: 85)
	Format  string `json:"format,omitempty"`  // Output format: jpeg, png (default: jpeg)
}

// CaptureImage godoc
// @Summary Capture image
// @Description Captures a still image from the camera
// @Tags Media
// @Accept json
// @Produce json
// @Param request body CaptureImageRequest false "Capture parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 500 {object} models.ErrorResponse "Failed to capture image"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/cameras/capture [post]
func (h *MediaHandler) CaptureImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CaptureImageRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	// Set defaults
	if req.Device == "" {
		req.Device = "video0"
	}
	if req.Width == 0 {
		req.Width = 1920
	}
	if req.Height == 0 {
		req.Height = 1080
	}
	if req.Quality == 0 {
		req.Quality = 85
	}
	if req.Format == "" {
		req.Format = "jpeg"
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.CaptureImage(ctx, req.Device, req.Width, req.Height, req.Quality, req.Format); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to capture image: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Image captured",
	})
}

// GetCapturedImage godoc
// @Summary Get captured image
// @Description Returns the most recently captured image as binary data
// @Tags Media
// @Accept json
// @Produce image/jpeg,image/png
// @Success 200 {file} binary "Captured image"
// @Failure 404 {object} models.ErrorResponse "No image captured"
// @Failure 500 {object} models.ErrorResponse "Failed to get image"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/cameras/capture [get]
func (h *MediaHandler) GetCapturedImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	imageData, err := h.halClient.GetCapturedImage(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get captured image: "+err.Error())
		return
	}

	if len(imageData) == 0 {
		writeError(w, http.StatusNotFound, "No image captured")
		return
	}

	// Detect content type from magic bytes
	contentType := "image/jpeg"
	if len(imageData) > 8 && string(imageData[1:4]) == "PNG" {
		contentType = "image/png"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(imageData)))
	w.WriteHeader(http.StatusOK)
	w.Write(imageData)
}

// GetStreamInfo godoc
// @Summary Get stream info
// @Description Returns information about the active video stream
// @Tags Media
// @Accept json
// @Produce json
// @Success 200 {object} hal.StreamInfo
// @Failure 500 {object} models.ErrorResponse "Failed to get stream info"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/cameras/stream [get]
func (h *MediaHandler) GetStreamInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	info, err := h.halClient.GetStreamInfo(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream info: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// StartStreamRequest represents a stream start request
type StartStreamRequest struct {
	Device    string `json:"device,omitempty"`    // Camera device (default: video0)
	Port      int    `json:"port,omitempty"`      // Stream port (default: 8080)
	Width     int    `json:"width,omitempty"`     // Stream width (default: 1280)
	Height    int    `json:"height,omitempty"`    // Stream height (default: 720)
	Framerate int    `json:"framerate,omitempty"` // Framerate (default: 30)
}

// StartStream godoc
// @Summary Start video stream
// @Description Starts an MJPEG video stream from the camera
// @Tags Media
// @Accept json
// @Produce json
// @Param request body StartStreamRequest false "Stream parameters"
// @Success 200 {object} StreamStartResponse
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 500 {object} models.ErrorResponse "Failed to start stream"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/cameras/stream/start [post]
func (h *MediaHandler) StartStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req StartStreamRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	// Set defaults
	if req.Device == "" {
		req.Device = "video0"
	}
	if req.Port == 0 {
		req.Port = 8080
	}
	if req.Width == 0 {
		req.Width = 1280
	}
	if req.Height == 0 {
		req.Height = 720
	}
	if req.Framerate == 0 {
		req.Framerate = 30
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.StartStream(ctx, req.Device, req.Port, req.Width, req.Height, req.Framerate); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to start stream: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, StreamStartResponse{
		Success:   true,
		Message:   "Stream started",
		StreamURL: "http://cubeos.cube:" + strconv.Itoa(req.Port) + "/stream",
	})
}

// StreamStartResponse contains stream start result
type StreamStartResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	StreamURL string `json:"stream_url"`
}

// StopStream godoc
// @Summary Stop video stream
// @Description Stops the active video stream
// @Tags Media
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} models.ErrorResponse "Failed to stop stream"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/cameras/stream/stop [post]
func (h *MediaHandler) StopStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.StopStream(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to stop stream: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Stream stopped",
	})
}

// =============================================================================
// Audio Endpoints
// =============================================================================

// GetAudioDevices godoc
// @Summary List audio devices
// @Description Returns list of all audio devices (playback and capture)
// @Tags Media
// @Accept json
// @Produce json
// @Success 200 {object} hal.AudioDevicesResponse
// @Failure 500 {object} models.ErrorResponse "Failed to list audio devices"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/audio [get]
func (h *MediaHandler) GetAudioDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetAudioDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get audio devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// GetPlaybackDevices godoc
// @Summary List playback devices
// @Description Returns list of audio playback devices (speakers, headphones)
// @Tags Media
// @Accept json
// @Produce json
// @Success 200 {object} AudioDevicesListResponse
// @Failure 500 {object} models.ErrorResponse "Failed to list playback devices"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/audio/playback [get]
func (h *MediaHandler) GetPlaybackDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetPlaybackDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get playback devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, AudioDevicesListResponse{Devices: devices})
}

// AudioDevicesListResponse contains a list of audio devices
type AudioDevicesListResponse struct {
	Devices []hal.AudioDevice `json:"devices"`
}

// GetCaptureDevices godoc
// @Summary List capture devices
// @Description Returns list of audio capture devices (microphones)
// @Tags Media
// @Accept json
// @Produce json
// @Success 200 {object} AudioDevicesListResponse
// @Failure 500 {object} models.ErrorResponse "Failed to list capture devices"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/audio/capture [get]
func (h *MediaHandler) GetCaptureDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetCaptureDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get capture devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, AudioDevicesListResponse{Devices: devices})
}

// GetVolume godoc
// @Summary Get volume
// @Description Returns current audio volume level and mute state
// @Tags Media
// @Accept json
// @Produce json
// @Success 200 {object} hal.VolumeInfo
// @Failure 500 {object} models.ErrorResponse "Failed to get volume"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/audio/volume [get]
func (h *MediaHandler) GetVolume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	volume, err := h.halClient.GetVolume(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get volume: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, volume)
}

// SetVolumeRequest represents a volume set request
type SetVolumeRequest struct {
	Volume int `json:"volume"` // 0-100
}

// SetVolume godoc
// @Summary Set volume
// @Description Sets the audio volume level (0-100)
// @Tags Media
// @Accept json
// @Produce json
// @Param request body SetVolumeRequest true "Volume level"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} models.ErrorResponse "Invalid volume"
// @Failure 500 {object} models.ErrorResponse "Failed to set volume"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/audio/volume [post]
func (h *MediaHandler) SetVolume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SetVolumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Volume < 0 || req.Volume > 100 {
		writeError(w, http.StatusBadRequest, "Volume must be between 0 and 100")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SetVolume(ctx, req.Volume); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set volume: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Volume set to " + strconv.Itoa(req.Volume) + "%",
	})
}

// SetMuteRequest represents a mute request
type SetMuteRequest struct {
	Muted bool `json:"muted"`
}

// SetMute godoc
// @Summary Set mute state
// @Description Mutes or unmutes the audio output
// @Tags Media
// @Accept json
// @Produce json
// @Param request body SetMuteRequest true "Mute state"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 500 {object} models.ErrorResponse "Failed to set mute"
// @Failure 503 {object} models.ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /api/v1/media/audio/mute [post]
func (h *MediaHandler) SetMute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SetMuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.SetMute(ctx, req.Muted); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set mute: "+err.Error())
		return
	}

	msg := "Audio unmuted"
	if req.Muted {
		msg = "Audio muted"
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: msg,
	})
}
