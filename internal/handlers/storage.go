package handlers

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
)

// validDeviceName matches safe device names (e.g., sda, sdb1, nvme0n1p1, mmcblk0)
var validDeviceName = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// validateMountPath checks that a mount path is safe (absolute, no traversal)
func validateMountPath(path string) bool {
	if path == "" {
		return false
	}
	if !filepath.IsAbs(path) {
		return false
	}
	if strings.Contains(path, "..") {
		return false
	}
	cleaned := filepath.Clean(path)
	return cleaned == path
}

// StorageHandler handles storage-related HTTP requests via HAL.
type StorageHandler struct {
	halClient *hal.Client
}

// NewStorageHandler creates a new storage handler.
func NewStorageHandler(halClient *hal.Client) *StorageHandler {
	return &StorageHandler{
		halClient: halClient,
	}
}

// Routes returns the storage routes.
func (h *StorageHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Block Devices
	r.Get("/devices", h.GetStorageDevices)
	r.Get("/devices/{device}", h.GetStorageDevice)
	r.Get("/devices/{device}/smart", h.GetSMARTInfo)
	r.Get("/usage", h.GetStorageUsage)

	// USB Storage
	r.Get("/usb", h.GetUSBStorageDevices)
	r.Post("/usb/{device}/mount", h.MountUSBStorage)
	r.Post("/usb/{device}/unmount", h.UnmountUSBStorage)
	r.Post("/usb/{device}/eject", h.EjectUSBStorage)

	// USB Devices (general)
	r.Get("/usb/devices", h.GetUSBDevices)
	r.Get("/usb/tree", h.GetUSBTree)
	r.Get("/usb/class/{class}", h.GetUSBDevicesByClass)
	r.Post("/usb/rescan", h.RescanUSB)
	r.Post("/usb/reset/{bus}/{device}", h.ResetUSBDevice)

	// Network Mounts
	r.Get("/network-mounts", h.GetNetworkMounts)
	r.Post("/network-mounts/smb", h.MountSMB)
	r.Post("/network-mounts/nfs", h.MountNFS)
	r.Post("/network-mounts/test", h.TestMountConnection)
	r.Delete("/network-mounts", h.UnmountNetwork)
	r.Get("/network-mounts/check", h.IsMounted)

	return r
}

// =============================================================================
// Block Device Endpoints
// =============================================================================

// GetStorageDevices godoc
// @Summary List storage devices
// @Description Returns list of all block storage devices (disks, partitions)
// @Tags Storage
// @Accept json
// @Produce json
// @Success 200 {object} hal.StorageDevicesResponse
// @Failure 500 {object} ErrorResponse "Failed to list storage devices"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/devices [get]
func (h *StorageHandler) GetStorageDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetStorageDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get storage devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// GetStorageDevice godoc
// @Summary Get storage device details
// @Description Returns detailed information about a specific storage device
// @Tags Storage
// @Accept json
// @Produce json
// @Param device path string true "Device name (without /dev/)" example(sda)
// @Success 200 {object} hal.StorageDevice
// @Failure 400 {object} ErrorResponse "Device name required"
// @Failure 500 {object} ErrorResponse "Failed to get storage device"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/devices/{device} [get]
func (h *StorageHandler) GetStorageDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	device := chi.URLParam(r, "device")

	if device == "" {
		writeError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	if !validDeviceName.MatchString(device) {
		writeError(w, http.StatusBadRequest, "Invalid device name")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	deviceInfo, err := h.halClient.GetStorageDevice(ctx, device)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get storage device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, deviceInfo)
}

// GetSMARTInfo godoc
// @Summary Get SMART data
// @Description Returns S.M.A.R.T. health data for a storage device
// @Tags Storage
// @Accept json
// @Produce json
// @Param device path string true "Device name (without /dev/)" example(sda)
// @Success 200 {object} hal.SMARTInfo
// @Failure 400 {object} ErrorResponse "Device name required"
// @Failure 500 {object} ErrorResponse "Failed to get SMART data"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/devices/{device}/smart [get]
func (h *StorageHandler) GetSMARTInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	device := chi.URLParam(r, "device")

	if device == "" {
		writeError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	if !validDeviceName.MatchString(device) {
		writeError(w, http.StatusBadRequest, "Invalid device name")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	smartInfo, err := h.halClient.GetSMARTInfo(ctx, device)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get SMART info: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, smartInfo)
}

// GetStorageUsage godoc
// @Summary Get storage usage
// @Description Returns filesystem usage for all mounted partitions
// @Tags Storage
// @Accept json
// @Produce json
// @Success 200 {object} hal.StorageUsageResponse
// @Failure 500 {object} ErrorResponse "Failed to get storage usage"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usage [get]
func (h *StorageHandler) GetStorageUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	usage, err := h.halClient.GetStorageUsage(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get storage usage: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, usage)
}

// =============================================================================
// USB Storage Endpoints
// =============================================================================

// GetUSBStorageDevices godoc
// @Summary List USB storage devices
// @Description Returns list of connected USB storage devices (flash drives, external disks)
// @Tags Storage
// @Accept json
// @Produce json
// @Success 200 {object} USBStorageResponse
// @Failure 500 {object} ErrorResponse "Failed to list USB storage"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb [get]
func (h *StorageHandler) GetUSBStorageDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetUSBStorageDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get USB storage devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, USBStorageResponse{Devices: devices})
}

// USBStorageResponse contains USB storage device list
type USBStorageResponse struct {
	Devices []hal.USBStorageDevice `json:"devices"`
}

// MountUSBStorage godoc
// @Summary Mount USB storage
// @Description Mounts a USB storage device to an auto-generated mount point
// @Tags Storage
// @Accept json
// @Produce json
// @Param device path string true "Device name (without /dev/)" example(sdb1)
// @Success 200 {object} MountResultResponse
// @Failure 400 {object} ErrorResponse "Device name required"
// @Failure 500 {object} ErrorResponse "Failed to mount USB storage"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb/{device}/mount [post]
func (h *StorageHandler) MountUSBStorage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	device := chi.URLParam(r, "device")

	if device == "" {
		writeError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	if !validDeviceName.MatchString(device) {
		writeError(w, http.StatusBadRequest, "Invalid device name")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	mountPoint, err := h.halClient.MountUSBStorage(ctx, device)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to mount USB storage: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, MountResultResponse{
		Success:    true,
		MountPoint: mountPoint,
		Message:    "USB storage mounted at " + mountPoint,
	})
}

// MountResultResponse contains mount operation result
type MountResultResponse struct {
	Success    bool   `json:"success"`
	MountPoint string `json:"mount_point,omitempty"`
	Message    string `json:"message"`
}

// UnmountUSBStorage godoc
// @Summary Unmount USB storage
// @Description Unmounts a USB storage device
// @Tags Storage
// @Accept json
// @Produce json
// @Param device path string true "Device name (without /dev/)" example(sdb1)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Device name required"
// @Failure 500 {object} ErrorResponse "Failed to unmount USB storage"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb/{device}/unmount [post]
func (h *StorageHandler) UnmountUSBStorage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	device := chi.URLParam(r, "device")

	if device == "" {
		writeError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	if !validDeviceName.MatchString(device) {
		writeError(w, http.StatusBadRequest, "Invalid device name")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.UnmountUSBStorage(ctx, device); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to unmount USB storage: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "USB storage unmounted",
	})
}

// EjectUSBStorage godoc
// @Summary Eject USB storage
// @Description Safely ejects a USB storage device (unmount + power off port)
// @Tags Storage
// @Accept json
// @Produce json
// @Param device path string true "Device name (without /dev/)" example(sdb)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Device name required"
// @Failure 500 {object} ErrorResponse "Failed to eject USB storage"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb/{device}/eject [post]
func (h *StorageHandler) EjectUSBStorage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	device := chi.URLParam(r, "device")

	if device == "" {
		writeError(w, http.StatusBadRequest, "Device name is required")
		return
	}

	if !validDeviceName.MatchString(device) {
		writeError(w, http.StatusBadRequest, "Invalid device name")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.EjectUSBStorage(ctx, device); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to eject USB storage: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "USB storage ejected safely",
	})
}

// =============================================================================
// USB Device Endpoints (General)
// =============================================================================

// GetUSBDevices godoc
// @Summary List all USB devices
// @Description Returns list of all connected USB devices (not just storage)
// @Tags Storage
// @Accept json
// @Produce json
// @Success 200 {object} hal.USBDevicesResponse
// @Failure 500 {object} ErrorResponse "Failed to list USB devices"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb/devices [get]
func (h *StorageHandler) GetUSBDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetUSBDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get USB devices: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, devices)
}

// GetUSBTree godoc
// @Summary Get USB device tree
// @Description Returns hierarchical USB device tree showing hub/port relationships
// @Tags Storage
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse "Failed to get USB tree"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb/tree [get]
func (h *StorageHandler) GetUSBTree(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	tree, err := h.halClient.GetUSBTree(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get USB tree: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, tree)
}

// GetUSBDevicesByClass godoc
// @Summary List USB devices by class
// @Description Returns USB devices filtered by device class
// @Tags Storage
// @Accept json
// @Produce json
// @Param class path string true "USB device class" example(storage) Enums(storage, hub, hid, audio, video, wireless, serial, printer)
// @Success 200 {object} USBDevicesByClassResponse
// @Failure 400 {object} ErrorResponse "Class is required"
// @Failure 500 {object} ErrorResponse "Failed to list USB devices"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb/class/{class} [get]
func (h *StorageHandler) GetUSBDevicesByClass(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	class := chi.URLParam(r, "class")

	if class == "" {
		writeError(w, http.StatusBadRequest, "Device class is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	devices, err := h.halClient.GetUSBDevicesByClass(ctx, class)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get USB devices by class: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, USBDevicesByClassResponse{
		Class:   class,
		Devices: devices,
	})
}

// USBDevicesByClassResponse contains USB devices filtered by class
type USBDevicesByClassResponse struct {
	Class   string          `json:"class"`
	Devices []hal.USBDevice `json:"devices"`
}

// RescanUSB godoc
// @Summary Rescan USB bus
// @Description Forces a rescan of the USB bus to detect new devices
// @Tags Storage
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse "Failed to rescan USB"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb/rescan [post]
func (h *StorageHandler) RescanUSB(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.RescanUSB(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to rescan USB: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "USB bus rescanned",
	})
}

// ResetUSBDevice godoc
// @Summary Reset USB device
// @Description Resets a specific USB device by bus and device number
// @Tags Storage
// @Accept json
// @Produce json
// @Param bus path int true "USB bus number" example(1)
// @Param device path int true "USB device number" example(4)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid bus or device number"
// @Failure 500 {object} ErrorResponse "Failed to reset USB device"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/usb/reset/{bus}/{device} [post]
func (h *StorageHandler) ResetUSBDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	busStr := chi.URLParam(r, "bus")
	deviceStr := chi.URLParam(r, "device")

	bus, err := strconv.Atoi(busStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid bus number")
		return
	}

	device, err := strconv.Atoi(deviceStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid device number")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.ResetUSBDevice(ctx, bus, device); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to reset USB device: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "USB device reset",
	})
}

// =============================================================================
// Network Mount Endpoints
// =============================================================================

// GetNetworkMounts godoc
// @Summary List network mounts
// @Description Returns list of active network mounts (SMB/NFS)
// @Tags Storage
// @Accept json
// @Produce json
// @Success 200 {object} hal.MountsResponse
// @Failure 500 {object} ErrorResponse "Failed to list mounts"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/network-mounts [get]
func (h *StorageHandler) GetNetworkMounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	mounts, err := h.halClient.GetNetworkMounts(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get network mounts: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, mounts)
}

// SMBMountRequest represents an SMB mount request
type SMBMountRequest struct {
	RemotePath string `json:"remote_path"` // //server/share
	MountPoint string `json:"mount_point"` // /mnt/share
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Options    string `json:"options,omitempty"`
}

// MountSMB godoc
// @Summary Mount SMB share
// @Description Mounts a Windows/Samba network share
// @Tags Storage
// @Accept json
// @Produce json
// @Param request body SMBMountRequest true "SMB mount parameters"
// @Success 200 {object} hal.MountResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to mount SMB share"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/network-mounts/smb [post]
func (h *StorageHandler) MountSMB(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SMBMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RemotePath == "" {
		writeError(w, http.StatusBadRequest, "Remote path is required (e.g., //server/share)")
		return
	}

	if req.MountPoint == "" {
		writeError(w, http.StatusBadRequest, "Mount point is required (e.g., /mnt/share)")
		return
	}

	if !validateMountPath(req.MountPoint) {
		writeError(w, http.StatusBadRequest, "Invalid mount point: must be an absolute path with no traversal")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	halReq := &hal.MountRequest{
		RemotePath: req.RemotePath,
		LocalPath:  req.MountPoint,
		Username:   req.Username,
		Password:   req.Password,
		Options:    req.Options,
	}

	result, err := h.halClient.MountSMB(ctx, halReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to mount SMB share: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// NFSMountRequest represents an NFS mount request
type NFSMountRequest struct {
	RemotePath string `json:"remote_path"` // server:/export/path
	MountPoint string `json:"mount_point"` // /mnt/nfs
	Options    string `json:"options,omitempty"`
}

// MountNFS godoc
// @Summary Mount NFS share
// @Description Mounts an NFS network share
// @Tags Storage
// @Accept json
// @Produce json
// @Param request body NFSMountRequest true "NFS mount parameters"
// @Success 200 {object} hal.MountResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Failed to mount NFS share"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/network-mounts/nfs [post]
func (h *StorageHandler) MountNFS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req NFSMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RemotePath == "" {
		writeError(w, http.StatusBadRequest, "Remote path is required (e.g., server:/export/path)")
		return
	}

	if req.MountPoint == "" {
		writeError(w, http.StatusBadRequest, "Mount point is required (e.g., /mnt/nfs)")
		return
	}

	if !validateMountPath(req.MountPoint) {
		writeError(w, http.StatusBadRequest, "Invalid mount point: must be an absolute path with no traversal")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	halReq := &hal.MountRequest{
		RemotePath: req.RemotePath,
		LocalPath:  req.MountPoint,
		Options:    req.Options,
	}

	result, err := h.halClient.MountNFS(ctx, halReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to mount NFS share: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// TestMountRequest represents a mount test request
type TestMountRequest struct {
	Type       string `json:"type"`        // "smb" or "nfs"
	RemotePath string `json:"remote_path"` // //server/share or server:/path
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
}

// TestMountConnection godoc
// @Summary Test mount connection
// @Description Tests connectivity to a network share without mounting
// @Tags Storage
// @Accept json
// @Produce json
// @Param request body TestMountRequest true "Mount test parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Connection test failed"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/network-mounts/test [post]
func (h *StorageHandler) TestMountConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req TestMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "Mount type is required (smb or nfs)")
		return
	}

	if req.RemotePath == "" {
		writeError(w, http.StatusBadRequest, "Remote path is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.TestMountConnection(ctx, req.Type, req.RemotePath, req.Username, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, "Connection test failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Connection successful",
	})
}

// UnmountNetworkRequest represents an unmount request
type UnmountNetworkRequest struct {
	Path string `json:"path"`
}

// UnmountNetwork godoc
// @Summary Unmount network share
// @Description Unmounts a network share by mount point path
// @Tags Storage
// @Accept json
// @Produce json
// @Param request body UnmountNetworkRequest true "Unmount parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Path is required"
// @Failure 500 {object} ErrorResponse "Failed to unmount"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/network-mounts [delete]
func (h *StorageHandler) UnmountNetwork(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req UnmountNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "Mount path is required")
		return
	}

	if !validateMountPath(req.Path) {
		writeError(w, http.StatusBadRequest, "Invalid mount path: must be an absolute path with no traversal")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.UnmountNetwork(ctx, req.Path); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to unmount: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Share unmounted",
	})
}

// IsMounted godoc
// @Summary Check if path is mounted
// @Description Checks if a specific path is currently mounted
// @Tags Storage
// @Accept json
// @Produce json
// @Param path query string true "Path to check" example(/mnt/share)
// @Success 200 {object} MountCheckResponse
// @Failure 400 {object} ErrorResponse "Path is required"
// @Failure 500 {object} ErrorResponse "Failed to check mount"
// @Failure 503 {object} ErrorResponse "HAL unavailable"
// @Security BearerAuth
// @Router /hal/storage/network-mounts/check [get]
func (h *StorageHandler) IsMounted(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := r.URL.Query().Get("path")

	if path == "" {
		writeError(w, http.StatusBadRequest, "Path query parameter is required")
		return
	}

	if !validateMountPath(path) {
		writeError(w, http.StatusBadRequest, "Invalid path: must be an absolute path with no traversal")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	mounted, err := h.halClient.IsMounted(ctx, path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check mount: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, MountCheckResponse{
		Path:    path,
		Mounted: mounted,
	})
}

// MountCheckResponse contains mount check result
type MountCheckResponse struct {
	Path    string `json:"path"`
	Mounted bool   `json:"mounted"`
}
