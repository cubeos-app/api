package managers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"sync"

	"cubeos-api/internal/models"
)

const (
	// maxWallpaperSize is the maximum allowed wallpaper upload size (5 MB).
	maxWallpaperSize = 5 * 1024 * 1024

	// wallpaperFilename is the stored custom wallpaper file (without extension).
	wallpaperFilename = "custom-wallpaper"
)

// allowedImageTypes maps MIME types to file extensions for validation.
var allowedImageTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/webp": ".webp",
}

// PreferencesManager handles user preferences
type PreferencesManager struct {
	filePath      string
	wallpaperDir  string
	prefs         models.Preferences
	wallpaperMime string // content-type of stored wallpaper
	lock          sync.RWMutex
}

// DefaultPreferences returns default preference values
func DefaultPreferences() models.Preferences {
	return models.Preferences{
		SetupComplete:       false,
		TourComplete:        false,
		Favorites:           []string{},
		RecentServices:      []string{},
		Theme:               "dark",
		CollapsedCategories: []string{},
		AdminExpanded:       false,
		UIMode:              "advanced",
	}
}

// NewPreferencesManager creates a new PreferencesManager
func NewPreferencesManager() *PreferencesManager {
	dataDir := "/cubeos/data"
	pm := &PreferencesManager{
		filePath:     filepath.Join(dataDir, "user-preferences.json"),
		wallpaperDir: filepath.Join(dataDir, "wallpapers"),
		prefs:        DefaultPreferences(),
	}

	// Ensure directories exist
	os.MkdirAll(filepath.Dir(pm.filePath), 0755)
	os.MkdirAll(pm.wallpaperDir, 0755)

	// Load existing preferences
	pm.load()

	return pm
}

// load reads preferences from file
func (pm *PreferencesManager) load() {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	data, err := os.ReadFile(pm.filePath)
	if err != nil {
		return // Use defaults
	}

	var loaded models.Preferences
	if err := json.Unmarshal(data, &loaded); err != nil {
		return // Use defaults
	}

	// Merge with defaults (to handle new fields)
	defaults := DefaultPreferences()

	if loaded.Theme != "" {
		pm.prefs.Theme = loaded.Theme
	} else {
		pm.prefs.Theme = defaults.Theme
	}

	if loaded.UIMode != "" {
		pm.prefs.UIMode = loaded.UIMode
	} else {
		pm.prefs.UIMode = defaults.UIMode
	}

	pm.prefs.SetupComplete = loaded.SetupComplete
	pm.prefs.TourComplete = loaded.TourComplete
	pm.prefs.AdminExpanded = loaded.AdminExpanded
	pm.prefs.Wallpaper = loaded.Wallpaper
	pm.prefs.Dashboard = loaded.Dashboard

	if loaded.Favorites != nil {
		pm.prefs.Favorites = loaded.Favorites
	}
	if loaded.RecentServices != nil {
		pm.prefs.RecentServices = loaded.RecentServices
	}
	if loaded.CollapsedCategories != nil {
		pm.prefs.CollapsedCategories = loaded.CollapsedCategories
	}

	// Detect stored wallpaper MIME type
	pm.detectWallpaperMime()
}

// detectWallpaperMime checks which wallpaper file variant exists on disk.
func (pm *PreferencesManager) detectWallpaperMime() {
	for mime, ext := range allowedImageTypes {
		path := filepath.Join(pm.wallpaperDir, wallpaperFilename+ext)
		if _, err := os.Stat(path); err == nil {
			pm.wallpaperMime = mime
			return
		}
	}
	pm.wallpaperMime = ""
}

// save writes preferences to file
func (pm *PreferencesManager) save() error {
	data, err := json.MarshalIndent(pm.prefs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(pm.filePath, data, 0644)
}

// Get returns current preferences
func (pm *PreferencesManager) Get() models.Preferences {
	pm.lock.RLock()
	defer pm.lock.RUnlock()
	return pm.prefs
}

// Update updates preferences with new values
func (pm *PreferencesManager) Update(update models.PreferencesUpdate) (models.Preferences, error) {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	// Apply updates (only non-nil fields)
	if update.SetupComplete != nil {
		pm.prefs.SetupComplete = *update.SetupComplete
	}
	if update.TourComplete != nil {
		pm.prefs.TourComplete = *update.TourComplete
	}
	if update.Favorites != nil {
		pm.prefs.Favorites = update.Favorites
	}
	if update.RecentServices != nil {
		pm.prefs.RecentServices = update.RecentServices
	}
	if update.Theme != nil {
		pm.prefs.Theme = *update.Theme
	}
	if update.CollapsedCategories != nil {
		pm.prefs.CollapsedCategories = update.CollapsedCategories
	}
	if update.AdminExpanded != nil {
		pm.prefs.AdminExpanded = *update.AdminExpanded
	}
	if update.UIMode != nil {
		pm.prefs.UIMode = *update.UIMode
	}
	if update.Wallpaper != nil {
		pm.prefs.Wallpaper = update.Wallpaper
	}
	if update.Dashboard != nil {
		// Merge dashboard config: each mode (Standard/Advanced) is merged independently
		// so that updating one mode doesn't wipe the other.
		if pm.prefs.Dashboard == nil {
			pm.prefs.Dashboard = update.Dashboard
		} else {
			if update.Dashboard.Standard != nil {
				pm.prefs.Dashboard.Standard = mergeDashboardLayout(pm.prefs.Dashboard.Standard, update.Dashboard.Standard)
			}
			if update.Dashboard.Advanced != nil {
				pm.prefs.Dashboard.Advanced = mergeDashboardLayout(pm.prefs.Dashboard.Advanced, update.Dashboard.Advanced)
			}
		}
	}

	// Save to file
	if err := pm.save(); err != nil {
		return pm.prefs, err
	}

	return pm.prefs, nil
}

// mergeDashboardLayout merges an incoming DashboardLayoutConfig update into an
// existing config. If the existing config is nil, the update is returned as-is.
// Only non-nil/non-zero fields from the update overwrite existing values, so
// partial updates (e.g. toggling a single widget) don't wipe sibling fields.
func mergeDashboardLayout(existing, update *models.DashboardLayoutConfig) *models.DashboardLayoutConfig {
	if existing == nil {
		return update
	}
	// Widget visibility
	if update.ShowClock != nil {
		existing.ShowClock = update.ShowClock
	}
	if update.ShowSearch != nil {
		existing.ShowSearch = update.ShowSearch
	}
	if update.ShowStatusPill != nil {
		existing.ShowStatusPill = update.ShowStatusPill
	}
	if update.ShowSystemVitals != nil {
		existing.ShowSystemVitals = update.ShowSystemVitals
	}
	if update.ShowNetwork != nil {
		existing.ShowNetwork = update.ShowNetwork
	}
	if update.ShowDisk != nil {
		existing.ShowDisk = update.ShowDisk
	}
	if update.ShowSignals != nil {
		existing.ShowSignals = update.ShowSignals
	}
	if update.ShowQuickActions != nil {
		existing.ShowQuickActions = update.ShowQuickActions
	}
	if update.ShowFavorites != nil {
		existing.ShowFavorites = update.ShowFavorites
	}
	if update.ShowRecent != nil {
		existing.ShowRecent = update.ShowRecent
	}
	if update.ShowMyApps != nil {
		existing.ShowMyApps = update.ShowMyApps
	}
	if update.ShowAlerts != nil {
		existing.ShowAlerts = update.ShowAlerts
	}
	// Clock settings
	if update.ClockFormat != "" {
		existing.ClockFormat = update.ClockFormat
	}
	if update.DateFormat != "" {
		existing.DateFormat = update.DateFormat
	}
	if update.ShowSeconds != nil {
		existing.ShowSeconds = update.ShowSeconds
	}
	if update.ShowGreeting != nil {
		existing.ShowGreeting = update.ShowGreeting
	}
	// Layout settings
	if update.MyAppsRows != 0 {
		existing.MyAppsRows = update.MyAppsRows
	}
	if update.FavoriteCols != 0 {
		existing.FavoriteCols = update.FavoriteCols
	}
	if update.QuickActions != nil {
		existing.QuickActions = update.QuickActions
	}
	if update.WidgetOrder != nil {
		existing.WidgetOrder = update.WidgetOrder
	}
	// Grid layout (row-based)
	if update.GridLayout != nil {
		existing.GridLayout = update.GridLayout
	}
	// Per-widget opacity
	if update.WidgetOpacity != nil {
		existing.WidgetOpacity = update.WidgetOpacity
	}
	// Per-widget dimensions
	if update.WidgetDimensions != nil {
		existing.WidgetDimensions = update.WidgetDimensions
	}
	// Advanced section order
	if update.AdvancedSectionOrder != nil {
		existing.AdvancedSectionOrder = update.AdvancedSectionOrder
	}
	// Advanced-specific section visibility
	if update.ShowInfoBar != nil {
		existing.ShowInfoBar = update.ShowInfoBar
	}
	if update.ShowSwarm != nil {
		existing.ShowSwarm = update.ShowSwarm
	}
	if update.ShowCoreServices != nil {
		existing.ShowCoreServices = update.ShowCoreServices
	}
	// Layout lock (Session 6)
	if update.LayoutLocked != nil {
		existing.LayoutLocked = update.LayoutLocked
	}
	return existing
}

// Reset resets preferences to defaults and removes custom wallpaper.
func (pm *PreferencesManager) Reset() models.Preferences {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	pm.prefs = DefaultPreferences()
	pm.save()
	pm.removeWallpaperFiles()
	pm.wallpaperMime = ""

	return pm.prefs
}

// =============================================================================
// Wallpaper Upload / Serve
// =============================================================================

// SaveWallpaper validates and stores a custom wallpaper image.
// It accepts JPEG, PNG, or WebP up to maxWallpaperSize bytes.
// Any previous custom wallpaper is removed first.
func (pm *PreferencesManager) SaveWallpaper(file io.Reader, contentType string, size int64) error {
	if size > maxWallpaperSize {
		return fmt.Errorf("file too large: %d bytes (max %d)", size, maxWallpaperSize)
	}

	ext, ok := allowedImageTypes[contentType]
	if !ok {
		return fmt.Errorf("unsupported image type: %s (allowed: image/jpeg, image/png, image/webp)", contentType)
	}

	// Read full file into memory for validation (max 5 MB, safe)
	data, err := io.ReadAll(io.LimitReader(file, maxWallpaperSize+1))
	if err != nil {
		return fmt.Errorf("failed to read upload: %w", err)
	}
	if int64(len(data)) > maxWallpaperSize {
		return fmt.Errorf("file exceeds maximum size of 5 MB")
	}

	// Validate it's a decodable image
	if contentType == "image/webp" {
		if !isWebP(data) {
			return fmt.Errorf("file is not a valid WebP image")
		}
	} else {
		if _, _, err := image.Decode(bytes.NewReader(data)); err != nil {
			return fmt.Errorf("invalid image: %w", err)
		}
	}

	pm.lock.Lock()
	defer pm.lock.Unlock()

	// Remove any previous custom wallpaper files
	pm.removeWallpaperFiles()

	// Write new file
	dest := filepath.Join(pm.wallpaperDir, wallpaperFilename+ext)
	if err := os.WriteFile(dest, data, 0644); err != nil {
		return fmt.Errorf("failed to save wallpaper: %w", err)
	}

	pm.wallpaperMime = contentType
	return nil
}

// GetWallpaperPath returns the path and MIME type of the stored custom
// wallpaper. Returns empty strings if no custom wallpaper is stored.
func (pm *PreferencesManager) GetWallpaperPath() (string, string) {
	pm.lock.RLock()
	defer pm.lock.RUnlock()

	if pm.wallpaperMime == "" {
		return "", ""
	}

	ext := allowedImageTypes[pm.wallpaperMime]
	path := filepath.Join(pm.wallpaperDir, wallpaperFilename+ext)

	if _, err := os.Stat(path); err != nil {
		return "", ""
	}

	return path, pm.wallpaperMime
}

// DeleteWallpaper removes the custom wallpaper from disk.
func (pm *PreferencesManager) DeleteWallpaper() {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	pm.removeWallpaperFiles()
	pm.wallpaperMime = ""
}

// removeWallpaperFiles deletes all custom wallpaper variants from disk.
// Must be called with lock held.
func (pm *PreferencesManager) removeWallpaperFiles() {
	for _, ext := range allowedImageTypes {
		os.Remove(filepath.Join(pm.wallpaperDir, wallpaperFilename+ext))
	}
}

// isWebP checks the RIFF/WEBP magic bytes.
func isWebP(data []byte) bool {
	return len(data) >= 12 &&
		data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F' &&
		data[8] == 'W' && data[9] == 'E' && data[10] == 'B' && data[11] == 'P'
}

// =============================================================================
// Favorites
// =============================================================================

// AddFavorite adds a service to favorites
func (pm *PreferencesManager) AddFavorite(service string) models.Preferences {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	// Check if already in favorites
	for _, f := range pm.prefs.Favorites {
		if f == service {
			return pm.prefs
		}
	}

	pm.prefs.Favorites = append(pm.prefs.Favorites, service)
	pm.save()

	return pm.prefs
}

// RemoveFavorite removes a service from favorites
func (pm *PreferencesManager) RemoveFavorite(service string) models.Preferences {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	filtered := []string{}
	for _, f := range pm.prefs.Favorites {
		if f != service {
			filtered = append(filtered, f)
		}
	}

	pm.prefs.Favorites = filtered
	pm.save()

	return pm.prefs
}

// AddRecentService adds a service to recent list
func (pm *PreferencesManager) AddRecentService(service string) models.Preferences {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	// Remove if already exists (to move to front)
	filtered := []string{service}
	for _, r := range pm.prefs.RecentServices {
		if r != service {
			filtered = append(filtered, r)
		}
	}

	// Keep max 10 recent
	if len(filtered) > 10 {
		filtered = filtered[:10]
	}

	pm.prefs.RecentServices = filtered
	pm.save()

	return pm.prefs
}

// ToggleCategory toggles collapsed state for a category
func (pm *PreferencesManager) ToggleCategory(category string) models.Preferences {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	// Check if already collapsed
	found := false
	filtered := []string{}
	for _, c := range pm.prefs.CollapsedCategories {
		if c == category {
			found = true
		} else {
			filtered = append(filtered, c)
		}
	}

	if found {
		// Was collapsed, now expanded
		pm.prefs.CollapsedCategories = filtered
	} else {
		// Was expanded, now collapsed
		pm.prefs.CollapsedCategories = append(pm.prefs.CollapsedCategories, category)
	}

	pm.save()

	return pm.prefs
}
