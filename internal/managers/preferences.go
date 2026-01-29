package managers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"cubeos-api/internal/models"
)

// PreferencesManager handles user preferences
type PreferencesManager struct {
	filePath string
	prefs    models.Preferences
	lock     sync.RWMutex
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
	}
}

// NewPreferencesManager creates a new PreferencesManager
func NewPreferencesManager() *PreferencesManager {
	pm := &PreferencesManager{
		filePath: "/cubeos/data/user-preferences.json",
		prefs:    DefaultPreferences(),
	}

	// Ensure directory exists
	os.MkdirAll(filepath.Dir(pm.filePath), 0755)

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

	pm.prefs.SetupComplete = loaded.SetupComplete
	pm.prefs.TourComplete = loaded.TourComplete
	pm.prefs.AdminExpanded = loaded.AdminExpanded

	if loaded.Favorites != nil {
		pm.prefs.Favorites = loaded.Favorites
	}
	if loaded.RecentServices != nil {
		pm.prefs.RecentServices = loaded.RecentServices
	}
	if loaded.CollapsedCategories != nil {
		pm.prefs.CollapsedCategories = loaded.CollapsedCategories
	}
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

	// Save to file
	if err := pm.save(); err != nil {
		return pm.prefs, err
	}

	return pm.prefs, nil
}

// Reset resets preferences to defaults
func (pm *PreferencesManager) Reset() models.Preferences {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	pm.prefs = DefaultPreferences()
	pm.save()

	return pm.prefs
}

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
