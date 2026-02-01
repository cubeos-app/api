// Package models defines data structures for CubeOS.
package models

import (
	"time"
)

// Profile represents an operational profile that defines which apps are enabled.
// System profiles (Full, Minimal, Offline) cannot be deleted.
type Profile struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	DisplayName string    `db:"display_name" json:"display_name"`
	Description string    `db:"description" json:"description"`
	IsActive    bool      `db:"is_active" json:"is_active"`
	IsSystem    bool      `db:"is_system" json:"is_system"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`

	// Related data
	Apps []ProfileApp `db:"-" json:"apps,omitempty"`
}

// ProfileApp represents an app's state within a profile.
type ProfileApp struct {
	ProfileID int64  `db:"profile_id" json:"profile_id"`
	AppID     int64  `db:"app_id" json:"app_id"`
	AppName   string `db:"app_name" json:"app_name,omitempty"` // Joined from apps table
	Enabled   bool   `db:"enabled" json:"enabled"`
}

// === Request Types ===

// CreateProfileRequest is the request to create a new profile.
type CreateProfileRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
}

// UpdateProfileRequest is the request to update a profile.
type UpdateProfileRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// SetProfileAppRequest is the request to enable/disable an app in a profile.
type SetProfileAppRequest struct {
	Enabled bool `json:"enabled"`
}

// ApplyProfileRequest is the request to apply a profile (make it active).
type ApplyProfileRequest struct {
	ProfileID          string   `json:"profile_id"`
	AdditionalServices []string `json:"additional_services,omitempty"`
	ExcludedServices   []string `json:"excluded_services,omitempty"`
}

// === Response Types ===

// ProfilesResponse is the response containing a list of profiles.
type ProfilesResponse struct {
	Profiles      []Profile `json:"profiles"`
	ActiveProfile string    `json:"active_profile"`
}

// ProfileResponse is the response containing a single profile.
type ProfileResponse struct {
	Profile Profile `json:"profile"`
}

// ApplyProfileResponse is the response after applying a profile.
type ApplyProfileResponse struct {
	Profile string   `json:"profile"`
	Started []string `json:"started"`
	Stopped []string `json:"stopped"`
	// Backward compatibility fields (used by wizard.go)
	Success          bool     `json:"success,omitempty"`
	Message          string   `json:"message,omitempty"`
	EnabledServices  []string `json:"enabled_services,omitempty"`
	DisabledServices []string `json:"disabled_services,omitempty"`
	TotalRAM         int      `json:"total_ram_mb,omitempty"`
}

// === Profile Constants ===

// DefaultProfiles defines the system profiles.
var DefaultProfiles = []Profile{
	{
		Name:        "full",
		DisplayName: "Full",
		Description: "All services enabled including AI/ML",
		IsSystem:    true,
	},
	{
		Name:        "minimal",
		DisplayName: "Minimal",
		Description: "Only essential infrastructure services",
		IsSystem:    true,
	},
	{
		Name:        "offline",
		DisplayName: "Offline",
		Description: "Optimized for air-gapped operation",
		IsSystem:    true,
	},
}

// ProfileFullApps lists apps enabled in the Full profile.
var ProfileFullApps = []string{
	"pihole",
	"npm",
	"registry",
	"cubeos-api",
	"cubeos-dashboard",
	"dozzle",
	"ollama",
	"chromadb",
}

// ProfileMinimalApps lists apps enabled in the Minimal profile.
var ProfileMinimalApps = []string{
	"pihole",
	"npm",
	"registry",
	"cubeos-api",
	"cubeos-dashboard",
}

// ProfileOfflineApps lists apps enabled in the Offline profile.
var ProfileOfflineApps = []string{
	"pihole",
	"npm",
	"registry",
	"cubeos-api",
	"cubeos-dashboard",
	"dozzle",
}

// === Helper Methods ===

// CanDelete returns true if this profile can be deleted.
func (p *Profile) CanDelete() bool {
	return !p.IsSystem
}

// GetEnabledApps returns the list of enabled app names.
func (p *Profile) GetEnabledApps() []string {
	var names []string
	for _, app := range p.Apps {
		if app.Enabled {
			names = append(names, app.AppName)
		}
	}
	return names
}

// GetDisabledApps returns the list of disabled app names.
func (p *Profile) GetDisabledApps() []string {
	var names []string
	for _, app := range p.Apps {
		if !app.Enabled {
			names = append(names, app.AppName)
		}
	}
	return names
}

// IsAppEnabled returns true if the app is enabled in this profile.
func (p *Profile) IsAppEnabled(appName string) bool {
	for _, app := range p.Apps {
		if app.AppName == appName {
			return app.Enabled
		}
	}
	return false
}
