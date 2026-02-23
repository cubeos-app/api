package models

// ReleaseManifest describes a CubeOS release available for update.
// @Description CubeOS release manifest with image tags and metadata.
type ReleaseManifest struct {
	Version       string            `json:"version"`        // e.g. "0.2.0-alpha.02"
	ReleaseDate   string            `json:"release_date"`   // ISO 8601
	Channel       string            `json:"channel"`        // "stable", "alpha", "beta"
	MinVersion    string            `json:"min_version"`    // Minimum current version required
	ReleaseNotes  string            `json:"release_notes"`  // Markdown
	Breaking      []string          `json:"breaking"`       // List of breaking changes
	Images        map[string]string `json:"images"`         // service_name -> "image:tag"
	Checksums     map[string]string `json:"checksums"`      // service_name -> sha256
	SchemaVersion int               `json:"schema_version"` // Required DB schema version
}

// UpdateCheckResponse is returned by GET /api/v1/system/updates.
// @Description Response for system update availability check.
type UpdateCheckResponse struct {
	CurrentVersion  string           `json:"current_version"`
	LatestVersion   string           `json:"latest_version"`
	UpdateAvailable bool             `json:"update_available"`
	Release         *ReleaseManifest `json:"release,omitempty"`
	LastChecked     string           `json:"last_checked"`
	Channel         string           `json:"channel"`
}

// UpdateApplyRequest is the body for POST /api/v1/system/updates/apply.
// @Description Request to apply a specific system update version.
type UpdateApplyRequest struct {
	Version string `json:"version"`         // Target version to apply
	Force   bool   `json:"force,omitempty"` // Skip breaking change confirmation
}

// UpdateHistoryEntry represents a past update attempt.
// @Description Historical record of a system update attempt.
type UpdateHistoryEntry struct {
	ID           int    `json:"id"`
	FromVersion  string `json:"from_version"`
	ToVersion    string `json:"to_version"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at"`
	CompletedAt  string `json:"completed_at,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}
