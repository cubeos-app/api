package models

import "time"

// App represents a registered application in CubeOS
type App struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	DisplayName string    `db:"display_name" json:"display_name"`
	Description string    `db:"description" json:"description"`
	Type        string    `db:"type" json:"type"`     // "system" or "user"
	Source      string    `db:"source" json:"source"` // "cubeos", "casaos", "custom"
	IconURL     string    `db:"icon_url" json:"icon_url,omitempty"`
	GithubRepo  string    `db:"github_repo" json:"github_repo,omitempty"`
	ComposePath string    `db:"compose_path" json:"compose_path,omitempty"`
	Enabled     bool      `db:"enabled" json:"enabled"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
	// Joined data
	Ports []PortAllocation `db:"-" json:"ports,omitempty"`
	FQDNs []FQDN           `db:"-" json:"fqdns,omitempty"`
}

// PortAllocation represents a port allocated to an app
type PortAllocation struct {
	ID          int64     `db:"id" json:"id"`
	AppID       int64     `db:"app_id" json:"app_id"`
	AppName     string    `db:"app_name" json:"app_name,omitempty"`
	Port        int       `db:"port" json:"port"`
	Protocol    string    `db:"protocol" json:"protocol"` // "tcp" or "udp"
	Description string    `db:"description" json:"description,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// FQDN represents a fully qualified domain name for an app
type FQDN struct {
	ID          int64     `db:"id" json:"id"`
	AppID       int64     `db:"app_id" json:"app_id"`
	AppName     string    `db:"app_name" json:"app_name,omitempty"`
	FQDN        string    `db:"fqdn" json:"fqdn"`
	Subdomain   string    `db:"subdomain" json:"subdomain"`
	BackendPort int       `db:"backend_port" json:"backend_port"`
	SSLEnabled  bool      `db:"ssl_enabled" json:"ssl_enabled"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// Profile represents an operational profile
type Profile struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description,omitempty"`
	IsActive    bool      `db:"is_active" json:"is_active"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
	// Joined data
	Apps []ProfileApp `db:"-" json:"apps,omitempty"`
}

// ProfileApp represents an app's state within a profile
type ProfileApp struct {
	ProfileID int64  `db:"profile_id" json:"profile_id"`
	AppID     int64  `db:"app_id" json:"app_id"`
	AppName   string `db:"app_name" json:"app_name,omitempty"`
	Enabled   bool   `db:"enabled" json:"enabled"`
}

// Request/Response types

type RegisterAppRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"` // "system" or "user"
	Source      string `json:"source,omitempty"`
	IconURL     string `json:"icon_url,omitempty"`
	GithubRepo  string `json:"github_repo,omitempty"`
	ComposePath string `json:"compose_path,omitempty"`
}

type AllocatePortRequest struct {
	AppName     string `json:"app_name"`
	Port        int    `json:"port,omitempty"`     // 0 = auto-allocate
	Protocol    string `json:"protocol,omitempty"` // default: tcp
	Description string `json:"description,omitempty"`
}

type RegisterFQDNRequest struct {
	AppName     string `json:"app_name"`
	Subdomain   string `json:"subdomain"`
	BackendPort int    `json:"backend_port"`
	SSLEnabled  bool   `json:"ssl_enabled,omitempty"`
}

type CreateProfileRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type SetProfileAppRequest struct {
	Enabled bool `json:"enabled"`
}

type CacheImageRequest struct {
	Image string `json:"image"`
}

type CasaOSImportRequest struct {
	JSON string `json:"json"`
}

// CasaOS app format
type CasaOSApp struct {
	Name        string            `json:"name"`
	Title       string            `json:"title,omitempty"`
	Tagline     string            `json:"tagline,omitempty"`
	Overview    string            `json:"overview,omitempty"`
	Developer   string            `json:"developer,omitempty"`
	Icon        string            `json:"icon,omitempty"`
	Category    string            `json:"category,omitempty"`
	Container   CasaOSContainer   `json:"container,omitempty"`
	WebUI       CasaOSWebUI       `json:"web_ui,omitempty"`
	Envs        []CasaOSEnv       `json:"envs,omitempty"`
	Ports       []CasaOSPort      `json:"ports,omitempty"`
	Volumes     []CasaOSVolume    `json:"volumes,omitempty"`
	Devices     []CasaOSDevice    `json:"devices,omitempty"`
	Sysctls     map[string]string `json:"sysctls,omitempty"`
	Constraints CasaOSConstraints `json:"constraints,omitempty"`
}

type CasaOSContainer struct {
	Image       string   `json:"image"`
	Privileged  bool     `json:"privileged,omitempty"`
	NetworkMode string   `json:"network_mode,omitempty"`
	CapAdd      []string `json:"cap_add,omitempty"`
	Command     string   `json:"command,omitempty"`
}

type CasaOSWebUI struct {
	Port int `json:"port,omitempty"`
}

type CasaOSEnv struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CasaOSPort struct {
	Container string `json:"container"`
	Host      string `json:"host"`
	Protocol  string `json:"protocol,omitempty"`
}

type CasaOSVolume struct {
	Container string `json:"container"`
	Host      string `json:"host"`
}

type CasaOSDevice struct {
	Container string `json:"container"`
	Host      string `json:"host"`
}

type CasaOSConstraints struct {
	MinMemory int `json:"min_memory,omitempty"` // MB
}

// Response types

type AppsResponse struct {
	Apps []App `json:"apps"`
}

type PortsResponse struct {
	Ports []PortAllocation `json:"ports"`
}

type AvailablePortResponse struct {
	Port int `json:"port"`
}

type FQDNsResponse struct {
	FQDNs []FQDN `json:"fqdns"`
}

type ProfilesResponse struct {
	Profiles []Profile `json:"profiles"`
}

type RegistryStatusResponse struct {
	Running    bool   `json:"running"`
	Uptime     string `json:"uptime,omitempty"`
	ImageCount int    `json:"image_count"`
	TagCount   int    `json:"tag_count"`
}

type RegistryImage struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type RegistryImagesResponse struct {
	Images []RegistryImage `json:"images"`
}

type CasaOSStoreResponse struct {
	Apps []CasaOSApp `json:"apps"`
}

type CasaOSPreviewResponse struct {
	App     CasaOSApp `json:"app"`
	Compose string    `json:"compose"`
}

type AppStatusResponse struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "running", "stopped", "partial", "unknown"
}
