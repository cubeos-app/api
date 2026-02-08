// Package models defines data structures for CubeOS.
package models

import (
	"time"
)

// AppType represents the classification of an application.
type AppType string

const (
	AppTypeSystem   AppType = "system"   // Infrastructure (pihole, npm, registry)
	AppTypePlatform AppType = "platform" // CubeOS services (api, dashboard, dozzle)
	AppTypeNetwork  AppType = "network"  // VPN, Tor
	AppTypeAI       AppType = "ai"       // Ollama, ChromaDB
	AppTypeUser     AppType = "user"     // User-installed apps
)

// AppSource represents where an app was installed from.
type AppSource string

const (
	AppSourceCubeOS AppSource = "cubeos" // Built-in CubeOS apps
	AppSourceCasaOS AppSource = "casaos" // Installed from CasaOS store
	AppSourceCustom AppSource = "custom" // Custom docker-compose
)

// DeployMode represents how an app is deployed.
type DeployMode string

const (
	DeployModeStack   DeployMode = "stack"   // Docker Swarm stack
	DeployModeCompose DeployMode = "compose" // docker-compose (for host network services)
)

// App represents a unified application in CubeOS.
// This replaces the old fragmented apps + installed_apps tables.
type App struct {
	ID          int64      `db:"id" json:"id"`
	Name        string     `db:"name" json:"name"`                 // Stack name (lowercase, no spaces)
	DisplayName string     `db:"display_name" json:"display_name"` // Human-readable name
	Description string     `db:"description" json:"description"`
	Type        AppType    `db:"type" json:"type"`
	Category    string     `db:"category" json:"category"`
	Source      AppSource  `db:"source" json:"source"`
	StoreID     *string    `db:"store_id" json:"store_id,omitempty"`
	StoreAppID  *string    `db:"store_app_id" json:"store_app_id,omitempty"`
	ComposePath string     `db:"compose_path" json:"compose_path"`
	DataPath    string     `db:"data_path" json:"data_path"`
	Enabled     bool       `db:"enabled" json:"enabled"`
	TorEnabled  bool       `db:"tor_enabled" json:"tor_enabled"`
	VPNEnabled  bool       `db:"vpn_enabled" json:"vpn_enabled"`
	DeployMode  DeployMode `db:"deploy_mode" json:"deploy_mode"`
	IconURL     string     `db:"icon_url" json:"icon_url"`
	Version     string     `db:"version" json:"version"`
	Homepage    string     `db:"homepage" json:"homepage"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at" json:"updated_at"`

	// Related data (loaded separately, not from main table)
	Ports []Port `db:"-" json:"ports,omitempty"`
	FQDNs []FQDN `db:"-" json:"fqdns,omitempty"`

	// Runtime status from Swarm (not persisted)
	Status *AppStatus `db:"-" json:"status,omitempty"`
}

// AppStatus represents the runtime status of an app from Docker/Swarm.
// This is NOT stored in the database - it's queried live from Swarm.
type AppStatus struct {
	Running     bool   `json:"running"`
	Health      string `json:"health"` // healthy, unhealthy, starting, stopped, unknown
	Replicas    string `json:"replicas"`
	LastStarted string `json:"last_started,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Port represents a port allocated to an app.
type Port struct {
	ID          int64     `db:"id" json:"id"`
	AppID       int64     `db:"app_id" json:"app_id"`
	Port        int       `db:"port" json:"port"`
	Protocol    string    `db:"protocol" json:"protocol"`
	Description string    `db:"description" json:"description"`
	IsPrimary   bool      `db:"is_primary" json:"is_primary"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// FQDN represents a DNS entry and reverse proxy mapping for an app.
type FQDN struct {
	ID          int64     `db:"id" json:"id"`
	AppID       int64     `db:"app_id" json:"app_id"`
	FQDN        string    `db:"fqdn" json:"fqdn"`
	Subdomain   string    `db:"subdomain" json:"subdomain"`
	BackendPort int       `db:"backend_port" json:"backend_port"`
	SSLEnabled  bool      `db:"ssl_enabled" json:"ssl_enabled"`
	NPMProxyID  *int      `db:"npm_proxy_id" json:"npm_proxy_id,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// AppHealth represents health check configuration for an app.
type AppHealth struct {
	ID            int64  `db:"id" json:"id"`
	AppID         int64  `db:"app_id" json:"app_id"`
	CheckEndpoint string `db:"check_endpoint" json:"check_endpoint"`
	CheckInterval int    `db:"check_interval" json:"check_interval"` // seconds
	CheckTimeout  int    `db:"check_timeout" json:"check_timeout"`   // seconds
	MaxRetries    int    `db:"max_retries" json:"max_retries"`
	AlertAfter    int    `db:"alert_after" json:"alert_after"` // seconds
}

// === Request Types ===

// InstallAppRequest is the request to install a new app.
type InstallAppRequest struct {
	Name        string     `json:"name"`
	DisplayName string     `json:"display_name"`
	Description string     `json:"description,omitempty"`
	Type        AppType    `json:"type,omitempty"`
	Category    string     `json:"category,omitempty"`
	Source      AppSource  `json:"source,omitempty"`
	StoreID     string     `json:"store_id,omitempty"`
	ComposePath string     `json:"compose_path,omitempty"` // If empty, will be generated
	DeployMode  DeployMode `json:"deploy_mode,omitempty"`  // stack or compose
	IconURL     string     `json:"icon_url,omitempty"`
	Homepage    string     `json:"homepage,omitempty"`

	// For CasaOS imports
	CasaOSJSON string `json:"casaos_json,omitempty"`
}

// UpdateAppRequest is the request to update an app.
type UpdateAppRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	TorEnabled  *bool   `json:"tor_enabled,omitempty"`
	VPNEnabled  *bool   `json:"vpn_enabled,omitempty"`
	IconURL     *string `json:"icon_url,omitempty"`
}

// AllocatePortRequest is the request to allocate a port.
type AllocatePortRequest struct {
	Port        int    `json:"port,omitempty"` // 0 = auto-allocate
	Protocol    string `json:"protocol,omitempty"`
	Description string `json:"description,omitempty"`
	IsPrimary   bool   `json:"is_primary,omitempty"`
}

// RegisterFQDNRequest is the request to register an FQDN.
type RegisterFQDNRequest struct {
	Subdomain   string `json:"subdomain"`
	BackendPort int    `json:"backend_port"`
	SSLEnabled  bool   `json:"ssl_enabled,omitempty"`
}

// === Response Types ===

// AppsResponse is the response containing a list of apps.
type AppsResponse struct {
	Apps  []App `json:"apps"`
	Total int   `json:"total"`
}

// AppResponse is the response containing a single app.
type AppResponse struct {
	App App `json:"app"`
}

// PortsResponse is the response containing a list of ports.
type PortsResponse struct {
	Ports []Port `json:"ports"`
}

// FQDNsResponse is the response containing a list of FQDNs.
type FQDNsResponse struct {
	FQDNs []FQDN `json:"fqdns"`
}

// PortAllocation represents a port allocation record for the port manager.
// This is used by the PortManager for tracking all allocated ports.
type PortAllocation struct {
	ID          int64     `db:"id" json:"id"`
	AppID       int64     `db:"app_id" json:"app_id"`
	AppName     string    `db:"app_name" json:"app_name,omitempty"`
	Port        int       `db:"port" json:"port"`
	Protocol    string    `db:"protocol" json:"protocol"`
	Description string    `db:"description" json:"description,omitempty"`
	IsPrimary   bool      `db:"is_primary" json:"is_primary"`
	InUse       bool      `db:"-" json:"in_use"` // From runtime check
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// AppFilter is used to filter apps in ListApps queries.
type AppFilter struct {
	Type    AppType `json:"type,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
	Source  string  `json:"source,omitempty"`
}

// === Helper Methods ===

// IsSystem returns true if this is a system app.
func (a *App) IsSystem() bool {
	return a.Type == AppTypeSystem
}

// IsPlatform returns true if this is a platform app.
func (a *App) IsPlatform() bool {
	return a.Type == AppTypePlatform
}

// IsUserApp returns true if this is a user-installed app.
func (a *App) IsUserApp() bool {
	return a.Type == AppTypeUser
}

// IsProtected returns true if this app should not be deleted.
func (a *App) IsProtected() bool {
	return a.Type == AppTypeSystem || a.Type == AppTypePlatform
}

// GetPrimaryPort returns the primary port for this app, or 0 if none.
func (a *App) GetPrimaryPort() int {
	for _, p := range a.Ports {
		if p.IsPrimary {
			return p.Port
		}
	}
	// Return first port if no primary is set
	if len(a.Ports) > 0 {
		return a.Ports[0].Port
	}
	return 0
}

// GetPrimaryFQDN returns the primary FQDN for this app, or empty if none.
func (a *App) GetPrimaryFQDN() string {
	if len(a.FQDNs) > 0 {
		return a.FQDNs[0].FQDN
	}
	return ""
}

// UsesSwarm returns true if this app is deployed as a Swarm stack.
func (a *App) UsesSwarm() bool {
	return a.DeployMode == DeployModeStack
}

// UsesCompose returns true if this app is deployed via docker-compose.
func (a *App) UsesCompose() bool {
	return a.DeployMode == DeployModeCompose
}
