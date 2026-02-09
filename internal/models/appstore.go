package models

import "time"

// AppStore represents a registered app store source
type AppStore struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	URL         string    `json:"url" db:"url"`
	Description string    `json:"description,omitempty" db:"description"`
	Author      string    `json:"author,omitempty" db:"author"`
	AppCount    int       `json:"app_count" db:"app_count"`
	LastSync    time.Time `json:"last_sync" db:"last_sync"`
	Enabled     bool      `json:"enabled" db:"enabled"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// AppCategory represents a category in the app store
type AppCategory struct {
	Name  string `json:"name" yaml:"name"`
	Font  string `json:"font,omitempty" yaml:"font"`
	Count int    `json:"count,omitempty"`
}

// StoreApp represents an app available in the store
type StoreApp struct {
	ID            string            `json:"id"`
	StoreID       string            `json:"store_id"`
	Name          string            `json:"name"`
	Title         map[string]string `json:"title"`
	Description   map[string]string `json:"description"`
	Icon          string            `json:"icon"`
	Screenshots   []string          `json:"screenshots,omitempty"`
	Category      string            `json:"category"`
	Author        string            `json:"author"`
	Architectures []string          `json:"architectures"`
	MainService   string            `json:"main_service"`
	PortMap       string            `json:"port_map,omitempty"`
	Index         string            `json:"index,omitempty"`
	Scheme        string            `json:"scheme,omitempty"`
	Version       string            `json:"version,omitempty"`
	Tagline       map[string]string `json:"tagline,omitempty"`
	Tips          map[string]string `json:"tips,omitempty"`
	Installed     bool              `json:"installed"`
	ManifestPath  string            `json:"-"`
}

// InstalledApp represents an installed app.
//
// Deprecated: This model and its backing `installed_apps` table are legacy from
// the pre-Swarm architecture. New code should use the unified `App` model in
// models/app.go and the `apps` table. The AppStore manager still uses this type
// and should be migrated in FS-05 (App Lifecycle fixes).
type InstalledApp struct {
	ID          string         `json:"id" db:"id"`
	StoreID     string         `json:"store_id,omitempty" db:"store_id"`
	StoreAppID  string         `json:"store_app_id,omitempty" db:"store_app_id"`
	Name        string         `json:"name" db:"name"`
	Title       string         `json:"title" db:"title"`
	Description string         `json:"description,omitempty" db:"description"`
	Icon        string         `json:"icon,omitempty" db:"icon"`
	Category    string         `json:"category,omitempty" db:"category"`
	Version     string         `json:"version,omitempty" db:"version"`
	Status      string         `json:"status" db:"status"`
	WebUI       string         `json:"webui,omitempty" db:"webui"`
	WebUIType   string         `json:"webui_type,omitempty" db:"webui_type"`
	ComposeFile string         `json:"-" db:"compose_file"`
	DataPath    string         `json:"data_path,omitempty" db:"data_path"`
	InstalledAt time.Time      `json:"installed_at" db:"installed_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
	Containers  []AppContainer `json:"containers,omitempty"`
	UpdateAvail bool           `json:"update_available,omitempty"`
}

// AppContainer represents a container within an installed app
type AppContainer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	Status  string `json:"status"`
	State   string `json:"state"`
	Created int64  `json:"created"`
}

// CasaOSManifest represents docker-compose.yml with x-casaos extensions
type CasaOSManifest struct {
	Name     string                    `yaml:"name"`
	Version  string                    `yaml:"version,omitempty"`
	Services map[string]ComposeService `yaml:"services"`
	Networks map[string]interface{}    `yaml:"networks,omitempty"`
	Volumes  map[string]interface{}    `yaml:"volumes,omitempty"`
	XCasaOS  XCasaOSApp                `yaml:"x-casaos"`
}

// ComposeService represents a service in docker-compose
type ComposeService struct {
	Image         string                 `yaml:"image"`
	ContainerName string                 `yaml:"container_name,omitempty"`
	Hostname      string                 `yaml:"hostname,omitempty"`
	Restart       string                 `yaml:"restart,omitempty"`
	Privileged    bool                   `yaml:"privileged,omitempty"`
	NetworkMode   string                 `yaml:"network_mode,omitempty"`
	Ports         []interface{}          `yaml:"ports,omitempty"`
	Volumes       []interface{}          `yaml:"volumes,omitempty"`
	Environment   interface{}            `yaml:"environment,omitempty"`
	Devices       []string               `yaml:"devices,omitempty"`
	CapAdd        []string               `yaml:"cap_add,omitempty"`
	Command       interface{}            `yaml:"command,omitempty"`
	Entrypoint    interface{}            `yaml:"entrypoint,omitempty"`
	Labels        map[string]string      `yaml:"labels,omitempty"`
	DependsOn     interface{}            `yaml:"depends_on,omitempty"`
	Healthcheck   map[string]interface{} `yaml:"healthcheck,omitempty"`
	Deploy        map[string]interface{} `yaml:"deploy,omitempty"`
	XCasaOS       XCasaOSService         `yaml:"x-casaos,omitempty"`
}

// XCasaOSApp represents app-level x-casaos metadata
type XCasaOSApp struct {
	Architectures []string          `yaml:"architectures"`
	Main          string            `yaml:"main"`
	Author        string            `yaml:"author,omitempty"`
	Category      string            `yaml:"category"`
	Description   map[string]string `yaml:"description"`
	Developer     string            `yaml:"developer,omitempty"`
	Icon          string            `yaml:"icon"`
	Index         string            `yaml:"index,omitempty"`
	PortMap       string            `yaml:"port_map,omitempty"`
	Scheme        string            `yaml:"scheme,omitempty"`
	StoreAppID    string            `yaml:"store_app_id,omitempty"`
	Tagline       map[string]string `yaml:"tagline,omitempty"`
	Thumbnail     string            `yaml:"thumbnail,omitempty"`
	Tips          map[string]string `yaml:"tips,omitempty"`
	Title         map[string]string `yaml:"title"`
	Screenshot    string            `yaml:"screenshot,omitempty"`
}

// XCasaOSService represents service-level x-casaos metadata
type XCasaOSService struct {
	Envs    []XCasaOSEnv    `yaml:"envs,omitempty"`
	Ports   []XCasaOSPort   `yaml:"ports,omitempty"`
	Volumes []XCasaOSVolume `yaml:"volumes,omitempty"`
}

// XCasaOSEnv describes an environment variable
type XCasaOSEnv struct {
	Container   string            `yaml:"container"`
	Description map[string]string `yaml:"description,omitempty"`
}

// XCasaOSPort describes a port mapping
type XCasaOSPort struct {
	Container   string            `yaml:"container"`
	Description map[string]string `yaml:"description,omitempty"`
	Protocol    string            `yaml:"protocol,omitempty"`
}

// XCasaOSVolume describes a volume mapping
type XCasaOSVolume struct {
	Container   string            `yaml:"container"`
	Description map[string]string `yaml:"description,omitempty"`
}

// AppInstallRequest represents a request to install an app
type AppInstallRequest struct {
	StoreID         string            `json:"store_id"`
	AppName         string            `json:"app_name"`
	Title           string            `json:"title,omitempty"`
	EnvOverrides    map[string]string `json:"env_overrides,omitempty"`
	PortOverrides   map[string]int    `json:"port_overrides,omitempty"`
	VolumeOverrides map[string]string `json:"volume_overrides,omitempty"`
}

// AppActionRequest represents an action request (start/stop/restart/remove)
type AppActionRequest struct {
	Action string `json:"action"` // start, stop, restart, remove
}

// DefaultAppStores contains the default app stores
var DefaultAppStores = []AppStore{
	{
		ID:          "casaos-official",
		Name:        "CasaOS Official",
		URL:         "https://github.com/IceWhaleTech/CasaOS-AppStore/archive/refs/heads/main.zip",
		Description: "Official CasaOS App Store",
		Author:      "IceWhaleTech",
		Enabled:     true,
	},
	{
		ID:          "big-bear",
		Name:        "Big Bear CasaOS",
		URL:         "https://github.com/bigbeartechworld/big-bear-casaos/archive/refs/heads/master.zip",
		Description: "Community app store with 200+ apps",
		Author:      "BigBearTechWorld",
		Enabled:     true,
	},
}

// InstalledAppToApp converts a legacy InstalledApp to the unified App model.
// This supports backward compatibility with CasaOS import flows.
//
// Deprecated: Use the unified App model directly for new code paths.
func InstalledAppToApp(ia *InstalledApp) *App {
	if ia == nil {
		return nil
	}

	storeID := &ia.StoreID
	if ia.StoreID == "" {
		storeID = nil
	}
	storeAppID := &ia.StoreAppID
	if ia.StoreAppID == "" {
		storeAppID = nil
	}

	return &App{
		Name:        ia.Name,
		DisplayName: ia.Title,
		Description: ia.Description,
		Type:        AppTypeUser,
		Category:    ia.Category,
		Source:      AppSourceCasaOS,
		StoreID:     storeID,
		StoreAppID:  storeAppID,
		ComposePath: ia.ComposeFile,
		DataPath:    ia.DataPath,
		Enabled:     true,
		DeployMode:  DeployModeStack,
		IconURL:     ia.Icon,
		Version:     ia.Version,
		Homepage:    ia.WebUI,
		CreatedAt:   ia.InstalledAt,
		UpdatedAt:   ia.UpdatedAt,
	}
}
