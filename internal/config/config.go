package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all application settings
type Config struct {
	// Server
	Host    string
	Port    int
	Version string

	// Database
	DatabasePath string

	// JWT
	JWTSecret          string
	JWTExpirationHours int

	// Docker
	DockerSocket         string
	ContainerStopTimeout int

	// Network - CubeOS specific
	GatewayIP string // 10.42.24.1
	Domain    string // cubeos.cube
	Subnet    string // 10.42.24.0/24

	// Network - Interfaces
	APInterface   string
	WANInterface  string
	APIP          string
	HostapdConf   string
	DnsmasqConf   string
	DnsmasqLeases string

	// Service Ports (from env)
	APIPort       int
	DashboardPort int
	NPMPort       int
	PiholePort    int
	OllamaPort    int
	ChromaDBPort  int

	// Paths
	DataDir   string
	BackupDir string

	// Monitoring
	StatsInterval int

	// UPS/Battery
	UPSI2CAddress      int
	BatteryCapacityMAH int
	CriticalBatteryPct int
}

// CoreServices that cannot be toggled
var CoreServices = map[string]bool{
	"nginx-proxy":        true,
	"pihole":             true,
	"cubeos-api":         true,
	"cubeos-dashboard":   true,
	"cubeos-pihole":      true,
	"cubeos-npm":         true,
	"cubeos-watchdog":    true,
	"cubeos-logs":        true,
	"cubeos-dozzle":      true,
	"cubeos-terminal":    true,
	"cubeos-diagnostics": true,
	"cubeos-docs-indexer": true,
	"uptime-kuma":        true,
	"beszel":             true,
	"beszel-agent":       true,
}

// CoreServicePatterns - containers matching these are also core
var CoreServicePatterns = []string{
	"watchtower",
	"postgres-",
	"meilisearch-",
}

// Categories for services
var Categories = map[string]CategoryInfo{
	"ai": {
		Name:        "AI Services",
		Description: "Local AI and machine learning",
		Icon:        "brain",
	},
	"knowledge": {
		Name:        "Knowledge",
		Description: "Offline encyclopedias, maps, and references",
		Icon:        "book-open",
	},
	"productivity": {
		Name:        "Productivity",
		Description: "Document editing and collaboration tools",
		Icon:        "edit",
	},
	"files": {
		Name:        "Files & Sync",
		Description: "File management and synchronization",
		Icon:        "folder",
	},
	"communication": {
		Name:        "Communication",
		Description: "Chat, messaging, and radio",
		Icon:        "message-circle",
	},
	"tools": {
		Name:        "Tools",
		Description: "Utilities and specialized tools",
		Icon:        "wrench",
	},
	"infrastructure": {
		Name:        "Infrastructure",
		Description: "System monitoring and management",
		Icon:        "server",
	},
	"admin": {
		Name:        "Admin",
		Description: "Administration tools",
		Icon:        "settings",
	},
}

type CategoryInfo struct {
	Name        string
	Description string
	Icon        string
}

// SystemServices for status checking
var SystemServices = map[string]string{
	"hostapd":    "WiFi Access Point",
	"dnsmasq":    "DNS/DHCP Server",
	"docker":     "Docker Engine",
	"nginx":      "Web Server",
	"pihole-FTL": "Pi-hole DNS",
}

// Load creates config from environment variables with fail-fast behavior
// CRITICAL: This function will log.Fatal if required config is missing
func Load() *Config {
	// Try to load defaults.env - fail-fast if missing
	envPath := "/cubeos/config/defaults.env"
	if err := godotenv.Load(envPath); err != nil {
		// Check if file exists but has other issues
		if _, statErr := os.Stat(envPath); os.IsNotExist(statErr) {
			log.Fatalf("FATAL: Configuration file not found: %s\nCubeOS cannot start without configuration.", envPath)
		}
		log.Fatalf("FATAL: Failed to load configuration from %s: %v", envPath, err)
	}

	// Also try to load secrets.env (optional, but log if missing)
	secretsPath := "/cubeos/config/secrets.env"
	if err := godotenv.Load(secretsPath); err != nil {
		log.Printf("Warning: Could not load secrets from %s: %v", secretsPath, err)
	}

	return &Config{
		// Server - REQUIRED
		Host:    getEnvOptional("API_HOST", "0.0.0.0"),
		Port:    mustGetEnvInt("API_PORT"),
		Version: getEnvOptional("VERSION", "2.0.0"),

		// Database - REQUIRED
		DatabasePath: mustGetEnv("DATABASE_PATH"),

		// JWT - Secret is required in production
		JWTSecret:          getEnvOptional("JWT_SECRET", "cubeos-dev-secret-change-in-production"),
		JWTExpirationHours: getEnvIntOptional("JWT_EXPIRATION_HOURS", 24),

		// Docker
		DockerSocket:         getEnvOptional("DOCKER_SOCKET", "/var/run/docker.sock"),
		ContainerStopTimeout: getEnvIntOptional("CONTAINER_STOP_TIMEOUT", 30),

		// Network - REQUIRED (these are critical for CubeOS operation)
		GatewayIP: mustGetEnv("GATEWAY_IP"),
		Domain:    mustGetEnv("DOMAIN"),
		Subnet:    getEnvOptional("SUBNET", "10.42.24.0/24"),

		// Network - Interfaces
		APInterface:   getEnvOptional("AP_INTERFACE", "wlan0"),
		WANInterface:  getEnvOptional("WAN_INTERFACE", "eth0"),
		APIP:          mustGetEnv("GATEWAY_IP"), // Same as GatewayIP
		HostapdConf:   getEnvOptional("HOSTAPD_CONF", "/etc/hostapd/hostapd.conf"),
		DnsmasqConf:   getEnvOptional("DNSMASQ_CONF", "/etc/dnsmasq.d/090_cubeos.conf"),
		DnsmasqLeases: getEnvOptional("DNSMASQ_LEASES", "/var/lib/misc/dnsmasq.leases"),

		// Service Ports - REQUIRED
		APIPort:       mustGetEnvInt("API_PORT"),
		DashboardPort: mustGetEnvInt("DASHBOARD_PORT"),
		NPMPort:       mustGetEnvInt("NPM_PORT"),
		PiholePort:    mustGetEnvInt("PIHOLE_PORT"),
		OllamaPort:    mustGetEnvInt("OLLAMA_PORT"),
		ChromaDBPort:  mustGetEnvInt("CHROMADB_PORT"),

		// Paths - use env vars with fallbacks
		DataDir:   getEnvOptional("CUBEOS_DATA_DIR", "/cubeos/data"),
		BackupDir: getEnvOptional("BACKUP_DIR", "/cubeos/backups"),

		// Monitoring
		StatsInterval: getEnvIntOptional("STATS_INTERVAL", 2),

		// UPS
		UPSI2CAddress:      getEnvHexOptional("UPS_I2C_ADDRESS", 0x36),
		BatteryCapacityMAH: getEnvIntOptional("BATTERY_CAPACITY_MAH", 3000),
		CriticalBatteryPct: getEnvIntOptional("CRITICAL_BATTERY_PERCENT", 10),
	}
}

// IsCoreService checks if a container is a core service
func IsCoreService(name string) bool {
	if CoreServices[name] {
		return true
	}
	for _, pattern := range CoreServicePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// mustGetEnv returns the environment variable value or fatals if not set
// Used for REQUIRED configuration that has no safe default
func mustGetEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("FATAL: Required environment variable %s is not set.\nCheck /cubeos/config/defaults.env", key)
	}
	return val
}

// mustGetEnvInt returns the environment variable as int or fatals if not set/invalid
func mustGetEnvInt(key string) int {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("FATAL: Required environment variable %s is not set.\nCheck /cubeos/config/defaults.env", key)
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		log.Fatalf("FATAL: Environment variable %s must be an integer, got: %s", key, val)
	}
	return i
}

// getEnvOptional returns the environment variable value or a default
// Used for OPTIONAL configuration with safe defaults
func getEnvOptional(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getEnvIntOptional returns the environment variable as int or a default
func getEnvIntOptional(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

// getEnvHexOptional returns the environment variable as hex int or a default
func getEnvHexOptional(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseInt(strings.TrimPrefix(val, "0x"), 16, 32); err == nil {
			return int(i)
		}
	}
	return defaultVal
}

// GetNPMURL returns the NPM API URL constructed from config
func (c *Config) GetNPMURL() string {
	return fmt.Sprintf("http://%s:%d", c.GatewayIP, c.NPMPort)
}

// GetOllamaURL returns the Ollama API URL constructed from config
func (c *Config) GetOllamaURL() string {
	return fmt.Sprintf("http://%s:%d", c.GatewayIP, c.OllamaPort)
}

// GetChromaDBURL returns the ChromaDB API URL constructed from config
func (c *Config) GetChromaDBURL() string {
	return fmt.Sprintf("http://%s:%d", c.GatewayIP, c.ChromaDBPort)
}

// ServiceDefinition holds static service metadata
type ServiceDefinition struct {
	Description  string
	Category     string
	RAMEstimate  int
	Icon         string
	URL          string
	Ports        []int
	Dependencies []string
}

// ServiceDefinitions holds metadata for known services
var ServiceDefinitions = map[string]ServiceDefinition{
	"kiwix": {
		Description: "Offline Wikipedia and other content",
		Category:    "knowledge",
		RAMEstimate: 512,
		Icon:        "book-open",
		Ports:       []int{8080},
	},
	"tileserver": {
		Description: "Offline map tiles server",
		Category:    "knowledge",
		RAMEstimate: 256,
		Icon:        "map",
		Ports:       []int{8080},
	},
	"calibre-web": {
		Description: "E-book library management",
		Category:    "knowledge",
		RAMEstimate: 256,
		Icon:        "book",
		Ports:       []int{8083},
	},
	"ollama": {
		Description: "Local LLM inference server",
		Category:    "ai",
		RAMEstimate: 2048,
		Icon:        "brain",
		Ports:       []int{11434},
	},
	"open-webui": {
		Description:  "ChatGPT-like UI for local LLMs",
		Category:     "ai",
		RAMEstimate:  512,
		Icon:         "message-square",
		Ports:        []int{8080},
		Dependencies: []string{"ollama"},
	},
	"libretranslate": {
		Description: "Offline translation service",
		Category:    "ai",
		RAMEstimate: 1024,
		Icon:        "globe",
		Ports:       []int{5000},
	},
	"cryptpad": {
		Description: "Collaborative document editing",
		Category:    "productivity",
		RAMEstimate: 512,
		Icon:        "file-text",
		Ports:       []int{3000},
	},
	"excalidraw": {
		Description: "Collaborative whiteboard",
		Category:    "productivity",
		RAMEstimate: 256,
		Icon:        "edit-3",
		Ports:       []int{80},
	},
	"filebrowser": {
		Description: "Web-based file manager",
		Category:    "files",
		RAMEstimate: 128,
		Icon:        "folder",
		Ports:       []int{80},
	},
	"syncthing": {
		Description: "P2P file synchronization",
		Category:    "files",
		RAMEstimate: 256,
		Icon:        "refresh-cw",
		Ports:       []int{8384, 22000},
	},
	"element": {
		Description:  "Matrix chat client",
		Category:     "communication",
		RAMEstimate:  256,
		Icon:         "message-circle",
		Ports:        []int{80},
		Dependencies: []string{"conduit"},
	},
	"conduit": {
		Description: "Lightweight Matrix homeserver",
		Category:    "communication",
		RAMEstimate: 256,
		Icon:        "server",
		Ports:       []int{6167},
	},
	"jellyfin": {
		Description: "Media streaming server",
		Category:    "tools",
		RAMEstimate: 1024,
		Icon:        "play-circle",
		Ports:       []int{8096},
	},
	"vaultwarden": {
		Description: "Password manager server",
		Category:    "tools",
		RAMEstimate: 128,
		Icon:        "lock",
		Ports:       []int{80},
	},
	"it-tools": {
		Description: "IT utilities collection",
		Category:    "tools",
		RAMEstimate: 128,
		Icon:        "wrench",
		Ports:       []int{80},
	},
	"meshtastic-web": {
		Description: "Meshtastic mesh network interface",
		Category:    "communication",
		RAMEstimate: 128,
		Icon:        "radio",
		Ports:       []int{80},
	},
	"signalk-server": {
		Description: "Marine data server",
		Category:    "tools",
		RAMEstimate: 256,
		Icon:        "anchor",
		Ports:       []int{3000},
	},
	"emergency-ref": {
		Description: "Emergency reference materials",
		Category:    "knowledge",
		RAMEstimate: 128,
		Icon:        "alert-triangle",
		Ports:       []int{80},
	},
}

// InferCategory tries to guess a service category from its name
func InferCategory(name string) string {
	name = strings.ToLower(name)

	// AI keywords
	if strings.Contains(name, "ollama") || strings.Contains(name, "llm") ||
		strings.Contains(name, "whisper") || strings.Contains(name, "translate") {
		return "ai"
	}

	// Knowledge keywords
	if strings.Contains(name, "wiki") || strings.Contains(name, "kiwix") ||
		strings.Contains(name, "calibre") || strings.Contains(name, "map") {
		return "knowledge"
	}

	// Communication keywords
	if strings.Contains(name, "chat") || strings.Contains(name, "matrix") ||
		strings.Contains(name, "element") || strings.Contains(name, "mesh") {
		return "communication"
	}

	// Files keywords
	if strings.Contains(name, "file") || strings.Contains(name, "sync") ||
		strings.Contains(name, "backup") || strings.Contains(name, "storage") {
		return "files"
	}

	// Productivity keywords
	if strings.Contains(name, "pad") || strings.Contains(name, "doc") ||
		strings.Contains(name, "note") || strings.Contains(name, "draw") {
		return "productivity"
	}

	// Infrastructure keywords
	if strings.Contains(name, "postgres") || strings.Contains(name, "nginx") ||
		strings.Contains(name, "proxy") || strings.Contains(name, "monitor") {
		return "infrastructure"
	}

	// Admin keywords
	if strings.Contains(name, "admin") || strings.Contains(name, "manager") ||
		strings.Contains(name, "dashboard") || strings.Contains(name, "portal") {
		return "admin"
	}

	return "tools"
}
