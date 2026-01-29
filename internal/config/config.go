package config

import (
	"os"
	"strconv"
	"strings"
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

	// Network
	APInterface   string
	WANInterface  string
	APIP          string
	HostapdConf   string
	DnsmasqConf   string
	DnsmasqLeases string

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
	"nginx-proxy":              true,
	"pihole":                   true,
	"postgres":                 true,
	"valkey":                   true,
	"cubeos-api":               true,
	"cubeos-dashboard":         true,
	"mulecube-hw-monitor":      true,
	"mulecube-status":          true,
	"mulecube-backup":          true,
	"mulecube-reset":           true,
	"mulecube-wifi-status":     true,
	"mulecube-watchdog":        true,
	"mulecube-usb-monitor":     true,
	"mulecube-diagnostics":     true,
	"mulecube-terminal":        true,
	"mulecube-terminal-ro":     true,
	"mulecube-gpio":            true,
	"mulecube-nettools":        true,
	"mulecube-logs":            true,
	"mulecube-service-manager": true,
	"mulecube-manager":         true,
	"mulecube-dockge":          true,
	"uptime-kuma":              true,
	"beszel":                   true,
	"beszel-agent":             true,
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

// Load creates config from environment variables
func Load() *Config {
	return &Config{
		// Server
		Host:    getEnv("API_HOST", "0.0.0.0"),
		Port:    getEnvInt("API_PORT", 9009),
		Version: getEnv("VERSION", "2.0.0"),

		// Database
		DatabasePath: getEnv("DATABASE_PATH", "/cubeos/data/cubeos.db"),

		// JWT
		JWTSecret:          getEnv("JWT_SECRET", "cubeos-secret-change-me-in-production"),
		JWTExpirationHours: getEnvInt("JWT_EXPIRATION_HOURS", 24),

		// Docker
		DockerSocket:         getEnv("DOCKER_SOCKET", "/var/run/docker.sock"),
		ContainerStopTimeout: getEnvInt("CONTAINER_STOP_TIMEOUT", 30),

		// Network
		APInterface:   getEnv("AP_INTERFACE", "wlan0"),
		WANInterface:  getEnv("WAN_INTERFACE", "eth0"),
		APIP:          getEnv("AP_IP", "192.168.42.1"),
		HostapdConf:   getEnv("HOSTAPD_CONF", "/etc/hostapd/hostapd.conf"),
		DnsmasqConf:   getEnv("DNSMASQ_CONF", "/etc/dnsmasq.d/090_mulecube.conf"),
		DnsmasqLeases: getEnv("DNSMASQ_LEASES", "/var/lib/misc/dnsmasq.leases"),

		// Paths
		DataDir:   getEnv("DATA_DIR", "/cubeos/data"),
		BackupDir: getEnv("BACKUP_DIR", "/cubeos/backups"),

		// Monitoring
		StatsInterval: getEnvInt("STATS_INTERVAL", 2),

		// UPS
		UPSI2CAddress:      getEnvHex("UPS_I2C_ADDRESS", 0x36),
		BatteryCapacityMAH: getEnvInt("BATTERY_CAPACITY_MAH", 3000),
		CriticalBatteryPct: getEnvInt("CRITICAL_BATTERY_PERCENT", 10),
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

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvHex(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseInt(strings.TrimPrefix(val, "0x"), 16, 32); err == nil {
			return int(i)
		}
	}
	return defaultVal
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
