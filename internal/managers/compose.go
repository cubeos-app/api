package managers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ComposeManager handles docker-compose file operations
type ComposeManager struct {
	coreAppsDir string
	userAppsDir string
}

// AppConfig represents an app's configuration files
type AppConfig struct {
	AppName       string `json:"app_name"`
	ComposeFile   string `json:"compose_file"`
	EnvFile       string `json:"env_file"`
	ComposePath   string `json:"compose_path"`
	EnvPath       string `json:"env_path"`
	HasEnv        bool   `json:"has_env"`
	ContainerName string `json:"container_name,omitempty"`
}

// PortMapping represents a port mapping from docker-compose
type PortMapping struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// NewComposeManager creates a new compose manager
func NewComposeManager(basePath string) *ComposeManager {
	return &ComposeManager{
		coreAppsDir: filepath.Join(basePath, "coreapps"),
		userAppsDir: filepath.Join(basePath, "apps"),
	}
}

// GetAppDir returns the base directory for an app
func (m *ComposeManager) GetAppDir(appName string) string {
	// Check coreapps first
	coreDir := filepath.Join(m.coreAppsDir, appName)
	if _, err := os.Stat(coreDir); err == nil {
		return coreDir
	}

	// Check user apps
	userDir := filepath.Join(m.userAppsDir, appName)
	if _, err := os.Stat(userDir); err == nil {
		return userDir
	}

	// Default to coreapps for new apps
	return coreDir
}

// GetComposePath returns the docker-compose.yml path for an app
func (m *ComposeManager) GetComposePath(appName string) string {
	appDir := m.GetAppDir(appName)
	return filepath.Join(appDir, "appconfig", "docker-compose.yml")
}

// GetEnvPath returns the .env path for an app
func (m *ComposeManager) GetEnvPath(appName string) string {
	appDir := m.GetAppDir(appName)
	return filepath.Join(appDir, "appconfig", ".env")
}

// GetConfig reads both compose and env files for an app
func (m *ComposeManager) GetConfig(appName string) (*AppConfig, error) {
	composePath := m.GetComposePath(appName)
	envPath := m.GetEnvPath(appName)

	config := &AppConfig{
		AppName:     appName,
		ComposePath: composePath,
		EnvPath:     envPath,
	}

	// Read compose file
	composeData, err := os.ReadFile(composePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file: %w", err)
	}
	config.ComposeFile = string(composeData)

	// Read env file (optional)
	envData, err := os.ReadFile(envPath)
	if err == nil {
		config.EnvFile = string(envData)
		config.HasEnv = true
	}

	// Try to extract container name
	config.ContainerName = m.ExtractContainerName(config.ComposeFile)

	return config, nil
}

// SaveConfig saves compose and optionally env files, with optional container recreate
func (m *ComposeManager) SaveConfig(appName, composeContent, envContent string, recreate bool) error {
	composePath := m.GetComposePath(appName)
	envPath := m.GetEnvPath(appName)

	// Ensure directory exists
	configDir := filepath.Dir(composePath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write compose file
	if composeContent != "" {
		if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
			return fmt.Errorf("failed to write compose file: %w", err)
		}
	}

	// Write env file (only if content provided)
	if envContent != "" {
		if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
			return fmt.Errorf("failed to write env file: %w", err)
		}
	}

	// Recreate container if requested
	if recreate {
		return m.RecreateContainer(appName)
	}

	return nil
}

// RecreateContainer runs docker compose up -d --force-recreate
func (m *ComposeManager) RecreateContainer(appName string) error {
	composePath := m.GetComposePath(appName)
	configDir := filepath.Dir(composePath)

	cmd := exec.Command("docker", "compose", "-f", composePath, "up", "-d", "--force-recreate")
	cmd.Dir = configDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to recreate container: %s - %w", string(output), err)
	}

	return nil
}

// StartContainer starts the container(s) for an app
func (m *ComposeManager) StartContainer(appName string) error {
	composePath := m.GetComposePath(appName)
	configDir := filepath.Dir(composePath)

	cmd := exec.Command("docker", "compose", "-f", composePath, "start")
	cmd.Dir = configDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start container: %s - %w", string(output), err)
	}

	return nil
}

// StopContainer stops the container(s) for an app
func (m *ComposeManager) StopContainer(appName string) error {
	composePath := m.GetComposePath(appName)
	configDir := filepath.Dir(composePath)

	cmd := exec.Command("docker", "compose", "-f", composePath, "stop")
	cmd.Dir = configDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop container: %s - %w", string(output), err)
	}

	return nil
}

// RestartContainer restarts the container(s) for an app
func (m *ComposeManager) RestartContainer(appName string) error {
	composePath := m.GetComposePath(appName)
	configDir := filepath.Dir(composePath)

	cmd := exec.Command("docker", "compose", "-f", composePath, "restart")
	cmd.Dir = configDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart container: %s - %w", string(output), err)
	}

	return nil
}

// GetContainerStatus returns the status of containers for an app
func (m *ComposeManager) GetContainerStatus(appName string) (map[string]interface{}, error) {
	composePath := m.GetComposePath(appName)
	configDir := filepath.Dir(composePath)

	cmd := exec.Command("docker", "compose", "-f", composePath, "ps", "--format", "json")
	cmd.Dir = configDir

	output, err := cmd.Output()
	if err != nil {
		// Try to get status by container name convention
		return m.getStatusByName(appName)
	}

	// Parse JSON output
	status := map[string]interface{}{
		"app_name": appName,
		"running":  false,
		"status":   "unknown",
		"raw":      string(output),
	}

	if strings.Contains(string(output), "running") {
		status["running"] = true
		status["status"] = "running"
	} else if strings.Contains(string(output), "exited") {
		status["status"] = "exited"
	}

	return status, nil
}

// getStatusByName tries to get container status by naming convention
func (m *ComposeManager) getStatusByName(appName string) (map[string]interface{}, error) {
	status := map[string]interface{}{
		"app_name": appName,
		"running":  false,
		"status":   "not found",
	}

	// Try common naming patterns
	names := []string{
		"cubeos-" + appName,
		appName,
		"mulecube-" + appName,
	}

	for _, name := range names {
		cmd := exec.Command("docker", "inspect", "--format", "{{.State.Status}}", name)
		output, err := cmd.Output()
		if err == nil {
			containerStatus := strings.TrimSpace(string(output))
			status["container_name"] = name
			status["status"] = containerStatus
			status["running"] = containerStatus == "running"
			return status, nil
		}
	}

	return status, nil
}

// ExtractContainerName extracts container_name from compose file content
func (m *ComposeManager) ExtractContainerName(composeContent string) string {
	// Simple regex to find container_name
	re := regexp.MustCompile(`container_name:\s*["']?([a-zA-Z0-9_-]+)["']?`)
	matches := re.FindStringSubmatch(composeContent)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractPorts extracts port mappings from compose file content
func (m *ComposeManager) ExtractPorts(composeContent string) []PortMapping {
	var ports []PortMapping

	// Look for ports section
	inPorts := false
	scanner := bufio.NewScanner(strings.NewReader(composeContent))

	portRe := regexp.MustCompile(`["']?(\d+):(\d+)(?:/(tcp|udp))?["']?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "ports:") {
			inPorts = true
			continue
		}

		if inPorts {
			// Check if we've left the ports section
			if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "#") && line != "" {
				if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
					inPorts = false
					continue
				}
			}

			matches := portRe.FindStringSubmatch(line)
			if len(matches) >= 3 {
				hostPort, _ := strconv.Atoi(matches[1])
				containerPort, _ := strconv.Atoi(matches[2])
				protocol := "tcp"
				if len(matches) > 3 && matches[3] != "" {
					protocol = matches[3]
				}
				ports = append(ports, PortMapping{
					HostPort:      hostPort,
					ContainerPort: containerPort,
					Protocol:      protocol,
				})
			}
		}
	}

	return ports
}

// ListApps returns all apps with compose files
func (m *ComposeManager) ListApps() ([]string, error) {
	var apps []string

	// Scan coreapps
	coreEntries, err := os.ReadDir(m.coreAppsDir)
	if err == nil {
		for _, entry := range coreEntries {
			if entry.IsDir() {
				composePath := filepath.Join(m.coreAppsDir, entry.Name(), "appconfig", "docker-compose.yml")
				if _, err := os.Stat(composePath); err == nil {
					apps = append(apps, entry.Name())
				}
			}
		}
	}

	// Scan user apps
	userEntries, err := os.ReadDir(m.userAppsDir)
	if err == nil {
		for _, entry := range userEntries {
			if entry.IsDir() {
				composePath := filepath.Join(m.userAppsDir, entry.Name(), "appconfig", "docker-compose.yml")
				if _, err := os.Stat(composePath); err == nil {
					apps = append(apps, entry.Name())
				}
			}
		}
	}

	return apps, nil
}

// CreateAppDir creates the directory structure for a new app
func (m *ComposeManager) CreateAppDir(appName string, isSystem bool) error {
	var baseDir string
	if isSystem {
		baseDir = m.coreAppsDir
	} else {
		baseDir = m.userAppsDir
	}

	appDir := filepath.Join(baseDir, appName)
	configDir := filepath.Join(appDir, "appconfig")
	dataDir := filepath.Join(appDir, "appdata")

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	return nil
}

// ValidateCompose does basic validation of compose file content
func (m *ComposeManager) ValidateCompose(content string) error {
	if content == "" {
		return fmt.Errorf("compose file cannot be empty")
	}

	// Check for version or services key (basic YAML validation)
	if !strings.Contains(content, "services:") && !strings.Contains(content, "version:") {
		return fmt.Errorf("compose file must contain 'services:' section")
	}

	return nil
}
