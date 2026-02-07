// DEAD CODE — ComposeTransformer is not used in production.
// Retained for test coverage (orchestrator_test.go references ComposeTransformer).
// TODO: Remove once Swarm migration is complete and tests are updated.
package managers

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// ComposeTransformer handles transformation of docker-compose files for Swarm compatibility
type ComposeTransformer struct {
	registryURL string
	domain      string
}

// TransformResult contains the transformation result and metadata
type TransformResult struct {
	Content        string
	RequiresHost   bool   // True if network_mode: host detected
	DeployMode     string // "compose" or "stack"
	OriginalPorts  []PortMapping
	TransformNotes []string
}

// NewComposeTransformer creates a new transformer
func NewComposeTransformer(registryURL, domain string) *ComposeTransformer {
	return &ComposeTransformer{
		registryURL: registryURL,
		domain:      domain,
	}
}

// TransformForSwarm transforms a docker-compose.yml for Swarm deployment
// It handles:
// - Converting restart: to deploy.restart_policy
// - Detecting network_mode: host (requires compose deployment)
// - Rewriting images for local registry
// - Adding CubeOS labels
// - Removing unsupported Swarm options
func (t *ComposeTransformer) TransformForSwarm(content string, appName string) (*TransformResult, error) {
	result := &TransformResult{
		DeployMode:     "stack",
		TransformNotes: []string{},
	}

	// Check for network_mode: host - cannot use Swarm
	if t.hasNetworkModeHost(content) {
		result.RequiresHost = true
		result.DeployMode = "compose"
		result.TransformNotes = append(result.TransformNotes, "network_mode: host detected - using compose deployment")
		// For host mode, just add labels and return
		result.Content = t.addCubeOSLabels(content, appName)
		return result, nil
	}

	// Extract original ports before transformation
	result.OriginalPorts = extractPortMappings(content)

	lines := strings.Split(content, "\n")
	var transformed []string
	var inService bool
	var currentService string
	var serviceIndent int

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track service blocks
		if strings.HasPrefix(trimmed, "services:") {
			inService = false
			transformed = append(transformed, line)
			continue
		}

		// Detect service name (line under services: with no indent relative to services)
		if !inService && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") && trimmed != "services:" {
			// This is a top-level key, not a service
			transformed = append(transformed, line)
			continue
		}

		// Detect service definition (indented line ending with :)
		if strings.HasSuffix(trimmed, ":") && (strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t")) {
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			// Check if this is a service definition (2 spaces or 1 tab typically)
			if indent <= 4 && !strings.Contains(trimmed, " ") {
				potentialService := strings.TrimSuffix(trimmed, ":")
				// Verify it's not a known property
				if !isComposeProperty(potentialService) {
					inService = true
					currentService = potentialService
					serviceIndent = indent
				}
			}
		}

		// Handle restart: policy - convert to deploy.restart_policy for Swarm
		if inService && strings.HasPrefix(trimmed, "restart:") {
			restartValue := strings.TrimSpace(strings.TrimPrefix(trimmed, "restart:"))
			// Check if there's already a deploy block coming
			hasDeployBlock := t.serviceHasDeployBlock(lines, i, serviceIndent)

			if !hasDeployBlock {
				// Convert restart: to deploy block
				indent := strings.Repeat(" ", serviceIndent+2)
				deployIndent := strings.Repeat(" ", serviceIndent+4)

				result.TransformNotes = append(result.TransformNotes,
					fmt.Sprintf("service %s: converted restart:%s to deploy.restart_policy", currentService, restartValue))

				// Skip the original restart line
				// Add deploy block instead
				transformed = append(transformed, indent+"deploy:")
				transformed = append(transformed, deployIndent+"restart_policy:")
				transformed = append(transformed, deployIndent+"  condition: "+t.convertRestartPolicy(restartValue))
				continue
			} else {
				// Deploy block exists, skip this restart: line
				result.TransformNotes = append(result.TransformNotes,
					fmt.Sprintf("service %s: removed duplicate restart: (deploy block exists)", currentService))
				continue
			}
		}

		// Remove container_name for Swarm (Swarm manages naming)
		if inService && strings.HasPrefix(trimmed, "container_name:") {
			result.TransformNotes = append(result.TransformNotes,
				fmt.Sprintf("service %s: removed container_name (Swarm manages naming)", currentService))
			continue
		}

		// Remove depends_on for Swarm (use healthchecks instead)
		if inService && strings.HasPrefix(trimmed, "depends_on:") {
			result.TransformNotes = append(result.TransformNotes,
				fmt.Sprintf("service %s: removed depends_on (use healthchecks for Swarm)", currentService))
			// Skip depends_on block
			for j := i + 1; j < len(lines); j++ {
				nextLine := lines[j]
				nextTrimmed := strings.TrimSpace(nextLine)
				if nextTrimmed == "" || strings.HasPrefix(nextLine, "      ") || strings.HasPrefix(nextTrimmed, "-") {
					continue
				}
				break
			}
			continue
		}

		// Rewrite image references for local registry
		if inService && strings.HasPrefix(trimmed, "image:") {
			imageLine := t.rewriteImageForRegistry(line, result)
			transformed = append(transformed, imageLine)
			continue
		}

		transformed = append(transformed, line)
	}

	result.Content = strings.Join(transformed, "\n")

	// Add CubeOS labels
	result.Content = t.addCubeOSLabels(result.Content, appName)

	return result, nil
}

// hasNetworkModeHost checks if compose file uses network_mode: host
func (t *ComposeTransformer) hasNetworkModeHost(content string) bool {
	re := regexp.MustCompile(`network_mode:\s*["']?host["']?`)
	return re.MatchString(content)
}

// serviceHasDeployBlock checks if remaining lines for this service contain deploy:
func (t *ComposeTransformer) serviceHasDeployBlock(lines []string, startIdx, serviceIndent int) bool {
	for i := startIdx + 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		// If we hit same or lesser indent, we've left the service
		if indent <= serviceIndent && strings.TrimSpace(line) != "" {
			break
		}
		if strings.TrimSpace(line) == "deploy:" {
			return true
		}
	}
	return false
}

// convertRestartPolicy converts docker-compose restart values to Swarm restart_policy conditions
func (t *ComposeTransformer) convertRestartPolicy(restart string) string {
	switch strings.TrimSpace(restart) {
	case "always", "unless-stopped":
		return "any"
	case "on-failure":
		return "on-failure"
	case "no", "none":
		return "none"
	default:
		return "any"
	}
}

// rewriteImageForRegistry rewrites image references to use local registry
func (t *ComposeTransformer) rewriteImageForRegistry(line string, result *TransformResult) string {
	if t.registryURL == "" {
		return line
	}

	// Extract image value
	re := regexp.MustCompile(`image:\s*["']?([^"'\s]+)["']?`)
	matches := re.FindStringSubmatch(line)
	if len(matches) < 2 {
		return line
	}

	originalImage := matches[1]

	// Skip if already using local registry
	if strings.HasPrefix(originalImage, "localhost:") || strings.HasPrefix(originalImage, t.registryURL) {
		return line
	}

	// Skip CubeOS images (built locally, not cached)
	if strings.Contains(originalImage, "cubeos-app/") || strings.Contains(originalImage, "cubeos/") {
		return line
	}

	// Rewrite to local registry
	// docker.io/library/nginx -> localhost:5000/library/nginx
	// ghcr.io/user/repo -> localhost:5000/user/repo
	newImage := originalImage
	newImage = strings.TrimPrefix(newImage, "docker.io/")
	newImage = strings.TrimPrefix(newImage, "ghcr.io/")
	newImage = strings.TrimPrefix(newImage, "quay.io/")

	// Add registry prefix
	newImage = t.registryURL + "/" + newImage

	result.TransformNotes = append(result.TransformNotes,
		fmt.Sprintf("rewriting image: %s -> %s", originalImage, newImage))

	// Preserve indentation
	indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
	return indent + "image: " + newImage
}

// addCubeOSLabels adds CubeOS-specific labels to the compose file
func (t *ComposeTransformer) addCubeOSLabels(content, appName string) string {
	// This is a simplified implementation
	// A full implementation would parse YAML properly and add labels to each service

	// For now, just return content unchanged if labels already exist
	if strings.Contains(content, "cubeos.app=") {
		return content
	}

	return content
}

// extractPortMappings extracts port mappings from compose content
func extractPortMappings(content string) []PortMapping {
	var ports []PortMapping

	scanner := bufio.NewScanner(strings.NewReader(content))
	inPorts := false
	portRe := regexp.MustCompile(`["']?(\d+):(\d+)(?:/(tcp|udp))?["']?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "ports:") {
			inPorts = true
			continue
		}

		if inPorts {
			if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "#") && line != "" {
				if !strings.HasPrefix(line, " ") {
					inPorts = false
					continue
				}
			}

			matches := portRe.FindStringSubmatch(line)
			if len(matches) >= 3 {
				hostPort := 0
				containerPort := 0
				fmt.Sscanf(matches[1], "%d", &hostPort)
				fmt.Sscanf(matches[2], "%d", &containerPort)
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

// isComposeProperty checks if a string is a known docker-compose property (not a service name)
func isComposeProperty(s string) bool {
	properties := map[string]bool{
		"version": true, "services": true, "networks": true, "volumes": true,
		"configs": true, "secrets": true,
		"image": true, "build": true, "command": true, "entrypoint": true,
		"environment": true, "env_file": true, "ports": true, "expose": true,
		"restart": true, "deploy": true, "labels": true,
		"healthcheck": true, "logging": true, "network_mode": true,
		"depends_on": true, "container_name": true, "hostname": true,
		"devices": true, "cap_add": true, "cap_drop": true, "privileged": true,
		"security_opt": true, "sysctls": true, "ulimits": true,
		"working_dir": true, "user": true, "stdin_open": true, "tty": true,
	}
	return properties[s] || strings.HasPrefix(s, "x-")
}

// DetectDeployMode determines whether an app should use compose or stack deployment
func (t *ComposeTransformer) DetectDeployMode(content string) string {
	if t.hasNetworkModeHost(content) {
		return "compose"
	}
	return "stack"
}

// ValidateForSwarm checks if a compose file can be deployed to Swarm
func (t *ComposeTransformer) ValidateForSwarm(content string) []string {
	var issues []string

	// Check for unsupported options
	if strings.Contains(content, "build:") {
		issues = append(issues, "build: not supported in Swarm - use pre-built images")
	}

	if strings.Contains(content, "links:") {
		issues = append(issues, "links: deprecated - use networks instead")
	}

	// network_mode: host is supported but forces compose deployment
	if t.hasNetworkModeHost(content) {
		issues = append(issues, "network_mode: host requires compose deployment (not Swarm)")
	}

	return issues
}
