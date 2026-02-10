package managers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"cubeos-api/internal/config"
	"cubeos-api/internal/models"
)

// DockerManager handles Docker container operations
type DockerManager struct {
	client *client.Client
	cfg    *config.Config
}

// NewDockerManager creates a new DockerManager
func NewDockerManager(cfg *config.Config) (*DockerManager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := cli.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to Docker: %w", err)
	}

	return &DockerManager{
		client: cli,
		cfg:    cfg,
	}, nil
}

// Close closes the Docker client
func (m *DockerManager) Close() error {
	return m.client.Close()
}

// ListContainers returns all containers with their status
func (m *DockerManager) ListContainers(ctx context.Context) ([]models.ContainerInfo, error) {
	containers, err := m.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	var result []models.ContainerInfo
	for _, c := range containers {
		// Guard against containers with no names (shouldn't happen, but be safe)
		if len(c.Names) == 0 || c.Names[0] == "" {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")

		info := models.ContainerInfo{
			ID:          c.ID[:12],
			Name:        name,
			DisplayName: formatDisplayName(name),
			Image:       c.Image,
			State:       c.State,
			Status:      c.Status,
			IsCore:      config.IsCoreService(name),
			Created:     time.Unix(c.Created, 0),
		}

		// Get health status
		if c.State == "running" {
			// Inspect for health
			inspect, err := m.client.ContainerInspect(ctx, c.ID)
			if err == nil && inspect.State.Health != nil {
				info.Health = inspect.State.Health.Status
				if inspect.State.StartedAt != "" {
					if t, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt); err == nil {
						info.StartedAt = &t
					}
				}
			}
		}

		// Get category from labels
		if cat, ok := c.Labels["cubeos.category"]; ok {
			info.Category = cat
		}

		// Parse ports
		for _, p := range c.Ports {
			port := models.PortBinding{
				PrivatePort: int(p.PrivatePort),
				PublicPort:  int(p.PublicPort),
				Type:        p.Type,
				IP:          p.IP,
			}
			info.Ports = append(info.Ports, port)
		}

		info.Labels = c.Labels

		result = append(result, info)
	}

	return result, nil
}

// GetContainer returns information about a single container
func (m *DockerManager) GetContainer(ctx context.Context, name string) (*models.ContainerInfo, error) {
	inspect, err := m.client.ContainerInspect(ctx, name)
	if err != nil {
		return nil, err
	}

	containerName := strings.TrimPrefix(inspect.Name, "/")

	// Parse created time
	createdTime, _ := time.Parse(time.RFC3339Nano, inspect.Created)

	info := &models.ContainerInfo{
		ID:          inspect.ID[:12],
		Name:        containerName,
		DisplayName: formatDisplayName(containerName),
		Image:       inspect.Config.Image,
		State:       inspect.State.Status,
		Status:      inspect.State.Status,
		IsCore:      config.IsCoreService(containerName),
		Created:     createdTime,
		Labels:      inspect.Config.Labels,
	}

	if inspect.State.Health != nil {
		info.Health = inspect.State.Health.Status
	}

	if inspect.State.StartedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt); err == nil {
			info.StartedAt = &t
		}
	}

	// Get category
	if cat, ok := inspect.Config.Labels["cubeos.category"]; ok {
		info.Category = cat
	}

	return info, nil
}

// GetContainerStatus returns the status of a container
func (m *DockerManager) GetContainerStatus(ctx context.Context, name string) (string, error) {
	inspect, err := m.client.ContainerInspect(ctx, name)
	if err != nil {
		if client.IsErrNotFound(err) {
			return "not_found", nil
		}
		return "", fmt.Errorf("failed to inspect container %s: %w", name, err)
	}
	return inspect.State.Status, nil
}

// GetContainerIP returns the first non-empty IP address found for a container.
// It prefers the docker_gwbridge network (used for outbound traffic in Swarm),
// then falls back to any other network, and finally the global NetworkSettings IP.
func (m *DockerManager) GetContainerIP(ctx context.Context, name string) (string, error) {
	inspect, err := m.client.ContainerInspect(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %s: %w", name, err)
	}

	if inspect.NetworkSettings == nil {
		return "", fmt.Errorf("container %s has no network settings", name)
	}

	// Prefer docker_gwbridge (Swarm outbound)
	if gw, ok := inspect.NetworkSettings.Networks["docker_gwbridge"]; ok && gw.IPAddress != "" {
		return gw.IPAddress, nil
	}

	// Fall back to any network with an IP
	for _, net := range inspect.NetworkSettings.Networks {
		if net.IPAddress != "" {
			return net.IPAddress, nil
		}
	}

	// Global fallback
	if inspect.NetworkSettings.IPAddress != "" {
		return inspect.NetworkSettings.IPAddress, nil
	}

	return "", fmt.Errorf("container %s has no IP address", name)
}

// StartContainer starts a container
func (m *DockerManager) StartContainer(ctx context.Context, name string) error {
	return m.client.ContainerStart(ctx, name, container.StartOptions{})
}

// StopContainer stops a container
func (m *DockerManager) StopContainer(ctx context.Context, name string, timeout int) error {
	stopTimeout := timeout
	return m.client.ContainerStop(ctx, name, container.StopOptions{Timeout: &stopTimeout})
}

// RestartContainer restarts a container
func (m *DockerManager) RestartContainer(ctx context.Context, name string, timeout int) error {
	return m.client.ContainerRestart(ctx, name, container.StopOptions{Timeout: &timeout})
}

// SetRestartPolicy updates the restart policy for a container
func (m *DockerManager) SetRestartPolicy(ctx context.Context, name string, policy string) error {
	_, err := m.client.ContainerUpdate(ctx, name, container.UpdateConfig{
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyMode(policy)},
	})
	return err
}

// EnableService enables a service (set restart policy and start)
func (m *DockerManager) EnableService(ctx context.Context, name string) (*models.ServiceAction, error) {
	result := &models.ServiceAction{
		Service: name,
		Action:  "enable",
	}

	// Set restart policy
	if err := m.SetRestartPolicy(ctx, name, "unless-stopped"); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to set restart policy: %v", err)
		return result, err
	}

	// Start the container
	if err := m.StartContainer(ctx, name); err != nil {
		// Rollback: revert restart policy to prevent auto-restart of a broken container
		if rbErr := m.SetRestartPolicy(ctx, name, "no"); rbErr != nil {
			result.Message = fmt.Sprintf("Failed to start container: %v (rollback also failed: %v)", err, rbErr)
		} else {
			result.Message = fmt.Sprintf("Failed to start container: %v (restart policy rolled back)", err)
		}
		result.Success = false
		return result, err
	}

	// Get current status
	status, _ := m.GetContainerStatus(ctx, name)

	result.Success = true
	result.Status = status
	result.Message = "Service enabled successfully"

	return result, nil
}

// DisableService disables a service (stop and set restart policy to no)
func (m *DockerManager) DisableService(ctx context.Context, name string) (*models.ServiceAction, error) {
	result := &models.ServiceAction{
		Service: name,
		Action:  "disable",
	}

	// Get RAM usage before stopping
	stats, err := m.GetContainerStats(ctx, name)
	if err == nil {
		result.RAMFreedMB = int(stats.MemoryMB)
	}

	// Stop the container
	if err := m.StopContainer(ctx, name, m.cfg.ContainerStopTimeout); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to stop container: %v", err)
		return result, err
	}

	// Set restart policy to 'no'
	if err := m.SetRestartPolicy(ctx, name, "no"); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to set restart policy: %v", err)
		return result, err
	}

	// Get current status
	status, _ := m.GetContainerStatus(ctx, name)

	result.Success = true
	result.Status = status
	result.Message = "Service disabled successfully"

	return result, nil
}

// GetContainerStats returns resource usage for a running container
func (m *DockerManager) GetContainerStats(ctx context.Context, name string) (*models.ContainerStats, error) {
	// First check if container is running
	inspect, err := m.client.ContainerInspect(ctx, name)
	if err != nil {
		return nil, err
	}

	if inspect.State.Status != "running" {
		return &models.ContainerStats{}, nil
	}

	// Get stats
	statsReader, err := m.client.ContainerStats(ctx, name, false)
	if err != nil {
		return nil, err
	}
	defer statsReader.Body.Close()

	body, err := io.ReadAll(statsReader.Body)
	if err != nil {
		return nil, err
	}

	var stats types.StatsJSON
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, err
	}

	// Calculate memory
	memoryMB := float64(stats.MemoryStats.Usage) / (1024 * 1024)
	memoryLimitMB := float64(stats.MemoryStats.Limit) / (1024 * 1024)

	// Calculate CPU percentage
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)

	var cpuPercent float64
	if systemDelta > 0 && cpuDelta > 0 {
		// Use OnlineCPUs (newer Docker API) with fallback to PercpuUsage length
		cpuCount := stats.CPUStats.OnlineCPUs
		if cpuCount == 0 {
			cpuCount = uint32(len(stats.CPUStats.CPUUsage.PercpuUsage))
		}
		if cpuCount == 0 {
			cpuCount = 1 // Final fallback
		}
		cpuPercent = (cpuDelta / systemDelta) * float64(cpuCount) * 100.0
	}

	return &models.ContainerStats{
		MemoryMB:      memoryMB,
		MemoryLimitMB: memoryLimitMB,
		CPUPercent:    cpuPercent,
	}, nil
}

// GetServicesResponse returns formatted services response
func (m *DockerManager) GetServicesResponse(ctx context.Context) (*models.ServicesResponse, error) {
	containers, err := m.ListContainers(ctx)
	if err != nil {
		return nil, err
	}

	var running int
	for _, c := range containers {
		if c.State == "running" {
			running++
		}
	}

	return &models.ServicesResponse{
		Services: containers,
		Total:    len(containers),
		Running:  running,
	}, nil
}

// GetContainerLogs returns logs for a container
func (m *DockerManager) GetContainerLogs(ctx context.Context, name string, tail int, since string) (string, error) {
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: true,
	}

	if tail > 0 {
		options.Tail = fmt.Sprintf("%d", tail)
	}

	if since != "" {
		options.Since = since
	}

	reader, err := m.client.ContainerLogs(ctx, name, options)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	// Use stdcopy to properly demultiplex Docker's stream format.
	// Docker multiplexes stdout/stderr with 8-byte headers per frame.
	var stdout, stderr strings.Builder
	if _, err := stdcopy.StdCopy(&stdout, &stderr, reader); err != nil {
		// Fallback: some containers (e.g. TTY mode) don't use multiplexed format.
		// Re-read as plain text.
		reader2, err2 := m.client.ContainerLogs(ctx, name, options)
		if err2 != nil {
			return "", err2
		}
		defer reader2.Close()
		data, err2 := io.ReadAll(reader2)
		if err2 != nil {
			return "", err2
		}
		return string(data), nil
	}

	// Combine stdout and stderr
	result := stdout.String()
	if stderr.Len() > 0 {
		if result != "" {
			result += "\n"
		}
		result += stderr.String()
	}

	return result, nil
}

// GetAllContainerStatus returns status map for all containers
func (m *DockerManager) GetAllContainerStatus(ctx context.Context) (map[string]map[string]interface{}, error) {
	containers, err := m.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	result := make(map[string]map[string]interface{})
	for _, c := range containers {
		if len(c.Names) == 0 || c.Names[0] == "" {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		result[name] = map[string]interface{}{
			"status":  c.State,
			"running": c.State == "running",
		}
	}

	return result, nil
}

// formatDisplayName converts container name to display name
func formatDisplayName(name string) string {
	// Remove common prefixes
	name = strings.TrimPrefix(name, "cubeos-")
	name = strings.TrimPrefix(name, "cubeos-")

	// Replace dashes and underscores with spaces
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, "_", " ")

	// Title case
	words := strings.Fields(name)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}

	return strings.Join(words, " ")
}

// PruneContainers removes stopped containers
func (m *DockerManager) PruneContainers(ctx context.Context) (string, error) {
	report, err := m.client.ContainersPrune(ctx, filters.Args{})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Removed %d containers, reclaimed %d bytes", len(report.ContainersDeleted), report.SpaceReclaimed), nil
}

// PruneImages removes unused images
func (m *DockerManager) PruneImages(ctx context.Context) (string, error) {
	report, err := m.client.ImagesPrune(ctx, filters.Args{})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Removed %d images, reclaimed %d bytes", len(report.ImagesDeleted), report.SpaceReclaimed), nil
}

// PruneVolumes removes unused volumes
func (m *DockerManager) PruneVolumes(ctx context.Context) (string, error) {
	report, err := m.client.VolumesPrune(ctx, filters.Args{})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Removed %d volumes, reclaimed %d bytes", len(report.VolumesDeleted), report.SpaceReclaimed), nil
}

// PruneAll runs all prune operations
func (m *DockerManager) PruneAll(ctx context.Context) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"containers":      nil,
		"images":          nil,
		"volumes":         nil,
		"total_reclaimed": int64(0),
	}

	var totalReclaimed int64

	// Prune containers
	cReport, err := m.client.ContainersPrune(ctx, filters.Args{})
	if err == nil {
		result["containers"] = map[string]interface{}{
			"deleted":   len(cReport.ContainersDeleted),
			"reclaimed": cReport.SpaceReclaimed,
		}
		totalReclaimed += int64(cReport.SpaceReclaimed)
	}

	// Prune images
	iReport, err := m.client.ImagesPrune(ctx, filters.Args{})
	if err == nil {
		result["images"] = map[string]interface{}{
			"deleted":   len(iReport.ImagesDeleted),
			"reclaimed": iReport.SpaceReclaimed,
		}
		totalReclaimed += int64(iReport.SpaceReclaimed)
	}

	// Prune volumes
	vReport, err := m.client.VolumesPrune(ctx, filters.Args{})
	if err == nil {
		result["volumes"] = map[string]interface{}{
			"deleted":   len(vReport.VolumesDeleted),
			"reclaimed": vReport.SpaceReclaimed,
		}
		totalReclaimed += int64(vReport.SpaceReclaimed)
	}

	result["total_reclaimed"] = totalReclaimed

	return result, nil
}

// GetDiskUsage returns Docker disk usage info
func (m *DockerManager) GetDiskUsage(ctx context.Context) (map[string]interface{}, error) {
	usage, err := m.client.DiskUsage(ctx, types.DiskUsageOptions{})
	if err != nil {
		return nil, err
	}

	var imagesSize, containersSize, volumesSize, buildCacheSize int64

	for _, img := range usage.Images {
		imagesSize += img.Size
	}

	for _, c := range usage.Containers {
		containersSize += c.SizeRw
	}

	for _, v := range usage.Volumes {
		volumesSize += v.UsageData.Size
	}

	if usage.BuildCache != nil {
		for _, bc := range usage.BuildCache {
			buildCacheSize += bc.Size
		}
	}

	return map[string]interface{}{
		"images_count":     len(usage.Images),
		"images_size":      imagesSize,
		"containers_count": len(usage.Containers),
		"containers_size":  containersSize,
		"volumes_count":    len(usage.Volumes),
		"volumes_size":     volumesSize,
		"build_cache_size": buildCacheSize,
		"total_size":       imagesSize + containersSize + volumesSize + buildCacheSize,
	}, nil
}

// ListServices returns all services with detailed info for wizard
func (m *DockerManager) ListServices(ctx context.Context) []models.ServiceInfo {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	containers, err := m.ListContainers(ctx)
	if err != nil {
		return nil
	}

	var services []models.ServiceInfo
	for _, c := range containers {
		svc := models.ServiceInfo{
			Name:        c.Name,
			DisplayName: c.DisplayName,
			Category:    c.Category,
			IsCore:      c.IsCore,
			Running:     c.State == "running",
			Status:      c.State,
			Health:      c.Health,
			Enabled:     true, // Default to enabled
		}

		// Get definition from config if available
		if def, ok := config.ServiceDefinitions[c.Name]; ok {
			svc.Description = def.Description
			svc.RAMEstimateMB = def.RAMEstimate
			svc.Icon = def.Icon
			svc.URL = def.URL
			svc.Ports = def.Ports
			svc.Dependencies = def.Dependencies
		} else {
			// Defaults
			svc.RAMEstimateMB = 256
			svc.Icon = "box"
		}

		// Infer category if not set
		if svc.Category == "" {
			svc.Category = config.InferCategory(c.Name)
		}

		services = append(services, svc)
	}

	return services
}
