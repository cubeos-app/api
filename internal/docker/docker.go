// Package docker provides Docker SDK integration for container management.
package docker

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
)

// Manager handles Docker container operations.
type Manager struct {
	client *client.Client
}

// NewManager creates a new Docker manager with the given client.
func NewManager(cli *client.Client) *Manager {
	return &Manager{client: cli}
}

// ContainerInfo represents basic container information for list views.
type ContainerInfo struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Status  string            `json:"status"`
	State   string            `json:"state"`
	Created time.Time         `json:"created"`
	Ports   []PortMapping     `json:"ports,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	IsCore  bool              `json:"is_core"`
}

// ContainerDetail represents detailed container information.
type ContainerDetail struct {
	ContainerInfo
	ImageID       string      `json:"image_id"`
	Command       string      `json:"command"`
	Env           []string    `json:"env,omitempty"`
	Mounts        []MountInfo `json:"mounts,omitempty"`
	Networks      []string    `json:"networks,omitempty"`
	RestartPolicy string      `json:"restart_policy"`
	HealthStatus  string      `json:"health_status,omitempty"`
	StartedAt     time.Time   `json:"started_at,omitempty"`
	FinishedAt    time.Time   `json:"finished_at,omitempty"`
}

// ContainerStats represents container resource usage.
type ContainerStats struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsage   uint64  `json:"memory_usage"`
	MemoryLimit   uint64  `json:"memory_limit"`
	MemoryPercent float64 `json:"memory_percent"`
	NetworkRx     uint64  `json:"network_rx"`
	NetworkTx     uint64  `json:"network_tx"`
	BlockRead     uint64  `json:"block_read"`
	BlockWrite    uint64  `json:"block_write"`
	PIDs          uint64  `json:"pids"`
}

// PortMapping represents a container port mapping.
type PortMapping struct {
	ContainerPort int    `json:"container_port"`
	HostPort      int    `json:"host_port,omitempty"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip,omitempty"`
}

// MountInfo represents a container mount/volume.
type MountInfo struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
}

// LogOptions configures container log retrieval.
type LogOptions struct {
	Tail       string
	Since      string
	Until      string
	Timestamps bool
	Follow     bool
}

// Core services that should not be toggled by users.
var coreServices = map[string]bool{
	"nginx-proxy":              true,
	"pihole":                   true,
	"postgres":                 true,
	"valkey":                   true,
	"cubeos-api":               true,
	"cubeos-dashboard":         true,
	"mulecube-dashboard":       true,
	"mulecube-hw-monitor":      true,
	"mulecube-service-manager": true,
	"mulecube-status":          true,
	"mulecube-backup":          true,
	"mulecube-watchdog":        true,
	"uptime-kuma":              true,
	"beszel":                   true,
	"beszel-agent":             true,
}

// Core service name patterns (prefix matching).
var coreServicePatterns = []string{
	"watchtower",
	"postgres-",
	"meilisearch-",
	"mulecube-",
	"cubeos-",
}

// IsConnected returns true if the Docker client is connected and responsive.
func (m *Manager) IsConnected(ctx context.Context) bool {
	if m.client == nil {
		return false
	}
	_, err := m.client.Ping(ctx)
	return err == nil
}

// ListContainers returns all containers (optionally filtered).
func (m *Manager) ListContainers(ctx context.Context, all bool) ([]ContainerInfo, error) {
	if m.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All: all,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	result := make([]ContainerInfo, 0, len(containers))
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		ports := make([]PortMapping, 0, len(c.Ports))
		for _, p := range c.Ports {
			ports = append(ports, PortMapping{
				ContainerPort: int(p.PrivatePort),
				HostPort:      int(p.PublicPort),
				Protocol:      p.Type,
				HostIP:        p.IP,
			})
		}

		result = append(result, ContainerInfo{
			ID:      c.ID[:12],
			Name:    name,
			Image:   c.Image,
			Status:  c.Status,
			State:   c.State,
			Created: time.Unix(c.Created, 0),
			Ports:   ports,
			Labels:  c.Labels,
			IsCore:  isCoreService(name),
		})
	}

	return result, nil
}

// GetContainer returns detailed information about a single container.
func (m *Manager) GetContainer(ctx context.Context, nameOrID string) (*ContainerDetail, error) {
	if m.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	inspect, err := m.client.ContainerInspect(ctx, nameOrID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	name := strings.TrimPrefix(inspect.Name, "/")

	// Extract ports
	ports := make([]PortMapping, 0)
	for port, bindings := range inspect.NetworkSettings.Ports {
		containerPort := port.Int()
		protocol := port.Proto()

		if len(bindings) == 0 {
			ports = append(ports, PortMapping{
				ContainerPort: containerPort,
				Protocol:      protocol,
			})
		} else {
			for _, b := range bindings {
				hostPort := 0
				fmt.Sscanf(b.HostPort, "%d", &hostPort)
				ports = append(ports, PortMapping{
					ContainerPort: containerPort,
					HostPort:      hostPort,
					Protocol:      protocol,
					HostIP:        b.HostIP,
				})
			}
		}
	}

	// Extract mounts
	mounts := make([]MountInfo, 0, len(inspect.Mounts))
	for _, mt := range inspect.Mounts {
		mounts = append(mounts, MountInfo{
			Type:        string(mt.Type),
			Source:      mt.Source,
			Destination: mt.Destination,
			ReadOnly:    !mt.RW,
		})
	}

	// Extract networks
	networks := make([]string, 0)
	for netName := range inspect.NetworkSettings.Networks {
		networks = append(networks, netName)
	}

	// Parse timestamps
	created, _ := time.Parse(time.RFC3339Nano, inspect.Created)
	startedAt, _ := time.Parse(time.RFC3339Nano, inspect.State.StartedAt)
	finishedAt, _ := time.Parse(time.RFC3339Nano, inspect.State.FinishedAt)

	// Health status
	healthStatus := ""
	if inspect.State.Health != nil {
		healthStatus = inspect.State.Health.Status
	}

	detail := &ContainerDetail{
		ContainerInfo: ContainerInfo{
			ID:      inspect.ID[:12],
			Name:    name,
			Image:   inspect.Config.Image,
			Status:  inspect.State.Status,
			State:   inspect.State.Status,
			Created: created,
			Ports:   ports,
			Labels:  inspect.Config.Labels,
			IsCore:  isCoreService(name),
		},
		ImageID:       inspect.Image,
		Command:       strings.Join(inspect.Config.Cmd, " "),
		Env:           filterEnv(inspect.Config.Env),
		Mounts:        mounts,
		Networks:      networks,
		RestartPolicy: string(inspect.HostConfig.RestartPolicy.Name),
		HealthStatus:  healthStatus,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
	}

	return detail, nil
}

// StartContainer starts a stopped container.
func (m *Manager) StartContainer(ctx context.Context, nameOrID string) error {
	if m.client == nil {
		return fmt.Errorf("docker client not initialized")
	}
	return m.client.ContainerStart(ctx, nameOrID, container.StartOptions{})
}

// StopContainer stops a running container.
func (m *Manager) StopContainer(ctx context.Context, nameOrID string, timeout time.Duration) error {
	if m.client == nil {
		return fmt.Errorf("docker client not initialized")
	}
	timeoutSecs := int(timeout.Seconds())
	return m.client.ContainerStop(ctx, nameOrID, container.StopOptions{
		Timeout: &timeoutSecs,
	})
}

// RestartContainer restarts a container.
func (m *Manager) RestartContainer(ctx context.Context, nameOrID string, timeout time.Duration) error {
	if m.client == nil {
		return fmt.Errorf("docker client not initialized")
	}
	timeoutSecs := int(timeout.Seconds())
	return m.client.ContainerRestart(ctx, nameOrID, container.StopOptions{
		Timeout: &timeoutSecs,
	})
}

// GetContainerLogs returns logs from a container.
func (m *Manager) GetContainerLogs(ctx context.Context, nameOrID string, opts LogOptions) (io.ReadCloser, error) {
	if m.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	logOpts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: opts.Timestamps,
		Follow:     opts.Follow,
		Tail:       opts.Tail,
		Since:      opts.Since,
		Until:      opts.Until,
	}

	return m.client.ContainerLogs(ctx, nameOrID, logOpts)
}

// GetContainerStats returns resource usage stats for a container.
func (m *Manager) GetContainerStats(ctx context.Context, nameOrID string) (*ContainerStats, error) {
	if m.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	resp, err := m.client.ContainerStats(ctx, nameOrID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}
	defer resp.Body.Close()

	var statsJSON types.StatsJSON
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&statsJSON); err != nil {
		return nil, fmt.Errorf("failed to decode stats: %w", err)
	}

	stats := &ContainerStats{}

	// Calculate CPU percentage
	cpuDelta := float64(statsJSON.CPUStats.CPUUsage.TotalUsage - statsJSON.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(statsJSON.CPUStats.SystemUsage - statsJSON.PreCPUStats.SystemUsage)
	if systemDelta > 0 && cpuDelta > 0 {
		stats.CPUPercent = (cpuDelta / systemDelta) * float64(statsJSON.CPUStats.OnlineCPUs) * 100.0
	}

	// Memory
	stats.MemoryUsage = statsJSON.MemoryStats.Usage
	stats.MemoryLimit = statsJSON.MemoryStats.Limit
	if stats.MemoryLimit > 0 {
		stats.MemoryPercent = float64(stats.MemoryUsage) / float64(stats.MemoryLimit) * 100.0
	}

	// Network I/O
	for _, netStats := range statsJSON.Networks {
		stats.NetworkRx += netStats.RxBytes
		stats.NetworkTx += netStats.TxBytes
	}

	// Block I/O
	for _, bioEntry := range statsJSON.BlkioStats.IoServiceBytesRecursive {
		switch bioEntry.Op {
		case "read", "Read":
			stats.BlockRead += bioEntry.Value
		case "write", "Write":
			stats.BlockWrite += bioEntry.Value
		}
	}

	// PIDs
	stats.PIDs = statsJSON.PidsStats.Current

	return stats, nil
}

// FindContainerByName finds a container by exact name match.
func (m *Manager) FindContainerByName(ctx context.Context, name string) (*ContainerInfo, error) {
	if m.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("name", "^/"+name+"$"),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find container: %w", err)
	}

	if len(containers) == 0 {
		return nil, nil
	}

	c := containers[0]
	containerName := ""
	if len(c.Names) > 0 {
		containerName = strings.TrimPrefix(c.Names[0], "/")
	}

	return &ContainerInfo{
		ID:      c.ID[:12],
		Name:    containerName,
		Image:   c.Image,
		Status:  c.Status,
		State:   c.State,
		Created: time.Unix(c.Created, 0),
		IsCore:  isCoreService(containerName),
	}, nil
}

// isCoreService checks if a container is a core service that shouldn't be toggled.
func isCoreService(name string) bool {
	if coreServices[name] {
		return true
	}
	for _, pattern := range coreServicePatterns {
		if strings.HasPrefix(name, pattern) {
			return true
		}
	}
	return false
}

// filterEnv removes sensitive environment variables.
func filterEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	sensitiveKeys := []string{"PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL"}

	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])

		isSensitive := false
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(key, sensitive) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			filtered = append(filtered, parts[0]+"=[REDACTED]")
		} else {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
