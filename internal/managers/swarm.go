// Package managers provides service management functionality for CubeOS.
package managers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"cubeos-api/internal/models"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
)

// SwarmManager handles Docker Swarm operations for CubeOS.
// It provides methods for initializing Swarm, deploying stacks,
// and managing services with self-healing capabilities.
//
// Architecture Note: CubeOS uses a hybrid deployment model:
// - Swarm stacks: API, Dashboard, Registry, Dozzle, Ollama, ChromaDB, user apps
// - docker-compose: Pi-hole, NPM (require host network mode for DHCP/proxy)
type SwarmManager struct {
	client *client.Client
	ctx    context.Context
}

// ServiceStatus represents the current state of a Swarm service.
type ServiceStatus struct {
	Name        string    `json:"name"`
	Running     bool      `json:"running"`
	Replicas    string    `json:"replicas"` // e.g., "1/1"
	Image       string    `json:"image"`
	Ports       []string  `json:"ports"`
	Health      string    `json:"health"` // healthy, unhealthy, starting, stopped, unknown
	Error       string    `json:"error,omitempty"`
	LastUpdated time.Time `json:"last_updated"`
}

// Stack represents a deployed Swarm stack.
type Stack struct {
	Name     string `json:"name"`
	Services int    `json:"services"`
}

// StackService represents a service within a stack.
type StackService struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Mode     string `json:"mode"`     // replicated or global
	Replicas string `json:"replicas"` // e.g., "1/1"
	Image    string `json:"image"`
	Ports    string `json:"ports"`
}

// SwarmConfig holds Swarm initialization configuration.
type SwarmConfig struct {
	AdvertiseAddr    string // e.g., "10.42.24.1"
	TaskHistoryLimit int    // Memory optimization, default 1
	ListenAddr       string // default "0.0.0.0:2377"
}

// DefaultSwarmConfig returns the default Swarm configuration for CubeOS.
func DefaultSwarmConfig() SwarmConfig {
	return SwarmConfig{
		AdvertiseAddr:    models.DefaultGatewayIP,
		TaskHistoryLimit: 1,
		ListenAddr:       "0.0.0.0:2377",
	}
}

// NewSwarmManager creates a new SwarmManager instance.
// It connects to the Docker daemon using the default socket.
func NewSwarmManager() (*SwarmManager, error) {
	return NewSwarmManagerWithContext(context.Background())
}

// NewSwarmManagerWithContext creates a SwarmManager with a custom context.
func NewSwarmManagerWithContext(ctx context.Context) (*SwarmManager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return &SwarmManager{
		client: cli,
		ctx:    ctx,
	}, nil
}

// Close releases the Docker client resources.
func (s *SwarmManager) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// IsSwarmActive checks if Docker Swarm is initialized and active.
func (s *SwarmManager) IsSwarmActive() (bool, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	info, err := s.client.Info(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get Docker info: %w", err)
	}

	return info.Swarm.LocalNodeState == swarm.LocalNodeStateActive, nil
}

// Init initializes Docker Swarm in single-node mode.
// This is idempotent - it will not error if Swarm is already active.
func (s *SwarmManager) Init(cfg SwarmConfig) error {
	active, err := s.IsSwarmActive()
	if err != nil {
		return fmt.Errorf("failed to check Swarm status: %w", err)
	}

	if active {
		// Swarm already initialized, ensure task history limit is set
		return s.SetTaskHistoryLimit(cfg.TaskHistoryLimit)
	}

	// Set defaults
	if cfg.AdvertiseAddr == "" {
		cfg.AdvertiseAddr = models.DefaultGatewayIP
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:2377"
	}
	if cfg.TaskHistoryLimit == 0 {
		cfg.TaskHistoryLimit = 1
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	// Initialize Swarm
	req := swarm.InitRequest{
		ListenAddr:    cfg.ListenAddr,
		AdvertiseAddr: cfg.AdvertiseAddr,
		Spec: swarm.Spec{
			Orchestration: swarm.OrchestrationConfig{
				TaskHistoryRetentionLimit: intPtr(cfg.TaskHistoryLimit),
			},
		},
	}

	_, err = s.client.SwarmInit(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to initialize Swarm: %w", err)
	}

	return nil
}

// InitWithDefaults initializes Swarm with CubeOS default settings.
func (s *SwarmManager) InitWithDefaults() error {
	return s.Init(DefaultSwarmConfig())
}

// SetTaskHistoryLimit updates the Swarm task history retention limit.
// Setting this to 1 prevents memory bloat from task history on Pi.
// IMPORTANT: Hardware watchdog max timeout is 15 seconds, so keep this low.
func (s *SwarmManager) SetTaskHistoryLimit(limit int) error {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	swarmInfo, err := s.client.SwarmInspect(ctx)
	if err != nil {
		return fmt.Errorf("failed to inspect Swarm: %w", err)
	}

	swarmInfo.Spec.Orchestration.TaskHistoryRetentionLimit = intPtr(limit)

	err = s.client.SwarmUpdate(ctx, swarmInfo.Version, swarmInfo.Spec, swarm.UpdateFlags{})
	if err != nil {
		return fmt.Errorf("failed to update Swarm settings: %w", err)
	}

	return nil
}

// DeployStack deploys a docker-compose.yml file as a Swarm stack.
// This uses `docker stack deploy` via exec because the Docker API
// doesn't have native stack support - stacks are a CLI concept.
//
// CRITICAL: --resolve-image=never is used for ARM64 compatibility
// to avoid manifest resolution issues on Raspberry Pi.
func (s *SwarmManager) DeployStack(name, composePath string) error {
	if name == "" {
		return fmt.Errorf("stack name cannot be empty")
	}
	if composePath == "" {
		return fmt.Errorf("compose path cannot be empty")
	}

	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer cancel()

	// Use docker stack deploy command
	// --resolve-image=never is critical for ARM64 to avoid manifest resolution issues
	cmd := exec.CommandContext(ctx, "docker", "stack", "deploy",
		"-c", composePath,
		"--resolve-image=never",
		name,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to deploy stack %s: %w\nOutput: %s", name, err, string(output))
	}

	return nil
}

// RemoveStack removes a Swarm stack and all its services.
func (s *SwarmManager) RemoveStack(name string) error {
	if name == "" {
		return fmt.Errorf("stack name cannot be empty")
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "stack", "rm", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove stack %s: %w\nOutput: %s", name, err, string(output))
	}

	return nil
}

// ListStacks returns all deployed Swarm stacks.
func (s *SwarmManager) ListStacks() ([]Stack, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	// Get all services with stack labels
	services, err := s.client.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	// Group services by stack name
	stackMap := make(map[string]int)
	for _, svc := range services {
		stackName := svc.Spec.Labels["com.docker.stack.namespace"]
		if stackName != "" {
			stackMap[stackName]++
		}
	}

	// Convert to Stack slice
	stacks := make([]Stack, 0, len(stackMap))
	for name, count := range stackMap {
		stacks = append(stacks, Stack{
			Name:     name,
			Services: count,
		})
	}

	return stacks, nil
}

// StackExists checks if a stack with the given name exists.
func (s *SwarmManager) StackExists(name string) (bool, error) {
	stacks, err := s.ListStacks()
	if err != nil {
		return false, err
	}

	for _, stack := range stacks {
		if stack.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// GetStackServices returns all services belonging to a stack.
func (s *SwarmManager) GetStackServices(stackName string) ([]StackService, error) {
	if stackName == "" {
		return nil, fmt.Errorf("stack name cannot be empty")
	}

	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	// Filter services by stack namespace
	filterArgs := filters.NewArgs()
	filterArgs.Add("label", fmt.Sprintf("com.docker.stack.namespace=%s", stackName))

	services, err := s.client.ServiceList(ctx, types.ServiceListOptions{
		Filters: filterArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list stack services: %w", err)
	}

	result := make([]StackService, 0, len(services))
	for _, svc := range services {
		// Get replica status
		replicas := s.getReplicaStatusWithContext(ctx, svc)

		// Get mode
		mode := "replicated"
		if svc.Spec.Mode.Global != nil {
			mode = "global"
		}

		// Get ports
		ports := s.formatPorts(svc.Endpoint.Ports)

		result = append(result, StackService{
			ID:       svc.ID,
			Name:     svc.Spec.Name,
			Mode:     mode,
			Replicas: replicas,
			Image:    svc.Spec.TaskTemplate.ContainerSpec.Image,
			Ports:    ports,
		})
	}

	return result, nil
}

// GetServiceStatus returns the current status of a service.
// The serviceName can be the full name (stack_service) or just the service name.
// FIXED: Now uses context with timeout to prevent blocking forever.
func (s *SwarmManager) GetServiceStatus(serviceName string) (*ServiceStatus, error) {
	// Use a 5-second timeout for status checks
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	return s.GetServiceStatusWithContext(ctx, serviceName)
}

// GetServiceStatusWithContext returns service status using the provided context.
func (s *SwarmManager) GetServiceStatusWithContext(ctx context.Context, serviceName string) (*ServiceStatus, error) {
	if serviceName == "" {
		return nil, fmt.Errorf("service name cannot be empty")
	}

	// Try to find the service
	filterArgs := filters.NewArgs()
	filterArgs.Add("name", serviceName)

	services, err := s.client.ServiceList(ctx, types.ServiceListOptions{
		Filters: filterArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("service %s not found", serviceName)
	}

	// Find exact match (filter is prefix-based)
	var svc *swarm.Service
	for i := range services {
		if services[i].Spec.Name == serviceName {
			svc = &services[i]
			break
		}
	}
	if svc == nil {
		// Take first match if no exact match
		svc = &services[0]
	}

	// Get replica status with context
	replicas := s.getReplicaStatusWithContext(ctx, *svc)
	running, desired := parseReplicas(replicas)

	// Determine health status
	health := s.determineHealth(*svc, running, desired)

	// Get ports
	ports := make([]string, 0)
	for _, p := range svc.Endpoint.Ports {
		ports = append(ports, fmt.Sprintf("%d/%s", p.PublishedPort, p.Protocol))
	}

	return &ServiceStatus{
		Name:        svc.Spec.Name,
		Running:     running > 0 && running == desired,
		Replicas:    replicas,
		Image:       svc.Spec.TaskTemplate.ContainerSpec.Image,
		Ports:       ports,
		Health:      health,
		LastUpdated: svc.UpdatedAt,
	}, nil
}

// GetServiceLogs retrieves the last N lines of logs from a service.
func (s *SwarmManager) GetServiceLogs(serviceName string, lines int) ([]string, error) {
	if serviceName == "" {
		return nil, fmt.Errorf("service name cannot be empty")
	}
	if lines <= 0 {
		lines = 100 // Default
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", lines),
		Timestamps: true,
	}

	logs, err := s.client.ServiceLogs(ctx, serviceName, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get service logs: %w", err)
	}
	defer logs.Close()

	// Read and parse logs
	var logLines []string
	reader := bufio.NewReader(logs)
	for {
		// Docker multiplexed stream format: 8 byte header + data
		header := make([]byte, 8)
		_, err := io.ReadFull(reader, header)
		if err == io.EOF {
			break
		}
		if err != nil {
			// Try reading as plain text (some services don't use multiplexed format)
			line, err := reader.ReadString('\n')
			if err == io.EOF {
				if line != "" {
					logLines = append(logLines, strings.TrimSpace(line))
				}
				break
			}
			if err != nil {
				return logLines, nil // Return what we have
			}
			logLines = append(logLines, strings.TrimSpace(line))
			continue
		}

		// Parse multiplexed frame
		size := int(header[4])<<24 | int(header[5])<<16 | int(header[6])<<8 | int(header[7])
		if size > 0 {
			data := make([]byte, size)
			_, err := io.ReadFull(reader, data)
			if err != nil {
				break
			}
			logLines = append(logLines, strings.TrimSpace(string(data)))
		}
	}

	return logLines, nil
}

// ScaleService updates the replica count for a service.
func (s *SwarmManager) ScaleService(serviceName string, replicas uint64) error {
	if serviceName == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	// Get current service spec
	svc, _, err := s.client.ServiceInspectWithRaw(ctx, serviceName, types.ServiceInspectOptions{})
	if err != nil {
		return fmt.Errorf("failed to inspect service: %w", err)
	}

	// Update replicas
	if svc.Spec.Mode.Replicated == nil {
		return fmt.Errorf("service %s is not in replicated mode", serviceName)
	}
	svc.Spec.Mode.Replicated.Replicas = &replicas

	// Apply update
	_, err = s.client.ServiceUpdate(ctx, svc.ID, svc.Version, svc.Spec, types.ServiceUpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to scale service: %w", err)
	}

	return nil
}

// RestartService forces a service to restart by updating it with a no-op change.
func (s *SwarmManager) RestartService(serviceName string) error {
	if serviceName == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	// Get current service spec
	svc, _, err := s.client.ServiceInspectWithRaw(ctx, serviceName, types.ServiceInspectOptions{})
	if err != nil {
		return fmt.Errorf("failed to inspect service: %w", err)
	}

	// Force update by incrementing ForceUpdate counter
	svc.Spec.TaskTemplate.ForceUpdate++

	// Apply update
	_, err = s.client.ServiceUpdate(ctx, svc.ID, svc.Version, svc.Spec, types.ServiceUpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to restart service: %w", err)
	}

	return nil
}

// WaitForService waits for a service to reach the desired state.
// It respects the parent context for cancellation and applies the given timeout.
func (s *SwarmManager) WaitForService(serviceName string, timeout time.Duration) error {
	return s.WaitForServiceWithContext(s.ctx, serviceName, timeout)
}

// WaitForServiceWithContext waits for a service using the provided context.
func (s *SwarmManager) WaitForServiceWithContext(ctx context.Context, serviceName string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		status, err := s.GetServiceStatusWithContext(ctx, serviceName)
		if err == nil && status.Running {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for service %s to be ready: %w", serviceName, ctx.Err())
		case <-ticker.C:
			// retry
		}
	}
}

// GetSwarmInfo returns information about the Swarm cluster.
func (s *SwarmManager) GetSwarmInfo() (*swarm.Swarm, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	info, err := s.client.SwarmInspect(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect Swarm: %w", err)
	}
	return &info, nil
}

// CreateOverlayNetwork creates an overlay network for Swarm services.
// Uses exec to call docker network create for simplicity.
func (s *SwarmManager) CreateOverlayNetwork(name, subnet string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	// Check if network already exists
	checkCmd := exec.CommandContext(ctx, "docker", "network", "inspect", name)
	if err := checkCmd.Run(); err == nil {
		return nil // Network already exists
	}

	// Create network
	args := []string{"network", "create", "--driver", "overlay", "--attachable"}
	if subnet != "" {
		args = append(args, "--subnet", subnet)
	}
	args = append(args, name)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create network %s: %w\nOutput: %s", name, err, string(output))
	}

	return nil
}

// Helper functions

// getReplicaStatusWithContext gets replica status with a context for timeout
func (s *SwarmManager) getReplicaStatusWithContext(ctx context.Context, svc swarm.Service) string {
	// Get running tasks
	filterArgs := filters.NewArgs()
	filterArgs.Add("service", svc.ID)
	filterArgs.Add("desired-state", "running")

	tasks, err := s.client.TaskList(ctx, types.TaskListOptions{
		Filters: filterArgs,
	})
	if err != nil {
		return "0/?"
	}

	running := 0
	for _, task := range tasks {
		if task.Status.State == swarm.TaskStateRunning {
			running++
		}
	}

	// Get desired replicas
	desired := 1
	if svc.Spec.Mode.Replicated != nil && svc.Spec.Mode.Replicated.Replicas != nil {
		desired = int(*svc.Spec.Mode.Replicated.Replicas)
	}

	return fmt.Sprintf("%d/%d", running, desired)
}

func (s *SwarmManager) formatPorts(ports []swarm.PortConfig) string {
	if len(ports) == 0 {
		return ""
	}

	var parts []string
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d:%d/%s", p.PublishedPort, p.TargetPort, p.Protocol))
	}
	return strings.Join(parts, ", ")
}

func (s *SwarmManager) determineHealth(svc swarm.Service, running, desired int) string {
	if desired == 0 {
		return "stopped"
	}
	if running == 0 {
		return "stopped"
	}
	if running < desired {
		return "starting"
	}
	if running == desired {
		// Even if a healthcheck is configured, Swarm reports tasks as "running"
		// before health checks pass. We can't distinguish "healthy" from
		// "health check pending" purely from service spec. Return "running"
		// and let the caller inspect task-level health if needed.
		return "running"
	}
	return "unknown"
}

func parseReplicas(replicas string) (running, desired int) {
	parts := strings.Split(replicas, "/")
	if len(parts) != 2 {
		return 0, 0
	}
	fmt.Sscanf(parts[0], "%d", &running)
	fmt.Sscanf(parts[1], "%d", &desired)
	return
}

func intPtr(i int) *int64 {
	v := int64(i)
	return &v
}
