// Package docker provides Docker SDK integration for container management.
package docker

import (
	"context"

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

// IsConnected returns true if the Docker client is connected and responsive.
func (m *Manager) IsConnected(ctx context.Context) bool {
	if m.client == nil {
		return false
	}
	_, err := m.client.Ping(ctx)
	return err == nil
}

// TODO: Implement in Sprint 1.2:
// - ListContainers(ctx context.Context, all bool) ([]ContainerInfo, error)
// - GetContainer(ctx context.Context, id string) (*ContainerDetail, error)
// - StartContainer(ctx context.Context, id string) error
// - StopContainer(ctx context.Context, id string, timeout time.Duration) error
// - RestartContainer(ctx context.Context, id string, timeout time.Duration) error
// - GetContainerLogs(ctx context.Context, id string, opts LogOptions) (io.ReadCloser, error)
// - GetContainerStats(ctx context.Context, id string) (*ContainerStats, error)
