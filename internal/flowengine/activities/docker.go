// Package activities provides FlowEngine activity implementations for CubeOS.
// All activities are idempotent: calling them twice with the same input produces the same result.
package activities

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cubeos-api/internal/flowengine"

	"github.com/rs/zerolog/log"
)

// DockerSwarmManager defines the Swarm operations needed by Docker activities.
// Satisfied by *managers.SwarmManager.
type DockerSwarmManager interface {
	DeployStack(name, composePath string) error
	RemoveStack(name string) error
	GetStackServices(name string) ([]interface{}, error)
	ListStacks() ([]interface{}, error)
}

// DockerContainerManager defines the Docker operations needed by Docker activities.
// Satisfied by *managers.DockerManager.
type DockerContainerManager interface {
	ImageExists(ctx context.Context, imageRef string) (bool, error)
	PullImage(ctx context.Context, imageRef string) error
	WaitForServiceConvergence(ctx context.Context, stackName string, timeout time.Duration) error
}

// --- Input/Output Schemas ---

// DeployStackInput is the input for the docker.deploy_stack activity.
type DeployStackInput struct {
	StackName   string `json:"stack_name"`
	ComposePath string `json:"compose_path"`
}

// DeployStackOutput is the output of the docker.deploy_stack activity.
type DeployStackOutput struct {
	StackName string `json:"stack_name"`
	Deployed  bool   `json:"deployed"`
	Skipped   bool   `json:"skipped"` // true if stack already existed
}

// RemoveStackInput is the input for the docker.remove_stack activity.
type RemoveStackInput struct {
	StackName string `json:"stack_name"`
}

// RemoveStackOutput is the output of the docker.remove_stack activity.
type RemoveStackOutput struct {
	StackName string `json:"stack_name"`
	Removed   bool   `json:"removed"`
}

// StopStackInput is the input for the docker.stop_stack activity.
type StopStackInput struct {
	StackName string `json:"stack_name"`
}

// StopStackOutput is the output of the docker.stop_stack activity.
type StopStackOutput struct {
	StackName string `json:"stack_name"`
	Stopped   bool   `json:"stopped"`
}

// PullImageInput is the input for the docker.pull_image activity.
type PullImageInput struct {
	Image string `json:"image"` // e.g. "kiwix/kiwix-serve:3.8.1" or "localhost:5000/nginx:latest"
}

// PullImageOutput is the output of the docker.pull_image activity.
type PullImageOutput struct {
	Image   string `json:"image"`
	Pulled  bool   `json:"pulled"`
	Skipped bool   `json:"skipped"` // true if image already existed locally
}

// WaitConvergenceInput is the input for the docker.wait_convergence activity.
type WaitConvergenceInput struct {
	StackName string        `json:"stack_name"`
	Timeout   time.Duration `json:"timeout,omitempty"` // default 90s
}

// WaitConvergenceOutput is the output of the docker.wait_convergence activity.
type WaitConvergenceOutput struct {
	StackName string `json:"stack_name"`
	Converged bool   `json:"converged"`
}

// RegisterDockerActivities registers all Docker-related activities in the registry.
// Activities: docker.deploy_stack, docker.remove_stack, docker.stop_stack,
// docker.pull_image, docker.wait_convergence.
func RegisterDockerActivities(registry *flowengine.ActivityRegistry, swarmMgr DockerSwarmManager, dockerMgr DockerContainerManager) {
	registry.MustRegister("docker.deploy_stack", makeDeployStack(swarmMgr))
	registry.MustRegister("docker.remove_stack", makeRemoveStack(swarmMgr))
	registry.MustRegister("docker.stop_stack", makeStopStack(swarmMgr))
	registry.MustRegister("docker.pull_image", makePullImage(dockerMgr))
	registry.MustRegister("docker.wait_convergence", makeWaitConvergence(dockerMgr))
}

// makeDeployStack creates the docker.deploy_stack activity.
// Idempotent: if the stack already exists, returns success with skipped=true.
func makeDeployStack(swarmMgr DockerSwarmManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in DeployStackInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid deploy_stack input: %w", err))
		}
		if in.StackName == "" || in.ComposePath == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("stack_name and compose_path are required"))
		}

		// Idempotency check: does the stack already exist?
		services, err := swarmMgr.GetStackServices(in.StackName)
		if err == nil && len(services) > 0 {
			log.Info().Str("stack", in.StackName).Msg("deploy_stack: stack already exists, skipping deploy")
			return marshalOutput(DeployStackOutput{
				StackName: in.StackName,
				Deployed:  true,
				Skipped:   true,
			})
		}

		// Deploy the stack
		log.Info().Str("stack", in.StackName).Str("compose", in.ComposePath).Msg("deploy_stack: deploying")
		if err := swarmMgr.DeployStack(in.StackName, in.ComposePath); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(DeployStackOutput{
			StackName: in.StackName,
			Deployed:  true,
			Skipped:   false,
		})
	}
}

// makeRemoveStack creates the docker.remove_stack activity.
// Idempotent: if the stack doesn't exist, returns success with removed=false.
func makeRemoveStack(swarmMgr DockerSwarmManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RemoveStackInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid remove_stack input: %w", err))
		}
		if in.StackName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("stack_name is required"))
		}

		// Idempotency check: does the stack exist?
		services, err := swarmMgr.GetStackServices(in.StackName)
		if err != nil || len(services) == 0 {
			log.Info().Str("stack", in.StackName).Msg("remove_stack: stack not found, nothing to remove")
			return marshalOutput(RemoveStackOutput{StackName: in.StackName, Removed: false})
		}

		if err := swarmMgr.RemoveStack(in.StackName); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(RemoveStackOutput{StackName: in.StackName, Removed: true})
	}
}

// makeStopStack creates the docker.stop_stack activity.
// Stops by removing the stack (Swarm doesn't have a native scale-to-zero for stacks).
// Idempotent: if the stack doesn't exist, returns success.
func makeStopStack(swarmMgr DockerSwarmManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in StopStackInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid stop_stack input: %w", err))
		}
		if in.StackName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("stack_name is required"))
		}

		services, err := swarmMgr.GetStackServices(in.StackName)
		if err != nil || len(services) == 0 {
			log.Info().Str("stack", in.StackName).Msg("stop_stack: stack not found, nothing to stop")
			return marshalOutput(StopStackOutput{StackName: in.StackName, Stopped: true})
		}

		if err := swarmMgr.RemoveStack(in.StackName); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(StopStackOutput{StackName: in.StackName, Stopped: true})
	}
}

// makePullImage creates the docker.pull_image activity.
// Idempotent: if the image already exists locally, returns success with skipped=true.
func makePullImage(dockerMgr DockerContainerManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in PullImageInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid pull_image input: %w", err))
		}
		if in.Image == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("image is required"))
		}

		// Idempotency check: does the image already exist locally?
		exists, err := dockerMgr.ImageExists(ctx, in.Image)
		if err == nil && exists {
			log.Info().Str("image", in.Image).Msg("pull_image: image already exists locally, skipping")
			return marshalOutput(PullImageOutput{Image: in.Image, Pulled: true, Skipped: true})
		}

		log.Info().Str("image", in.Image).Msg("pull_image: pulling image")
		if err := dockerMgr.PullImage(ctx, in.Image); err != nil {
			// Connection refused / registry down → transient
			// Image not found (404) → permanent
			if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "manifest unknown") {
				return nil, flowengine.NewPermanentError(fmt.Errorf("image not found: %s: %w", in.Image, err))
			}
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(PullImageOutput{Image: in.Image, Pulled: true, Skipped: false})
	}
}

// makeWaitConvergence creates the docker.wait_convergence activity.
// Polls Swarm service status every 2s until all replicas match desired count.
// Idempotent: observation-only, no side effects.
func makeWaitConvergence(dockerMgr DockerContainerManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in WaitConvergenceInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid wait_convergence input: %w", err))
		}
		if in.StackName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("stack_name is required"))
		}

		timeout := in.Timeout
		if timeout == 0 {
			timeout = 90 * time.Second
		}

		log.Info().Str("stack", in.StackName).Dur("timeout", timeout).Msg("wait_convergence: waiting for services")

		if err := dockerMgr.WaitForServiceConvergence(ctx, in.StackName, timeout); err != nil {
			// Timeout is transient — the service might converge on retry
			return nil, flowengine.NewTransientError(fmt.Errorf("convergence timeout for %s: %w", in.StackName, err))
		}

		return marshalOutput(WaitConvergenceOutput{StackName: in.StackName, Converged: true})
	}
}

// marshalOutput is a helper to marshal activity output to JSON.
func marshalOutput(v interface{}) (json.RawMessage, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, flowengine.NewPermanentError(fmt.Errorf("failed to marshal output: %w", err))
	}
	return json.RawMessage(data), nil
}
