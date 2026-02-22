// Package activities provides workflow activity implementations for the FlowEngine.
// Activities are registered by name and resolved at runtime by the step executor.
package activities

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/managers"
)

// RegisterDockerActivities registers all Docker-related activities with the registry.
// Called once at engine startup from main.go.
func RegisterDockerActivities(reg *flowengine.ActivityRegistry, swarm *managers.SwarmManager, docker *managers.DockerManager) {
	reg.MustRegister("docker.remove_stack", makeRemoveStackActivity(swarm))
	reg.MustRegister("docker.stop_stack", makeStopStackActivity(swarm))

	// Stubs for Batch 2.4 (AppInstall workflows)
	reg.MustRegister("docker.deploy_stack", makeDeployStackStub())
	reg.MustRegister("docker.pull_image", makePullImageStub())
	reg.MustRegister("docker.wait_convergence", makeWaitConvergenceStub())
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

// makeRemoveStackActivity creates an idempotent stack removal activity.
// Idempotent: returns success if the stack doesn't exist (already removed).
func makeRemoveStackActivity(swarm *managers.SwarmManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RemoveStackInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("unmarshal input: %w", err))
		}

		if in.StackName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("stack_name is required"))
		}

		log.Info().Str("stack", in.StackName).Msg("Activity: removing Docker stack")

		err := swarm.RemoveStack(in.StackName)
		if err != nil {
			// Stack not found is OK — idempotent
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "no such") {
				log.Debug().Str("stack", in.StackName).Msg("Stack already removed (idempotent)")
				return marshalOutput(RemoveStackOutput{StackName: in.StackName, Removed: false})
			}
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(RemoveStackOutput{StackName: in.StackName, Removed: true})
	}
}

// StopStackInput is the input for the docker.stop_stack activity.
type StopStackInput struct {
	StackName   string `json:"stack_name"`
	ServiceName string `json:"service_name,omitempty"` // if empty, derived as stackname_stackname
}

// makeStopStackActivity creates an activity that scales a service to 0 replicas.
// Idempotent: scaling an already-stopped service to 0 is a no-op.
func makeStopStackActivity(swarm *managers.SwarmManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in StopStackInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("unmarshal input: %w", err))
		}

		if in.StackName == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("stack_name is required"))
		}

		serviceName := in.ServiceName
		if serviceName == "" {
			serviceName = in.StackName + "_" + in.StackName
		}

		log.Info().Str("service", serviceName).Msg("Activity: stopping stack (scale to 0)")

		err := swarm.ScaleService(serviceName, 0)
		if err != nil {
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "no such") {
				log.Debug().Str("service", serviceName).Msg("Service not found (already removed, idempotent)")
				return marshalOutput(map[string]string{"status": "not_found"})
			}
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(map[string]string{"status": "stopped"})
	}
}

// Stubs for Batch 2.4

func makeDeployStackStub() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("docker.deploy_stack not yet implemented (Batch 2.4)"))
	}
}

func makePullImageStub() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("docker.pull_image not yet implemented (Batch 2.4)"))
	}
}

func makeWaitConvergenceStub() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("docker.wait_convergence not yet implemented (Batch 2.4)"))
	}
}

// marshalOutput is a helper that marshals output and handles errors.
func marshalOutput(v interface{}) (json.RawMessage, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, flowengine.NewPermanentError(fmt.Errorf("marshal output: %w", err))
	}
	return data, nil
}
