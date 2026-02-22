// Package workflows provides FlowEngine workflow definitions for CubeOS.
package workflows

import (
	"time"

	"cubeos-api/internal/flowengine"
)

const (
	// AppInstallType is the workflow type for app installation.
	AppInstallType = "app_install"
	// AppInstallVersion is the current version of the workflow definition.
	AppInstallVersion = 1
)

// AppInstallWorkflow defines the step sequence for installing an app.
// Replaces Orchestrator.InstallApp() with tracked, retried, compensating steps.
//
// Step order rationale:
//  0. validate — fail fast before any side effects
//  1. allocate_port — needed before compose write (port goes into compose YAML)
//  2. create_dirs — create app directories for compose + data
//  3. write_compose — write docker-compose.yml with allocated port
//  4. deploy_stack — deploy to Swarm (idempotent via docker stack deploy)
//  5. wait_convergence — observe replicas converging (no side effect)
//  6. insert_db — record in database AFTER successful deploy
//  7. add_dns — Pi-hole DNS entry (AFTER db so we have the app ID for FQDN record)
//  8. create_proxy — NPM reverse proxy (last external service)
//
// Key improvement over Orchestrator.InstallApp():
//   - Deploy happens BEFORE db insert (step 4 before step 6). If deploy fails,
//     compensation skips db cleanup because step 6 never ran.
//   - Port allocation has explicit compensation (db.release_port) — fixes the
//     existing port leak bug where failed installs never release allocated ports.
type AppInstallWorkflow struct{}

func (w *AppInstallWorkflow) Type() string { return AppInstallType }
func (w *AppInstallWorkflow) Version() int { return AppInstallVersion }

func (w *AppInstallWorkflow) Steps() []flowengine.StepDefinition {
	return []flowengine.StepDefinition{
		{
			Name:       "validate",
			Action:     "app_install.validate",
			Compensate: "", // read-only, no compensation needed
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			Name:       "allocate_port",
			Action:     "db.allocate_port",
			Compensate: "db.release_port",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 500 * time.Millisecond},
			Timeout:    10 * time.Second,
		},
		{
			Name:       "create_dirs",
			Action:     "app.create_dirs",
			Compensate: "app.remove_dirs",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			Name:       "write_compose",
			Action:     "app.write_compose",
			Compensate: "app.remove_dirs", // cleanup compose file via dir removal
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 1},
			Timeout:    10 * time.Second,
		},
		{
			Name:       "deploy_stack",
			Action:     "docker.deploy_stack",
			Compensate: "docker.remove_stack",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    60 * time.Second,
		},
		{
			Name:       "wait_convergence",
			Action:     "docker.wait_convergence",
			Compensate: "", // observation-only, no compensation
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 2, InitialInterval: 5 * time.Second},
			Timeout:    120 * time.Second,
		},
		{
			Name:       "insert_db",
			Action:     "db.insert_app",
			Compensate: "db.delete_app",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    10 * time.Second,
		},
		{
			Name:       "add_dns",
			Action:     "infra.add_dns",
			Compensate: "infra.remove_dns",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    15 * time.Second,
		},
		{
			Name:       "create_proxy",
			Action:     "infra.create_proxy",
			Compensate: "infra.remove_proxy",
			Retry:      &flowengine.RetryPolicy{MaxAttempts: 3, InitialInterval: 1 * time.Second, MaxInterval: 10 * time.Second},
			Timeout:    15 * time.Second,
		},
	}
}

// NewAppInstallWorkflow creates a new AppInstallWorkflow definition.
func NewAppInstallWorkflow() *AppInstallWorkflow {
	return &AppInstallWorkflow{}
}
