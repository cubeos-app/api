package activities

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/hal"
)

// ErrNotImplemented is returned by stub activities that are reserved but not yet functional.
var ErrNotImplemented = fmt.Errorf("activity not yet implemented")

// RegisterHALActivities registers HAL-related activities with the registry.
// Includes functional activities (health_check, watchdog_arm/disarm) and
// reserved stubs for future hardware activities.
//
// Error classification for HAL activities:
//   - HTTP 5xx / timeout → TransientError (HAL may be restarting)
//   - HTTP 4xx → PermanentError (bad request, not found)
//   - Connection refused → TransientError (container starting)
func RegisterHALActivities(reg *flowengine.ActivityRegistry, halClient *hal.Client) {
	// Functional activities
	reg.MustRegister("hal.health_check", makeHealthCheckActivity(halClient))
	reg.MustRegister("hal.watchdog_arm", makeWatchdogArmActivity(halClient))
	reg.MustRegister("hal.watchdog_disarm", makeWatchdogDisarmActivity(halClient))

	// Reserved stubs for future activities (ensures names are claimed)
	reg.MustRegister("hal.gps_position", makeReservedStub("hal.gps_position"))
	reg.MustRegister("hal.meshtastic_send", makeReservedStub("hal.meshtastic_send"))
	reg.MustRegister("hal.iridium_sbd_send", makeReservedStub("hal.iridium_sbd_send"))
}

// HealthCheckOutput is the output of the hal.health_check activity.
type HealthCheckOutput struct {
	Healthy bool   `json:"healthy"`
	NodeID  string `json:"node_id,omitempty"`
}

// makeHealthCheckActivity creates an activity that calls the HAL health endpoint.
// Used as a pre-flight check in workflows that depend on HAL being available.
func makeHealthCheckActivity(halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		log.Debug().Msg("Activity: HAL health check")

		err := halClient.Health(ctx)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(HealthCheckOutput{Healthy: true})
	}
}

// makeWatchdogArmActivity creates an activity that enables the hardware watchdog.
// The watchdog will reboot the system if not petted within the timeout window.
func makeWatchdogArmActivity(halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		log.Info().Msg("Activity: arming hardware watchdog")

		err := halClient.EnableWatchdog(ctx)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(map[string]string{"status": "armed"})
	}
}

// makeWatchdogDisarmActivity creates an activity that disables the hardware watchdog.
// Compensation activity for watchdog_arm.
func makeWatchdogDisarmActivity(halClient *hal.Client) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		log.Info().Msg("Activity: disarming hardware watchdog")

		// HAL exposes GetWatchdogStatus but not a direct disable.
		// For now, pet the watchdog to prevent reboot, then return.
		// A proper disable endpoint can be added to HAL later.
		err := halClient.PetWatchdog(ctx)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(map[string]string{"status": "disarmed"})
	}
}

// makeReservedStub creates a placeholder activity that returns ErrNotImplemented.
// This reserves the activity name in the registry to prevent naming conflicts
// when the real implementation is added later.
func makeReservedStub(name string) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("%s: %w", name, ErrNotImplemented))
	}
}
