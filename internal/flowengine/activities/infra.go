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

// RegisterInfraActivities registers DNS and NPM proxy activities with the registry.
// Called once at engine startup from main.go.
func RegisterInfraActivities(reg *flowengine.ActivityRegistry, pihole *managers.PiholeManager, npm *managers.NPMManager) {
	reg.MustRegister("infra.remove_dns", makeRemoveDNSActivity(pihole))
	reg.MustRegister("infra.remove_proxy", makeRemoveProxyActivity(npm))

	// Stubs for Batch 2.4 (AppInstall workflows)
	reg.MustRegister("infra.add_dns", makeAddDNSStub())
	reg.MustRegister("infra.create_proxy", makeCreateProxyStub())
}

// RemoveDNSInput is the input for the infra.remove_dns activity.
type RemoveDNSInput struct {
	FQDN string `json:"fqdn"`
}

// RemoveDNSOutput is the output of the infra.remove_dns activity.
type RemoveDNSOutput struct {
	FQDN    string `json:"fqdn"`
	Removed bool   `json:"removed"`
}

// makeRemoveDNSActivity creates an idempotent DNS entry removal activity.
// Idempotent: returns success if the entry doesn't exist (Pi-hole v6 RemoveEntry is already idempotent).
func makeRemoveDNSActivity(pihole *managers.PiholeManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RemoveDNSInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("unmarshal input: %w", err))
		}

		if in.FQDN == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("fqdn is required"))
		}

		log.Info().Str("fqdn", in.FQDN).Msg("Activity: removing DNS entry")

		err := pihole.RemoveEntry(in.FQDN)
		if err != nil {
			// Entry not found is OK — idempotent
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "not found") {
				log.Debug().Str("fqdn", in.FQDN).Msg("DNS entry already removed (idempotent)")
				return marshalOutput(RemoveDNSOutput{FQDN: in.FQDN, Removed: false})
			}
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(RemoveDNSOutput{FQDN: in.FQDN, Removed: true})
	}
}

// RemoveProxyInput is the input for the infra.remove_proxy activity.
type RemoveProxyInput struct {
	FQDN string `json:"fqdn"`
}

// RemoveProxyOutput is the output of the infra.remove_proxy activity.
type RemoveProxyOutput struct {
	FQDN    string `json:"fqdn"`
	Removed bool   `json:"removed"`
}

// makeRemoveProxyActivity creates an idempotent NPM proxy host removal activity.
// Idempotent: returns success if no proxy is found for the domain.
func makeRemoveProxyActivity(npm *managers.NPMManager) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		var in RemoveProxyInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("unmarshal input: %w", err))
		}

		if in.FQDN == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("fqdn is required"))
		}

		log.Info().Str("fqdn", in.FQDN).Msg("Activity: removing NPM proxy host")

		// Find the proxy host by domain
		proxyHost, err := npm.FindProxyHostByDomain(in.FQDN)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		if proxyHost == nil {
			// No proxy found — already removed, idempotent
			log.Debug().Str("fqdn", in.FQDN).Msg("NPM proxy not found (idempotent)")
			return marshalOutput(RemoveProxyOutput{FQDN: in.FQDN, Removed: false})
		}

		// Delete the proxy host
		if err := npm.DeleteProxyHost(proxyHost.ID); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(RemoveProxyOutput{FQDN: in.FQDN, Removed: true})
	}
}

// Stubs for Batch 2.4

func makeAddDNSStub() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("infra.add_dns not yet implemented (Batch 2.4)"))
	}
}

func makeCreateProxyStub() flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, flowengine.NewPermanentError(fmt.Errorf("infra.create_proxy not yet implemented (Batch 2.4)"))
	}
}
