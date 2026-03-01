package activities

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// DNSManager defines the Pi-hole operations needed by infra activities.
// Satisfied by *managers.PiholeManager.
type DNSManager interface {
	AddEntry(domain, ip string) error
	RemoveEntry(domain string) error
	GetEntry(domain string) (string, error) // returns IP or empty string
}

// ProxyManager defines the NPM operations needed by infra activities.
// Satisfied by *managers.NPMManager.
type ProxyManager interface {
	CreateProxyHost(ctx context.Context, domain string, forwardHost string, forwardPort int, forwardScheme string) (int64, error)
	FindProxyHostByDomain(domain string) (int64, error) // returns host ID or 0
	DeleteProxyHost(ctx context.Context, id int64) error
}

// AccessProfileReader provides the current access profile to infra activities.
// When profile is "standard", DNS and proxy steps are skipped entirely.
type AccessProfileReader interface {
	GetAccessProfile() (string, error)
}

// --- Input/Output Schemas ---

// AddDNSInput is the input for the infra.add_dns activity.
type AddDNSInput struct {
	Domain     string `json:"domain"`                // e.g. "nextcloud.cubeos.cube" (if empty, generated from AppName)
	IP         string `json:"ip"`                    // e.g. "10.42.24.1" (defaults to gateway IP)
	AppName    string `json:"app_name,omitempty"`    // used to generate prettified subdomain
	StoreID    string `json:"store_id,omitempty"`    // store ID for prefix stripping
	BaseDomain string `json:"base_domain,omitempty"` // e.g. "cubeos.cube" (defaults to "cubeos.cube")
}

// AddDNSOutput is the output of the infra.add_dns activity.
type AddDNSOutput struct {
	Domain    string `json:"domain"`
	Subdomain string `json:"subdomain"` // clean subdomain portion
	IP        string `json:"ip"`
	Created   bool   `json:"created"`
	Skipped   bool   `json:"skipped"` // true if entry already existed or profile=standard
}

// RemoveDNSInput is the input for the infra.remove_dns activity.
type RemoveDNSInput struct {
	Domain string `json:"domain"`
}

// RemoveDNSOutput is the output of the infra.remove_dns activity.
type RemoveDNSOutput struct {
	Domain  string `json:"domain"`
	Removed bool   `json:"removed"`
}

// CreateProxyInput is the input for the infra.create_proxy activity.
type CreateProxyInput struct {
	Domain        string `json:"domain"`         // e.g. "nextcloud.cubeos.cube"
	ForwardHost   string `json:"forward_host"`   // e.g. "10.42.24.1"
	ForwardPort   int    `json:"forward_port"`   // e.g. 6100
	ForwardScheme string `json:"forward_scheme"` // "http" or "https", defaults to "http"
}

// CreateProxyOutput is the output of the infra.create_proxy activity.
type CreateProxyOutput struct {
	Domain  string `json:"domain"`
	HostID  int64  `json:"host_id"`
	Created bool   `json:"created"`
	Skipped bool   `json:"skipped"` // true if proxy already existed or profile=standard
}

// RemoveProxyInput is the input for the infra.remove_proxy activity.
type RemoveProxyInput struct {
	Domain string `json:"domain"`            // used to look up proxy host ID
	HostID int64  `json:"host_id,omitempty"` // optional direct ID
}

// RemoveProxyOutput is the output of the infra.remove_proxy activity.
type RemoveProxyOutput struct {
	Domain  string `json:"domain"`
	Removed bool   `json:"removed"`
}

// RegisterInfraActivities registers all infrastructure activities in the registry.
// Activities: infra.add_dns, infra.remove_dns, infra.create_proxy, infra.remove_proxy.
func RegisterInfraActivities(registry *flowengine.ActivityRegistry, dnsMgr DNSManager, proxyMgr ProxyManager, profileReader AccessProfileReader) {
	registry.MustRegister("infra.add_dns", makeAddDNS(dnsMgr, profileReader))
	registry.MustRegister("infra.remove_dns", makeRemoveDNS(dnsMgr, profileReader))
	registry.MustRegister("infra.create_proxy", makeCreateProxy(proxyMgr, profileReader))
	registry.MustRegister("infra.remove_proxy", makeRemoveProxy(proxyMgr, profileReader))
}

// makeAddDNS creates the infra.add_dns activity.
// Idempotent: if the DNS entry already exists with the same IP, returns skipped=true.
// If Domain is empty but AppName is provided, generates from prettified subdomain.
// When access profile is "standard", skips DNS creation entirely.
func makeAddDNS(dnsMgr DNSManager, profileReader AccessProfileReader) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		// Check access profile — standard skips DNS entirely
		profile, err := profileReader.GetAccessProfile()
		if err != nil {
			return nil, fmt.Errorf("add_dns: failed to read access profile: %w", err)
		}
		if profile == "standard" {
			log.Info().Str("profile", profile).Msg("add_dns: skipping DNS setup (standard profile)")
			return marshalOutput(AddDNSOutput{
				Skipped: true,
				Created: false,
			})
		}

		var in AddDNSInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid add_dns input: %w", err))
		}
		if in.IP == "" {
			in.IP = models.DefaultGatewayIP // default gateway IP
		}

		// Generate domain from app name if not explicitly provided
		subdomain := ""
		if in.Domain == "" {
			if in.AppName == "" {
				return nil, flowengine.NewPermanentError(fmt.Errorf("domain or app_name is required"))
			}
			baseDomain := in.BaseDomain
			if baseDomain == "" {
				baseDomain = "cubeos.cube"
			}
			subdomain = prettifySubdomain(in.AppName, in.StoreID)
			in.Domain = subdomain + "." + baseDomain
		} else {
			// Extract subdomain from provided domain
			subdomain = strings.Split(in.Domain, ".")[0]
		}

		// Idempotency check: does the entry already exist?
		existingIP, err := dnsMgr.GetEntry(in.Domain)
		if err == nil && existingIP != "" {
			log.Info().Str("domain", in.Domain).Str("ip", existingIP).Msg("add_dns: entry already exists, skipping")
			return marshalOutput(AddDNSOutput{
				Domain:    in.Domain,
				Subdomain: subdomain,
				IP:        existingIP,
				Created:   true,
				Skipped:   true,
			})
		}

		log.Info().Str("domain", in.Domain).Str("ip", in.IP).Msg("add_dns: creating DNS entry")
		if err := dnsMgr.AddEntry(in.Domain, in.IP); err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(AddDNSOutput{
			Domain:    in.Domain,
			Subdomain: subdomain,
			IP:        in.IP,
			Created:   true,
			Skipped:   false,
		})
	}
}

// makeRemoveDNS creates the infra.remove_dns activity.
// Idempotent: if the entry doesn't exist, returns success with removed=false.
// When access profile is "standard", skips DNS removal entirely.
func makeRemoveDNS(dnsMgr DNSManager, profileReader AccessProfileReader) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		// Check access profile — standard skips DNS removal
		profile, err := profileReader.GetAccessProfile()
		if err != nil {
			return nil, fmt.Errorf("remove_dns: failed to read access profile: %w", err)
		}
		if profile == "standard" {
			log.Info().Str("profile", profile).Msg("remove_dns: skipping DNS removal (standard profile)")
			return marshalOutput(RemoveDNSOutput{Removed: false})
		}

		var in RemoveDNSInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid remove_dns input: %w", err))
		}
		if in.Domain == "" {
			return nil, flowengine.NewPermanentError(fmt.Errorf("domain is required"))
		}

		log.Info().Str("domain", in.Domain).Msg("remove_dns: removing DNS entry")
		if err := dnsMgr.RemoveEntry(in.Domain); err != nil {
			// Not found → already removed → success
			if isNotFoundError(err) {
				return marshalOutput(RemoveDNSOutput{Domain: in.Domain, Removed: false})
			}
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(RemoveDNSOutput{Domain: in.Domain, Removed: true})
	}
}

// makeCreateProxy creates the infra.create_proxy activity.
// Idempotent: if a proxy host for the domain already exists, returns skipped=true.
// When access profile is "standard", skips proxy creation entirely.
func makeCreateProxy(proxyMgr ProxyManager, profileReader AccessProfileReader) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		// Check access profile — standard skips proxy creation
		profile, err := profileReader.GetAccessProfile()
		if err != nil {
			return nil, fmt.Errorf("create_proxy: failed to read access profile: %w", err)
		}
		if profile == "standard" {
			log.Info().Str("profile", profile).Msg("create_proxy: skipping proxy setup (standard profile)")
			return marshalOutput(CreateProxyOutput{
				Skipped: true,
				Created: false,
			})
		}

		var in CreateProxyInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid create_proxy input: %w", err))
		}

		// Fat-envelope passes allocated port as "port", but this struct reads "forward_port".
		// Accept either key so callers don't need to rename the field in workflow input.
		// Must run BEFORE validation so the port fallback is applied before we check.
		if in.ForwardPort == 0 {
			var portFallback struct {
				Port int `json:"port"`
			}
			_ = json.Unmarshal(input, &portFallback)
			in.ForwardPort = portFallback.Port
		}

		if in.Domain == "" || in.ForwardPort == 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("domain and forward_port are required"))
		}
		if in.ForwardHost == "" {
			in.ForwardHost = models.DefaultGatewayIP
		}
		if in.ForwardScheme == "" {
			in.ForwardScheme = "http"
		}

		// Idempotency check: does a proxy host for this domain already exist?
		existingID, err := proxyMgr.FindProxyHostByDomain(in.Domain)
		if err == nil && existingID > 0 {
			log.Info().Str("domain", in.Domain).Int64("host_id", existingID).Msg("create_proxy: proxy already exists, skipping")
			return marshalOutput(CreateProxyOutput{
				Domain:  in.Domain,
				HostID:  existingID,
				Created: true,
				Skipped: true,
			})
		}

		log.Info().Str("domain", in.Domain).Int("port", in.ForwardPort).Msg("create_proxy: creating proxy host")
		hostID, err := proxyMgr.CreateProxyHost(ctx, in.Domain, in.ForwardHost, in.ForwardPort, in.ForwardScheme)
		if err != nil {
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(CreateProxyOutput{
			Domain:  in.Domain,
			HostID:  hostID,
			Created: true,
			Skipped: false,
		})
	}
}

// makeRemoveProxy creates the infra.remove_proxy activity.
// Idempotent: if the proxy host doesn't exist, returns success with removed=false.
// When access profile is "standard", skips proxy removal entirely.
func makeRemoveProxy(proxyMgr ProxyManager, profileReader AccessProfileReader) flowengine.ActivityFunc {
	return func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		// Check access profile — standard skips proxy removal
		profile, err := profileReader.GetAccessProfile()
		if err != nil {
			return nil, fmt.Errorf("remove_proxy: failed to read access profile: %w", err)
		}
		if profile == "standard" {
			log.Info().Str("profile", profile).Msg("remove_proxy: skipping proxy removal (standard profile)")
			return marshalOutput(RemoveProxyOutput{Removed: false})
		}

		var in RemoveProxyInput
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, flowengine.NewPermanentError(fmt.Errorf("invalid remove_proxy input: %w", err))
		}
		if in.Domain == "" && in.HostID == 0 {
			return nil, flowengine.NewPermanentError(fmt.Errorf("domain or host_id is required"))
		}

		// Resolve host ID from domain if not provided directly
		hostID := in.HostID
		if hostID == 0 {
			var err error
			hostID, err = proxyMgr.FindProxyHostByDomain(in.Domain)
			if err != nil || hostID == 0 {
				log.Info().Str("domain", in.Domain).Msg("remove_proxy: proxy not found, nothing to remove")
				return marshalOutput(RemoveProxyOutput{Domain: in.Domain, Removed: false})
			}
		}

		log.Info().Str("domain", in.Domain).Int64("host_id", hostID).Msg("remove_proxy: deleting proxy host")
		if err := proxyMgr.DeleteProxyHost(context.Background(), hostID); err != nil {
			if isNotFoundError(err) {
				return marshalOutput(RemoveProxyOutput{Domain: in.Domain, Removed: false})
			}
			return nil, flowengine.ClassifyError(err)
		}

		return marshalOutput(RemoveProxyOutput{Domain: in.Domain, Removed: true})
	}
}

// prettifySubdomain strips common CasaOS store prefixes from app names to produce
// clean subdomains. E.g. "big-bear-ghostfolio" → "ghostfolio", "linuxserver-nextcloud" → "nextcloud".
func prettifySubdomain(appName, storeID string) string {
	subdomain := appName

	// Strip known store prefixes
	prefixes := []string{
		"big-bear-",
		"linuxserver-",
		"casaos-",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(subdomain, prefix) {
			stripped := strings.TrimPrefix(subdomain, prefix)
			if stripped != "" {
				subdomain = stripped
			}
			break
		}
	}

	// If storeID contains a slash (org/app format), try the app portion
	if storeID != "" && strings.Contains(storeID, "/") {
		parts := strings.SplitN(storeID, "/", 2)
		if len(parts) == 2 && parts[1] != "" {
			candidate := strings.ToLower(strings.ReplaceAll(parts[1], "_", "-"))
			if len(candidate) > 0 && len(candidate) <= 63 {
				subdomain = candidate
			}
		}
	}

	return subdomain
}

// isNotFoundError checks if an error indicates a resource was not found.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no such") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "404")
}
