// Package docker provides transport-level circuit breaking for Docker SDK clients.
//
// The Docker Go SDK routes all non-hijack operations through http.Client.Do() →
// http.RoundTripper. By injecting a custom RoundTripper via client.WithHTTPClient(),
// we get a single funnel for circuit breaking, metrics, and observability without
// touching any SDK call sites.
//
// ~95% of SDK operations flow through RoundTrip(). The only exceptions are
// ContainerAttach(), ContainerExecAttach(), and DialHijack() which dial raw sockets.
// CubeOS does not use these — all operations are management-level.
package docker

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"cubeos-api/internal/circuitbreaker"
)

// funnelTransport wraps an inner http.RoundTripper with circuit breaker protection.
// All Docker SDK HTTP calls flow through this transport, enabling:
//   - Circuit breaking: fast-fail when Docker daemon is unresponsive
//   - Request counting: atomic counters for future Prometheus metrics (Batch 2.6)
//
// Error classification:
//   - Network/transport errors → breaker failure
//   - HTTP 5xx responses → breaker failure
//   - HTTP 4xx responses → NOT a failure (expected application responses)
type funnelTransport struct {
	inner    http.RoundTripper
	cb       *circuitbreaker.CircuitBreaker
	requests atomic.Int64
	failures atomic.Int64
}

// RoundTrip implements http.RoundTripper. Every Docker SDK HTTP call passes through
// this method, which wraps the inner transport with circuit breaker protection.
//
// When the circuit is open, returns ErrCircuitOpen in <1ms without contacting Docker.
// When the circuit is closed/half-open, delegates to the inner transport and classifies
// the result: network errors and 5xx count as failures, everything else is a success.
func (t *funnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests.Add(1)

	var resp *http.Response
	cbErr := t.cb.Execute(func() error {
		var err error
		resp, err = t.inner.RoundTrip(req)
		if err != nil {
			// Network/transport error → breaker failure
			t.failures.Add(1)
			return err
		}

		// Classify HTTP status codes
		if resp.StatusCode >= 500 {
			// 5xx → breaker failure (Docker daemon error)
			t.failures.Add(1)
			return fmt.Errorf("docker: server error %d", resp.StatusCode)
		}

		// 2xx, 3xx, 4xx → success (normal application responses)
		return nil
	})

	if cbErr != nil {
		// If the circuit breaker rejected the call (ErrCircuitOpen),
		// resp is nil — return the error directly
		if resp == nil {
			return nil, cbErr
		}
		// If we got a resp but the error was from 5xx classification,
		// return the response so callers can read the error body
		return resp, nil
	}

	return resp, nil
}

// Requests returns the total number of requests that entered the transport.
// Safe for concurrent use (atomic counter).
func (t *funnelTransport) Requests() int64 {
	return t.requests.Load()
}

// Failures returns the total number of failures recorded by the transport.
// Safe for concurrent use (atomic counter).
func (t *funnelTransport) Failures() int64 {
	return t.failures.Load()
}

// NewDockerHTTPClient creates an *http.Client with the funnelTransport wrapping
// the provided inner transport. The circuit breaker is shared — both DockerManager
// and SwarmManager should use the same breaker since they hit the same daemon.
//
// Usage:
//
//	// Extract the SDK-configured transport (has Unix socket dialer)
//	tmpCli, _ := client.NewClientWithOpts(client.FromEnv)
//	innerTransport := tmpCli.HTTPClient().Transport
//	tmpCli.Close()
//
//	// Create wrapped HTTP client
//	httpClient := docker.NewDockerHTTPClient(innerTransport, cb)
//
//	// Build the real SDK client with our transport
//	cli, _ := client.NewClientWithOpts(
//	    client.FromEnv,
//	    client.WithHTTPClient(httpClient),
//	    client.WithAPIVersionNegotiation(),
//	)
func NewDockerHTTPClient(inner http.RoundTripper, cb *circuitbreaker.CircuitBreaker) *http.Client {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &http.Client{
		Transport: &funnelTransport{
			inner: inner,
			cb:    cb,
		},
	}
}

// TransportCircuitState returns the circuit breaker state from an *http.Client
// that was created by NewDockerHTTPClient. Returns StateClosed if the client
// doesn't use a funnelTransport (defensive).
func TransportCircuitState(httpClient *http.Client) circuitbreaker.State {
	if httpClient == nil {
		return circuitbreaker.StateClosed
	}
	if ft, ok := httpClient.Transport.(*funnelTransport); ok {
		return ft.cb.State()
	}
	return circuitbreaker.StateClosed
}

// TransportMetrics returns (requests, failures) counters from an *http.Client
// that was created by NewDockerHTTPClient. Returns (0, 0) if the client
// doesn't use a funnelTransport.
func TransportMetrics(httpClient *http.Client) (requests, failures int64) {
	if httpClient == nil {
		return 0, 0
	}
	if ft, ok := httpClient.Transport.(*funnelTransport); ok {
		return ft.Requests(), ft.Failures()
	}
	return 0, 0
}
