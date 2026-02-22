package docker

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"cubeos-api/internal/circuitbreaker"
)

// mockTransport is a configurable http.RoundTripper for testing.
type mockTransport struct {
	statusCode int
	err        error
	body       string
	calls      int
	mu         sync.Mutex
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()

	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.body)),
		Header:     make(http.Header),
	}, nil
}

func (m *mockTransport) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// newTestBreaker creates a circuit breaker with fast timeout for testing.
func newTestBreaker() *circuitbreaker.CircuitBreaker {
	return circuitbreaker.New("docker-test", circuitbreaker.Config{
		Threshold:        3, // low threshold for fast tests
		Timeout:          50 * time.Millisecond,
		SuccessThreshold: 2,
	})
}

func TestFunnelTransport_ClosedPassthrough(t *testing.T) {
	inner := &mockTransport{statusCode: 200, body: `{"ok":true}`}
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(inner, cb)

	req, _ := http.NewRequest("GET", "http://localhost/v1.45/containers/json", nil)
	resp, err := httpClient.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if inner.callCount() != 1 {
		t.Fatalf("expected 1 call to inner transport, got %d", inner.callCount())
	}
	if cb.State() != circuitbreaker.StateClosed {
		t.Fatalf("expected closed, got %s", cb.State())
	}
}

func TestFunnelTransport_OpensAfterThresholdFailures(t *testing.T) {
	inner := &mockTransport{err: errors.New("connection refused")}
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(inner, cb)

	req, _ := http.NewRequest("GET", "http://localhost/v1.45/info", nil)

	// Trip the breaker with threshold failures
	for i := 0; i < 3; i++ {
		_, err := httpClient.Transport.RoundTrip(req)
		if err == nil {
			t.Fatalf("iteration %d: expected error", i)
		}
	}

	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("expected open after %d failures, got %s", 3, cb.State())
	}

	// Next call should be rejected immediately without calling inner
	callsBefore := inner.callCount()
	start := time.Now()
	_, err := httpClient.Transport.RoundTrip(req)
	elapsed := time.Since(start)

	if !errors.Is(err, circuitbreaker.ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got: %v", err)
	}
	if elapsed > 5*time.Millisecond {
		t.Fatalf("open rejection took %v, expected <5ms", elapsed)
	}
	if inner.callCount() != callsBefore {
		t.Fatalf("inner transport should not be called when circuit is open")
	}
}

func TestFunnelTransport_5xxTripsBreaker(t *testing.T) {
	inner := &mockTransport{statusCode: 503, body: `{"message":"service unavailable"}`}
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(inner, cb)

	req, _ := http.NewRequest("GET", "http://localhost/v1.45/info", nil)

	for i := 0; i < 3; i++ {
		resp, _ := httpClient.Transport.RoundTrip(req)
		// 5xx should still return the response (so callers can read error body)
		if resp == nil {
			t.Fatalf("iteration %d: expected response even on 5xx", i)
		}
		if resp.StatusCode != 503 {
			t.Fatalf("iteration %d: expected 503, got %d", i, resp.StatusCode)
		}
	}

	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("expected open after 5xx errors, got %s", cb.State())
	}
}

func TestFunnelTransport_4xxDoesNotTripBreaker(t *testing.T) {
	inner := &mockTransport{statusCode: 404, body: `{"message":"not found"}`}
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(inner, cb)

	req, _ := http.NewRequest("GET", "http://localhost/v1.45/containers/abc123/json", nil)

	// 10 consecutive 404s should NOT trip the breaker
	for i := 0; i < 10; i++ {
		resp, err := httpClient.Transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("iteration %d: expected no error for 4xx, got: %v", i, err)
		}
		if resp.StatusCode != 404 {
			t.Fatalf("iteration %d: expected 404, got %d", i, resp.StatusCode)
		}
	}

	if cb.State() != circuitbreaker.StateClosed {
		t.Fatalf("expected closed after 4xx responses, got %s", cb.State())
	}
}

func TestFunnelTransport_RequestCounter(t *testing.T) {
	inner := &mockTransport{statusCode: 200}
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(inner, cb)

	req, _ := http.NewRequest("GET", "http://localhost/v1.45/info", nil)

	for i := 0; i < 5; i++ {
		httpClient.Transport.RoundTrip(req) //nolint:errcheck
	}

	reqs, _ := TransportMetrics(httpClient)
	if reqs != 5 {
		t.Fatalf("expected 5 requests, got %d", reqs)
	}
}

func TestFunnelTransport_FailureCounter(t *testing.T) {
	inner := &mockTransport{err: errors.New("dial timeout")}
	cb := circuitbreaker.New("docker-test", circuitbreaker.Config{
		Threshold:        100, // high threshold so breaker stays closed
		Timeout:          time.Second,
		SuccessThreshold: 2,
	})
	httpClient := NewDockerHTTPClient(inner, cb)

	req, _ := http.NewRequest("GET", "http://localhost/v1.45/info", nil)

	for i := 0; i < 3; i++ {
		httpClient.Transport.RoundTrip(req) //nolint:errcheck
	}

	_, fails := TransportMetrics(httpClient)
	if fails != 3 {
		t.Fatalf("expected 3 failures, got %d", fails)
	}
}

func TestFunnelTransport_HalfOpenRecovery(t *testing.T) {
	inner := &mockTransport{err: errors.New("connection refused")}
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(inner, cb)

	req, _ := http.NewRequest("GET", "http://localhost/v1.45/info", nil)

	// Trip the breaker
	for i := 0; i < 3; i++ {
		httpClient.Transport.RoundTrip(req) //nolint:errcheck
	}
	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("expected open, got %s", cb.State())
	}

	// Wait for timeout → half-open
	time.Sleep(60 * time.Millisecond)
	if cb.State() != circuitbreaker.StateHalfOpen {
		t.Fatalf("expected half-open after timeout, got %s", cb.State())
	}

	// Fix the inner transport
	inner.err = nil
	inner.statusCode = 200

	// Two successes → close
	for i := 0; i < 2; i++ {
		_, err := httpClient.Transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("half-open success %d: unexpected error: %v", i, err)
		}
	}

	if cb.State() != circuitbreaker.StateClosed {
		t.Fatalf("expected closed after recovery, got %s", cb.State())
	}
}

func TestFunnelTransport_ConcurrentAccess(t *testing.T) {
	inner := &mockTransport{statusCode: 200}
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(inner, cb)

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost/v1.45/containers/%d/json", n), nil)
			for j := 0; j < 10; j++ {
				_, err := httpClient.Transport.RoundTrip(req)
				if err != nil {
					errCh <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("unexpected error: %v", err)
	}

	reqs, _ := TransportMetrics(httpClient)
	if reqs != 500 {
		t.Fatalf("expected 500 requests, got %d", reqs)
	}
}

func TestNewDockerHTTPClient_NilInner(t *testing.T) {
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(nil, cb)

	if httpClient == nil {
		t.Fatal("expected non-nil http client")
	}
	if httpClient.Transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestTransportCircuitState_NilClient(t *testing.T) {
	state := TransportCircuitState(nil)
	if state != circuitbreaker.StateClosed {
		t.Fatalf("expected closed for nil client, got %s", state)
	}
}

func TestTransportCircuitState_RegularClient(t *testing.T) {
	// A regular http.Client without funnelTransport should return closed (defensive)
	regularClient := &http.Client{}
	state := TransportCircuitState(regularClient)
	if state != circuitbreaker.StateClosed {
		t.Fatalf("expected closed for regular client, got %s", state)
	}
}

func TestTransportMetrics_NilClient(t *testing.T) {
	reqs, fails := TransportMetrics(nil)
	if reqs != 0 || fails != 0 {
		t.Fatalf("expected (0, 0) for nil client, got (%d, %d)", reqs, fails)
	}
}

func TestTransportCircuitState_WithFunnelTransport(t *testing.T) {
	inner := &mockTransport{err: errors.New("fail")}
	cb := newTestBreaker()
	httpClient := NewDockerHTTPClient(inner, cb)

	// Trip the breaker
	req, _ := http.NewRequest("GET", "http://localhost/test", nil)
	for i := 0; i < 3; i++ {
		httpClient.Transport.RoundTrip(req) //nolint:errcheck
	}

	state := TransportCircuitState(httpClient)
	if state != circuitbreaker.StateOpen {
		t.Fatalf("expected open, got %s", state)
	}
}
