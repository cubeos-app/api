package circuitbreaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errTest = errors.New("test error")

// newTestCB creates a circuit breaker with injectable time for deterministic tests.
func newTestCB(name string, cfg Config) (*CircuitBreaker, *fakeTime) {
	ft := &fakeTime{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	cb := New(name, cfg)
	cb.nowFunc = ft.Now
	return cb, ft
}

type fakeTime struct {
	now time.Time
}

func (f *fakeTime) Now() time.Time          { return f.now }
func (f *fakeTime) Advance(d time.Duration) { f.now = f.now.Add(d) }

func TestClosedPassthrough(t *testing.T) {
	cb, _ := newTestCB("test", DefaultConfig())

	called := false
	err := cb.Execute(func() error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !called {
		t.Fatal("function was not called")
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected closed, got: %s", cb.State())
	}
	if cb.Failures() != 0 {
		t.Fatalf("expected 0 failures, got: %d", cb.Failures())
	}
}

func TestOpensAfterThresholdFailures(t *testing.T) {
	cb, _ := newTestCB("test", Config{Threshold: 3, Timeout: 30 * time.Second, SuccessThreshold: 2})

	// 2 failures — still closed
	for i := 0; i < 2; i++ {
		cb.Execute(func() error { return errTest })
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected closed after 2 failures, got: %s", cb.State())
	}
	if cb.Failures() != 2 {
		t.Fatalf("expected 2 failures, got: %d", cb.Failures())
	}

	// 3rd failure — opens
	cb.Execute(func() error { return errTest })
	if cb.State() != StateOpen {
		t.Fatalf("expected open after 3 failures, got: %s", cb.State())
	}
}

func TestSuccessResetsFailureCount(t *testing.T) {
	cb, _ := newTestCB("test", Config{Threshold: 3, Timeout: 30 * time.Second, SuccessThreshold: 2})

	// 2 failures, then 1 success
	cb.Execute(func() error { return errTest })
	cb.Execute(func() error { return errTest })
	cb.Execute(func() error { return nil })

	if cb.Failures() != 0 {
		t.Fatalf("expected 0 failures after success, got: %d", cb.Failures())
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected closed, got: %s", cb.State())
	}
}

func TestOpenRejectsImmediately(t *testing.T) {
	cb, _ := newTestCB("test", Config{Threshold: 1, Timeout: 30 * time.Second, SuccessThreshold: 1})

	// Trip the breaker
	cb.Execute(func() error { return errTest })
	if cb.State() != StateOpen {
		t.Fatalf("expected open, got: %s", cb.State())
	}

	// Verify rejection is fast and doesn't call fn
	called := false
	start := time.Now()
	err := cb.Execute(func() error {
		called = true
		return nil
	})
	elapsed := time.Since(start)

	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got: %v", err)
	}
	if called {
		t.Fatal("function should not have been called when circuit is open")
	}
	if elapsed > time.Millisecond {
		t.Fatalf("rejection took %v, expected <1ms", elapsed)
	}
}

func TestHalfOpenAfterTimeout(t *testing.T) {
	cb, ft := newTestCB("test", Config{Threshold: 1, Timeout: 10 * time.Second, SuccessThreshold: 2})

	// Trip the breaker
	cb.Execute(func() error { return errTest })
	if cb.State() != StateOpen {
		t.Fatalf("expected open, got: %s", cb.State())
	}

	// Advance time past timeout
	ft.Advance(11 * time.Second)

	// State() should now report half-open
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected half-open after timeout, got: %s", cb.State())
	}
}

func TestHalfOpenClosesAfterSuccessThreshold(t *testing.T) {
	cb, ft := newTestCB("test", Config{Threshold: 1, Timeout: 10 * time.Second, SuccessThreshold: 2})

	// Trip → open
	cb.Execute(func() error { return errTest })
	ft.Advance(11 * time.Second)

	// First success in half-open — still half-open
	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected half-open after 1 success, got: %s", cb.State())
	}

	// Second success — should close
	cb.Execute(func() error { return nil })
	if cb.State() != StateClosed {
		t.Fatalf("expected closed after 2 successes, got: %s", cb.State())
	}
	if cb.Failures() != 0 {
		t.Fatalf("expected 0 failures after close, got: %d", cb.Failures())
	}
}

func TestHalfOpenReopensOnFailure(t *testing.T) {
	cb, ft := newTestCB("test", Config{Threshold: 1, Timeout: 10 * time.Second, SuccessThreshold: 3})

	// Trip → open → wait → half-open
	cb.Execute(func() error { return errTest })
	ft.Advance(11 * time.Second)

	// One success, then failure
	cb.Execute(func() error { return nil })
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected half-open, got: %s", cb.State())
	}

	cb.Execute(func() error { return errTest })
	if cb.State() != StateOpen {
		t.Fatalf("expected open after half-open failure, got: %s", cb.State())
	}
}

func TestResetClosesCircuit(t *testing.T) {
	cb, _ := newTestCB("test", Config{Threshold: 1, Timeout: 30 * time.Second, SuccessThreshold: 1})

	// Trip the breaker
	cb.Execute(func() error { return errTest })
	if cb.State() != StateOpen {
		t.Fatalf("expected open, got: %s", cb.State())
	}

	// Manual reset
	cb.Reset()
	if cb.State() != StateClosed {
		t.Fatalf("expected closed after reset, got: %s", cb.State())
	}
	if cb.Failures() != 0 {
		t.Fatalf("expected 0 failures after reset, got: %d", cb.Failures())
	}

	// Should accept calls again
	called := false
	cb.Execute(func() error {
		called = true
		return nil
	})
	if !called {
		t.Fatal("function should be called after reset")
	}
}

func TestName(t *testing.T) {
	cb := New("hal", DefaultConfig())
	if cb.Name() != "hal" {
		t.Fatalf("expected name 'hal', got: %s", cb.Name())
	}
}

func TestDefaultConfig(t *testing.T) {
	cb := New("test", Config{})
	cfg := cb.cfg
	if cfg.Threshold != 5 {
		t.Fatalf("expected threshold 5, got: %d", cfg.Threshold)
	}
	if cfg.Timeout != 30*time.Second {
		t.Fatalf("expected timeout 30s, got: %v", cfg.Timeout)
	}
	if cfg.SuccessThreshold != 2 {
		t.Fatalf("expected success threshold 2, got: %d", cfg.SuccessThreshold)
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{State(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", int(tt.state), got, tt.want)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	cb, _ := newTestCB("test", Config{Threshold: 100, Timeout: 30 * time.Second, SuccessThreshold: 2})

	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	// 50 goroutines each doing 100 calls
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				err := cb.Execute(func() error {
					if j%3 == 0 {
						return errTest
					}
					return nil
				})
				if err != nil {
					errorCount.Add(1)
				} else {
					successCount.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	total := successCount.Load() + errorCount.Load()
	if total != 5000 {
		t.Fatalf("expected 5000 total calls, got: %d", total)
	}

	// Circuit should still be in a valid state (no panics, no deadlocks)
	state := cb.State()
	if state != StateClosed && state != StateOpen && state != StateHalfOpen {
		t.Fatalf("invalid state after concurrent access: %s", state)
	}
}

func TestExecutePassesThroughFunctionError(t *testing.T) {
	cb, _ := newTestCB("test", DefaultConfig())

	customErr := errors.New("custom error")
	err := cb.Execute(func() error { return customErr })

	if !errors.Is(err, customErr) {
		t.Fatalf("expected custom error, got: %v", err)
	}
}

func TestOpenToHalfOpenViaExecute(t *testing.T) {
	// Verify that Execute() transitions open → half-open when timeout has passed,
	// rather than requiring a State() call first.
	cb, ft := newTestCB("test", Config{Threshold: 1, Timeout: 5 * time.Second, SuccessThreshold: 1})

	// Trip
	cb.Execute(func() error { return errTest })

	// Advance past timeout
	ft.Advance(6 * time.Second)

	// Next Execute should go through (half-open), not return ErrCircuitOpen
	called := false
	err := cb.Execute(func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error in half-open, got: %v", err)
	}
	if !called {
		t.Fatal("function should have been called in half-open state")
	}
	// After success in half-open (threshold=1), should be closed
	if cb.State() != StateClosed {
		t.Fatalf("expected closed after half-open success, got: %s", cb.State())
	}
}
