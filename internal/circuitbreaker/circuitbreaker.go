// Package circuitbreaker provides a thread-safe circuit breaker implementation
// for wrapping fallible external calls. When a dependency fails repeatedly,
// the breaker trips to "open" state and rejects calls immediately (<1ms),
// preventing cascade failures and giving the dependency time to recover.
//
// States:
//   - Closed: normal operation, calls pass through
//   - Open: dependency is down, calls rejected with ErrCircuitOpen
//   - HalfOpen: testing recovery, limited calls allowed through
//
// Zero external dependencies — stdlib + sync only.
package circuitbreaker

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit breaker is in open state.
// Callers should handle this as a fast-fail signal — the dependency is down.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// State represents the current state of the circuit breaker.
type State int

const (
	StateClosed   State = iota // Normal operation
	StateOpen                  // Rejecting calls
	StateHalfOpen              // Testing recovery
)

// String returns the human-readable state name.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// Config holds circuit breaker configuration.
type Config struct {
	// Threshold is the number of consecutive failures before the circuit opens.
	// Default: 5
	Threshold int

	// Timeout is how long the circuit stays open before transitioning to half-open.
	// Default: 30s
	Timeout time.Duration

	// SuccessThreshold is the number of consecutive successes in half-open state
	// needed to close the circuit again.
	// Default: 2
	SuccessThreshold int
}

// DefaultConfig returns sensible defaults for most HTTP client use cases.
func DefaultConfig() Config {
	return Config{
		Threshold:        5,
		Timeout:          30 * time.Second,
		SuccessThreshold: 2,
	}
}

// CircuitBreaker implements the circuit breaker pattern.
// All methods are safe for concurrent use.
type CircuitBreaker struct {
	name string
	cfg  Config

	mu              sync.Mutex
	state           State
	failures        int // consecutive failures in closed state
	successes       int // consecutive successes in half-open state
	lastFailureTime time.Time
	nowFunc         func() time.Time // injectable for testing
}

// New creates a new CircuitBreaker with the given name and config.
// Name is used for logging and metrics identification.
// Pass Config{} to use defaults for any zero-value fields.
func New(name string, cfg Config) *CircuitBreaker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultConfig().Threshold
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = DefaultConfig().SuccessThreshold
	}

	return &CircuitBreaker{
		name:    name,
		cfg:     cfg,
		state:   StateClosed,
		nowFunc: time.Now,
	}
}

// Execute wraps a fallible function call with circuit breaker protection.
//
// In closed state: calls fn, records success/failure. Opens after Threshold
// consecutive failures.
//
// In open state: returns ErrCircuitOpen immediately (<1ms) without calling fn.
// Transitions to half-open after Timeout has elapsed.
//
// In half-open state: calls fn. On success, increments success counter and
// closes circuit after SuccessThreshold consecutive successes. On failure,
// reopens immediately.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()

	switch cb.state {
	case StateOpen:
		// Check if timeout has elapsed → transition to half-open
		if cb.nowFunc().Sub(cb.lastFailureTime) > cb.cfg.Timeout {
			cb.state = StateHalfOpen
			cb.successes = 0
			cb.mu.Unlock()
			// Fall through to execute in half-open
		} else {
			cb.mu.Unlock()
			return ErrCircuitOpen
		}

	case StateClosed:
		cb.mu.Unlock()
		// Fall through to execute

	case StateHalfOpen:
		cb.mu.Unlock()
		// Fall through to execute
	}

	// Execute the function
	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.recordFailureLocked()
	} else {
		cb.recordSuccessLocked()
	}

	return err
}

// recordFailureLocked records a failure. Must be called with mu held.
func (cb *CircuitBreaker) recordFailureLocked() {
	switch cb.state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.cfg.Threshold {
			cb.state = StateOpen
			cb.lastFailureTime = cb.nowFunc()
		}

	case StateHalfOpen:
		// Any failure in half-open → reopen immediately
		cb.state = StateOpen
		cb.lastFailureTime = cb.nowFunc()
		cb.failures = cb.cfg.Threshold // Keep at threshold
		cb.successes = 0
	}
}

// recordSuccessLocked records a success. Must be called with mu held.
func (cb *CircuitBreaker) recordSuccessLocked() {
	switch cb.state {
	case StateClosed:
		cb.failures = 0

	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.cfg.SuccessThreshold {
			cb.state = StateClosed
			cb.failures = 0
			cb.successes = 0
		}
	}
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Check for timeout-based transition (so State() reflects reality)
	if cb.state == StateOpen && cb.nowFunc().Sub(cb.lastFailureTime) > cb.cfg.Timeout {
		cb.state = StateHalfOpen
		cb.successes = 0
	}

	return cb.state
}

// Name returns the circuit breaker's name.
func (cb *CircuitBreaker) Name() string {
	return cb.name
}

// Failures returns the current consecutive failure count.
func (cb *CircuitBreaker) Failures() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failures
}

// Reset manually closes the circuit breaker, clearing all counters.
// Useful for administrative override or after a known recovery.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
}
