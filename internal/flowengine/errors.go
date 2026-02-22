// Package flowengine implements a saga-based workflow engine for CubeOS.
// It provides crash-recoverable, step-by-step execution of multi-step operations
// like app install/remove with automatic compensation on failure.
package flowengine

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
)

// ErrActivityNotFound is returned when the step executor cannot resolve an activity name.
var ErrActivityNotFound = errors.New("activity not found in registry")

// ErrDuplicateActivity is returned when registering an activity with an already-used name.
var ErrDuplicateActivity = errors.New("activity already registered")

// ErrWorkflowNotFound is returned when a workflow ID doesn't exist in the store.
var ErrWorkflowNotFound = errors.New("workflow not found")

// ErrDuplicateWorkflow is returned when a workflow with the same idempotency key already exists.
var ErrDuplicateWorkflow = errors.New("duplicate active workflow for this external_id")

// ErrStepTransitionDenied is returned when an atomic step status update fails
// because the current status doesn't match the expected status (concurrent modification).
var ErrStepTransitionDenied = errors.New("step status transition denied")

// TransientError represents a temporary failure that may succeed on retry.
// Examples: network timeout, service temporarily unavailable, Docker daemon restart.
type TransientError struct {
	Err error
}

func (e *TransientError) Error() string {
	return fmt.Sprintf("transient: %v", e.Err)
}

func (e *TransientError) Unwrap() error {
	return e.Err
}

// NewTransientError wraps an error as transient.
func NewTransientError(err error) *TransientError {
	return &TransientError{Err: err}
}

// PermanentError represents a failure that will not succeed on retry.
// Examples: invalid configuration, resource not found (when expected to exist),
// validation failure, permission denied.
type PermanentError struct {
	Err error
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("permanent: %v", e.Err)
}

func (e *PermanentError) Unwrap() error {
	return e.Err
}

// NewPermanentError wraps an error as permanent.
func NewPermanentError(err error) *PermanentError {
	return &PermanentError{Err: err}
}

// IsTransient returns true if the error is a TransientError.
func IsTransient(err error) bool {
	var te *TransientError
	return errors.As(err, &te)
}

// IsPermanent returns true if the error is a PermanentError.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// ClassifyError determines whether an error is transient or permanent.
// If the error is already classified (TransientError or PermanentError), it is returned as-is.
// Otherwise, heuristics are applied:
//   - Network errors (timeout, connection refused, DNS) → transient
//   - Syscall errors (ECONNREFUSED, ECONNRESET, EPIPE) → transient
//   - Unknown errors → transient (safer to retry than to fail permanently)
func ClassifyError(err error) error {
	if err == nil {
		return nil
	}

	// Already classified — pass through
	if IsTransient(err) || IsPermanent(err) {
		return err
	}

	// Network errors are transient
	var netErr net.Error
	if errors.As(err, &netErr) {
		return NewTransientError(err)
	}

	// OS-level connection errors are transient
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ETIMEDOUT) {
		return NewTransientError(err)
	}

	// EOF during read (connection dropped) is transient
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return NewTransientError(err)
	}

	// Check error message heuristics for common transient patterns
	msg := strings.ToLower(err.Error())
	transientPatterns := []string{
		"connection refused",
		"connection reset",
		"no such host",
		"i/o timeout",
		"temporary failure",
		"service unavailable",
		"too many requests",
		"deadline exceeded",
		"context deadline exceeded",
		"broken pipe",
	}
	for _, pattern := range transientPatterns {
		if strings.Contains(msg, pattern) {
			return NewTransientError(err)
		}
	}

	// Default: treat unknown errors as transient (safer to retry)
	return NewTransientError(err)
}

// ClassifyHTTPStatus classifies an HTTP status code as transient or permanent error.
// Used by HAL and other HTTP-based activity implementations.
//   - 5xx → transient (server error, may recover)
//   - 408 Request Timeout → transient
//   - 429 Too Many Requests → transient
//   - 4xx (other) → permanent (client error, won't recover on retry)
func ClassifyHTTPStatus(statusCode int, body string) error {
	if statusCode >= 200 && statusCode < 400 {
		return nil // Success
	}

	msg := fmt.Sprintf("HTTP %d: %s", statusCode, body)

	switch {
	case statusCode == http.StatusRequestTimeout: // 408
		return NewTransientError(errors.New(msg))
	case statusCode == http.StatusTooManyRequests: // 429
		return NewTransientError(errors.New(msg))
	case statusCode >= 500: // 5xx
		return NewTransientError(errors.New(msg))
	default: // 4xx (other)
		return NewPermanentError(errors.New(msg))
	}
}
