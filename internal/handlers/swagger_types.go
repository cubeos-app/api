package handlers

import "cubeos-api/internal/models"

// ErrorResponse is a type alias for Swagger annotation resolution.
// The canonical definition lives in models.ErrorResponse.
// Previously this file had a separate struct with a field name mismatch
// (Details vs Detail). The alias ensures a single source of truth.
// @Description API error response
type ErrorResponse = models.ErrorResponse
