package handlers

// ErrorResponse represents an API error response
// @Description API error response
type ErrorResponse struct {
	Error   string `json:"error" example:"Something went wrong"`
	Code    int    `json:"code,omitempty" example:"500"`
	Details string `json:"details,omitempty"`
}
