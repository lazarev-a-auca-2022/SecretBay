package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/monitoring"
)

// ErrorResponse represents a structured error response
type ErrorResponse struct {
	Error     string    `json:"error"`
	Code      string    `json:"code"`
	RequestID string    `json:"request_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details,omitempty"`
	Path      string    `json:"path,omitempty"`
}

// JSONError writes a structured JSON error response
func JSONError(w http.ResponseWriter, message string, code int) {
	// Set CORS headers first to ensure they're present in error responses
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin == "" {
		// Only set CORS headers if they haven't been set already
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
		w.Header().Set("Vary", "Origin")
	}

	resp := ErrorResponse{
		Error:     message,
		Code:      http.StatusText(code),
		Timestamp: time.Now().UTC(),
	}

	// Track error in monitoring
	monitoring.LogError(fmt.Errorf("%s: %s", resp.Code, message))

	// Log detailed error
	logger.Log.Printf("Error response: %+v", resp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

// JSONErrorWithDetails writes a detailed error response with optional fields
func JSONErrorWithDetails(w http.ResponseWriter, err error, code int, requestID string, path string) {
	// Set CORS headers first to ensure they're present in error responses
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin == "" {
		// Only set CORS headers if they haven't been set already
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
		w.Header().Set("Vary", "Origin")
	}

	resp := ErrorResponse{
		Error:     err.Error(),
		Code:      http.StatusText(code),
		RequestID: requestID,
		Timestamp: time.Now().UTC(),
		Path:      path,
	}

	if details, ok := err.(interface{ Details() string }); ok {
		resp.Details = details.Details()
	}

	// Track error in monitoring
	monitoring.LogError(err)

	// Log detailed error
	logger.Log.Printf("Detailed error response: %+v", resp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// JSONValidationError writes a validation error response
func JSONValidationError(w http.ResponseWriter, errors []ValidationError) {
	// Set CORS headers first to ensure they're present in error responses
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin == "" {
		// Only set CORS headers if they haven't been set already
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
		w.Header().Set("Vary", "Origin")
	}

	resp := ErrorResponse{
		Error:     "Validation Error",
		Code:      http.StatusText(http.StatusBadRequest),
		Timestamp: time.Now().UTC(),
		Details:   "One or more fields failed validation",
	}

	response := struct {
		ErrorResponse
		ValidationErrors []ValidationError `json:"validation_errors"`
	}{
		ErrorResponse:    resp,
		ValidationErrors: errors,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response)
}
