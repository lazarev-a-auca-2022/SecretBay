package utils

import (
	"encoding/json"
	"net/http"
)

// JSONError writes a JSON error response with the given message and status code
func JSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
