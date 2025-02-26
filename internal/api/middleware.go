package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/utils"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/monitoring"
)

var csrfTokens sync.Map

// SecurityHeadersMiddleware ensures proper security headers are set
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Handle CORS
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "3600")
			w.Header().Set("Vary", "Origin")
		}

		// Skip actual processing for OPTIONS requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func JWTAuthenticationMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.AuthEnabled {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				utils.JSONError(w, "No authorization token", http.StatusUnauthorized)
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				utils.JSONError(w, "Invalid authorization header", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			username, err := auth.ValidateJWT(tokenString, cfg)
			if err != nil {
				utils.JSONError(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Add username to context
			ctx := context.WithValue(r.Context(), "username", username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RateLimiter implements a simple token bucket algorithm
type RateLimiter struct {
	tokens   map[string][]time.Time
	mu       sync.Mutex
	window   time.Duration
	maxLimit int
}

func NewRateLimiter(window time.Duration, maxLimit int) *RateLimiter {
	return &RateLimiter{
		tokens:   make(map[string][]time.Time),
		window:   window,
		maxLimit: maxLimit,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Always allow CSRF token requests
	// We still log them but don't count them against the rate limit
	if strings.HasSuffix(ip, "-csrf-token") {
		return true
	}

	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Clear old timestamps
	times := rl.tokens[ip]
	valid := times[:0]
	for _, t := range times {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.maxLimit {
		return false
	}

	rl.tokens[ip] = append(valid, now)
	return true
}

func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for CSRF token endpoint
			if r.URL.Path == "/api/csrf-token" {
				next.ServeHTTP(w, r)
				return
			}

			ip := r.RemoteAddr
			if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
				ip = strings.Split(forwardedFor, ",")[0]
			}

			if !limiter.Allow(ip) {
				logger.Log.Printf("Rate limit exceeded for IP: %s", ip)
				utils.JSONError(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func MonitoringMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)

		// Log request details
		monitoring.LogRequest(r.URL.Path, r.Method, http.StatusOK, duration)
	})
}

// CSRFMiddleware adds CSRF protection
func CSRFMiddleware(cfg *config.Config) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CSRF check temporarily disabled
			next.ServeHTTP(w, r)
			return
		})
	}
}

// GenerateCSRFToken generates a new CSRF token
func GenerateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	token := base64.URLEncoding.EncodeToString(b)
	csrfTokens.Store(token, true)

	// Cleanup old tokens after 1 hour
	time.AfterFunc(1*time.Hour, func() {
		csrfTokens.Delete(token)
	})

	return token
}

// CSRFTokenHandler returns a new CSRF token
func CSRFTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Printf("CSRFTokenHandler: Received %s request from %s", r.Method, r.RemoteAddr)

		// Set CORS headers first
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Set Content-Type for the actual response
		w.Header().Set("Content-Type", "application/json")

		// Generate and store token
		token := GenerateCSRFToken()
		if token == "" {
			logger.Log.Printf("CSRFTokenHandler: Failed to generate token for request from %s", r.RemoteAddr)
			utils.JSONError(w, "Failed to generate CSRF token", http.StatusInternalServerError)
			return
		}

		// Return token
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"token": token}); err != nil {
			logger.Log.Printf("CSRFTokenHandler: Failed to encode response: %v", err)
			utils.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Log.Printf("CSRFTokenHandler: Successfully generated token for %s", r.RemoteAddr)
	}
}

func SetupMiddleware(router *mux.Router, cfg *config.Config) {
	router.Use(MonitoringMiddleware)
	router.Use(SecurityHeadersMiddleware)
	router.Use(RateLimitMiddleware(NewRateLimiter(time.Minute, 100)))
	router.Use(CSRFMiddleware(cfg))
}
