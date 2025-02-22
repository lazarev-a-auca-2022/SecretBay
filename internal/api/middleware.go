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
		// Set base security headers for all requests
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Handle CORS pre-flight
		if r.Method == "OPTIONS" {
			origin := r.Header.Get("Origin")
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "3600")
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func JWTAuthenticationMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Log.Println("JWTAuthenticationMiddleware: Request received")

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Log.Println("JWTAuthenticationMiddleware: Missing Authorization Header")
				utils.JSONError(w, "Missing Authorization Header", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				logger.Log.Println("JWTAuthenticationMiddleware: Invalid Authorization Header format")
				utils.JSONError(w, "Invalid Authorization Header format", http.StatusUnauthorized)
				return
			}

			claims, err := auth.ValidateJWT(parts[1], cfg)
			if err != nil {
				logger.Log.Printf("JWTAuthenticationMiddleware: Invalid Token: %v", err)
				utils.JSONError(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "username", claims.Username)
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
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF check for GET, HEAD, OPTIONS
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Verify CSRF token
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			utils.JSONError(w, "Missing CSRF token", http.StatusForbidden)
			return
		}

		// Check if token exists and is valid
		if _, ok := csrfTokens.Load(token); !ok {
			utils.JSONError(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		// Token is valid, remove it from the map (one-time use)
		csrfTokens.Delete(token)
		next.ServeHTTP(w, r)
	})
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

		// Set Content-Type first
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Handle CORS and preflight
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, X-CSRF-Token")
			w.Header().Set("Access-Control-Max-Age", "3600")
			w.Header().Set("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
		}

		// Handle preflight OPTIONS request first
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Generate new token
		token := GenerateCSRFToken()
		if token == "" {
			logger.Log.Printf("CSRFTokenHandler: Failed to generate token for request from %s", r.RemoteAddr)
			utils.JSONError(w, "Failed to generate CSRF token", http.StatusInternalServerError)
			return
		}

		// Return token with proper error handling
		resp := map[string]string{"token": token}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Log.Printf("CSRFTokenHandler: Failed to encode response: %v", err)
			utils.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Log.Printf("CSRFTokenHandler: Successfully generated token for %s", r.RemoteAddr)
	}
}

func SetupMiddleware(router *mux.Router) {
	router.Use(MonitoringMiddleware)
	router.Use(SecurityHeadersMiddleware)
	router.Use(RateLimitMiddleware(NewRateLimiter(time.Minute, 100)))
	router.Use(CSRFMiddleware)
}
