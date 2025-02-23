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
			logger.Log.Println("JWTAuthenticationMiddleware: Request received")

			// If auth is disabled, skip all authentication
			if !cfg.AuthEnabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip auth for public paths and static assets
			if r.URL.Path == "/login.html" ||
				r.URL.Path == "/register.html" ||
				r.URL.Path == "/api/csrf-token" ||
				r.URL.Path == "/api/auth/login" ||
				r.URL.Path == "/api/auth/register" ||
				strings.HasPrefix(r.URL.Path, "/error/") ||
				strings.HasSuffix(r.URL.Path, ".css") ||
				strings.HasSuffix(r.URL.Path, ".js") {
				next.ServeHTTP(w, r)
				return
			}

			// Special handling for index.html and root path
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				token := ""

				// Check Authorization header first
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					token = strings.TrimPrefix(authHeader, "Bearer ")
				}

				// If no valid token, redirect to login
				if token == "" {
					http.Redirect(w, r, "/login.html", http.StatusSeeOther)
					return
				}

				// Validate token
				claims, err := auth.ValidateJWT(token, cfg)
				if err != nil {
					logger.Log.Printf("Token validation failed: %v", err)
					http.Redirect(w, r, "/login.html", http.StatusSeeOther)
					return
				}

				// Valid token, set context and continue
				ctx := context.WithValue(r.Context(), "username", claims.Username)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Handle API authentication
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Log.Println("JWTAuthenticationMiddleware: Missing Authorization Header")
				w.Header().Set("WWW-Authenticate", `Bearer realm="SecretBay VPN"`)
				utils.JSONError(w, "Missing Authorization Header", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				logger.Log.Println("JWTAuthenticationMiddleware: Invalid Authorization Header format")
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_request"`)
				utils.JSONError(w, "Invalid Authorization Header format", http.StatusUnauthorized)
				return
			}

			claims, err := auth.ValidateJWT(parts[1], cfg)
			if err != nil {
				logger.Log.Printf("JWTAuthenticationMiddleware: Token validation error: %v", err)
				if tokenErr, ok := err.(*auth.TokenError); ok {
					switch tokenErr.Type {
					case "Expired":
						w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Token expired"`)
					case "InvalidSignature":
						w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Invalid signature"`)
					case "Malformed":
						w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Malformed token"`)
					case "InvalidIssuer":
						w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Invalid issuer"`)
					default:
						w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
					}
				} else {
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				}
				utils.JSONError(w, err.Error(), http.StatusUnauthorized)
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
func CSRFMiddleware(cfg *config.Config) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF check if auth is disabled
			if !cfg.AuthEnabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF check for endpoints that issue tokens
			if r.URL.Path == "/api/csrf-token" {
				next.ServeHTTP(w, r)
				return
			}

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

			// Consume the token for one-time use if not a login request
			if r.URL.Path != "/api/auth/login" {
				csrfTokens.Delete(token)
			}

			next.ServeHTTP(w, r)
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
