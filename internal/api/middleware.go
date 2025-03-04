package api

import (
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

// JWTAuthenticationMiddleware wraps handlers requiring JWT authentication
func JWTAuthenticationMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers first
			origin := r.Header.Get("Origin")
			if origin != "" && isValidOrigin(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
			}

			// Handle preflight requests immediately
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			// Skip auth check for auth-related endpoints and health checks
			if r.URL.Path == "/api/auth/status" ||
				r.URL.Path == "/api/auth/login" ||
				r.URL.Path == "/api/csrf-token" ||
				r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			logger.Log.Printf("Authenticating request to %s", r.URL.Path)

			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Log.Printf("Auth failed: Authorization header missing for %s", r.URL.Path)
				utils.JSONError(w, "Authorization required", http.StatusUnauthorized)
				return
			}

			// Remove "Bearer " prefix if present
			token := authHeader
			if len(authHeader) > 7 && authHeader[0:7] == "Bearer " {
				token = authHeader[7:]
			} else {
				logger.Log.Printf("Auth failed: Bearer prefix missing in Authorization header for %s", r.URL.Path)
				utils.JSONError(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}

			// Verify token with explicit error handling
			claims, err := auth.ValidateJWT(token, cfg)
			if err != nil {
				tokenErr, ok := err.(*auth.TokenError)
				if ok {
					switch tokenErr.Type {
					case "Expired":
						logger.Log.Printf("Auth failed: Token expired for %s", r.URL.Path)
						utils.JSONError(w, "Token has expired", http.StatusUnauthorized)
					case "Malformed":
						logger.Log.Printf("Auth failed: Malformed token for %s", r.URL.Path)
						utils.JSONError(w, "Invalid token format", http.StatusBadRequest)
					case "InvalidSignature":
						logger.Log.Printf("Auth failed: Invalid signature for %s", r.URL.Path)
						utils.JSONError(w, "Invalid token", http.StatusUnauthorized)
					default:
						logger.Log.Printf("Auth failed: Invalid token for %s: %v", r.URL.Path, tokenErr)
						utils.JSONError(w, "Invalid token", http.StatusUnauthorized)
					}
				} else {
					logger.Log.Printf("Auth failed: Invalid token for %s: %v", r.URL.Path, err)
					utils.JSONError(w, "Invalid token", http.StatusUnauthorized)
				}
				return
			}

			// Add claims to request context for use in handlers
			ctx := auth.AddUserClaimsToContext(r.Context(), claims)

			// Log successful authentication
			logger.Log.Printf("Authentication successful for user %s accessing %s", claims.Username, r.URL.Path)

			// Call next handler with updated context
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

// CSRFMiddleware wraps handlers with CSRF protection
func CSRFMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Don't check CSRF for OPTIONS requests
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF check for these endpoints
			if r.URL.Path == "/api/csrf-token" || r.URL.Path == "/api/auth/status" || r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			// Set security headers
			setSecurityHeaders(w)

			// Get the CSRF token from the header or query parameter
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				token = r.URL.Query().Get("csrf_token")
			}

			// Log the token being verified (truncated for security)
			if token != "" && len(token) > 10 {
				logger.Log.Printf("Verifying CSRF token: %s... for path: %s", token[:10], r.URL.Path)
			} else {
				logger.Log.Printf("Missing or invalid CSRF token format for path: %s", r.URL.Path)
			}

			// Verify token
			if !auth.VerifyCSRFToken(token, cfg) {
				logger.Log.Printf("Invalid CSRF token rejected for path: %s", r.URL.Path)
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		}

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Set Content-Type for the actual response
		w.Header().Set("Content-Type", "application/json")

		// Use the improved token generation function from auth package
		token, err := auth.GenerateCSRFToken()
		if err != nil || token == "" {
			logger.Log.Printf("CSRFTokenHandler: Failed to generate token: %v", err)
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

		logger.Log.Printf("CSRFTokenHandler: Successfully generated token: %s... for %s", token[:10], r.RemoteAddr)
	}
}

func SetupMiddleware(router *mux.Router, cfg *config.Config) {
	router.Use(MonitoringMiddleware)
	router.Use(SecurityHeadersMiddleware)
	router.Use(RateLimitMiddleware(NewRateLimiter(time.Minute, 100)))
	// Remove the global CSRF middleware - it will be applied only to protected routes
	// router.Use(CSRFMiddleware(cfg))
}
