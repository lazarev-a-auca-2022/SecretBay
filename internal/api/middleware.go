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

func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
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
		token := GenerateCSRFToken()
		if token == "" {
			utils.JSONError(w, "Failed to generate CSRF token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

func SetupMiddleware(router *mux.Router) {
	router.Use(MonitoringMiddleware)
	router.Use(SecurityHeadersMiddleware)
	router.Use(RateLimitMiddleware(NewRateLimiter(time.Minute, 100)))
	router.Use(CSRFMiddleware)
}
