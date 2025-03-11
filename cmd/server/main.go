// Package main implements the SecretBay VPN server.
//
// The server provides automated VPN configuration for remote Ubuntu servers,
// supporting both OpenVPN and IKEv2 (StrongSwan) setups. It includes features
// for authentication, monitoring, and secure configuration management.
//
// The server uses JWT for authentication, implements rate limiting and CSRF
// protection, and provides endpoints for VPN setup, configuration download,
// and server management.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/database" // Add this import
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/monitoring"
)

var (
	version   = "dev"
	activeOps sync.WaitGroup
)

// Define custom type for context keys
type contextKey string

const (
	configContextKey contextKey = "config"
)

func main() {
	versionFlag := flag.Bool("version", false, "Print version information")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("vpn-setup-server version %s\n", version)
		return
	}

	logger.Log.Println("Server main: Loading configuration")

	// Try to load .env from multiple possible locations
	envPaths := []string{
		".env",
		"/app/.env",
		filepath.Join("..", ".env"),
		filepath.Join("..", "..", ".env"),
	}

	var envLoaded bool
	for _, path := range envPaths {
		if err := godotenv.Load(path); err == nil {
			logger.Log.Printf("Loaded environment from: %s", path)
			envLoaded = true
			break
		}
	}

	if !envLoaded {
		logger.Log.Println("Warning: No .env file found, using environment variables")
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Log.Fatalf("Error loading config: %v", err)
	}

	// Initialize database connection
	db, err := database.InitDB()
	if err != nil {
		logger.Log.Fatalf("Error initializing database: %v", err)
	}
	defer db.Close()

	// Store DB in config
	cfg.DB = db

	// Start metrics collection before anything else
	monitoring.StartMetricsCollection()

	// Create metrics directory
	if err := os.MkdirAll("/app/metrics", 0755); err != nil {
		logger.Log.Printf("Warning: Failed to create metrics directory: %v", err)
	}

	// Start periodic metrics file writing with context for graceful shutdown
	ctx, cancelShutdown := context.WithCancel(context.Background())
	defer cancelShutdown()

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := monitoring.WriteMetricsToFile(); err != nil {
					logger.Log.Printf("Failed to write metrics: %v", err)
				}
			case <-ctx.Done():
				logger.Log.Println("Stopping metrics collection")
				return
			}
		}
	}()

	// Create router with rate limiting and monitoring
	router := mux.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			monitoring.IncrementConnections()
			activeOps.Add(1)
			defer func() {
				activeOps.Done()
				monitoring.DecrementConnections()
			}()
			next.ServeHTTP(w, r)
		})
	})

	// Add base security headers middleware
	router.Use(api.SecurityHeadersMiddleware)

	// Public endpoints (no auth required)
	router.HandleFunc("/health", api.HealthCheckHandler()).Methods("GET")
	router.HandleFunc("/metrics", api.MetricsHandler(cfg)).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/csrf-token", api.CSRFTokenHandler(cfg)).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/auth/status", api.AuthStatusHandler(cfg)).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/auth/login", api.LoginHandler(cfg)).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/auth/register", api.RegisterHandler(cfg.DB, cfg)).Methods("POST", "OPTIONS")

	// Handle static files
	staticRouter := router.PathPrefix("/").Subrouter()
	fs := http.FileServer(http.Dir("./static"))

	// Serve static files without any auth check for js/css
	staticRouter.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inject config into context with custom key type
		ctx := context.WithValue(r.Context(), configContextKey, cfg)
		r = r.WithContext(ctx)

		// Always serve .js, .css and error pages without auth
		if strings.HasSuffix(r.URL.Path, ".js") ||
			strings.HasSuffix(r.URL.Path, ".css") ||
			strings.HasPrefix(r.URL.Path, "/error/") ||
			r.URL.Path == "/login.html" ||
			r.URL.Path == "/register.html" {
			fs.ServeHTTP(w, r)
			return
		}

		// For index.html and other protected pages, skip auth if disabled
		if !cfg.AuthEnabled {
			fs.ServeHTTP(w, r)
			return
		}

		// Check auth when enabled
		var tokenStr string
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
		} else if cookie, err := r.Cookie("Authorization"); err == nil {
			tokenStr = strings.TrimPrefix(cookie.Value, "Bearer ")
		}

		if tokenStr == "" {
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}

		if _, err := auth.ValidateJWT(tokenStr, cfg); err != nil {
			http.Redirect(w, r, "/login.html", http.StatusSeeOther)
			return
		}

		fs.ServeHTTP(w, r)
	}).Methods("GET")

	// Protected API routes
	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(api.RateLimitMiddleware(api.NewRateLimiter(time.Minute, 100)))
	apiRouter.Use(api.JWTAuthenticationMiddleware(cfg))
	apiRouter.Use(api.CSRFMiddleware(cfg))

	// Protected endpoints
	apiRouter.HandleFunc("/setup", api.SetupVPNHandler(cfg)).Methods("POST")
	apiRouter.HandleFunc("/vpn/status", api.StatusHandler(cfg)).Methods("GET")
	apiRouter.HandleFunc("/config/download", api.DownloadConfigHandler()).Methods("GET")
	apiRouter.HandleFunc("/backup", api.BackupHandler(cfg)).Methods("POST")
	apiRouter.HandleFunc("/restore", api.RestoreHandler(cfg)).Methods("POST")

	// Register all routes properly through the handlers.go RegisterRoutes function
	api.RegisterRoutes(router, cfg, db)

	// Configure TLS
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: false, // Let clients choose their preferred cipher
		NextProtos:               []string{"h2", "http/1.1"},
		SessionTicketsDisabled:   false,
		Renegotiation:            tls.RenegotiateNever,
	}

	// Get certificate paths with fallbacks
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	if certFile == "" {
		// Try Let's Encrypt path first, fall back to local
		if _, err := os.Stat("/etc/letsencrypt/live/secretbay.me/fullchain.pem"); err == nil {
			certFile = "/etc/letsencrypt/live/secretbay.me/fullchain.pem"
			keyFile = "/etc/letsencrypt/live/secretbay.me/privkey.pem"
		} else {
			certFile = "/app/certs/server.crt"
			keyFile = "/app/certs/server.key"
		}
	}

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "9999" // default port if not set
	}

	// Configure HTTP server with larger buffer sizes
	srv := &http.Server{
		Addr:              ":" + serverPort,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Enable TCP keep-alive
	srv.SetKeepAlivesEnabled(true)

	// Start server in a goroutine
	go func() {
		logger.Log.Printf("Server main: Starting HTTPS server on %s using cert: %s", srv.Addr, certFile)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			logger.Log.Printf("Server main: Failed to start HTTPS server: %v", err)
			// Don't exit immediately to allow cleanup
			time.Sleep(1 * time.Second)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Log.Println("Server main: Initiating graceful shutdown...")

	// Cancel the background tasks context
	cancelShutdown()

	// Create shutdown timeout context
	shutdownTimeout := 30 * time.Second
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Start monitoring active operations
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				metrics := monitoring.GetSystemMetrics()
				count := int(metrics.Goroutines)
				if count <= 2 { // Main goroutine and monitoring goroutine
					logger.Log.Println("No active operations remaining")
					close(done)
					return
				}
				logger.Log.Printf("Waiting for %d active operations to complete", count-2)
			case <-shutdownCtx.Done():
				return
			}
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		logger.Log.Println("All active operations completed")
	case <-shutdownCtx.Done():
		logger.Log.Println("Shutdown timeout reached, forcing exit")
	}

	// Shutdown the server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Log.Printf("Server main: Error during shutdown: %v", err)
	}

	// Wait for any remaining operations with a short timeout
	cleanupDone := make(chan struct{})
	go func() {
		activeOps.Wait()
		close(cleanupDone)
	}()

	select {
	case <-cleanupDone:
		logger.Log.Println("Server main: All operations completed successfully")
	case <-time.After(5 * time.Second):
		logger.Log.Println("Server main: Some operations did not complete in time")
	}

	logger.Log.Println("Server main: Server stopped")
}
