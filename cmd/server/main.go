package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/monitoring"
)

// Track active operations
var activeOps sync.WaitGroup

func main() {
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

	router := mux.NewRouter()

	// Create shutdown context that will be used by background tasks
	ctx, cancelShutdown = context.WithCancel(context.Background())
	defer cancelShutdown()

	// Initialize rate limiter (100 requests per minute per IP)
	rateLimiter := api.NewRateLimiter(time.Minute, 100)

	// Add middlewares with operation tracking
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip tracking for health checks
			if r.URL.Path != "/health" {
				activeOps.Add(1)
				monitoring.IncrementConnections()
				defer func() {
					activeOps.Done()
					monitoring.DecrementConnections()
				}()
			}
			next.ServeHTTP(w, r)
		})
	})
	router.Use(api.MonitoringMiddleware)
	router.Use(api.RateLimitMiddleware(rateLimiter))
	router.Use(api.SecurityHeadersMiddleware)

	// Public routes
	router.HandleFunc("/api/auth/login", api.LoginHandler(cfg)).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/csrf-token", api.CSRFTokenHandler()).Methods("GET", "OPTIONS")  // Add CSRF token endpoint

	// Protected routes
	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(api.JWTAuthenticationMiddleware(cfg))
	api.SetupRoutes(apiRouter, cfg)

	// Static files with caching headers
	fs := http.FileServer(http.Dir("./static"))
	router.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fs.ServeHTTP(w, r)
	}))

	// TLS Configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // Required for HTTP/2
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // Required for HTTP/2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
	}

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "9999" // default port if not set
	}

	srv := &http.Server{
		Addr:         ":" + serverPort,
		Handler:      router,
		TLSConfig:    tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Log.Printf("Server main: Starting HTTPS server on %s", srv.Addr)
		if err := srv.ListenAndServeTLS("/app/certs/server.crt", "/app/certs/server.key"); err != nil && err != http.ErrServerClosed {
			logger.Log.Fatalf("Server main: Failed to start HTTPS server: %v", err)
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
