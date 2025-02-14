package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

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
	for _, path := envPaths {
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

	router := mux.NewRouter()

	// Initialize rate limiter (100 requests per minute per IP)
	rateLimiter := api.NewRateLimiter(time.Minute, 100)

	// Add middlewares in order: rate limiting, security headers
	router.Use(api.RateLimitMiddleware(rateLimiter))
	router.Use(api.SecurityHeadersMiddleware)

	// Public routes
	router.HandleFunc("/api/auth/login", api.LoginHandler(cfg)).Methods("POST", "OPTIONS")

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
		ReadTimeout:  15 * time.Second,  // Increased from 5
		WriteTimeout:  15 * time.Second,  // Increased from 10
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

	logger.Log.Println("Server main: Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Log.Fatalf("Server main: Server forced to shutdown: %v", err)
	}

	logger.Log.Println("Server main: Server gracefully stopped")
}
