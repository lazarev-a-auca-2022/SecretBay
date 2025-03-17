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
	"io"
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
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/database"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/monitoring"
)

var (
	// Command line flags
	configFile  = flag.String("config", ".env", "Path to configuration file")
	port        = flag.Int("port", 0, "Server port (overrides config)")
	metricsPath = flag.String("metrics-path", "./metrics", "Path to store metrics")
	logsPath    = flag.String("logs-path", "./logs", "Path to store logs")
	certFile    = flag.String("cert", "", "Path to TLS certificate file")
	keyFile     = flag.String("key", "", "Path to TLS key file")
	debugMode   = flag.Bool("debug", false, "Enable debug mode")
)

func main() {
	// Parse command line flags
	flag.Parse()

	// Create logs directory if it doesn't exist
	if _, err := os.Stat(*logsPath); os.IsNotExist(err) {
		err = os.MkdirAll(*logsPath, 0755)
		if err != nil {
			fmt.Printf("Error creating logs directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Configure standard logging to a file
	logFile, err := os.OpenFile(filepath.Join(*logsPath, "vpn-server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	// Setup dual logging to both file and stdout for better visibility
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger.SetOutput(multiWriter)
	logger.SetDebug(*debugMode)

	// Print banner with version information
	logger.Log.Println("Starting SecretBay VPN Server...")
	logger.Log.Println("Version: 2.1.0")
	logger.Log.Println("Build date: 2023-03-15")

	// Log startup parameters
	logger.Log.Printf("Config file: %s", *configFile)
	logger.Log.Printf("Logs path: %s", *logsPath)
	logger.Log.Printf("Metrics path: %s", *metricsPath)
	logger.Log.Printf("Debug mode: %t", *debugMode)

	// Load environment variables from .env file if it exists
	if _, err := os.Stat(*configFile); err == nil {
		logger.Log.Printf("Loading configuration from %s", *configFile)
		err := godotenv.Load(*configFile)
		if err != nil {
			logger.Log.Printf("Warning: Error loading .env file: %v", err)
		}
	} else {
		logger.Log.Printf("Configuration file %s not found, using environment variables", *configFile)
	}

	// Initialize the configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Log.Fatalf("Error loading configuration: %v", err)
	}

	// Override port if specified on command line
	if *port > 0 {
		// Depending on the Config structure, assign the port to the appropriate field
		portStr := fmt.Sprintf("%d", *port)
		cfg.Server.Port = portStr
		logger.Log.Printf("Overriding port from command line: %d", *port)
	}

	// Override TLS certificate and key if specified on command line
	if *certFile != "" {
		cfg.TLSCert = *certFile
	}
	if *keyFile != "" {
		cfg.TLSKey = *keyFile
	}

	// Create metrics path field if it doesn't exist in the config
	cfg.MetricsPath = *metricsPath
	cfg.LogsPath = *logsPath

	// Ensure required directories exist
	if _, err := os.Stat(*metricsPath); os.IsNotExist(err) {
		err = os.MkdirAll(*metricsPath, 0755)
		if err != nil {
			logger.Log.Fatalf("Error creating metrics directory: %v", err)
		}
	}

	// Initialize monitoring
	monitoring.InitMetrics(*metricsPath)

	// Initialize database connection
	db, err := database.InitDB()
	if err != nil {
		logger.Log.Printf("Warning: Database initialization failed: %v", err)
	}

	// Store DB in config
	if db != nil {
		cfg.DB = db
		defer db.Close()
	}

	// Create router with middleware
	router := mux.NewRouter()

	// Apply middleware
	api.SetupMiddleware(router, cfg)

	// Register API routes
	api.RegisterRoutes(router, cfg, cfg.DB)

	// Setup HTTP server
	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Capture startup time for uptime reporting
	startTime := time.Now()

	// Create a WaitGroup to ensure graceful shutdown
	var wg sync.WaitGroup

	// Channel for receiving shutdown signal
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Start HTTP server in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		logger.Log.Printf("Starting server on %s...", addr)
		var err error

		// Check if TLS is enabled and configured
		tlsEnabled := cfg.TLSCert != "" && cfg.TLSKey != ""

		if tlsEnabled {
			// Configure TLS
			tlsConfig := &tls.Config{
				MinVersion:               tls.VersionTLS12,
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			}
			srv.TLSConfig = tlsConfig

			logger.Log.Printf("HTTPS enabled with TLS certificate: %s", cfg.TLSCert)
			err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			logger.Log.Printf("WARNING: HTTPS is disabled. Running in HTTP mode, which is insecure.")
			err = srv.ListenAndServe()
		}

		if err != http.ErrServerClosed {
			logger.Log.Fatalf("Server error: %v", err)
		}
	}()

	// Start metrics collector in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Log.Println("Starting metrics collector...")
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopChan:
				logger.Log.Println("Stopping metrics collector...")
				return
			case <-ticker.C:
				metrics := monitoring.CollectSystemMetrics()
				metrics.Uptime = time.Since(startTime).Seconds()
				if err := monitoring.SaveMetrics(metrics); err != nil {
					logger.Log.Printf("Error saving metrics: %v", err)
				}
			}
		}
	}()

	// Wait for shutdown signal
	<-stopChan
	logger.Log.Println("Shutting down server...")

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		logger.Log.Printf("Server shutdown error: %v", err)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	logger.Log.Println("Server stopped gracefully")
}
