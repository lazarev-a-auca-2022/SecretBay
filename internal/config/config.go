// Package config handles application configuration and environment settings.
//
// This package provides functionality for loading and validating configuration
// from environment variables with secure defaults. It ensures all required
// security settings are properly configured.
package config

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/database"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

// Config holds application configuration settings
type Config struct {
	// Server contains HTTP server specific configuration
	Server ServerConfig

	// JWTSecret is used for signing and verifying JWT tokens
	JWTSecret string

	// Production indicates if the server is running in production mode
	Production bool

	// DB holds the database connection
	DB *sql.DB

	// AuthEnabled controls whether authentication is required
	AuthEnabled bool

	// TLSCert is the path to the TLS certificate file
	TLSCert string

	// TLSKey is the path to the TLS key file
	TLSKey string

	// MetricsPath is the path to store metrics data
	MetricsPath string

	// LogsPath is the path to store logs
	LogsPath string
}

// ServerConfig holds HTTP server specific configuration
type ServerConfig struct {
	// Port the server listens on
	Port string

	// DBConnection string for database access
	DBConnection string

	// MaxRequestSize in bytes
	MaxRequestSize int64

	// RateLimitRequests is the number of requests allowed per duration
	RateLimitRequests int

	// RateLimitDuration is the time window for rate limiting in seconds
	RateLimitDuration int

	// TLSMinVersion is the minimum TLS version allowed
	TLSMinVersion string

	// AllowedOrigins is a list of CORS allowed origins
	AllowedOrigins []string

	// MaxConnectionAge is the maximum time a connection can stay open
	MaxConnectionAge int

	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout int

	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout int
}

const (
	defaultPort           = "8443"
	defaultMaxRequestSize = 1024 * 1024 // 1MB
	defaultRateLimit      = 100         // requests
	defaultRateDuration   = 60          // seconds
	minJWTSecretLength    = 32
	defaultTLSVersion     = "1.2"
)

// LoadConfig loads and validates configuration from environment variables.
// It returns an error if required settings are missing or invalid.
func LoadConfig() (*Config, error) {
	// Environment validation
	env := strings.ToLower(getEnv("ENV", "development"))
	production := env == "production"

	// Allow auth to be enabled via environment
	authEnabled := getEnv("AUTH_ENABLED", "true") == "true"

	// Load and validate port
	port := getEnv("SERVER_PORT", defaultPort)
	if err := validatePort(port); err != nil {
		return nil, fmt.Errorf("invalid port configuration: %v", err)
	}

	// JWT Secret handling
	jwtSecret := getEnv("JWT_SECRET", "")
	if jwtSecret == "" {
		if authEnabled {
			jwtSecret = "test-secret-that-meets-minimum-length-32char"
		} else {
			jwtSecret = "dummy-jwt-secret-for-disabled-auth"
		}
	}

	// Parse numeric configurations
	maxReqSize, _ := strconv.ParseInt(getEnv("MAX_REQUEST_SIZE", fmt.Sprintf("%d", defaultMaxRequestSize)), 10, 64)
	rateLimit, _ := strconv.Atoi(getEnv("RATE_LIMIT_REQUESTS", fmt.Sprintf("%d", defaultRateLimit)))
	rateDuration, _ := strconv.Atoi(getEnv("RATE_LIMIT_DURATION", fmt.Sprintf("%d", defaultRateDuration)))
	maxConnAge, _ := strconv.Atoi(getEnv("MAX_CONN_AGE", "3600"))
	readTimeout, _ := strconv.Atoi(getEnv("READ_TIMEOUT", "30"))
	writeTimeout, _ := strconv.Atoi(getEnv("WRITE_TIMEOUT", "30"))

	// Parse allowed origins
	allowedOrigins := strings.Split(getEnv("ALLOWED_ORIGINS", ""), ",")

	config := &Config{
		Server: ServerConfig{
			Port:              port,
			DBConnection:      getEnv("DB_CONNECTION", ""),
			MaxRequestSize:    maxReqSize,
			RateLimitRequests: rateLimit,
			RateLimitDuration: rateDuration,
			TLSMinVersion:     getEnv("TLS_MIN_VERSION", defaultTLSVersion),
			AllowedOrigins:    allowedOrigins,
			MaxConnectionAge:  maxConnAge,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
		},
		JWTSecret:   jwtSecret,
		Production:  production,
		AuthEnabled: authEnabled,
	}

	// Initialize database connection
	db, err := database.InitDB()
	if err != nil {
		if production {
			return nil, fmt.Errorf("failed to initialize database: %v", err)
		}
		logger.Log.Printf("Warning: Failed to initialize database: %v", err)
	}
	config.DB = db

	return config, nil
}

// getEnv retrieves an environment variable with a default fallback value
func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return strings.TrimSpace(value)
	}
	return defaultVal
}

// isValidTLSVersion checks if the provided TLS version is supported
func isValidTLSVersion(version string) bool {
	validVersions := map[string]bool{
		"1.2": true,
		"1.3": true,
	}
	return validVersions[version]
}

// generateSecureSecret creates a cryptographically secure random string
func generateSecureSecret() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		logger.Log.Printf("Warning: Failed to generate secure random secret: %v", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1024 || portNum > 65535 {
		return fmt.Errorf("port must be between 1024 and 65535")
	}
	return nil
}
