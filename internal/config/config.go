package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type ServerConfig struct {
	Port              string
	DBConnection      string
	MaxRequestSize    int64
	RateLimitRequests int
	RateLimitDuration int
	TLSMinVersion     string
	AllowedOrigins    []string
	MaxConnectionAge  int
	ReadTimeout       int
	WriteTimeout      int
}

type Config struct {
	Server     ServerConfig
	JWTSecret  string
	Production bool
}

const (
	defaultPort           = "8443"
	defaultMaxRequestSize = 1024 * 1024 // 1MB
	defaultRateLimit      = 100         // requests
	defaultRateDuration   = 60          // seconds
	minJWTSecretLength    = 32
	defaultTLSVersion     = "1.2"
)

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

func LoadConfig() (*Config, error) {
	// Environment validation
	env := strings.ToLower(getEnv("ENV", "development"))
	production := env == "production"

	// Load and validate port
	port := getEnv("SERVER_PORT", defaultPort)
	if err := validatePort(port); err != nil {
		return nil, fmt.Errorf("invalid port configuration: %v", err)
	}

	// JWT Secret handling
	jwtSecret := getEnv("JWT_SECRET", "")
	if jwtSecret == "" {
		if production {
			return nil, fmt.Errorf("JWT_SECRET is required in production")
		}
		// Generate secure secret for development
		jwtSecret = generateSecureSecret()
		if jwtSecret == "" {
			return nil, fmt.Errorf("failed to generate secure JWT secret")
		}
		logger.Log.Println("Warning: Generated temporary JWT secret for development")
	}

	if len(jwtSecret) < minJWTSecretLength {
		return nil, fmt.Errorf("JWT_SECRET must be at least %d characters", minJWTSecretLength)
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
	if production && len(allowedOrigins) == 0 {
		return nil, fmt.Errorf("ALLOWED_ORIGINS must be set in production")
	}

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
		JWTSecret:  jwtSecret,
		Production: production,
	}

	// Validate TLS version
	if !isValidTLSVersion(config.Server.TLSMinVersion) {
		return nil, fmt.Errorf("invalid TLS_MIN_VERSION: %s", config.Server.TLSMinVersion)
	}

	return config, nil
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return strings.TrimSpace(value)
	}
	return defaultVal
}

func isValidTLSVersion(version string) bool {
	validVersions := map[string]bool{
		"1.2": true,
		"1.3": true,
	}
	return validVersions[version]
}
