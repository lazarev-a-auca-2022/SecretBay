package config

import (
	"fmt"
	"os"
)

type ServerConfig struct {
	Port         string
	JWTSecret    string
	DBConnection string // If using a database
}

type Config struct {
	Server ServerConfig
}

func LoadConfig() (*Config, error) {
	port := getEnv("SERVER_PORT", "8080")
	jwtSecret := getEnv("JWT_SECRET", "your-secret-key")
	dbConn := getEnv("DB_CONNECTION", "")

	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	config := &Config{
		Server: ServerConfig{
			Port:         port,
			JWTSecret:    jwtSecret,
			DBConnection: dbConn,
		},
	}

	return config, nil
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}
