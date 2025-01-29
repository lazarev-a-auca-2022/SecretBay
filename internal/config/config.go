package config

import (
	"fmt"
	"os"
)

type ServerConfig struct {
	Port         string
	DBConnection string // if we are using a db
}

type Config struct {
	Server    ServerConfig
	JWTSecret string
}

func LoadConfig() (*Config, error) {
	port := getEnv("SERVER_PORT", "9999")
	jwtSecret := getEnv("JWT_SECRET", "your-secret-key")
	dbConn := getEnv("DB_CONNECTION", "")

	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	config := &Config{
		Server: ServerConfig{
			Port:         port,
			DBConnection: dbConn,
		},
		JWTSecret: jwtSecret, // Ensure JWTSecret is set correctly
	}

	return config, nil
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}
