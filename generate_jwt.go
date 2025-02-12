package main

import (
	"fmt"
	"log"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger" // added

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
)

func main() {
	logger.Log.Println("generate_jwt: Loading config")
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	logger.Log.Println("generate_jwt: Generating JWT Token")
	token, err := auth.GenerateJWT("your-username", cfg)
	if err != nil {
		log.Fatalf("Error generating JWT: %v", err)
	}

	logger.Log.Println("generate_jwt: JWT Token generated successfully")
	fmt.Println("JWT Token:", token)
}
