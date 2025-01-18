package main

import (
    "fmt"
    "log"

    "github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
    "github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
)

func main() {
    cfg, err := config.LoadConfig()
    if err != nil {
        log.Fatalf("Error loading config: %v", err)
    }

    token, err := auth.GenerateJWT("your-username", cfg)
    if err != nil {
        log.Fatalf("Error generating JWT: %v", err)
    }

    fmt.Println("JWT Token:", token)
}