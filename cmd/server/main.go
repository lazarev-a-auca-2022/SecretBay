package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Initialize router
	router := mux.NewRouter()

	// Setup API routes
	api.SetupRoutes(router, cfg)

	// Start server
	log.Printf("Server is running on port %s", cfg.Server.Port)
	if err := http.ListenAndServe(":"+cfg.Server.Port, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
