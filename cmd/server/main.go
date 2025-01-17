package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
)

func main() {
	// config loader
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// router init
	router := mux.NewRouter()

	// api route setup
	api.SetupRoutes(router, cfg)

	// start the server
	log.Printf("Server is running on port %s", cfg.Server.Port)
	if err := http.ListenAndServe(":"+cfg.Server.Port, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
