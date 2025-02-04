package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	router := mux.NewRouter()

	// Public routes (no auth required)
	router.HandleFunc("/api/auth/login", api.LoginHandler(cfg)).Methods("POST")

	// Protected routes
	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(api.JWTAuthenticationMiddleware(cfg))
	api.SetupRoutes(apiRouter, cfg)

	// Static files
	fs := http.FileServer(http.Dir("./static"))
	router.PathPrefix("/").Handler(fs)

	log.Printf("Server is running on port %s", cfg.Server.Port)
	if err := http.ListenAndServe(":"+cfg.Server.Port, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
