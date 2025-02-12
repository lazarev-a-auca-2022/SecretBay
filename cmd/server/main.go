package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger" // added
)

func main() {
	logger.Log.Println("Server main: Loading configuration")
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	router := mux.NewRouter()

	certFile := "server.crt"
	keyFile := "server.key"
	logger.Log.Println("Server main: Starting HTTPS server on port 8443")
	if err := http.ListenAndServeTLS(":8443", certFile, keyFile, router); err != nil {
		log.Fatal(err)
	}

	// Public routes (no auth required)
	router.HandleFunc("/api/auth/login", api.LoginHandler(cfg)).Methods("POST")

	// Protected routes
	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(api.JWTAuthenticationMiddleware(cfg))
	api.SetupRoutes(apiRouter, cfg)

	// Static files
	fs := http.FileServer(http.Dir("./static"))
	router.PathPrefix("/").Handler(fs)

	logger.Log.Printf("Server main: Server is running on port %s", cfg.Server.Port)
	if err := http.ListenAndServe(":"+cfg.Server.Port, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
