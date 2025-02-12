package main

import (
	"log"
	"net/http"

	// Import the os package
	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/api"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"

	"github.com/joho/godotenv"
)

func main() {
	logger.Log.Println("Server main: Loading configuration")

	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

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

	// Start HTTPS server in a goroutine
	go func() {
		certFile := "server.crt"
		keyFile := "server.key"
		logger.Log.Println("Server main: Starting HTTPS server on port 8443")
		if err := http.ListenAndServeTLS(":8443", certFile, keyFile, router); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server failed to start: %v", err)
		}
	}()

	// Start HTTP server
	logger.Log.Printf("Server main: Server is running on port %s", cfg.Server.Port)
	if err := http.ListenAndServe(":"+cfg.Server.Port, router); err != nil {
		log.Fatalf("HTTP server failed to start: %v", err)
	}
}
