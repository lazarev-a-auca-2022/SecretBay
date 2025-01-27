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

    // public routes
    router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("VPN Setup Server is running"))
    }).Methods("GET")

    // secured routes
    secured := router.PathPrefix("/").Subrouter()
    secured.Use(api.JWTAuthenticationMiddleware(cfg))
    api.SetupRoutes(secured, cfg)

    log.Printf("Server is running on port %s", cfg.Server.Port)
    if err := http.ListenAndServe(":"+cfg.Server.Port, router); err != nil {
        log.Fatalf("Server failed to start: %v", err)
    }
}