// Package api implements HTTP handlers and middleware for the VPN server.
//
// It provides handlers for VPN setup, configuration management, and server maintenance.
// The package includes security middleware for JWT authentication, CSRF protection,
// and rate limiting. All handlers follow RESTful principles and include proper
// error handling and logging.
package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/utils"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/vpn"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/models"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/monitoring"
)

// StatusResponse defines the response structure for VPN status requests
type StatusResponse struct {
	Status string `json:"status"`
}

// AuthStatusResponse represents the auth status response
type AuthStatusResponse struct {
	Enabled bool `json:"enabled"`
}

// SetupVPNHandler returns an http.HandlerFunc that handles VPN setup requests.
// It validates the request, connects to the remote server via SSH, sets up the
// requested VPN type, and returns the configuration.
func SetupVPNHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Println("SetupVPNHandler: Processing request")
		var req models.VPNSetupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Log.Printf("SetupVPNHandler: Invalid payload: %v", err)
			utils.JSONError(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if err := req.Validate(); err != nil {
			logger.Log.Printf("SetupVPNHandler: Validation error: %v", err)
			utils.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}

		setupID := uuid.New().String()
		configPath := generateVPNConfigPath(req.VPNType, setupID)

		// Determine the authentication method
		var authMethod string
		if req.AuthMethod == "password" {
			authMethod = "password"
		} else if req.AuthMethod == "key" {
			authMethod = "key"
		} else {
			logger.Log.Printf("SetupVPNHandler: Unsupported auth method: %s", req.AuthMethod)
			utils.JSONError(w, "Unsupported auth method", http.StatusBadRequest)
			return
		}

		sshClient, err := sshclient.NewSSHClient(req.ServerIP, req.Username, authMethod, req.AuthCredential)
		if err != nil {
			logger.Log.Printf("SetupVPNHandler: SSH connection failed: %v", err)
			utils.JSONError(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		switch req.VPNType {
		case "openvpn":
			openvpn := vpn.OpenVPNSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := openvpn.Setup(); err != nil {
				logger.Log.Printf("SetupVPNHandler: OpenVPN setup failed: %v", err)
				utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
				return
			}
		case "ios_vpn":
			strongswan := vpn.StrongSwanSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := strongswan.Setup(); err != nil {
				logger.Log.Printf("SetupVPNHandler: StrongSwan setup failed: %v", err)
				utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
				return
			}

			// Generate mobile config
			configPath, err = strongswan.GenerateMobileConfig(req.Username)
			if err != nil {
				logger.Log.Printf("SetupVPNHandler: Mobile config generation failed: %v", err)
				utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
				return
			}
		default:
			logger.Log.Printf("SetupVPNHandler: Unsupported VPN type: %s", req.VPNType)
			utils.JSONError(w, "Unsupported VPN type", http.StatusBadRequest)
			return
		}

		security := vpn.SecuritySetup{SSHClient: sshClient}
		if err := security.SetupFail2Ban(); err != nil {
			logger.Log.Printf("SetupVPNHandler: Fail2Ban setup failed: %v", err)
			utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
			return
		}

		if err := security.DisableUnnecessaryServices(); err != nil {
			logger.Log.Printf("SetupVPNHandler: DisableUnnecessaryServices failed: %v", err)
			monitoring.LogError(err)
		}

		newPassword, err := generatePassword()
		if err != nil {
			logger.Log.Printf("SetupVPNHandler: Password generation failed: %v", err)
			utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
			return
		}

		if err := security.ChangeRootPassword(newPassword); err != nil {
			logger.Log.Printf("SetupVPNHandler: ChangeRootPassword failed: %v", err)
			utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
			return
		}

		// Create backup after successful setup
		backupManager := utils.BackupManager{SSHClient: sshClient}
		_, err = backupManager.CreateBackup()
		if err != nil {
			logger.Log.Printf("SetupVPNHandler: Backup creation failed: %v", err)
			monitoring.LogError(err)
		}

		cleanup := utils.DataCleanup{SSHClient: sshClient}
		if err := cleanup.RemoveClientData(); err != nil {
			logger.Log.Printf("SetupVPNHandler: RemoveClientData failed: %v", err)
			// Log but continue as this is not critical
		}

		response := models.VPNSetupResponse{
			VPNConfig:   configPath,
			NewPassword: newPassword,
		}

		logger.Log.Println("SetupVPNHandler: Setup completed successfully")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// StatusHandler returns an http.HandlerFunc that handles VPN status requests.
// It verifies authentication and returns the current status of the VPN service.
func StatusHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Println("StatusHandler: Request received")
		// Get username from context (set by JWT middleware)
		username := r.Context().Value("username")
		if username == nil {
			logger.Log.Println("StatusHandler: Unauthorized access attempt")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		response := StatusResponse{
			Status: "authenticated",
		}
		logger.Log.Println("StatusHandler: Sending response")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// HealthCheckHandler returns an http.HandlerFunc that provides basic health check.
// It returns a 200 OK response if the server is running.
func HealthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}
}

// MetricsHandler returns an http.HandlerFunc that provides system metrics.
// It only allows access from internal networks for security.
func MetricsHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only allow metrics access from localhost or internal network
		clientIP := r.Header.Get("X-Real-IP")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		if !isInternalIP(clientIP) {
			utils.JSONError(w, "Access denied", http.StatusForbidden)
			return
		}

		metrics := monitoring.GetMetrics()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
	}
}

func isInternalIP(ip string) bool {
	// Remove port if present
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}

	// Check if localhost
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}

	// Check if in private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipnet.Contains(net.ParseIP(ip)) {
			return true
		}
	}

	return false
}

func SetupRoutes(router *mux.Router, cfg *config.Config) {
	// Public endpoints that don't need CSRF
	router.HandleFunc("/health", HealthCheckHandler()).Methods("GET")
	router.HandleFunc("/metrics", MetricsHandler(cfg)).Methods("GET")
	router.HandleFunc("/api/auth/status", AuthStatusHandler(cfg)).Methods("GET")
	router.HandleFunc("/api/auth/login", LoginHandler(cfg)).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/auth/register", RegisterHandler(cfg.DB, cfg)).Methods("POST", "OPTIONS")

	// Protected API routes with CSRF
	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(JWTAuthenticationMiddleware(cfg))
	apiRouter.Use(func(next http.Handler) http.Handler {
		return CSRFMiddleware(cfg)(next)
	})

	apiRouter.HandleFunc("/setup", SetupVPNHandler(cfg)).Methods("POST")
	apiRouter.HandleFunc("/vpn/status", StatusHandler(cfg)).Methods("GET")
	apiRouter.HandleFunc("/config/download", DownloadConfigHandler()).Methods("GET")
	apiRouter.HandleFunc("/backup", BackupHandler(cfg)).Methods("POST")
	apiRouter.HandleFunc("/restore", RestoreHandler(cfg)).Methods("POST")
}

func generatePassword() (string, error) {
	logger.Log.Println("generatePassword: Generating new password")
	const passwordLength = 16 // Increased from 12 for better security
	const minSpecialChars = 2

	bytes := make([]byte, passwordLength)
	if _, err := rand.Read(bytes); err != nil {
		logger.Log.Printf("generatePassword: Error generating random bytes: %v", err)
		return "", fmt.Errorf("failed to generate secure password: %v", err)
	}

	// Ensure password contains special characters
	specialChars := "!@#$%^&*"
	for i := 0; i < minSpecialChars; i++ {
		bytes[i] = specialChars[bytes[i]%byte(len(specialChars))]
	}

	password := base64.URLEncoding.EncodeToString(bytes)[:passwordLength]
	logger.Log.Println("generatePassword: Password generated successfully")
	return password, nil
}

func DownloadConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get required query parameters
		serverIP := r.URL.Query().Get("server_ip")
		if serverIP == "" {
			http.Error(w, "Missing server_ip", http.StatusBadRequest)
			return
		}

		// Instead of using hardcoded credentials, extract them from the query.
		// In production you may extract these securely (e.g., from JWT claims).
		username := r.URL.Query().Get("username")
		if username == "" {
			username = "root"
		}
		authCredential := r.URL.Query().Get("credential")
		if authCredential == "" {
			http.Error(w, "Missing credential", http.StatusBadRequest)
			return
		}

		// Initialize SSH client with the provided credentials.
		sshClient, err := sshclient.NewSSHClient(serverIP, username, "password", authCredential)
		if err != nil {
			logger.Log.Printf("DownloadConfigHandler: SSH connection failed: %v", err)
			http.Error(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		// Check whether a VPN config file exists.
		out, err := sshClient.RunCommand("test -f /etc/vpn-configs/openvpn_config.ovpn && echo exists || echo notfound")
		if err != nil {
			logger.Log.Printf("DownloadConfigHandler: error checking VPN config: %v", err)
			http.Error(w, fmt.Sprintf("Error checking VPN config: %v", err), http.StatusInternalServerError)
			return
		}
		if out != "exists\n" {
			http.Error(w, "No VPN detected on the remote host", http.StatusNotFound)
			return
		}

		// If found, read the configuration file.
		configContent, err := sshClient.RunCommand("cat /etc/vpn-configs/openvpn_config.ovpn")
		if err != nil {
			logger.Log.Printf("DownloadConfigHandler: failed to read config file: %v", err)
			http.Error(w, fmt.Sprintf("Failed to read config file: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=openvpn_config.ovpn")
		w.Write([]byte(configContent))
	}
}
func LoginHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Println("LoginHandler: Request received")
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Log.Printf("LoginHandler: Error decoding request: %v", err)
			utils.JSONError(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Log the attempted username to help with debugging
		logger.Log.Printf("LoginHandler: Login attempt for user: %s", req.Username)

		// Get credentials from environment
		adminUser := os.Getenv("ADMIN_USERNAME")
		adminPass := os.Getenv("ADMIN_PASSWORD")

		// Log if environment variables are empty (but not their values)
		if adminUser == "" || adminPass == "" {
			logger.Log.Println("LoginHandler: Warning - ADMIN_USERNAME or ADMIN_PASSWORD environment variables are empty")
			utils.JSONError(w, "Server configuration error", http.StatusInternalServerError)
			return
		}

		// Compare credentials
		if req.Username != adminUser || req.Password != adminPass {
			logger.Log.Printf("LoginHandler: Invalid credentials for user: %s", req.Username)
			utils.JSONError(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		token, err := auth.GenerateJWT(req.Username, cfg)
		if err != nil {
			logger.Log.Printf("LoginHandler: Error generating token: %v", err)
			utils.JSONError(w, "Error generating token", http.StatusInternalServerError)
			return
		}

		// Successful login
		logger.Log.Printf("LoginHandler: Successful login for user: %s", req.Username)
		response := map[string]string{"token": token}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func generateVPNConfigPath(vpnType, setupID string) string {
	logger.Log.Println("generateVPNConfigPath: Generating VPN config path")
	configDir := "/etc/vpn-configs"
	filename := fmt.Sprintf("%s_%s.ovpn", vpnType, setupID)
	path := filepath.Join(configDir, filename)
	logger.Log.Printf("generateVPNConfigPath: Generated path: %s", path)
	return path
}

func BackupHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get server IP and credentials from JWT context
		username := r.Context().Value("username").(string)
		serverIP := r.URL.Query().Get("server_ip")
		if serverIP == "" {
			utils.JSONError(w, "Missing server_ip parameter", http.StatusBadRequest)
			return
		}

		sshClient, err := sshclient.NewSSHClient(serverIP, username, "key", "")
		if err != nil {
			logger.Log.Printf("BackupHandler: SSH connection failed: %v", err)
			utils.JSONError(w, "Failed to connect to server", http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		backupManager := utils.BackupManager{SSHClient: sshClient}
		backupFile, err := backupManager.CreateBackup()
		if err != nil {
			logger.Log.Printf("BackupHandler: Backup creation failed: %v", err)
			utils.JSONError(w, "Failed to create backup", http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"status":      "success",
			"backup_file": backupFile,
			"message":     "Backup created successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func RestoreHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.Context().Value("username").(string)
		var req struct {
			ServerIP   string `json:"server_ip"`
			BackupFile string `json:"backup_file"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.JSONError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		sshClient, err := sshclient.NewSSHClient(req.ServerIP, username, "key", "")
		if err != nil {
			logger.Log.Printf("RestoreHandler: SSH connection failed: %v", err)
			utils.JSONError(w, "Failed to connect to server", http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		backupManager := utils.BackupManager{SSHClient: sshClient}
		if err := backupManager.RestoreBackup(req.BackupFile); err != nil {
			logger.Log.Printf("RestoreHandler: Restore failed: %v", err)
			utils.JSONError(w, "Failed to restore backup", http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"status":  "success",
			"message": "Backup restored successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// RegisterHandler handles user registration
func RegisterHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var registration models.UserRegistration
		if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
			utils.JSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate registration data
		if err := registration.Validate(); err != nil {
			utils.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Check if username already exists
		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", registration.Username).Scan(&exists)
		if err != nil {
			logger.Log.Printf("Database error checking username: %v", err)
			utils.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if exists {
			utils.JSONError(w, "Username already taken", http.StatusConflict)
			return
		}

		// Check if email already exists
		err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", registration.Email).Scan(&exists)
		if err != nil {
			logger.Log.Printf("Database error checking email: %v", err)
			utils.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if exists {
			utils.JSONError(w, "Email already registered", http.StatusConflict)
			return
		}

		// Create new user
		user := &models.User{
			Username: registration.Username,
			Email:    registration.Email,
		}

		if err := user.SetPassword(registration.Password); err != nil {
			logger.Log.Printf("Error hashing password: %v", err)
			utils.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Insert user into database
		_, err = db.Exec(
			`INSERT INTO users (username, email, password) VALUES ($1, $2, $3)`,
			user.Username, user.Email, user.Password,
		)
		if err != nil {
			logger.Log.Printf("Database error creating user: %v", err)
			utils.JSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Registration successful",
		})
	}
}

// AuthStatusHandler returns an http.HandlerFunc that handles auth status checks
func AuthStatusHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Always set JSON content type
		w.Header().Set("Content-Type", "application/json")

		// Always return JSON with auth status, never redirect
		response := AuthStatusResponse{
			Enabled: cfg.AuthEnabled,
		}
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.Log.Printf("AuthStatusHandler: Failed to encode response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Internal server error",
				"enabled": "false",
			})
			return
		}
	}
}
