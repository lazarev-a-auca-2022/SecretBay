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
	Enabled       bool `json:"enabled"`
	Authenticated bool `json:"authenticated"`
}

type VPNStatusResponse struct {
	Status    string `json:"status"`
	IsRunning bool   `json:"is_running"`
	ServerIP  string `json:"server_ip,omitempty"`
	VPNType   string `json:"vpn_type,omitempty"`
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

		// The setupID variable was declared but not used, removing it

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

		var vpnConfig string
		switch req.VPNType {
		case "openvpn":
			openvpn := vpn.OpenVPNSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := openvpn.Setup(); err != nil {
				logger.Log.Printf("SetupVPNHandler: OpenVPN setup failed: %v", err)
				utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
				return
			}
			vpnConfig = "/etc/vpn-configs/openvpn_config.ovpn"

		case "ios_vpn":
			strongswan := vpn.StrongSwanSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := strongswan.Setup(); err != nil {
				logger.Log.Printf("SetupVPNHandler: StrongSwan setup failed: %v", err)
				utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
				return
			}
			vpnConfig = "/etc/vpn-configs/ios_vpn.mobileconfig"

		default:
			logger.Log.Printf("SetupVPNHandler: Unsupported VPN type: %s", req.VPNType)
			utils.JSONError(w, "Unsupported VPN type", http.StatusBadRequest)
			return
		}

		// Verify the config file exists after setup
		exists, err := verifyConfigExists(sshClient, vpnConfig)
		if err != nil {
			logger.Log.Printf("SetupVPNHandler: Error verifying config file: %v", err)
			utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
			return
		}
		if !exists {
			logger.Log.Printf("SetupVPNHandler: Config file not found after setup: %s", vpnConfig)
			utils.JSONError(w, "VPN setup completed but config file not found", http.StatusInternalServerError)
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
			VPNConfig:   vpnConfig,
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
	// Public endpoints that don't need auth
	router.HandleFunc("/health", HealthCheckHandler()).Methods("GET")
	router.HandleFunc("/metrics", MetricsHandler(cfg)).Methods("GET")

	// API endpoints with /api prefix
	apiRouter := router.PathPrefix("/api").Subrouter()

	// Public API endpoints
	apiRouter.HandleFunc("/csrf-token", CSRFTokenHandler()).Methods("GET", "OPTIONS")
	apiRouter.HandleFunc("/auth/status", AuthStatusHandler(cfg)).Methods("GET", "OPTIONS")
	apiRouter.HandleFunc("/auth/login", LoginHandler(cfg)).Methods("POST", "OPTIONS")
	apiRouter.HandleFunc("/auth/register", RegisterHandler(cfg.DB, cfg)).Methods("POST", "OPTIONS")

	// Protected API routes
	protectedRouter := apiRouter.PathPrefix("").Subrouter()
	protectedRouter.Use(JWTAuthenticationMiddleware(cfg))
	protectedRouter.Use(CSRFMiddleware(cfg))

	protectedRouter.HandleFunc("/setup", SetupVPNHandler(cfg)).Methods("POST")
	protectedRouter.HandleFunc("/vpn/status", VPNStatusHandler(cfg)).Methods("GET")                     // Added VPN status endpoint
	protectedRouter.HandleFunc("/config/download", DownloadConfigHandler()).Methods("GET")              // Legacy path
	protectedRouter.HandleFunc("/config/download/client", DownloadClientConfigHandler()).Methods("GET") // New client config endpoint
	protectedRouter.HandleFunc("/config/download/server", DownloadServerConfigHandler()).Methods("GET") // New server config endpoint
	protectedRouter.HandleFunc("/backup", BackupHandler(cfg)).Methods("POST")
	protectedRouter.HandleFunc("/restore", RestoreHandler(cfg)).Methods("POST")
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
		vars := mux.Vars(r)
		vpnType := vars["type"]

		// Validate VPN type
		if vpnType != "openvpn" && vpnType != "ios" {
			http.Error(w, "Invalid VPN type", http.StatusBadRequest)
			return
		}

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

		// Define config file path based on VPN type
		var configPath string
		if vpnType == "openvpn" {
			configPath = "/etc/vpn-configs/openvpn_config.ovpn"
		} else {
			configPath = "/etc/vpn-configs/ios_vpn.mobileconfig"
		}

		// Check whether VPN config file exists.
		out, err := sshClient.RunCommand(fmt.Sprintf("test -f %s && echo exists || echo notfound", configPath))
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
		configContent, err := sshClient.RunCommand(fmt.Sprintf("cat %s", configPath))
		if err != nil {
			logger.Log.Printf("DownloadConfigHandler: failed to read config file: %v", err)
			http.Error(w, fmt.Sprintf("Failed to read config file: %v", err), http.StatusInternalServerError)
			return
		}

		// Set appropriate filename based on VPN type
		filename := "openvpn_config.ovpn"
		contentType := "application/octet-stream"
		if vpnType == "ios" {
			filename = "vpn_config.mobileconfig"
			contentType = "application/x-apple-aspen-config"
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
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

		// Check for missing credentials
		if req.Username == "" || req.Password == "" {
			logger.Log.Println("LoginHandler: Missing credentials")
			utils.JSONError(w, "Missing credentials", http.StatusBadRequest)
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
		// Set CORS headers FIRST
		origin := r.Header.Get("Origin")
		if origin != "" && isValidOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
			w.Header().Set("Vary", "Origin")
		}

		// Handle preflight immediately
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Set content type and security headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

		// THEN perform validation - with less strict rules for HTTP/1.1 requests
		if r.ProtoMajor != 2 {
			if err := validateHeaders(w, r); err != nil {
				// Error response already has CORS headers since we set them first
				return
			}
		}

		// Check authentication status - either auth is disabled or we have a valid token
		isAuthenticated := !cfg.AuthEnabled

		// Only check token if auth is enabled
		if cfg.AuthEnabled {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenString := strings.TrimPrefix(authHeader, "Bearer ")
				// Verify the token using ValidateJWT instead of VerifyToken
				_, err := auth.ValidateJWT(tokenString, cfg)
				if err == nil {
					isAuthenticated = true
				}
			}
		}

		// Use the AuthStatusResponse struct
		response := AuthStatusResponse{
			Enabled:       cfg.AuthEnabled,
			Authenticated: isAuthenticated,
		}

		// Use standard encoding instead of direct marshaling to avoid response issues
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

func handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && isValidOrigin(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	w.WriteHeader(http.StatusOK)
}

func validateHeaders(w http.ResponseWriter, r *http.Request) error {
	// Skip validation for OPTIONS requests
	if r.Method == http.MethodOptions {
		return nil
	}

	// Relax Accept header validation - only check if it's provided and not allowed
	accept := r.Header.Get("Accept")
	if accept != "" && !strings.Contains(accept, "application/json") && !strings.Contains(accept, "*/*") {
		utils.JSONError(w, "Invalid Accept header", http.StatusBadRequest)
		return fmt.Errorf("invalid accept header")
	}

	// Validate Origin if present
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !isValidOrigin(origin) {
			utils.JSONError(w, "Invalid origin", http.StatusForbidden)
			return fmt.Errorf("invalid origin")
		}
	}

	return nil
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// isValidOrigin checks if the origin is allowed
func isValidOrigin(origin string) bool {
	allowedOrigins := []string{
		"http://localhost",
		"http://127.0.0.1",
		"https://secretbay.me",
	}

	for _, allowed := range allowedOrigins {
		if strings.HasPrefix(origin, allowed) {
			return true
		}
	}

	return false
}

// DownloadClientConfigHandler handles downloading the client VPN configuration file
func DownloadClientConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get required query parameters
		serverIP := r.URL.Query().Get("serverIp")
		if serverIP == "" {
			http.Error(w, "Missing serverIp parameter", http.StatusBadRequest)
			return
		}

		username := r.URL.Query().Get("username")
		if username == "" {
			username = "root"
		}

		credential := r.URL.Query().Get("credential")
		if credential == "" {
			http.Error(w, "Missing credential parameter", http.StatusBadRequest)
			return
		}

		vpnType := r.URL.Query().Get("vpnType")
		if vpnType != "openvpn" && vpnType != "ios_vpn" {
			vpnType = "openvpn" // Default to OpenVPN if not specified
		}

		// Initialize SSH client with the provided credentials
		sshClient, err := sshclient.NewSSHClient(serverIP, username, "password", credential)
		if err != nil {
			logger.Log.Printf("DownloadClientConfigHandler: SSH connection failed: %v", err)
			http.Error(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		// Define config file path based on VPN type
		var configPath string
		if vpnType == "openvpn" {
			configPath = "/etc/vpn-configs/openvpn_config.ovpn"
		} else {
			configPath = "/etc/vpn-configs/ios_vpn.mobileconfig"
		}

		// Check whether VPN config file exists
		out, err := sshClient.RunCommand(fmt.Sprintf("test -f %s && echo exists || echo notfound", configPath))
		if err != nil {
			logger.Log.Printf("DownloadClientConfigHandler: Error checking VPN client config: %v", err)
			http.Error(w, fmt.Sprintf("Error checking VPN client config: %v", err), http.StatusInternalServerError)
			return
		}

		if out != "exists\n" {
			http.Error(w, "No VPN client configuration found on the remote host", http.StatusNotFound)
			return
		}

		// Read the configuration file
		configContent, err := sshClient.RunCommand(fmt.Sprintf("cat %s", configPath))
		if err != nil {
			logger.Log.Printf("DownloadClientConfigHandler: Failed to read client config file: %v", err)
			http.Error(w, fmt.Sprintf("Failed to read client config file: %v", err), http.StatusInternalServerError)
			return
		}

		// Set appropriate filename and content type
		filename := "client.ovpn"
		contentType := "application/octet-stream"

		if vpnType == "ios_vpn" {
			filename = "vpn_config.mobileconfig"
			contentType = "application/x-apple-aspen-config"
		}

		// Send the file
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		w.Write([]byte(configContent))
	}
}

// DownloadServerConfigHandler handles downloading the VPN server configuration file
func DownloadServerConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get required query parameters
		serverIP := r.URL.Query().Get("serverIp")
		if serverIP == "" {
			http.Error(w, "Missing serverIp parameter", http.StatusBadRequest)
			return
		}

		username := r.URL.Query().Get("username")
		if username == "" {
			username = "root"
		}

		credential := r.URL.Query().Get("credential")
		if credential == "" {
			http.Error(w, "Missing credential parameter", http.StatusBadRequest)
			return
		}

		vpnType := r.URL.Query().Get("vpnType")
		if vpnType != "openvpn" && vpnType != "ios_vpn" {
			vpnType = "openvpn" // Default to OpenVPN if not specified
		}

		// Initialize SSH client with the provided credentials
		sshClient, err := sshclient.NewSSHClient(serverIP, username, "password", credential)
		if err != nil {
			logger.Log.Printf("DownloadServerConfigHandler: SSH connection failed: %v", err)
			http.Error(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		// Define server config file path based on VPN type
		var configPath string
		if vpnType == "openvpn" {
			configPath = "/etc/openvpn/server.conf"
		} else {
			configPath = "/etc/ipsec.conf"
		}

		// Check whether server config file exists
		out, err := sshClient.RunCommand(fmt.Sprintf("test -f %s && echo exists || echo notfound", configPath))
		if err != nil {
			logger.Log.Printf("DownloadServerConfigHandler: Error checking VPN server config: %v", err)
			http.Error(w, fmt.Sprintf("Error checking VPN server config: %v", err), http.StatusInternalServerError)
			return
		}

		if out != "exists\n" {
			http.Error(w, "No VPN server configuration found on the remote host", http.StatusNotFound)
			return
		}

		// Read the server configuration file
		configContent, err := sshClient.RunCommand(fmt.Sprintf("cat %s", configPath))
		if err != nil {
			logger.Log.Printf("DownloadServerConfigHandler: Failed to read server config file: %v", err)
			http.Error(w, fmt.Sprintf("Failed to read server config file: %v", err), http.StatusInternalServerError)
			return
		}

		// Set appropriate filename based on VPN type
		filename := "server.conf"
		if vpnType == "ios_vpn" {
			filename = "ipsec.conf"
		}

		// Send the file
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		w.Write([]byte(configContent))
	}
}

// verifyConfigExists checks if a config file exists on the remote server
func verifyConfigExists(client *sshclient.SSHClient, configPath string) (bool, error) {
	out, err := client.RunCommand(fmt.Sprintf("test -f %s && echo exists || echo notfound", configPath))
	if err != nil {
		return false, fmt.Errorf("error checking config file: %v", err)
	}
	return strings.TrimSpace(out) == "exists", nil
}

// VPNStatusHandler returns an http.HandlerFunc that handles VPN status requests
func VPNStatusHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Println("VPNStatusHandler: Processing request")

		// Extract server IP from query parameters
		serverIP := r.URL.Query().Get("server_ip")
		if serverIP == "" {
			utils.JSONError(w, "Missing server_ip parameter", http.StatusBadRequest)
			return
		}

		// Get username from context (set by JWT middleware)
		username := r.Context().Value("username")
		if username == nil {
			logger.Log.Println("VPNStatusHandler: Unauthorized access attempt")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Connect to server via SSH
		sshClient, err := sshclient.NewSSHClient(serverIP, username.(string), "key", "")
		if err != nil {
			logger.Log.Printf("VPNStatusHandler: SSH connection failed: %v", err)
			utils.JSONError(w, fmt.Sprintf("Failed to connect to server: %v", err), http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		// Check OpenVPN status
		ovpnStatus, _ := sshClient.RunCommand("systemctl is-active openvpn")
		strongswanStatus, _ := sshClient.RunCommand("systemctl is-active strongswan")

		var vpnType string
		var isRunning bool

		if strings.TrimSpace(ovpnStatus) == "active" {
			vpnType = "openvpn"
			isRunning = true
		} else if strings.TrimSpace(strongswanStatus) == "active" {
			vpnType = "ios_vpn"
			isRunning = true
		}

		response := VPNStatusResponse{
			Status:    "ok",
			IsRunning: isRunning,
			ServerIP:  serverIP,
			VPNType:   vpnType,
		}

		logger.Log.Println("VPNStatusHandler: Sending response")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
