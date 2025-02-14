package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/utils"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/vpn"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/models"
)

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

		sshClient, err := sshclient.NewSSHClient(req.ServerIP, req.Username, req.AuthMethod, req.AuthCredential)
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
				utils.JSONError(w, fmt.Sprintf("OpenVPN setup failed: %v", err), http.StatusInternalServerError)
				return
			}
		case "ios_vpn":
			strongswan := vpn.StrongSwanSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := strongswan.Setup(); err != nil {
				logger.Log.Printf("SetupVPNHandler: StrongSwan setup failed: %v", err)
				utils.JSONError(w, fmt.Sprintf("StrongSwan setup failed: %v", err), http.StatusInternalServerError)
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
			utils.JSONError(w, fmt.Sprintf("Fail2Ban setup failed: %v", err), http.StatusInternalServerError)
			return
		}

		if err := security.DisableUnnecessaryServices(); err != nil {
			logger.Log.Printf("SetupVPNHandler: DisableUnnecessaryServices failed: %v", err)
			// Continue execution but log the error
		}

		newPassword, err := generatePassword()
		if err != nil {
			logger.Log.Printf("SetupVPNHandler: Password generation failed: %v", err)
			utils.JSONError(w, "Failed to generate secure password", http.StatusInternalServerError)
			return
		}

		if err := security.ChangeRootPassword(newPassword); err != nil {
			logger.Log.Printf("SetupVPNHandler: ChangeRootPassword failed: %v", err)
			utils.JSONError(w, fmt.Sprintf("Failed to change root password: %v", err), http.StatusInternalServerError)
			return
		}

		cleanup := utils.DataCleanup{SSHClient: sshClient}
		if err := cleanup.RemoveClientData(); err != nil {
			logger.Log.Printf("SetupVPNHandler: RemoveClientData failed: %v", err)
			// Log but continue as this is not critical
		}

		vpnConfigPath := generateVPNConfigPath(req.VPNType, setupID)

		response := models.VPNSetupResponse{
			VPNConfig:   vpnConfigPath,
			NewPassword: newPassword,
		}

		logger.Log.Println("SetupVPNHandler: Setup completed successfully")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// StatusResponse defines the structure for status responses
type StatusResponse struct {
	Status string `json:"status"`
}

// StatusHandler handles the /api/vpn/status endpoint
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

func SetupRoutes(router *mux.Router, cfg *config.Config) {
	router.HandleFunc("/auth/login", LoginHandler(cfg)).Methods("POST")
	router.HandleFunc("/setup", SetupVPNHandler(cfg)).Methods("POST")
	router.HandleFunc("/vpn/status", StatusHandler(cfg)).Methods("GET")
	router.HandleFunc("/config/download", DownloadConfigHandler()).Methods("GET")
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
