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
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// request validation
		if err := req.Validate(); err != nil {
			logger.Log.Printf("SetupVPNHandler: Validation error: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// unique id verification for the setup
		setupID := uuid.New().String()

		// ssh client initialization
		sshClient, err := sshclient.NewSSHClient(req.ServerIP, req.Username, req.AuthMethod, req.AuthCredential)
		if err != nil {
			logger.Log.Printf("SetupVPNHandler: SSH connection failed: %v", err)
			http.Error(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		// start vpn setup based on type
		switch req.VPNType {
		case "openvpn":
			openvpn := vpn.OpenVPNSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := openvpn.Setup(); err != nil {
				logger.Log.Printf("SetupVPNHandler: OpenVPN setup failed: %v", err)
				http.Error(w, fmt.Sprintf("OpenVPN setup failed: %v", err), http.StatusInternalServerError)
				return
			}
		case "ios_vpn":
			strongswan := vpn.StrongSwanSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := strongswan.Setup(); err != nil {
				logger.Log.Printf("SetupVPNHandler: StrongSwan setup failed: %v", err)
				http.Error(w, fmt.Sprintf("StrongSwan setup failed: %v", err), http.StatusInternalServerError)
				return
			}
		default:
			logger.Log.Printf("SetupVPNHandler: Unsupported VPN type: %s", req.VPNType)
			http.Error(w, "Unsupported VPN type", http.StatusBadRequest)
			return
		}

		// security application
		security := vpn.SecuritySetup{SSHClient: sshClient}
		if err := security.SetupFail2Ban(); err != nil {
			logger.Log.Printf("SetupVPNHandler: Fail2Ban setup failed: %v", err)
			http.Error(w, fmt.Sprintf("Fail2Ban setup failed: %v", err), http.StatusInternalServerError)
			return
		}
		if err := security.DisableUnnecessaryServices(); err != nil {
			logger.Log.Println("SetupVPNHandler: DisableUnnecessaryServices encountered non-fatal error")
		}

		// generate password
		newPassword := generatePassword()

		// change root password
		if err := security.ChangeRootPassword(newPassword); err != nil {
			logger.Log.Printf("SetupVPNHandler: ChangeRootPassword failed: %v", err)
			http.Error(w, fmt.Sprintf("Failed to change root password: %v", err), http.StatusInternalServerError)
			return
		}

		// client data cleanup
		cleanup := utils.DataCleanup{SSHClient: sshClient}
		if err := cleanup.RemoveClientData(); err != nil {
			logger.Log.Println("SetupVPNHandler: RemoveClientData encountered non-fatal error")
		}

		// generate vpn config path
		vpnConfigPath := generateVPNConfigPath(req.VPNType, setupID)

		// response
		response := models.VPNSetupResponse{
			VPNConfig:   vpnConfigPath,
			NewPassword: newPassword,
		}

		logger.Log.Println("SetupVPNHandler: Setup completed, sending response")
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
}

func generatePassword() string {
	logger.Log.Println("generatePassword: Generating new password")
	const passwordLength = 12
	bytes := make([]byte, passwordLength)
	if _, err := rand.Read(bytes); err != nil {
		logger.Log.Printf("generatePassword: Error generating random bytes: %v", err)
		// backup pass incase stuff goes wrong
		return "backuppassword12213131231!"
	}
	password := base64.URLEncoding.EncodeToString(bytes)[:passwordLength]
	logger.Log.Println("generatePassword: Password generated")
	return password
}

func LoginHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Println("LoginHandler: Request received")
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Log.Printf("LoginHandler: Invalid payload: %v", err)
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Verify credentials
		if req.Username != os.Getenv("ADMIN_USERNAME") ||
			req.Password != os.Getenv("ADMIN_PASSWORD") {
			logger.Log.Println("LoginHandler: Invalid credentials")
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Generate JWT token
		token, err := auth.GenerateJWT(req.Username, cfg)
		if err != nil {
			logger.Log.Printf("LoginHandler: Token generation failed: %v", err)
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		logger.Log.Println("LoginHandler: Login successful")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token": token,
		})
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
