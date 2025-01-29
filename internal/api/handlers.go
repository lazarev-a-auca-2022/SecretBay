package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/utils"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/vpn"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/models"
)

func SetupVPNHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.VPNSetupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// request validation
		if err := req.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// unique id verification for the setup
		setupID := uuid.New().String()

		// ssh client initialization
		sshClient, err := sshclient.NewSSHClient(req.ServerIP, req.Username, req.AuthMethod, req.AuthCredential)
		if err != nil {
			http.Error(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		// start vpn setup based on type
		switch req.VPNType {
		case "openvpn":
			openvpn := vpn.OpenVPNSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := openvpn.Setup(); err != nil {
				http.Error(w, fmt.Sprintf("OpenVPN setup failed: %v", err), http.StatusInternalServerError)
				return
			}
		case "ios_vpn":
			strongswan := vpn.StrongSwanSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := strongswan.Setup(); err != nil {
				http.Error(w, fmt.Sprintf("StrongSwan setup failed: %v", err), http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "Unsupported VPN type", http.StatusBadRequest)
			return
		}

		// security application
		security := vpn.SecuritySetup{SSHClient: sshClient}
		if err := security.SetupFail2Ban(); err != nil {
			http.Error(w, fmt.Sprintf("Fail2Ban setup failed: %v", err), http.StatusInternalServerError)
			return
		}
		if err := security.DisableUnnecessaryServices(); err != nil {
			// log no fail
		}

		// generate password
		newPassword := generatePassword()

		// change root password
		if err := security.ChangeRootPassword(newPassword); err != nil {
			http.Error(w, fmt.Sprintf("Failed to change root password: %v", err), http.StatusInternalServerError)
			return
		}

		// client data cleanup
		cleanup := utils.DataCleanup{SSHClient: sshClient}
		if err := cleanup.RemoveClientData(); err != nil {
			// log no fail
		}

		// generate vpn config path
		vpnConfigPath := generateVPNConfigPath(req.VPNType, setupID)

		// response
		response := models.VPNSetupResponse{
			VPNConfig:   vpnConfigPath,
			NewPassword: newPassword,
		}

		// response
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
		response := StatusResponse{
			Status: "VPN Setup Server is running",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func SetupRoutes(router *mux.Router, cfg *config.Config) {
	router.HandleFunc("/setup", SetupVPNHandler(cfg)).Methods("POST")
	router.HandleFunc("/api/vpn/status", StatusHandler(cfg)).Methods("GET") // Added route
}

func generatePassword() string {
	const passwordLength = 12
	bytes := make([]byte, passwordLength)
	if _, err := rand.Read(bytes); err != nil {
		// backup pass incase stuff goes wrong
		return "backuppassword12213131231!"
	}
	return base64.URLEncoding.EncodeToString(bytes)[:passwordLength]
}

func generateVPNConfigPath(vpnType, setupID string) string {
	configDir := "/etc/vpn-configs"
	filename := fmt.Sprintf("%s_%s.ovpn", vpnType, setupID)
	return filepath.Join(configDir, filename)
}
