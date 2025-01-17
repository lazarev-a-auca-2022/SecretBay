package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/utils"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/vpn"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/models"
)

func setupVPNHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.VPNSetupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Validate request
		if err := req.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Generate a unique identifier for the setup process
		setupID := uuid.New().String()

		// Initialize SSH client
		sshClient, err := sshclient.NewSSHClient(req.ServerIP, req.Username, req.AuthMethod, req.AuthCredential)
		if err != nil {
			http.Error(w, fmt.Sprintf("SSH connection failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		// Start VPN setup based on VPN type
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

		// Apply security measures
		security := vpn.SecuritySetup{SSHClient: sshClient}
		if err := security.SetupFail2Ban(); err != nil {
			http.Error(w, fmt.Sprintf("Fail2Ban setup failed: %v", err), http.StatusInternalServerError)
			return
		}
		if err := security.DisableUnnecessaryServices(); err != nil {
			// Log but do not fail
		}

		// Generate new root password
		newPassword := generatePassword()

		// Change root password
		if err := security.ChangeRootPassword(newPassword); err != nil {
			http.Error(w, fmt.Sprintf("Failed to change root password: %v", err), http.StatusInternalServerError)
			return
		}

		// Clean up client data
		cleanup := utils.DataCleanup{SSHClient: sshClient}
		if err := cleanup.RemoveClientData(); err != nil {
			// Log but do not fail
		}

		// Generate VPN configuration file path
		vpnConfigPath := generateVPNConfigPath(req.VPNType, setupID)

		// Example: Generate response
		response := models.VPNSetupResponse{
			VPNConfig:   vpnConfigPath,
			NewPassword: newPassword,
		}

		// Respond to client
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func SetupRoutes(router *mux.Router, cfg *config.Config) {
	router.HandleFunc("/setup", setupVPNHandler(cfg)).Methods("POST")
}

func generatePassword() string {
	// Implement password generation logic
	return "NewSecurePassword123!" // Replace with actual generation
}

func generateVPNConfigPath(vpnType, setupID string) string {
	// Generate the path or URL to the VPN config file
	return fmt.Sprintf("/configs/%s/%s.ovpn", vpnType, setupID)
}
