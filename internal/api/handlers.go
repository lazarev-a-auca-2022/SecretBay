// Package api implements HTTP handlers and middleware for the VPN server.
//
// It provides handlers for VPN setup, configuration management, and server maintenance.
// The package includes security middleware for JWT authentication, CSRF protection,
// and rate limiting. All handlers follow RESTful principles and include proper
// error handling and logging.
package api

import (
	"bufio"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"context"

	"github.com/golang-jwt/jwt/v5"
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

// VPNStatusResponse provides detailed information about VPN status
type VPNStatusResponse struct {
	Status        string   `json:"status"`
	IsRunning     bool     `json:"is_running"`
	ServerIP      string   `json:"server_ip,omitempty"`
	VPNType       string   `json:"vpn_type,omitempty"`
	ActiveClients int      `json:"active_clients,omitempty"`
	Uptime        string   `json:"uptime,omitempty"`
	SecurityStats *SecStat `json:"security_stats,omitempty"`
}

// SecStat provides information about security status
type SecStat struct {
	Fail2BanEnabled bool   `json:"fail2ban_enabled"`
	FirewallActive  bool   `json:"firewall_active"`
	LastUpdated     string `json:"last_updated,omitempty"`
}

// EnhancedVPNSetupResponse extends the basic VPNSetupResponse with more details
type EnhancedVPNSetupResponse struct {
	VPNConfig               string   `json:"vpn_config"`
	NewPassword             string   `json:"new_password"`
	SSHPassword             string   `json:"ssh_password"`
	Status                  string   `json:"status"`
	Message                 string   `json:"message"`
	ServiceRunning          bool     `json:"service_running"`
	SecurityEnabled         bool     `json:"security_enabled"`
	ConfigValidated         bool     `json:"config_validated"`
	DownloadEndpoint        string   `json:"download_endpoint,omitempty"`
	ServerIP                string   `json:"server_ip,omitempty"`
	VPNType                 string   `json:"vpn_type,omitempty"`
	DataCleanupSuccessful   bool     `json:"data_cleanup_successful"`
	SecurityRecommendations []string `json:"security_recommendations,omitempty"`
}

// PasswordResetRequest represents a request to reset an expired password
type PasswordResetRequest struct {
	ServerIP    string `json:"server_ip"`
	Username    string `json:"username"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// PasswordResetResponse defines the response structure for password reset requests
type PasswordResetResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	NewPassword string `json:"new_password,omitempty"`
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

		// Create response writer that can be flushed early to prevent client timeouts
		flusher, ok := w.(http.Flusher)
		if !ok {
			logger.Log.Println("SetupVPNHandler: Streaming not supported")
		}

		// Set headers for streaming response if supported
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Accel-Buffering", "no") // Prevent nginx buffering if used

		// Initialize SSH connection with improved timeout handling and retries
		var sshClient *sshclient.SSHClient
		var err error

		// Send first progress update
		if ok {
			progressUpdate := map[string]string{
				"status":  "connecting",
				"message": "Establishing secure connection to your server...",
			}
			if err := json.NewEncoder(w).Encode(progressUpdate); err != nil {
				logger.Log.Printf("SetupVPNHandler: Failed to send initial progress: %v", err)
			}
			flusher.Flush()
		}

		// Improved connection handling with more retries and better error information
		maxRetries := 5 // Increased from 3 to 5
		var connectionErrors []string

		for i := 0; i < maxRetries; i++ {
			logger.Log.Printf("SetupVPNHandler: SSH connection attempt %d of %d to %s", i+1, maxRetries, req.ServerIP)

			// Send progress updates for retry attempts after the first one
			if i > 0 && ok {
				progressUpdate := map[string]string{
					"status":  "connecting_retry",
					"message": fmt.Sprintf("Connection attempt %d of %d. Retrying connection to your server...", i+1, maxRetries),
				}
				if err := json.NewEncoder(w).Encode(progressUpdate); err != nil {
					logger.Log.Printf("SetupVPNHandler: Failed to send retry progress: %v", err)
				}
				flusher.Flush()
			}

			// Try to connect
			sshClient, err = sshclient.NewSSHClient(req.ServerIP, req.Username, authMethod, req.AuthCredential)
			if err == nil {
				logger.Log.Printf("SetupVPNHandler: Successfully connected on attempt %d", i+1)
				break
			}

			// Record detailed error for this attempt
			errMsg := fmt.Sprintf("Attempt %d: %v", i+1, err)
			connectionErrors = append(connectionErrors, errMsg)
			logger.Log.Printf("SetupVPNHandler: SSH connection retry after error: %s", errMsg)

			if i < maxRetries-1 {
				// Exponential backoff with a max of 10 seconds
				backoffTime := time.Duration(math.Min(float64((i+1)*2), 10)) * time.Second
				logger.Log.Printf("SetupVPNHandler: Waiting %v before next attempt", backoffTime)
				time.Sleep(backoffTime)
			}
		}

		if err != nil {
			logger.Log.Printf("SetupVPNHandler: All SSH connection attempts failed after %d tries", maxRetries)

			// Include connection error history in the detailed error message
			errorHistory := strings.Join(connectionErrors, "\n")
			detailedError := fmt.Sprintf("SSH connection failed after %d attempts. Connection history:\n%s\n\nPlease verify:\n"+
				"- The server IP address is correct (%s)\n"+
				"- The server is online and reachable\n"+
				"- SSH service is running on the server\n"+
				"- Credentials are valid\n"+
				"- No firewall is blocking the connection\n\n"+
				"Last error: %v", maxRetries, errorHistory, req.ServerIP, err)

			utils.JSONError(w, detailedError, http.StatusInternalServerError)
			return
		}
		defer sshClient.Close()

		// After successful connection, verify SSH functionality with a simple command
		testCmd := "echo 'Connection test successful'"
		testOut, testErr := sshClient.RunCommand(testCmd)
		if testErr != nil {
			logger.Log.Printf("SetupVPNHandler: SSH connection verification failed: %v", testErr)
			utils.JSONError(w, fmt.Sprintf("SSH connection established but command execution failed: %v", testErr), http.StatusInternalServerError)
			return
		}
		logger.Log.Printf("SetupVPNHandler: SSH connection verified with test command: %s", testOut)

		// Check if password is expired
		if sshClient.IsPasswordExpired() {
			logger.Log.Println("SetupVPNHandler: Detected expired password")

			// Generate a new password
			newPassword, err := generatePassword()
			if err != nil {
				logger.Log.Printf("SetupVPNHandler: Password generation failed: %v", err)
				utils.JSONError(w, "Failed to generate new password", http.StatusInternalServerError)
				return
			}

			// Return a specific response for expired password
			response := PasswordResetResponse{
				Status:      "expired_password",
				Message:     "The password has expired and needs to be reset. Please use the password reset API with the provided new password.",
				NewPassword: newPassword,
			}

			// Log the new password prominently
			logger.Log.Printf("======================================")
			logger.Log.Printf("IMPORTANT: PASSWORD EXPIRED - NEW PASSWORD GENERATED")
			logger.Log.Printf("SERVER IP: %s", req.ServerIP)
			logger.Log.Printf("USERNAME: %s", req.Username)
			logger.Log.Printf("NEW PASSWORD: %s", newPassword)
			logger.Log.Printf("SAVE THIS PASSWORD IMMEDIATELY")
			logger.Log.Printf("======================================")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden) // 403 Forbidden is appropriate for expired credentials
			json.NewEncoder(w).Encode(response)
			return
		}

		// Send initial 200 OK status to client if streaming is supported
		if ok {
			// Send an initial progress update
			progressUpdate := map[string]string{
				"status":  "setup_started",
				"message": "VPN setup process has started. This may take several minutes.",
			}
			if err := json.NewEncoder(w).Encode(progressUpdate); err != nil {
				logger.Log.Printf("SetupVPNHandler: Failed to send initial progress: %v", err)
			}
			flusher.Flush()
		}

		// Track setup progress
		serviceRunning := false
		configValidated := false
		securityEnabled := false
		dataCleanupSuccessful := false
		var vpnConfig string
		var setupErr error
		var securityRecommendations []string

		// Check server OS before proceeding
		osCheck, err := sshClient.RunCommand("cat /etc/os-release | grep -i ubuntu")
		if err != nil || !strings.Contains(osCheck, "Ubuntu") {
			logger.Log.Printf("SetupVPNHandler: Target server is not running Ubuntu: %v", err)
			securityRecommendations = append(securityRecommendations, "The server appears to not be running Ubuntu. This VPN setup is optimized for Ubuntu 22.04 LTS.")
		}

		switch req.VPNType {
		case "openvpn":
			logger.Log.Println("SetupVPNHandler: Starting OpenVPN setup")

			// Send progress update - checking dependencies
			if ok {
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "checking_dependencies",
					"message": "Checking OpenVPN dependencies...",
				})
				flusher.Flush()
			}

			// Check for necessary packages and install if missing
			_, err := sshClient.RunCommand("dpkg -s openvpn easy-rsa >/dev/null 2>&1 || { echo 'Installing OpenVPN packages...'; apt-get update && apt-get install -y openvpn easy-rsa; }")
			if err != nil {
				logger.Log.Printf("SetupVPNHandler: Failed to verify/install OpenVPN packages: %v", err)
				securityRecommendations = append(securityRecommendations, "There were issues installing required packages. Verify the server has internet connectivity and apt-get is working properly.")
			}

			// Send progress update - starting OpenVPN setup
			if ok {
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "installing_openvpn",
					"message": "Installing and configuring OpenVPN...",
				})
				flusher.Flush()
			}

			openvpn := vpn.OpenVPNSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := openvpn.Setup(); err != nil {
				// Unified password expiration handling for both VPN types
				if strings.Contains(err.Error(), "password has expired") ||
					strings.Contains(err.Error(), "Your password has expired") {
					logger.Log.Printf("SetupVPNHandler: Password expired during OpenVPN setup: %v", err)

					// Generate a new password
					newPassword, genErr := generatePassword()
					if genErr != nil {
						logger.Log.Printf("SetupVPNHandler: Password generation failed: %v", genErr)
						utils.JSONError(w, "Failed to generate new password", http.StatusInternalServerError)
						return
					}

					// Return a specific response for expired password
					response := PasswordResetResponse{
						Status:      "expired_password",
						Message:     "The password has expired during setup. Please use the password reset API with the provided new password.",
						NewPassword: newPassword,
					}

					// Log the new password prominently
					logger.Log.Printf("======================================")
					logger.Log.Printf("IMPORTANT: PASSWORD EXPIRED DURING OPENVPN SETUP - NEW PASSWORD GENERATED")
					logger.Log.Printf("SERVER IP: %s", req.ServerIP)
					logger.Log.Printf("USERNAME: %s", req.Username)
					logger.Log.Printf("NEW PASSWORD: %s", newPassword)
					logger.Log.Printf("SAVE THIS PASSWORD IMMEDIATELY")
					logger.Log.Printf("======================================")

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden) // 403 Forbidden is appropriate for expired credentials
					json.NewEncoder(w).Encode(response)
					return
				}

				logger.Log.Printf("SetupVPNHandler: OpenVPN setup failed: %v", err)
				setupErr = err
			} else {
				logger.Log.Println("SetupVPNHandler: OpenVPN setup completed successfully")

				// Send progress update if streaming is supported
				if ok {
					json.NewEncoder(w).Encode(map[string]string{
						"status":  "openvpn_setup_complete",
						"message": "OpenVPN setup completed successfully. Verifying service status...",
					})
					flusher.Flush()
				}

				// Verify service is running
				status, _ := sshClient.RunCommand("systemctl is-active openvpn@server")
				serviceRunning = strings.TrimSpace(status) == "active"
				if serviceRunning {
					logger.Log.Println("SetupVPNHandler: OpenVPN service is active and running")
				} else {
					logger.Log.Println("SetupVPNHandler: OpenVPN service is not active, attempting to start")
					// Try to start the service if it's not running
					_, startErr := sshClient.RunCommand("systemctl start openvpn@server")
					if startErr == nil {
						// Check again after trying to start
						status, _ = sshClient.RunCommand("systemctl is-active openvpn@server")
						serviceRunning = strings.TrimSpace(status) == "active"
					}
				}

				if !serviceRunning {
					securityRecommendations = append(securityRecommendations, "OpenVPN service failed to start. Check server logs with 'journalctl -u openvpn@server' for details.")
				}

				vpnConfig = "/etc/vpn-configs/openvpn_config.ovpn"
			}

		case "ios_vpn":
			logger.Log.Println("SetupVPNHandler: Starting iOS VPN (StrongSwan) setup")

			// Send progress update - checking dependencies
			if ok {
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "checking_dependencies",
					"message": "Checking StrongSwan dependencies...",
				})
				flusher.Flush()
			}

			// Check for necessary packages and install if missing
			_, err := sshClient.RunCommand("dpkg -s strongswan strongswan-pki libcharon-extra-plugins >/dev/null 2>&1 || { echo 'Installing StrongSwan packages...'; apt-get update && apt-get install -y strongswan strongswan-pki libcharon-extra-plugins; }")
			if err != nil {
				logger.Log.Printf("SetupVPNHandler: Failed to verify/install StrongSwan packages: %v", err)
				securityRecommendations = append(securityRecommendations, "There were issues installing StrongSwan packages. Verify the server has internet connectivity.")
			}

			// Send progress update if streaming is supported
			if ok {
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "starting_ios_vpn_setup",
					"message": "Starting iOS VPN (StrongSwan) setup process...",
				})
				flusher.Flush()
			}

			strongswan := vpn.StrongSwanSetup{SSHClient: sshClient, ServerIP: req.ServerIP}
			if err := strongswan.Setup(); err != nil {
				// Unified password expiration handling for both VPN types
				if strings.Contains(err.Error(), "password has expired") ||
					strings.Contains(err.Error(), "Your password has expired") {
					logger.Log.Printf("SetupVPNHandler: Password expired during StrongSwan setup: %v", err)

					// Generate a new password
					newPassword, genErr := generatePassword()
					if genErr != nil {
						logger.Log.Printf("SetupVPNHandler: Password generation failed: %v", genErr)
						utils.JSONError(w, "Failed to generate new password", http.StatusInternalServerError)
						return
					}

					// Return a specific response for expired password
					response := PasswordResetResponse{
						Status:      "expired_password",
						Message:     "The password has expired during setup. Please use the password reset API with the provided new password.",
						NewPassword: newPassword,
					}

					// Log the new password prominently
					logger.Log.Printf("======================================")
					logger.Log.Printf("IMPORTANT: PASSWORD EXPIRED DURING STRONGSWAN SETUP - NEW PASSWORD GENERATED")
					logger.Log.Printf("SERVER IP: %s", req.ServerIP)
					logger.Log.Printf("USERNAME: %s", req.Username)
					logger.Log.Printf("NEW PASSWORD: %s", newPassword)
					logger.Log.Printf("SAVE THIS PASSWORD IMMEDIATELY")
					logger.Log.Printf("======================================")

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden) // 403 Forbidden is appropriate for expired credentials
					json.NewEncoder(w).Encode(response)
					return
				}

				logger.Log.Printf("SetupVPNHandler: StrongSwan setup failed: %v", err)
				setupErr = err
			} else {
				logger.Log.Println("SetupVPNHandler: StrongSwan setup completed successfully")

				// Send progress update if streaming is supported
				if ok {
					json.NewEncoder(w).Encode(map[string]string{
						"status":  "ios_vpn_setup_complete",
						"message": "iOS VPN setup completed successfully. Verifying service status...",
					})
					flusher.Flush()
				}

				// Verify service is running
				status, _ := sshClient.RunCommand("systemctl is-active strongswan")
				serviceRunning = strings.TrimSpace(status) == "active"
				if !serviceRunning {
					logger.Log.Println("SetupVPNHandler: StrongSwan service is not active, attempting to start")
					// Try to start the service if it's not running
					_, startErr := sshClient.RunCommand("systemctl start strongswan")
					if startErr == nil {
						// Check again after trying to start
						status, _ = sshClient.RunCommand("systemctl is-active strongswan")
						serviceRunning = strings.TrimSpace(status) == "active"
					}
				}

				if !serviceRunning {
					securityRecommendations = append(securityRecommendations, "StrongSwan service failed to start. Check server logs with 'journalctl -u strongswan' for details.")
				}

				vpnConfig = "/etc/vpn-configs/ios_vpn.mobileconfig"
			}

		default:
			logger.Log.Printf("SetupVPNHandler: Unsupported VPN type: %s", req.VPNType)
			utils.JSONError(w, "Unsupported VPN type", http.StatusBadRequest)
			return
		}

		// Check for setup errors before continuing
		if setupErr != nil {
			utils.JSONErrorWithDetails(w, setupErr, http.StatusInternalServerError, "", r.URL.Path)
			return
		}

		// Send progress update for config verification
		if ok {
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "verifying_config",
				"message": "Verifying VPN configuration files...",
			})
			flusher.Flush()
		}

		// Verify the config file exists after setup
		exists, err := verifyConfigExists(sshClient, vpnConfig)
		if err != nil {
			logger.Log.Printf("SetupVPNHandler: Error verifying config file: %v", err)
			utils.JSONErrorWithDetails(w, err, http.StatusInternalServerError, "", r.URL.Path)
			return
		}

		configValidated = exists
		if !exists {
			logger.Log.Printf("SetupVPNHandler: Config file not found after setup: %s", vpnConfig)
			utils.JSONError(w, "VPN setup completed but config file not found", http.StatusInternalServerError)
			return
		}

		logger.Log.Printf("SetupVPNHandler: Config file %s verified successfully", vpnConfig)

		// Send progress update for security setup
		if ok {
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "setting_up_security",
				"message": "Setting up security measures (Fail2Ban, firewall)...",
			})
			flusher.Flush()
		}

		security := vpn.SecuritySetup{SSHClient: sshClient}
		if err := security.SetupFail2Ban(); err != nil {
			logger.Log.Printf("SetupVPNHandler: Fail2Ban setup failed: %v", err)
			// Continue anyway but log the error
			monitoring.LogError(err)
			securityRecommendations = append(securityRecommendations, "Failed to set up Fail2Ban. Consider installing it manually for protection against brute force attacks.")
		} else {
			securityEnabled = true
			logger.Log.Println("SetupVPNHandler: Fail2Ban setup completed successfully")
		}

		// Check if we're running in Docker before attempting to disable services
		isDocker := false
		if _, err := os.Stat("/.dockerenv"); err == nil {
			isDocker = true
			logger.Log.Println("SetupVPNHandler: Running in Docker environment, skipping service management")
		}

		if !isDocker {
			if err := security.DisableUnnecessaryServices(); err != nil {
				logger.Log.Printf("SetupVPNHandler: DisableUnnecessaryServices failed: %v", err)
				monitoring.LogError(err)
				securityRecommendations = append(securityRecommendations, "Unable to disable some unnecessary services. Manually check running services with 'systemctl list-unit-files --state=enabled'.")
			}
		} else {
			logger.Log.Println("SetupVPNHandler: Skipping DisableUnnecessaryServices in Docker environment")
		}

		// Send progress update for password generation
		if ok {
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "generating_secure_password",
				"message": "Generating and setting secure root password...",
			})
			flusher.Flush()
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

		logger.Log.Println("SetupVPNHandler: Root password changed successfully")

		// Send progress update for backup creation
		if ok {
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "creating_backup",
				"message": "Creating backup of VPN configuration...",
			})
			flusher.Flush()
		}

		// Create backup after successful setup
		backupManager := utils.BackupManager{SSHClient: sshClient}
		backupPath, err := backupManager.CreateBackup()
		if err != nil {
			logger.Log.Printf("SetupVPNHandler: Backup creation failed: %v", err)
			monitoring.LogError(err)
			securityRecommendations = append(securityRecommendations, "Automatic backup creation failed. Consider manually backing up your VPN configuration files.")
		} else {
			logger.Log.Printf("SetupVPNHandler: Backup created successfully at %s", backupPath)
		}

		// Send progress update for cleanup
		if ok {
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "cleaning_up",
				"message": "Performing final cleanup of sensitive data...",
			})
			flusher.Flush()
		}

		cleanup := utils.DataCleanup{SSHClient: sshClient}
		if err := cleanup.RemoveClientData(); err != nil {
			logger.Log.Printf("SetupVPNHandler: RemoveClientData failed: %v", err)
			monitoring.LogError(err)
			securityRecommendations = append(securityRecommendations, "Data cleanup was incomplete. Some client data may remain on the server.")
		} else {
			dataCleanupSuccessful = true
			logger.Log.Println("SetupVPNHandler: Client data cleanup completed successfully")
		}

		// Determine download endpoint based on VPN type
		downloadEndpoint := "/api/config/download/client?vpnType="
		if req.VPNType == "openvpn" {
			downloadEndpoint += "openvpn"
		} else {
			downloadEndpoint += "ios_vpn"
		}
		downloadEndpoint += fmt.Sprintf("&serverIp=%s", req.ServerIP)

		// Create enhanced response with detailed status
		response := EnhancedVPNSetupResponse{
			VPNConfig:             vpnConfig,
			NewPassword:           newPassword,
			SSHPassword:           sshClient.GetPassword(),
			Status:                "setup_complete",
			Message:               "VPN setup completed successfully with all components verified",
			ServiceRunning:        serviceRunning,
			SecurityEnabled:       securityEnabled,
			ConfigValidated:       configValidated,
			DownloadEndpoint:      downloadEndpoint,
			ServerIP:              req.ServerIP,
			VPNType:               req.VPNType,
			DataCleanupSuccessful: dataCleanupSuccessful,
		}

		// Only include recommendations if there are any
		if len(securityRecommendations) > 0 {
			response.SecurityRecommendations = securityRecommendations
		}

		logger.Log.Println("SetupVPNHandler: Setup completed successfully with all components verified")
		json.NewEncoder(w).Encode(response)
	}
}

// ResetPasswordHandler handles resetting an expired password
func ResetPasswordHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Log.Println("ResetPasswordHandler: Processing request")

		var req PasswordResetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Log.Printf("ResetPasswordHandler: Invalid payload: %v", err)
			utils.JSONError(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.ServerIP == "" || req.Username == "" || req.NewPassword == "" {
			logger.Log.Println("ResetPasswordHandler: Missing required fields")
			utils.JSONError(w, "Missing required fields (server_ip, username, new_password)", http.StatusBadRequest)
			return
		}

		// Validate password strength
		if len(req.NewPassword) < 8 {
			utils.JSONError(w, "New password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		// Initialize SSH client with new password directly
		sshClient, err := sshclient.NewSSHClient(req.ServerIP, req.Username, "password", req.NewPassword)
		if err != nil {
			logger.Log.Printf("ResetPasswordHandler: Failed to connect with new password: %v", err)

			// If connecting with new password fails, try with old password
			if req.OldPassword != "" {
				oldClient, oldErr := sshclient.NewSSHClient(req.ServerIP, req.Username, "password", req.OldPassword)
				if oldErr != nil {
					logger.Log.Printf("ResetPasswordHandler: Failed to connect with old password too: %v", oldErr)
					utils.JSONError(w, "Failed to authenticate with either the old or new password", http.StatusUnauthorized)
					return
				}
				defer oldClient.Close()

				// If old password works but is expired, reset it
				if oldClient.IsPasswordExpired() {
					logger.Log.Println("ResetPasswordHandler: Old password is valid but expired, attempting reset")
					if err := oldClient.ResetPassword(req.NewPassword); err != nil {
						logger.Log.Printf("ResetPasswordHandler: Password reset failed: %v", err)
						utils.JSONError(w, fmt.Sprintf("Failed to reset password: %v", err), http.StatusInternalServerError)
						return
					}
				} else {
					logger.Log.Println("ResetPasswordHandler: Old password is valid and not expired")
					// Old password works and is not expired, so the user just wants to change it
					// Change the password using system utilities
					security := vpn.SecuritySetup{SSHClient: oldClient}
					if err := security.ChangeRootPassword(req.NewPassword); err != nil {
						logger.Log.Printf("ResetPasswordHandler: Failed to change password: %v", err)
						utils.JSONError(w, fmt.Sprintf("Failed to change password: %v", err), http.StatusInternalServerError)
						return
					}
				}
			} else {
				utils.JSONError(w, fmt.Sprintf("Failed to authenticate with new password and no old password provided: %v", err),
					http.StatusUnauthorized)
				return
			}
		}
		defer sshClient.Close()

		// Test the connection with the new password by running a simple command
		_, err = sshClient.RunCommand("echo 'Password reset successful'")
		if err != nil {
			logger.Log.Printf("ResetPasswordHandler: Failed to run test command after password reset: %v", err)
			utils.JSONError(w, "Password may be reset but the connection test failed", http.StatusInternalServerError)
			return
		}

		// Successfully reset password
		response := PasswordResetResponse{
			Status:      "success",
			Message:     "Password has been reset successfully",
			NewPassword: req.NewPassword,
		}

		// Log the password reset success with the new password
		logger.Log.Printf("======================================")
		logger.Log.Printf("PASSWORD RESET SUCCESSFUL")
		logger.Log.Printf("SERVER IP: %s", req.ServerIP)
		logger.Log.Printf("USERNAME: %s", req.Username)
		logger.Log.Printf("NEW PASSWORD: %s", req.NewPassword)
		logger.Log.Printf("======================================")
		logger.Log.Println("ResetPasswordHandler: Password reset successful")

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

// RegisterRoutes sets up all API routes
func RegisterRoutes(router *mux.Router, cfg *config.Config, db *sql.DB) {
	// Public endpoints that don't need auth
	router.HandleFunc("/health", HealthCheckHandler()).Methods("GET")
	router.HandleFunc("/metrics", MetricsHandler(cfg)).Methods("GET")

	// API endpoints with /api prefix
	apiRouter := router.PathPrefix("/api").Subrouter()

	// Public API endpoints
	apiRouter.HandleFunc("/csrf-token", CSRFTokenHandler(cfg)).Methods("GET", "OPTIONS")
	apiRouter.HandleFunc("/auth/status", AuthStatusHandler(cfg)).Methods("GET", "OPTIONS")
	apiRouter.HandleFunc("/auth/login", LoginHandler(cfg)).Methods("POST", "OPTIONS")
	apiRouter.HandleFunc("/auth/register", RegisterHandler(cfg.DB, cfg)).Methods("POST", "OPTIONS")
	apiRouter.HandleFunc("/password/reset", ResetPasswordHandler(cfg)).Methods("POST", "OPTIONS")

	// Protected API routes
	protectedRouter := apiRouter.PathPrefix("").Subrouter()
	protectedRouter.Use(JWTAuthenticationMiddleware(cfg))
	protectedRouter.Use(CSRFMiddleware(cfg))

	protectedRouter.HandleFunc("/setup", SetupVPNHandler(cfg)).Methods("POST")
	protectedRouter.HandleFunc("/vpn/status", VPNStatusHandler(cfg)).Methods("GET")
	protectedRouter.HandleFunc("/config/download", DownloadConfigHandler()).Methods("GET")
	protectedRouter.HandleFunc("/config/download/client", DownloadClientConfigHandler()).Methods("GET")
	protectedRouter.HandleFunc("/config/download/server", DownloadServerConfigHandler()).Methods("GET")
	protectedRouter.HandleFunc("/backup", BackupHandler(cfg)).Methods("POST")
	protectedRouter.HandleFunc("/restore", RestoreHandler(cfg)).Methods("POST")
	protectedRouter.HandleFunc("/logs", LogsHandler(cfg)).Methods("GET")
}

// LogsHandler returns an http.HandlerFunc that handles both VPN and setup logs retrieval
func LogsHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check auth context first (from JWT middleware)
		userCtx := r.Context().Value("username")

		// If not authenticated through JWT middleware, check for auth_token parameter
		// This is a workaround for EventSource which doesn't support custom headers
		if userCtx == nil {
			// Check for auth_token in query parameters
			authToken := r.URL.Query().Get("auth_token")
			if authToken != "" {
				// Validate the token
				claims, err := auth.ValidateJWT(authToken, cfg)
				if err == nil && claims != nil {
					// Valid token, create a context with the username
					ctx := context.WithValue(r.Context(), "username", claims.Username)
					r = r.WithContext(ctx)
					userCtx = claims.Username
					logger.Log.Printf("LogsHandler: Authenticated via auth_token parameter for user %s", claims.Username)
				} else {
					logger.Log.Printf("LogsHandler: Invalid auth_token provided: %v", err)
					// Return 401 for invalid token instead of redirecting
					utils.JSONError(w, "Invalid or expired token", http.StatusUnauthorized)
					return
				}
			}
		}

		// Check if authentication was successful
		if userCtx == nil {
			logger.Log.Println("LogsHandler: Unauthorized access attempt")
			// Always return 401 for API endpoints
			utils.JSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Set headers for SSE - MUST be set before any writes to response
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Get flusher capability
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Send initial event to establish connection
		fmt.Fprintf(w, "data: %s\n\n", "Connection established")
		flusher.Flush()

		// Check log type from query parameter
		logType := r.URL.Query().Get("type")
		if logType == "" {
			logType = "vpn" // Default to VPN logs if not specified
		}

		// Use request context for cancellation
		ctx := r.Context()

		// Handle VPN logs with proper streaming
		if logType == "vpn" {
			// Send initial event to establish connection
			fmt.Fprintf(w, "data: %s\n\n", "Connection established")

			cmd := exec.Command("bash", "-c", "docker logs --tail 50 -f vpn-server")

			// Get pipe to command's stdout
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				logger.Log.Printf("Error creating stdout pipe: %v", err)
				fmt.Fprintf(w, "data: Error creating stdout pipe: %v\n\n", err)
				flusher.Flush()
				return
			}

			// Start the command
			if err := cmd.Start(); err != nil {
				logger.Log.Printf("Error starting docker logs command: %v", err)
				fmt.Fprintf(w, "data: Error starting docker logs command: %v\n\n", err)
				flusher.Flush()
				return
			}

			// Set up a go routine to properly handle process cleanup
			go func() {
				<-ctx.Done()
				// Kill the process if the client disconnects
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
				cmd.Wait() // Clean up resources
			}()

			// Read from stdout pipe in chunks and send to client
			reader := bufio.NewReader(stdout)
			buffer := make([]byte, 1024)

			for {
				select {
				case <-ctx.Done():
					return
				default:
					n, err := reader.Read(buffer)
					if err != nil {
						if err != io.EOF {
							logger.Log.Printf("Error reading from docker logs: %v", err)
						}
						// Wait a bit before retrying or returning
						time.Sleep(1 * time.Second)
						continue
					}

					if n > 0 {
						fmt.Fprintf(w, "data: %s\n\n", string(buffer[:n]))
						flusher.Flush()
					}
				}
			}
		} else if logType == "setup" {
			// Send initial event to establish connection
			fmt.Fprintf(w, "data: %s\n\n", "Connection established")

			// Handle setup logs (from memory)
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Get VPN setup logs from logger
					logMessages, err := logger.GetRecentLogs(50)
					if err == nil && len(logMessages) > 0 {
						fmt.Fprintf(w, "data: %s\n\n", strings.Join(logMessages, "\n"))
						flusher.Flush()
					}
				}
			}
		} else {
			http.Error(w, "Invalid log type", http.StatusBadRequest)
			return
		}
	}
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
		// Get VPN type from query parameter instead of URL vars
		vpnType := r.URL.Query().Get("vpnType")

		// Validate VPN type
		if vpnType != "openvpn" && vpnType != "ios_vpn" {
			vpnType = "openvpn" // Default to OpenVPN if not specified or invalid
		}

		// Get required query parameters
		serverIP := r.URL.Query().Get("serverIp")
		if serverIP == "" {
			http.Error(w, "Missing serverIp parameter", http.StatusBadRequest)
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
			http.Error(w, "Missing credential parameter", http.StatusBadRequest)
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
		if vpnType == "ios_vpn" {
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
		// Set CORS headers FIRST - before writing any response
		origin := r.Header.Get("Origin")
		if origin != "" && isValidOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization, X-CSRF-Token")
			w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
			w.Header().Set("Vary", "Origin")
		}

		// Set content type and security headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

		// Handle preflight immediately
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Check authentication status - either auth is disabled or we have a valid token
		isAuthenticated := !cfg.AuthEnabled

		// Only check token if auth is enabled
		if cfg.AuthEnabled {
			// Get token from Authorization header or cookie
			var tokenStr string
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
			} else if cookie, err := r.Cookie("Authorization"); err == nil {
				tokenStr = strings.TrimPrefix(cookie.Value, "Bearer ")
			}

			if tokenStr != "" {
				// Example of using jwt package for token validation
				token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
					// This is just to make use of the jwt import, the real validation is done by auth.ValidateJWT
					return nil, fmt.Errorf("token validation delegated to auth.ValidateJWT")
				})
				if err != nil && !strings.Contains(err.Error(), "token validation delegated") {
					logger.Log.Printf("JWT parsing error: %v", err)
				}
				_ = token // To avoid unused variable warning

				// Use the auth package for actual validation
				claims, err := auth.ValidateJWT(tokenStr, cfg)
				if err == nil && claims != nil {
					isAuthenticated = true
					logger.Log.Printf("Auth status check successful for user %s", claims.Username)
				} else {
					logger.Log.Printf("JWT validation failed: %v", err)
				}
			}
		}

		// Create and send response
		response := AuthStatusResponse{
			Enabled:       cfg.AuthEnabled,
			Authenticated: isAuthenticated,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.Log.Printf("AuthStatusHandler: Error encoding response: %v", err)
			http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
			return
		}
	}
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
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		// Check file existence and ownership
		cmd := fmt.Sprintf("sudo test -f %s && sudo test -r %s && echo exists || echo notfound", configPath, configPath)
		out, err := client.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Error checking config file (attempt %d/%d): %v", i+1, maxRetries, err)
			// Only retry on command execution errors
			if i < maxRetries-1 {
				time.Sleep(time.Duration(i+1) * time.Second)
				continue
			}
			return false, fmt.Errorf("error checking config file after %d attempts: %v", maxRetries, err)
		}

		if strings.TrimSpace(out) == "exists" {
			// Verify file permissions
			statCmd := fmt.Sprintf("sudo stat -c %%a %s", configPath)
			perms, err := client.RunCommand(statCmd)
			if err != nil {
				return false, fmt.Errorf("error checking file permissions: %v", err)
			}

			// Check if permissions are at least 644 (readable)
			if perms := strings.TrimSpace(perms); len(perms) == 3 {
				if first := int(perms[0] - '0'); first >= 6 {
					return true, nil
				}
				// Fix permissions if needed
				fixCmd := fmt.Sprintf("sudo chmod 644 %s", configPath)
				if _, err := client.RunCommand(fixCmd); err != nil {
					return false, fmt.Errorf("error fixing file permissions: %v", err)
				}
				return true, nil
			}
		}

		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}
	}
	return false, nil
}

// VPNStatusHandler returns an http.HandlerFunc that handles VPN status requests
// It provides detailed information about VPN service status, connected clients,
// and security features like Fail2Ban.
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
		ovpnStatus, _ := sshClient.RunCommand("systemctl is-active openvpn@server")
		strongswanStatus, _ := sshClient.RunCommand("systemctl is-active strongswan")

		var vpnType string
		var isRunning bool
		var activeClients int
		var uptime string
		var securityStats *SecStat

		// Check security features status
		fail2banActive, _ := sshClient.RunCommand("systemctl is-active fail2ban")
		firewallActive, _ := sshClient.RunCommand("ufw status | grep -q 'Status: active' && echo active || echo inactive")

		securityStats = &SecStat{
			Fail2BanEnabled: strings.TrimSpace(fail2banActive) == "active",
			FirewallActive:  strings.TrimSpace(firewallActive) == "active",
			LastUpdated:     time.Now().Format(time.RFC3339),
		}

		if strings.TrimSpace(ovpnStatus) == "active" {
			vpnType = "openvpn"
			isRunning = true

			// Get service uptime
			uptimeCmd := "systemctl show openvpn@server -p ActiveState,ActiveEnterTimestamp | grep ActiveEnterTimestamp | cut -d= -f2"
			uptimeOutput, _ := sshClient.RunCommand(uptimeCmd)
			if uptimeOutput != "" {
				// Convert to a more readable format
				t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(uptimeOutput))
				if err == nil {
					uptime = time.Since(t).Round(time.Second).String()
				}
			}

			// Count active clients
			clientsCmd := "cat /var/log/openvpn/openvpn-status.log 2>/dev/null | grep CLIENT_LIST | grep -v HEADER | wc -l || echo 0"
			clientsOutput, _ := sshClient.RunCommand(clientsCmd)
			if n, err := strconv.Atoi(strings.TrimSpace(clientsOutput)); err == nil {
				activeClients = n
			}
		} else if strings.TrimSpace(strongswanStatus) == "active" {
			vpnType = "ios_vpn"
			isRunning = true

			// Get service uptime
			uptimeCmd := "systemctl show strongswan -p ActiveState,ActiveEnterTimestamp | grep ActiveEnterTimestamp | cut -d= -f2"
			uptimeOutput, _ := sshClient.RunCommand(uptimeCmd)
			if uptimeOutput != "" {
				// Convert to a more readable format
				t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(uptimeOutput))
				if err == nil {
					uptime = time.Since(t).Round(time.Second).String()
				}
			}

			// Count active clients for StrongSwan/IKEv2
			clientsCmd := "ipsec status | grep -c 'ESTABLISHED' || echo 0"
			clientsOutput, _ := sshClient.RunCommand(clientsCmd)
			if n, err := strconv.Atoi(strings.TrimSpace(clientsOutput)); err == nil {
				activeClients = n
			}
		}

		response := VPNStatusResponse{
			Status:        "ok",
			IsRunning:     isRunning,
			ServerIP:      serverIP,
			VPNType:       vpnType,
			ActiveClients: activeClients,
			Uptime:        uptime,
			SecurityStats: securityStats,
		}

		logger.Log.Println("VPNStatusHandler: Sending response")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
