// Package vpn provides VPN server configuration functionality.
//
// This package implements the core VPN setup logic for OpenVPN and StrongSwan (IKEv2).
// It handles secure certificate generation, server configuration, and client profile
// generation. The package ensures secure defaults and follows best practices for
// VPN server configuration.
package vpn

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

// StrongSwanSetup handles IKEv2/IPSec configuration using StrongSwan.
type StrongSwanSetup struct {
	SSHClient *sshclient.SSHClient
	ServerIP  string
}

func generateStrongVPNPassword() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, 32)
	rand.Read(b)
	password := make([]byte, 32)
	for i := range b {
		password[i] = chars[int(b[i])%len(chars)]
	}
	return string(password)
}

// Setup configures StrongSwan IKEv2 on the remote server.
// It installs required packages, generates certificates, and configures
// IPSec with secure cipher suites and settings.
func (s *StrongSwanSetup) Setup() error {
	logger.Log.Println("Starting StrongSwan setup")

	// Generate secure VPN password
	logger.Log.Println("Generating secure VPN password...")
	vpnPassword := generateStrongVPNPassword()
	logger.Log.Println("Secure password generated successfully")

	// First try to clean any stuck locks and fix package state
	cleanupCmds := []string{
		// Kill any stuck apt/dpkg processes
		"sudo killall apt apt-get dpkg",
		// Remove locks
		"sudo rm -f /var/lib/apt/lists/lock",
		"sudo rm -f /var/cache/apt/archives/lock",
		"sudo rm -f /var/lib/dpkg/lock*",
		// Clean package cache
		"sudo apt-get clean",
		"sudo apt-get autoclean",
		// Fix interrupted dpkg
		"sudo dpkg --configure -a",
		// Clean and update package cache
		"sudo apt-get clean",
		"sudo rm -rf /var/lib/apt/lists/*",
		"sudo apt-get update --fix-missing",
	}

	for _, cmd := range cleanupCmds {
		logger.Log.Printf("Running cleanup command: %s", cmd)
		if _, err := s.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Warning: Cleanup command failed: %s, Error: %v", cmd, err)
			// Continue even if cleanup fails
		}
		time.Sleep(2 * time.Second)
	}

	// Wait for any existing apt processes to finish
	waitCmd := `while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 || sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || sudo fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 1; done`
	if _, err := s.SSHClient.RunCommand(waitCmd); err != nil {
		logger.Log.Printf("Warning: Wait command failed: %v", err)
	}

	// Package installation with enhanced security packages
	logger.Log.Println("Step 1/6: Updating system and installing StrongSwan packages...")
	cmds := []string{
		"sudo apt-get update",
		"sudo apt-get install -f", // Fix any broken dependencies first
		"sudo DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins fail2ban ufw openssl",
	}

	maxRetries := 3
	for _, cmd := range cmds {
		success := false
		for attempt := 1; attempt <= maxRetries; attempt++ {
			logger.Log.Printf("Running command (attempt %d/%d): %s", attempt, maxRetries, cmd)
			output, err := s.SSHClient.RunCommand(cmd)
			if err != nil {
				logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
				if attempt < maxRetries {
					logger.Log.Printf("Waiting before retry...")
					// Clean up and wait before retry
					s.SSHClient.RunCommand("sudo apt-get clean")
					s.SSHClient.RunCommand("sudo rm -rf /var/lib/apt/lists/*")
					s.SSHClient.RunCommand("sudo apt-get update --fix-missing")
					time.Sleep(time.Duration(attempt) * 10 * time.Second)
					continue
				}
				return fmt.Errorf("package installation failed after %d attempts: %v", maxRetries, err)
			}
			success = true
			break
		}
		if !success {
			return fmt.Errorf("package installation failed after %d attempts", maxRetries)
		}
		// Force immediate flush of logs
		time.Sleep(2 * time.Second)
	}
	logger.Log.Println("Packages installed successfully")

	// Secure certificate generation with stronger parameters
	logger.Log.Println("Step 2/6: Generating secure certificates...")
	certSetup := []string{
		"sudo mkdir -p /etc/ipsec.d/{cacerts,certs,private}",
		"sudo chmod 700 /etc/ipsec.d/{cacerts,certs,private}",
		"cd /etc/ipsec.d && sudo ipsec pki --gen --type rsa --size 4096 --outform pem > private/ca.key.pem",
		"sudo chmod 600 /etc/ipsec.d/private/ca.key.pem",
		"cd /etc/ipsec.d && sudo ipsec pki --self --ca --lifetime 3650 --in private/ca.key.pem --type rsa --dn 'CN=VPN CA' --outform pem > cacerts/ca.cert.pem",
		"cd /etc/ipsec.d && sudo ipsec pki --gen --type rsa --size 4096 --outform pem > private/server.key.pem",
		"sudo chmod 600 /etc/ipsec.d/private/server.key.pem",
		fmt.Sprintf("cd /etc/ipsec.d && sudo ipsec pki --pub --in private/server.key.pem | sudo ipsec pki --issue --lifetime 1825 --cacert cacerts/ca.cert.pem --cakey private/ca.key.pem --dn 'CN=%s' --san '%s' --flag serverAuth --flag ikeIntermediate --outform pem > certs/server.cert.pem", s.ServerIP, s.ServerIP),
	}

	for i, cmd := range certSetup {
		logger.Log.Printf("Certificate setup step %d/%d: %s", i+1, len(certSetup), cmd)
		out, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: Output: %s, Error: %v", out, err)
			return fmt.Errorf("certificate generation failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}
	logger.Log.Println("Certificates generated successfully")

	// Enhanced StrongSwan configuration with modern crypto
	logger.Log.Println("Step 3/6: Creating StrongSwan configuration...")
	strongswanConf := fmt.Sprintf(`config setup
    charondebug="ike 2, knl 2, cfg 2"
    uniqueids=no

conn %default
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    
    # Strong crypto settings
    ike=aes256gcm16-prfsha384-ecp384!
    esp=aes256gcm16-ecp384!
    
    left=%any
    leftid=%s
    leftcert=server.cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    
    right=%any
    rightid=%%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=1.1.1.1,1.0.0.1
    rightsendcert=never
    eap_identity=%%identity

conn ikev2-vpn
    also=%%default
    auto=add`, s.ServerIP)

	// Write main config
	logger.Log.Println("Writing IPsec configuration file...")
	if out, err := s.SSHClient.RunCommand(fmt.Sprintf("echo '%s' | sudo tee /etc/ipsec.conf", strongswanConf)); err != nil {
		logger.Log.Printf("Command failed: Output: %s, Error: %v", out, err)
		return fmt.Errorf("failed to write ipsec.conf: %v", err)
	}
	logger.Log.Println("IPsec configuration written successfully")

	// Secure secrets configuration with generated password
	logger.Log.Println("Step 4/6: Setting up secure secrets...")
	secretsConf := fmt.Sprintf(`: RSA "server.key.pem"
%%any : EAP "%s"`, vpnPassword)

	logger.Log.Println("Writing IPsec secrets file...")
	if out, err := s.SSHClient.RunCommand(fmt.Sprintf("echo '%s' | sudo tee /etc/ipsec.secrets", secretsConf)); err != nil {
		logger.Log.Printf("Command failed: Output: %s, Error: %v", out, err)
		return fmt.Errorf("failed to write ipsec.secrets: %v", err)
	}
	logger.Log.Println("IPsec secrets written successfully")

	// Create VPN configs directory
	logger.Log.Println("Creating directory for VPN configurations...")
	if out, err := s.SSHClient.RunCommand("sudo mkdir -p /etc/vpn-configs && sudo chmod 755 /etc/vpn-configs"); err != nil {
		logger.Log.Printf("Warning: Failed to create VPN configs directory: %v, Output: %s", err, out)
	}

	// Secure permissions
	logger.Log.Println("Step 5/6: Setting up system security...")
	securityCmds := []string{
		"sudo chmod 600 /etc/ipsec.secrets",
		"sudo chmod 644 /etc/ipsec.conf",
		"sudo sysctl -w net.ipv4.ip_forward=1",
		"sudo sysctl -w net.ipv4.conf.all.accept_redirects=0",
		"sudo sysctl -w net.ipv4.conf.all.send_redirects=0",
		"sudo sysctl -p",
	}

	for i, cmd := range securityCmds {
		logger.Log.Printf("Security step %d/%d: %s", i+1, len(securityCmds), cmd)
		out, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Warning: Security command failed: %s, Output: %s, Error: %v", cmd, out, err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}
	logger.Log.Println("Security settings applied")

	// Configure and start service
	logger.Log.Println("Step 6/6: Starting and enabling StrongSwan service...")
	serviceCmds := []string{
		"sudo systemctl restart strongswan-starter",
		"sudo systemctl enable strongswan-starter",
	}

	for i, cmd := range serviceCmds {
		logger.Log.Printf("Service step %d/%d: %s", i+1, len(serviceCmds), cmd)
		out, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, out, err)
			return fmt.Errorf("service configuration failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}

	// Verify service status
	logger.Log.Println("Verifying StrongSwan service status...")
	out, err := s.SSHClient.RunCommand("systemctl is-active strongswan-starter")
	if err != nil {
		logger.Log.Printf("Service status check failed: Output: %s, Error: %v", out, err)
		return fmt.Errorf("StrongSwan service failed to start: %v", err)
	}

	trimmedStatus := strings.TrimSpace(out)
	if trimmedStatus != "active" {
		logger.Log.Printf("Service is not active, status: %s", trimmedStatus)
		return fmt.Errorf("StrongSwan service is not active, status: %s", trimmedStatus)
	}
	logger.Log.Println("StrongSwan service is active and running")

	// Save the VPN credentials securely
	logger.Log.Println("Saving VPN credentials...")
	credsOutput := fmt.Sprintf("VPN_USERNAME=vpnuser\nVPN_PASSWORD=%s", vpnPassword)
	if out, err := s.SSHClient.RunCommand(fmt.Sprintf("echo '%s' | sudo tee /etc/vpn-configs/credentials.txt && sudo chmod 600 /etc/vpn-configs/credentials.txt", credsOutput)); err != nil {
		logger.Log.Printf("Warning: Failed to save credentials: %v, Output: %s", err, out)
	} else {
		logger.Log.Println("VPN credentials saved to /etc/vpn-configs/credentials.txt")
	}

	logger.Log.Println("StrongSwan setup completed successfully")
	return nil
}
