package vpn

import (
	"fmt"
	"strings"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type OpenVPNSetup struct {
	SSHClient *sshclient.SSHClient
	ServerIP  string
}

func (o *OpenVPNSetup) Setup() error {
	logger.Log.Println("Starting OpenVPN setup")

	// Update and install required packages
	logger.Log.Println("Step 1/6: Updating system and installing packages...")

	// First try to clean any stuck locks
	cleanupCmds := []string{
		"sudo rm -f /var/lib/dpkg/lock-frontend",
		"sudo rm -f /var/lib/dpkg/lock",
		"sudo rm -f /var/cache/apt/archives/lock",
		"sudo dpkg --configure -a",
	}

	for _, cmd := range cleanupCmds {
		logger.Log.Printf("Running cleanup command: %s", cmd)
		if _, err := o.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Warning: Cleanup command failed: %s, Error: %v", cmd, err)
			// Continue even if cleanup fails
		}
		time.Sleep(2 * time.Second)
	}

	cmds := []string{
		"sudo apt-get update",
		"sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
		"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn easy-rsa fail2ban ufw openssl",
	}

	maxRetries := 3
	for _, cmd := range cmds {
		success := false
		for attempt := 1; attempt <= maxRetries; attempt++ {
			logger.Log.Printf("Running command (attempt %d/%d): %s", attempt, maxRetries, cmd)
			output, err := o.SSHClient.RunCommand(cmd)
			if err != nil {
				logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
				if attempt < maxRetries {
					logger.Log.Printf("Waiting before retry...")
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

	// Clean up any existing easy-rsa directory and create new setup
	logger.Log.Println("Step 2/6: Setting up PKI infrastructure...")
	setupCmds := []string{
		"sudo rm -rf ~/easy-rsa",           // Remove existing directory
		"sudo rm -rf /etc/openvpn/certs/*", // Clean up existing certs
		"make-cadir ~/easy-rsa",
		"cd ~/easy-rsa && ./easyrsa init-pki",
		"cd ~/easy-rsa && echo 'set_var EASYRSA_KEY_SIZE 4096' > vars",
		"cd ~/easy-rsa && echo 'set_var EASYRSA_DIGEST \"sha512\"' >> vars",
		// Use the full path to easyrsa and export the vars
		"cd ~/easy-rsa && export EASYRSA=$(pwd) && ./easyrsa --batch build-ca nopass",
		"cd ~/easy-rsa && export EASYRSA=$(pwd) && ./easyrsa --batch gen-req server nopass",
		"cd ~/easy-rsa && export EASYRSA=$(pwd) && ./easyrsa --batch sign-req server server",
		"cd ~/easy-rsa && openssl dhparam -out dh.pem 2048", // Reduced to 2048 for faster generation while still secure
		"sudo mkdir -p /etc/openvpn/certs",
		"sudo chmod -R 700 /etc/openvpn/certs",
		"sudo cp ~/easy-rsa/pki/ca.crt /etc/openvpn/certs/",
		"sudo cp ~/easy-rsa/pki/issued/server.crt /etc/openvpn/certs/",
		"sudo cp ~/easy-rsa/pki/private/server.key /etc/openvpn/certs/",
		"sudo cp ~/easy-rsa/dh.pem /etc/openvpn/certs/",
		"sudo chmod -R 600 /etc/openvpn/certs/*",
	}

	for i, cmd := range setupCmds {
		logger.Log.Printf("PKI setup %d/%d: %s", i+1, len(setupCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("PKI setup failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}
	logger.Log.Println("PKI setup completed successfully")

	// Enhanced OpenVPN server configuration
	logger.Log.Println("Step 3/6: Creating OpenVPN server configuration...")
	serverConfig := `port 1194
proto udp
dev tun
ca /etc/openvpn/certs/ca.crt
cert /etc/openvpn/certs/server.crt
key /etc/openvpn/certs/server.key
dh /etc/openvpn/certs/dh.pem
server 10.8.0.0 255.255.255.0
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
push "block-outside-dns"
keepalive 10 120
cipher AES-256-GCM
auth SHA512
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
ncp-ciphers AES-256-GCM:AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
mute 20
tls-server
remote-cert-tls client
duplicate-cn
max-clients 10
script-security 2
verify-client-cert require`

	// Create log directory and set permissions
	logger.Log.Println("Step 4/6: Setting up log directories...")
	logSetupCmds := []string{
		"sudo mkdir -p /var/log/openvpn",
		"sudo chown nobody:nogroup /var/log/openvpn",
		"sudo chmod 755 /var/log/openvpn",
	}

	for _, cmd := range logSetupCmds {
		logger.Log.Printf("Running command: %s", cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Warning: Log directory setup failed: %s, Output: %s, Error: %v", cmd, output, err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}

	// Write server config
	logger.Log.Println("Writing server configuration...")
	cmd := fmt.Sprintf("echo '%s' | sudo tee /etc/openvpn/server.conf", serverConfig)
	output, err := o.SSHClient.RunCommand(cmd)
	if err != nil {
		logger.Log.Printf("Command failed: Output: %s, Error: %v", output, err)
		return fmt.Errorf("failed to write server config: %v", err)
	}

	// Create directory for client configs
	logger.Log.Println("Creating directory for client configs...")
	createClientDirCmd := "sudo mkdir -p /etc/vpn-configs && sudo chmod 755 /etc/vpn-configs"
	_, err = o.SSHClient.RunCommand(createClientDirCmd)
	if err != nil {
		logger.Log.Printf("Warning: Failed to create client config directory: %v", err)
	}

	// Configure system settings
	logger.Log.Println("Step 5/6: Configuring system settings...")
	sysctlCmds := []string{
		"echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-openvpn.conf",
		"echo 'net.ipv4.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.d/99-openvpn.conf",
		"sudo sysctl --system",
	}

	for _, cmd := range sysctlCmds {
		logger.Log.Printf("Running command: %s", cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("system configuration failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}

	// Start and enable OpenVPN service
	logger.Log.Println("Step 6/6: Starting OpenVPN service...")
	serviceCmds := []string{
		"sudo systemctl daemon-reload",
		"sudo systemctl start openvpn@server",
		"sudo systemctl enable openvpn@server",
	}

	for _, cmd := range serviceCmds {
		logger.Log.Printf("Running command: %s", cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("service activation failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}

	// Verify service status
	logger.Log.Println("Verifying OpenVPN service status...")
	status, err := o.SSHClient.RunCommand("systemctl is-active openvpn@server")
	if err != nil {
		logger.Log.Printf("Service status check failed: Output: %s, Error: %v", status, err)
		return fmt.Errorf("OpenVPN service failed to start: %v", err)
	}

	trimmedStatus := strings.TrimSpace(status)
	if trimmedStatus != "active" {
		logger.Log.Printf("Service is not active, status: %s", trimmedStatus)
		return fmt.Errorf("OpenVPN service is not active, status: %s", trimmedStatus)
	}

	// Generate client config
	logger.Log.Println("Generating client configuration...")
	clientConfig := fmt.Sprintf(`client
dev tun
proto udp
remote %s 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
verb 3
key-direction 1`, o.ServerIP)

	clientConfigCmd := fmt.Sprintf("echo '%s' | sudo tee /etc/vpn-configs/openvpn_config.ovpn", clientConfig)
	_, err = o.SSHClient.RunCommand(clientConfigCmd)
	if err != nil {
		logger.Log.Printf("Warning: Failed to generate client config: %v", err)
	} else {
		logger.Log.Println("Client configuration created at /etc/vpn-configs/openvpn_config.ovpn")
	}

	logger.Log.Println("OpenVPN setup completed successfully")
	return nil
}
