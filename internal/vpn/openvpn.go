package vpn

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

// OpenVPNSetup handles the configuration of the OpenVPN server.
type OpenVPNSetup struct {
	SSHClient *sshclient.SSHClient
	ServerIP  string
}

// Setup configures an OpenVPN server on the given host.
func (o *OpenVPNSetup) Setup() error {
	logger.Log.Println("Starting OpenVPN setup")

	// Check if we're running in Docker
	isDocker := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isDocker = true
		logger.Log.Println("Running in Docker environment")
	}

	// Check disk space first
	spaceCheckCmd := "df -h / | awk 'NR==2 {print $4}'"
	if out, err := o.SSHClient.RunCommand(spaceCheckCmd); err == nil {
		logger.Log.Printf("Available disk space: %s", out)
	}

	// Wait for any existing apt processes to finish
	waitCmd := `while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 1; done`
	if isDocker {
		// In Docker, we likely don't need sudo
		waitCmd = `while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 1; done`
	}

	if out, err := o.SSHClient.RunCommand(waitCmd); err != nil {
		logger.Log.Printf("Warning: Wait command failed: %v, output: %s", err, out)
	}

	// Prepare commands based on environment
	var cmds []string
	if isDocker {
		// In Docker, don't use sudo
		cmds = []string{
			"apt-get update",
			"apt-get install -f", // Fix any broken dependencies first
			"DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y openvpn easy-rsa fail2ban ufw openssl",
		}
	} else {
		cmds = []string{
			"sudo apt-get update",
			"sudo apt-get install -f", // Fix any broken dependencies first
			"sudo DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y openvpn easy-rsa fail2ban ufw openssl",
		}
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
					// Clean up and wait before retry
					cleanCmd := "apt-get clean"
					rmCmd := "rm -rf /var/lib/apt/lists/*"
					fixCmd := "apt-get update --fix-missing"

					if !isDocker {
						cleanCmd = "sudo " + cleanCmd
						rmCmd = "sudo " + rmCmd
						fixCmd = "sudo " + fixCmd
					}

					o.SSHClient.RunCommand(cleanCmd)
					o.SSHClient.RunCommand(rmCmd)
					o.SSHClient.RunCommand(fixCmd)
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
		"rm -rf ~/easy-rsa",           // Remove existing directory
		"rm -rf /etc/openvpn/certs/*", // Clean up existing certs
		"make-cadir ~/easy-rsa",
		"cd ~/easy-rsa && ./easyrsa init-pki",
		"cd ~/easy-rsa && echo 'set_var EASYRSA_KEY_SIZE 4096' > vars",
		"cd ~/easy-rsa && echo 'set_var EASYRSA_DIGEST sha512' >> vars", // Fixed escape sequence issue
		// Use the full path to easyrsa and export the vars
		"cd ~/easy-rsa && export EASYRSA=$(pwd) && ./easyrsa --batch build-ca nopass",
		"cd ~/easy-rsa && export EASYRSA=$(pwd) && ./easyrsa --batch gen-req server nopass",
		"cd ~/easy-rsa && export EASYRSA=$(pwd) && ./easyrsa --batch sign-req server server",
		"cd ~/easy-rsa && openssl dhparam -out dh.pem 2048", // Reduced to 2048 for faster generation while still secure
		"mkdir -p /etc/openvpn/certs",
		"chmod -R 700 /etc/openvpn/certs",
		"cp ~/easy-rsa/pki/ca.crt /etc/openvpn/certs/",
		"cp ~/easy-rsa/pki/issued/server.crt /etc/openvpn/certs/",
		"cp ~/easy-rsa/pki/private/server.key /etc/openvpn/certs/",
		"cp ~/easy-rsa/dh.pem /etc/openvpn/certs/",
		"chmod -R 600 /etc/openvpn/certs/*",
	}

	// Add sudo prefix if not in Docker
	if !isDocker {
		for i := 10; i < len(setupCmds); i++ { // Start from index 10 which is "mkdir -p" command
			setupCmds[i] = "sudo " + setupCmds[i]
		}
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
verb 3
mute 20
explicit-exit-notify 1`

	// Write server config
	logger.Log.Println("Writing server configuration...")
	echoCmd := fmt.Sprintf("echo '%s'", serverConfig)
	teeCmd := "tee /etc/openvpn/server.conf"
	if !isDocker {
		teeCmd = "sudo " + teeCmd
	}
	cmd := fmt.Sprintf("%s | %s", echoCmd, teeCmd)

	output, err := o.SSHClient.RunCommand(cmd)
	if err != nil {
		logger.Log.Printf("Command failed: Output: %s, Error: %v", output, err)
		return fmt.Errorf("failed to write server config: %v", err)
	}

	// Create directory for client configs
	logger.Log.Println("Creating directory for client configs...")
	createClientDirCmd := "mkdir -p /etc/vpn-configs && chmod 755 /etc/vpn-configs"
	if !isDocker {
		createClientDirCmd = "sudo " + createClientDirCmd
	}
	output, err = o.SSHClient.RunCommand(createClientDirCmd)
	if err != nil {
		logger.Log.Printf("Warning: Failed to create client config directory: %v, output: %s", err, output)
	}

	// Configure system settings
	logger.Log.Println("Step 5/6: Configuring system settings...")
	systemCmds := []string{
		"mkdir -p /var/log/openvpn",
		"sysctl -w net.ipv4.ip_forward=1",
		"echo 'net.ipv4.ip_forward=1' | tee -a /etc/sysctl.conf",
		"sysctl -p",
		"ufw allow 1194/udp",
	}

	// Add sudo prefix if not in Docker
	if !isDocker {
		for i := range systemCmds {
			systemCmds[i] = "sudo " + systemCmds[i]
		}
	}

	for i, cmd := range systemCmds {
		logger.Log.Printf("System setup %d/%d: %s", i+1, len(systemCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("system configuration failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}

	// Configure iptables with more robustness
	logger.Log.Println("Configuring iptables...")
	iptablesCmds := []string{
		// Get the main interface - fixed the escape sequence issue by using double backslash
		"IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\\S+)' | head -1)",
		// NAT settings for routing
		"iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $IFACE -j MASQUERADE",
		// Make iptables rules persistent across reboots
		"apt-get -y install iptables-persistent",
		"netfilter-persistent save",
		"netfilter-persistent reload",
	}

	// Add sudo prefix if not in Docker
	if !isDocker {
		for i := range iptablesCmds {
			if i > 0 { // Skip the first one which is just setting a variable
				iptablesCmds[i] = "sudo " + iptablesCmds[i]
			}
		}
	}

	for i, cmd := range iptablesCmds {
		logger.Log.Printf("IPTables setup %d/%d: %s", i+1, len(iptablesCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Warning: IPTables command failed: %s, Output: %s, Error: %v", cmd, output, err)
			// Continue anyway as some commands might fail if rules already exist
		}
	}

	// Setup OpenVPN service
	logger.Log.Println("Step 6/6: Setting up and starting OpenVPN service...")
	serviceCmds := []string{
		"systemctl enable openvpn@server",
		"systemctl restart openvpn@server",
	}

	// Add sudo prefix if not in Docker
	if !isDocker {
		for i := range serviceCmds {
			serviceCmds[i] = "sudo " + serviceCmds[i]
		}
	}

	for i, cmd := range serviceCmds {
		logger.Log.Printf("Service setup %d/%d: %s", i+1, len(serviceCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("service configuration failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(3 * time.Second) // Longer wait for service restart
	}

	// Verify OpenVPN is running
	logger.Log.Println("Verifying OpenVPN service status...")
	statusCmd := "systemctl is-active openvpn@server"
	if !isDocker {
		statusCmd = "sudo " + statusCmd
	}
	status, err := o.SSHClient.RunCommand(statusCmd)
	if err != nil {
		logger.Log.Printf("Service status check failed: %v", err)
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

	clientConfigCmd := fmt.Sprintf("echo '%s' | tee /etc/vpn-configs/openvpn_config.ovpn", clientConfig)
	if !isDocker {
		clientConfigCmd = fmt.Sprintf("echo '%s' | sudo tee /etc/vpn-configs/openvpn_config.ovpn", clientConfig)
	}

	output, err = o.SSHClient.RunCommand(clientConfigCmd)
	if err != nil {
		logger.Log.Printf("Warning: Failed to generate client config: %v, output: %s", err, output)
	} else {
		logger.Log.Println("Client configuration created at /etc/vpn-configs/openvpn_config.ovpn")
	}

	logger.Log.Println("OpenVPN setup completed successfully")
	return nil
}
