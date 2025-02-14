package vpn

import (
	"fmt"
	"strings"

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
	cmds := []string{
		"sudo apk update && sudo apk upgrade -y",
		"sudo apk install -y openvpn easy-rsa fail2ban ufw openssl",
	}

	for _, cmd := range cmds {
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("package installation failed: %v", err)
		}
	}

	// Generate strong DH parameters and improved PKI setup
	setupCmds := []string{
		"make-cadir ~/easy-rsa",
		"cd ~/easy-rsa && ./easyrsa init-pki",
		"cd ~/easy-rsa && echo 'set_var EASYRSA_KEY_SIZE 4096' > vars",
		"cd ~/easy-rsa && echo 'set_var EASYRSA_DIGEST \"sha512\"' >> vars",
		"cd ~/easy-rsa && source vars && echo yes | ./easyrsa build-ca nopass",
		"cd ~/easy-rsa && ./easyrsa gen-req server nopass",
		"cd ~/easy-rsa && ./easyrsa sign-req server server",
		"cd ~/easy-rsa && openssl dhparam -out dh.pem 4096", // Stronger DH params
		"sudo mkdir -p /etc/openvpn/certs",
		"sudo chmod 700 /etc/openvpn/certs",
		"sudo cp ~/easy-rsa/pki/ca.crt /etc/openvpn/certs/",
		"sudo cp ~/easy-rsa/pki/issued/server.crt /etc/openvpn/certs/",
		"sudo cp ~/easy-rsa/pki/private/server.key /etc/openvpn/certs/",
		"sudo cp ~/easy-rsa/dh.pem /etc/openvpn/certs/",
		"sudo chmod 600 /etc/openvpn/certs/*",
	}

	for _, cmd := range setupCmds {
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("PKI setup failed: %v", err)
		}
	}

	// Enhanced OpenVPN server configuration
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
	logSetupCmds := []string{
		"sudo mkdir -p /var/log/openvpn",
		"sudo chown nobody:nogroup /var/log/openvpn",
		"sudo chmod 755 /var/log/openvpn",
	}

	for _, cmd := range logSetupCmds {
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Warning: Log directory setup failed: %s, Output: %s, Error: %v", cmd, output, err)
		}
	}

	// Write server config
	cmd := fmt.Sprintf("echo '%s' | sudo tee /etc/openvpn/server.conf", serverConfig)
	output, err := o.SSHClient.RunCommand(cmd)
	if err != nil {
		logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", serverConfig, output, err)
		return fmt.Errorf("failed to write server config: %v", err)
	}

	// Configure system settings
	sysctlCmds := []string{
		"echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-openvpn.conf",
		"echo 'net.ipv4.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.d/99-openvpn.conf",
		"sudo sysctl --system",
	}

	for _, cmd := range sysctlCmds {
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("system configuration failed: %v", err)
		}
	}

	// Start and enable OpenVPN service
	serviceCmds := []string{
		"sudo systemctl daemon-reload",
		"sudo systemctl start openvpn@server",
		"sudo systemctl enable openvpn@server",
	}

	for _, cmd := range serviceCmds {
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("service activation failed: %v", err)
		}
	}

	// Verify service status
	status, err := o.SSHClient.RunCommand("sudo systemctl is-active openvpn@server")
	if err != nil || !strings.Contains(strings.TrimSpace(status), "active") {
		logger.Log.Printf("Service status check failed: Output: %s, Error: %v", status, err)
		return fmt.Errorf("OpenVPN service failed to start")
	}

	logger.Log.Println("OpenVPN setup completed successfully")
	return nil
}
