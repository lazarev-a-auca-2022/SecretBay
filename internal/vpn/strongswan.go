package vpn

import (
	"fmt"
	"strings"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type StrongSwanSetup struct {
	SSHClient *sshclient.SSHClient
	ServerIP  string
}

func (s *StrongSwanSetup) Setup() error {
	logger.Log.Println("Starting StrongSwan setup")

	// Package installation with enhanced security packages
	cmds := []string{
		"sudo apt update && sudo apt upgrade -y",
		"sudo apt install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins fail2ban ufw openssl",
	}

	for _, cmd := range cmds {
		output, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("package installation failed: %v", err)
		}
	}

	// Secure certificate generation with stronger parameters
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

	for _, cmd := range certSetup {
		output, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("certificate generation failed: %v", err)
		}
	}

	// Enhanced StrongSwan configuration with modern crypto
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
	output, err := s.SSHClient.RunCommand(fmt.Sprintf("echo '%s' | sudo tee /etc/ipsec.conf", strongswanConf))
	if err != nil {
		logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", strongswanConf, output, err)
		return fmt.Errorf("failed to write ipsec.conf: %v", err)
	}

	// Secure secrets configuration
	secretsConf := `: RSA "server.key.pem"
%any : EAP "VpnSecretPass123!"` // This should be replaced with a generated password

	output, err = s.SSHClient.RunCommand(fmt.Sprintf("echo '%s' | sudo tee /etc/ipsec.secrets", secretsConf))
	if err != nil {
		logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", secretsConf, output, err)
		return fmt.Errorf("failed to write ipsec.secrets: %v", err)
	}

	// Secure permissions
	securityCmds := []string{
		"sudo chmod 600 /etc/ipsec.secrets",
		"sudo chmod 644 /etc/ipsec.conf",
		"sudo sysctl -w net.ipv4.ip_forward=1",
		"sudo sysctl -w net.ipv4.conf.all.accept_redirects=0",
		"sudo sysctl -w net.ipv4.conf.all.send_redirects=0",
		"sudo sysctl -p",
	}

	for _, cmd := range securityCmds {
		output, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Warning: Security command failed: %s, Output: %s, Error: %v", cmd, output, err)
		}
	}

	// Configure and start service
	serviceCmds := []string{
		"sudo systemctl restart strongswan-starter",
		"sudo systemctl enable strongswan-starter",
	}

	for _, cmd := range serviceCmds {
		output, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("service configuration failed: %v", err)
		}
	}

	// Verify service status
	status, err := s.SSHClient.RunCommand("sudo systemctl is-active strongswan-starter")
	if err != nil || !strings.Contains(strings.TrimSpace(status), "active") {
		logger.Log.Printf("Service status check failed: Output: %s, Error: %v", status, err)
		return fmt.Errorf("StrongSwan service failed to start properly")
	}

	logger.Log.Println("StrongSwan setup completed successfully")
	return nil
}
