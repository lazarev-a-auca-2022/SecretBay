package vpn

import (
	"fmt"
	"strings"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type SecuritySetup struct {
	SSHClient *sshclient.SSHClient
}

func (s *SecuritySetup) SetupFail2Ban() error {
	logger.Log.Println("Starting SetupFail2Ban")

	// Install fail2ban with additional dependencies
	cmd := "sudo DEBIAN_FRONTEND=noninteractive apt-get update && sudo apt-get install -y fail2ban ufw"
	_, err := s.SSHClient.RunCommand(cmd)
	if err != nil {
		logger.Log.Printf("SetupFail2Ban error: %v", err)
		return fmt.Errorf("failed to install fail2ban: %v", err)
	}

	// Enhanced fail2ban configuration
	fail2banConfig := `
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 300
bantime = 3600
ignoreip = 127.0.0.1/8

[openvpn]
enabled = true
port = 1194
protocol = udp
filter = openvpn
logpath = /var/log/openvpn/openvpn.log
maxretry = 3
findtime = 300
bantime = 3600
`

	cmd = fmt.Sprintf("echo '%s' | sudo tee /etc/fail2ban/jail.local", fail2banConfig)
	_, err = s.SSHClient.RunCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to configure fail2ban: %v", err)
	}

	// Configure UFW firewall
	firewallCmds := []string{
		"sudo ufw default deny incoming",
		"sudo ufw default allow outgoing",
		"sudo ufw allow ssh",
		"sudo ufw allow 1194/udp",     // OpenVPN
		"sudo ufw allow 500,4500/udp", // IKEv2/IPsec
		"sudo ufw --force enable",
	}

	for _, cmd := range firewallCmds {
		if _, err := s.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Firewall setup warning: %v", err)
		}
	}

	// Restart and enable services
	serviceCmds := []string{
		"sudo systemctl restart fail2ban",
		"sudo systemctl enable fail2ban",
	}

	for _, cmd := range serviceCmds {
		if _, err := s.SSHClient.RunCommand(cmd); err != nil {
			return fmt.Errorf("failed to restart services: %v", err)
		}
	}

	return nil
}

func (s *SecuritySetup) DisableUnnecessaryServices() error {
	logger.Log.Println("Starting DisableUnnecessaryServices")

	servicesToDisable := []string{
		"apache2",
		"nginx",
		"rpcbind",
		"telnet",
		"xinetd",
	}

	for _, service := range servicesToDisable {
		cmds := []string{
			fmt.Sprintf("sudo systemctl stop %s 2>/dev/null || true", service),
			fmt.Sprintf("sudo systemctl disable %s 2>/dev/null || true", service),
		}

		for _, cmd := range cmds {
			_, _ = s.SSHClient.RunCommand(cmd) // Ignore errors as services might not exist
		}
	}

	// Set up system hardening
	hardeningCmds := []string{
		"sudo sysctl -w net.ipv4.tcp_syncookies=1",
		"sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1",
		"sudo sysctl -w net.ipv4.conf.all.accept_redirects=0",
		"sudo sysctl -w net.ipv4.conf.all.send_redirects=0",
		"sudo sysctl -w net.ipv4.conf.all.accept_source_route=0",
		"sudo sysctl -w kernel.sysrq=0",
		"sudo sysctl -p",
	}

	for _, cmd := range hardeningCmds {
		if _, err := s.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("System hardening warning: %v", err)
		}
	}

	return nil
}

func (s *SecuritySetup) ChangeRootPassword(newPassword string) error {
	logger.Log.Println("Starting ChangeRootPassword")

	// Validate password
	if len(newPassword) < 12 {
		return fmt.Errorf("password too short")
	}

	// Escape special characters in password
	escapedPassword := strings.Replace(newPassword, "'", "'\"'\"'", -1)

	// Change password and enforce password policies
	cmds := []string{
		fmt.Sprintf("echo 'root:%s' | sudo chpasswd", escapedPassword),
		"sudo chage -d 0 root", // Force password change on next login
		"sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs", // Max password age
		"sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs",  // Min password age
	}

	for _, cmd := range cmds {
		if _, err := s.SSHClient.RunCommand(cmd); err != nil {
			return fmt.Errorf("failed to update password configuration: %v", err)
		}
	}

	return nil
}
