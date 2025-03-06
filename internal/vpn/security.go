package vpn

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type SecuritySetup struct {
	SSHClient *sshclient.SSHClient
}

func (s *SecuritySetup) SetupFail2Ban() error {
	logger.Log.Println("Starting SetupFail2Ban")

	// Check if we're running in Docker
	isDocker := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isDocker = true
		logger.Log.Println("Running fail2ban setup in Docker environment")
	}

	// First, make sure the package lists are up-to-date
	updateCmd := "apt-get update"
	if !isDocker {
		updateCmd = "sudo " + updateCmd
	}

	_, err := s.SSHClient.RunCommand(updateCmd)
	if err != nil {
		logger.Log.Printf("Warning: Package update failed: %v", err)
		// Continue anyway as the package might still be installable
	}

	// Install fail2ban with additional dependencies
	installCmd := "DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban ufw"
	if !isDocker {
		installCmd = "sudo " + installCmd
	}

	output, err := s.SSHClient.RunCommand(installCmd)
	if err != nil {
		// Check if the error is because fail2ban is already installed
		checkCmd := "dpkg -l | grep fail2ban || echo 'not installed'"
		checkOutput, _ := s.SSHClient.RunCommand(checkCmd)

		if strings.Contains(checkOutput, "not installed") {
			logger.Log.Printf("SetupFail2Ban error: %v, output: %s", err, output)
			return fmt.Errorf("failed to install fail2ban: %v", err)
		} else {
			logger.Log.Printf("fail2ban appears to be already installed, continuing with configuration")
		}
	}

	// Make sure the necessary directories exist for logs
	logDirsCmd := "mkdir -p /var/log/fail2ban /var/log/openvpn"
	if !isDocker {
		logDirsCmd = "sudo " + logDirsCmd
	}

	_, err = s.SSHClient.RunCommand(logDirsCmd)
	if err != nil {
		logger.Log.Printf("Warning: Creating log directories failed: %v", err)
		// Continue anyway as directories might already exist
	}

	// Create OpenVPN filter for fail2ban if it doesn't exist
	openvpnFilterContent := `[Definition]
failregex = ^.*Connection reset, restarting .* \[AF_INET\]<HOST>:.*$
            ^.*TLS Error: TLS handshake failed .* \[AF_INET\]<HOST>:.*$
            ^.*VERIFY ERROR: .* \[AF_INET\]<HOST>:.*$
            ^.*Bad username/password provided by \[AF_INET\]<HOST>:.*$
ignoreregex =
`

	// Ensure filter directory exists
	filterDirCmd := "mkdir -p /etc/fail2ban/filter.d"
	if !isDocker {
		filterDirCmd = "sudo " + filterDirCmd
	}

	_, err = s.SSHClient.RunCommand(filterDirCmd)
	if err != nil {
		logger.Log.Printf("Warning: Creating filter directory failed: %v", err)
		// Continue anyway as directory might already exist
	}

	// Write the OpenVPN filter
	writeFilterCmd := fmt.Sprintf("echo '%s' | tee /etc/fail2ban/filter.d/openvpn.conf", openvpnFilterContent)
	if !isDocker {
		writeFilterCmd = fmt.Sprintf("echo '%s' | sudo tee /etc/fail2ban/filter.d/openvpn.conf", openvpnFilterContent)
	}

	_, err = s.SSHClient.RunCommand(writeFilterCmd)
	if err != nil {
		logger.Log.Printf("Warning: Failed to create OpenVPN filter: %v", err)
		// Continue with default filter if available
	}

	// Enhanced fail2ban configuration
	fail2banConfig := `
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 3600
findtime  = 600
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 300
bantime = 3600

[openvpn]
enabled = true
port = 1194
protocol = udp
filter = openvpn
logpath = /var/log/openvpn/openvpn-status.log /var/log/syslog
maxretry = 3
findtime = 300
bantime = 3600
`

	writeConfigCmd := fmt.Sprintf("echo '%s' | tee /etc/fail2ban/jail.local", fail2banConfig)
	if !isDocker {
		writeConfigCmd = fmt.Sprintf("echo '%s' | sudo tee /etc/fail2ban/jail.local", fail2banConfig)
	}

	_, err = s.SSHClient.RunCommand(writeConfigCmd)
	if err != nil {
		return fmt.Errorf("failed to configure fail2ban: %v", err)
	}

	// Configure UFW firewall
	firewallCmds := []string{
		"ufw default deny incoming",
		"ufw default allow outgoing",
		"ufw allow ssh",
		"ufw allow 1194/udp",     // OpenVPN
		"ufw allow 500,4500/udp", // IKEv2/IPsec
		"ufw --force enable",
	}

	if !isDocker {
		for i := range firewallCmds {
			firewallCmds[i] = "sudo " + firewallCmds[i]
		}
	}

	for _, cmd := range firewallCmds {
		if _, err := s.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Firewall setup warning: %v", err)
			// Continue as some firewall commands might fail in certain environments
		}
	}

	// Restart and enable services
	serviceCmds := []string{
		"systemctl restart fail2ban || service fail2ban restart",
		"systemctl enable fail2ban || update-rc.d fail2ban defaults",
	}

	if !isDocker {
		for i := range serviceCmds {
			serviceCmds[i] = "sudo " + serviceCmds[i]
		}
	}

	for _, cmd := range serviceCmds {
		if output, err := s.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Service command '%s' failed: %v, output: %s", cmd, err, output)
			// Don't return an error as fail2ban might still be working
			// or might not be available in certain environments
		}
	}

	// Verify fail2ban is working
	time.Sleep(2 * time.Second) // Give fail2ban a moment to start
	statusCmd := "fail2ban-client status || echo 'fail2ban not available'"
	if !isDocker {
		statusCmd = "sudo " + statusCmd
	}

	if statusOutput, err := s.SSHClient.RunCommand(statusCmd); err != nil {
		logger.Log.Printf("fail2ban status check warning: %v, output: %s", err, statusOutput)
	} else {
		logger.Log.Printf("fail2ban status: %s", statusOutput)
	}

	logger.Log.Println("fail2ban setup completed")
	return nil
}

func (s *SecuritySetup) DisableUnnecessaryServices() error {
	logger.Log.Println("Starting DisableUnnecessaryServices")

	// Check if we're running in Docker
	isDocker := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isDocker = true
		logger.Log.Println("Running in Docker environment - skipping some service operations")
	}

	servicesToDisable := []string{
		"apache2",
		"nginx",
		"rpcbind",
		"telnet",
		"xinetd",
	}

	for _, service := range servicesToDisable {
		cmds := []string{
			fmt.Sprintf("systemctl stop %s 2>/dev/null || true", service),
			fmt.Sprintf("systemctl disable %s 2>/dev/null || true", service),
		}

		if !isDocker {
			for i := range cmds {
				cmds[i] = "sudo " + cmds[i]
			}
		}

		for _, cmd := range cmds {
			_, _ = s.SSHClient.RunCommand(cmd) // Ignore errors as services might not exist
		}
	}

	// Set up system hardening
	hardeningCmds := []string{
		"sysctl -w net.ipv4.tcp_syncookies=1",
		"sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1",
		"sysctl -w net.ipv4.conf.all.accept_redirects=0",
		"sysctl -w net.ipv4.conf.all.send_redirects=0",
		"sysctl -w net.ipv4.conf.all.accept_source_route=0",
		"sysctl -w kernel.sysrq=0",
		"sysctl -p",
	}

	if !isDocker {
		for i := range hardeningCmds {
			hardeningCmds[i] = "sudo " + hardeningCmds[i]
		}
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

	// Print the new password during VPN setup
	fmt.Println("New VPN Password:", newPassword)

	// Check if we're running in Docker
	isDocker := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isDocker = true
	}

	// Validate password
	if len(newPassword) < 12 {
		return fmt.Errorf("password too short")
	}

	// Escape special characters in password
	escapedPassword := strings.Replace(newPassword, "'", "'\"'\"'", -1)

	// Change password using a single sudo session
	var cmd string
	if isDocker {
		cmd = fmt.Sprintf(`sh -c '
echo "root:%s" | chpasswd
chage -d 0 root
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/" /etc/login.defs
'`, escapedPassword)
	} else {
		cmd = fmt.Sprintf(`sudo sh -c '
echo "root:%s" | chpasswd
chage -d 0 root
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/" /etc/login.defs
'`, escapedPassword)
	}

	output, err := s.SSHClient.RunCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to update password configuration: %v, output: %s", err, output)
	}

	return nil
}
