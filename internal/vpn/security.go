package vpn

import (
	"fmt"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
)

type SecuritySetup struct {
	SSHClient *sshclient.SSHClient
}

func (s *SecuritySetup) SetupFail2Ban() error {
	// Install Fail2Ban
	cmd := "sudo apt install -y fail2ban"
	_, err := s.SSHClient.RunCommand(cmd)
	if err != nil {
		return err
	}

	// Configure Fail2Ban for SSH
	fail2banConfig := `
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5
`

	cmd = fmt.Sprintf("echo \"%s\" | sudo tee /etc/fail2ban/jail.d/sshd.conf", fail2banConfig)
	_, err = s.SSHClient.RunCommand(cmd)
	if err != nil {
		return err
	}

	// Restart Fail2Ban service
	cmds := []string{
		"sudo systemctl restart fail2ban",
		"sudo systemctl enable fail2ban",
	}

	for _, cmd := range cmds {
		_, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SecuritySetup) DisableUnnecessaryServices() error {
	// Example: Disable Apache if installed
	cmds := []string{
		"sudo systemctl stop apache2",
		"sudo systemctl disable apache2",
	}

	for _, cmd := range cmds {
		_, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			// It's okay if the service is not installed
			continue
		}
	}

	return nil
}

func (s *SecuritySetup) ChangeRootPassword(newPassword string) error {
	cmd := fmt.Sprintf(`echo "root:%s" | sudo chpasswd`, newPassword)
	_, err := s.SSHClient.RunCommand(cmd)
	return err
}
