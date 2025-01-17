package vpn

import (
	"fmt"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
)

type SecuritySetup struct {
	SSHClient *sshclient.SSHClient
}

func (s *SecuritySetup) SetupFail2Ban() error {
	// fail2ban installation
	cmd := "sudo apt install -y fail2ban"
	_, err := s.SSHClient.RunCommand(cmd)
	if err != nil {
		return err
	}

	// create a custom jail for SSH
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

	// restart and enable fail2ban
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
	// extra security measure
	cmds := []string{
		"sudo systemctl stop apache2",
		"sudo systemctl disable apache2",
	}

	for _, cmd := range cmds {
		_, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			// do not fail
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
