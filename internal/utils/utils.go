package utils

import (
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
)

type DataCleanup struct {
	SSHClient *sshclient.SSHClient
}

// remove everything
func (d *DataCleanup) RemoveClientData() error {
	cmds := []string{
		"rm -rf ~/easy-rsa",
		"rm -rf ~/pki",
		"rm -rf /etc/openvpn/client_configs",
	}

	for _, cmd := range cmds {
		_, err := d.SSHClient.RunCommand(cmd)
		if err != nil {
			continue
		}
	}

	return nil
}
