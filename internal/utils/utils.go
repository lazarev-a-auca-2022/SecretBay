package utils

import (
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
)

type DataCleanup struct {
	SSHClient *sshclient.SSHClient
}

func (d *DataCleanup) RemoveClientData() error {
	cmds := []string{
		"rm -rf ~/easy-rsa",                  // Remove EasyRSA directory
		"rm -rf ~/pki",                       // Remove PKI directory
		"rm -rf /etc/openvpn/client_configs", // Remove client configs
		// Add more cleanup commands as needed
	}

	for _, cmd := range cmds {
		_, err := d.SSHClient.RunCommand(cmd)
		if err != nil {
			// Log the error but don't fail the cleanup
			continue
		}
	}

	return nil
}
