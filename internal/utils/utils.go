package utils

import (
	"fmt"
	"strings"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type DataCleanup struct {
	SSHClient *sshclient.SSHClient
}

func (d *DataCleanup) RemoveClientData() error {
	paths := []string{
		"~/easy-rsa",
		"~/pki",
		"/etc/openvpn/client_configs",
		"/tmp/vpn_setup_*",
	}

	var errors []string
	for _, path := range paths {
		// Use find to safely handle wildcards and ensure files exist before removal
		cmd := fmt.Sprintf("find %s -type f -exec shred -u {} \\; 2>/dev/null || true", path)
		if _, err := d.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Failed to securely remove files in %s: %v", path, err)
			errors = append(errors, fmt.Sprintf("cleanup of %s", path))
		}

		// Remove empty directories
		cmd = fmt.Sprintf("rm -rf %s 2>/dev/null || true", path)
		if _, err := d.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Failed to remove directory %s: %v", path, err)
			errors = append(errors, fmt.Sprintf("directory removal of %s", path))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("some cleanup operations failed: %s", strings.Join(errors, ", "))
	}

	return nil
}
