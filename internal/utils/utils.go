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
	// Paths to clean
	paths := []string{
		"~/easy-rsa",
		"~/pki",
		"/etc/openvpn/client_configs",
		"/tmp/vpn_setup_*",
		"/var/log/openvpn/*",
		"/etc/ipsec.d/private/*.bak",
		"/etc/ipsec.d/certs/*.bak",
		"/var/log/ipsec.log*",
	}

	// Files to securely wipe content but not delete
	sensitiveFiles := []string{
		"/etc/ssh/sshd_config",
		"/etc/ipsec.secrets",
		"/etc/openvpn/server.conf",
	}

	var errors []string

	// Clear sensitive file contents while preserving the files
	for _, file := range sensitiveFiles {
		cmd := fmt.Sprintf("if [ -f %s ]; then shred -n 3 %s 2>/dev/null || true; fi", file, file)
		if _, err := d.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Failed to securely wipe %s: %v", file, err)
			errors = append(errors, fmt.Sprintf("wiping of %s", file))
		}
	}

	// Remove temporary and client-specific files
	for _, path := range paths {
		// Use find to safely handle wildcards and ensure files exist before removal
		cmd := fmt.Sprintf("find %s -type f -exec shred -n 3 -u {} \\; 2>/dev/null || true", path)
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

	// Clear system logs of sensitive data
	logCleanupCmds := []string{
		"journalctl --vacuum-time=1d",
		"rm -f /var/log/auth.log*",
		"rm -f /var/log/syslog*",
		"touch /var/log/auth.log /var/log/syslog",
		"systemctl restart rsyslog",
	}

	for _, cmd := range logCleanupCmds {
		if _, err := d.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Log cleanup command failed: %v", err)
			errors = append(errors, "log cleanup")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("some cleanup operations failed: %s", strings.Join(errors, ", "))
	}

	return nil
}
