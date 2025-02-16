package utils

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type BackupManager struct {
	SSHClient *sshclient.SSHClient
}

// Allowed backup paths
var allowedBackupPaths = []string{
	"/var/backups/vpn-server",
	"/etc/vpn-configs",
	"/etc/openvpn",
	"/etc/ipsec.d",
}

func (b *BackupManager) CreateBackup() (string, error) {
	timestamp := time.Now().UTC().Format("20060102-150405")
	backupDir := "/var/backups/vpn-server"
	backupFile := fmt.Sprintf("%s/backup-%s.tar.gz", backupDir, timestamp)

	// Validate backup path
	if err := ValidatePath(backupFile, allowedBackupPaths); err != nil {
		return "", fmt.Errorf("invalid backup path: %v", err)
	}

	// Ensure backup directory exists
	if _, err := b.SSHClient.RunCommand(fmt.Sprintf("mkdir -p %s", backupDir)); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %v", err)
	}

	// Critical paths to backup (with validation)
	paths := []string{
		"/etc/openvpn/server.conf",
		"/etc/openvpn/certs",
		"/etc/ipsec.conf",
		"/etc/ipsec.d/cacerts",
		"/etc/ipsec.d/certs",
		"/etc/vpn-configs",
	}

	// Validate each path
	for _, path := range paths {
		if err := ValidatePath(path, allowedBackupPaths); err != nil {
			return "", fmt.Errorf("invalid backup source path %s: %v", path, err)
		}
	}

	// Create tar command with validated paths
	tarCmd := fmt.Sprintf(
		"tar czf %s --exclude='*.key' --exclude='*.pem' --exclude='*.secrets' %s",
		backupFile,
		strings.Join(paths, " "),
	)

	if _, err := b.SSHClient.RunCommand(tarCmd); err != nil {
		return "", fmt.Errorf("backup creation failed: %v", err)
	}

	// Set secure permissions
	if _, err := b.SSHClient.RunCommand(fmt.Sprintf("chmod 600 %s", backupFile)); err != nil {
		return "", fmt.Errorf("failed to set backup permissions: %v", err)
	}

	// Cleanup old backups (keep last 5)
	cleanupCmd := fmt.Sprintf(
		"ls -t %s/backup-*.tar.gz | tail -n +6 | xargs -r rm --",
		backupDir,
	)
	if _, err := b.SSHClient.RunCommand(cleanupCmd); err != nil {
		logger.Log.Printf("Warning: Failed to cleanup old backups: %v", err)
	}

	return backupFile, nil
}

func (b *BackupManager) RestoreBackup(backupFile string) error {
	// Validate backup file path
	if err := ValidatePath(backupFile, allowedBackupPaths); err != nil {
		return fmt.Errorf("invalid backup file path: %v", err)
	}

	// Validate backup file exists
	checkCmd := fmt.Sprintf("test -f %s", backupFile)
	if _, err := b.SSHClient.RunCommand(checkCmd); err != nil {
		return fmt.Errorf("backup file not found: %s", backupFile)
	}

	// Create temporary restoration directory
	restoreDir := "/tmp/vpn-restore"
	if _, err := b.SSHClient.RunCommand(fmt.Sprintf("rm -rf %s && mkdir -p %s", restoreDir, restoreDir)); err != nil {
		return fmt.Errorf("failed to create restore directory: %v", err)
	}

	// Extract backup with path validation
	if _, err := b.SSHClient.RunCommand(fmt.Sprintf("tar xzf %s -C %s", backupFile, restoreDir)); err != nil {
		return fmt.Errorf("failed to extract backup: %v", err)
	}

	// Validate and restore each path
	for _, path := range allowedBackupPaths {
		srcPath := filepath.Join(restoreDir, path)
		if err := ValidatePath(srcPath, []string{restoreDir}); err != nil {
			return fmt.Errorf("invalid restore source path: %v", err)
		}

		destPath := path
		if err := ValidatePath(destPath, allowedBackupPaths); err != nil {
			return fmt.Errorf("invalid restore destination path: %v", err)
		}

		if _, err := b.SSHClient.RunCommand(fmt.Sprintf("cp -a %s/* %s/ 2>/dev/null || true", srcPath, destPath)); err != nil {
			logger.Log.Printf("Warning: Failed to restore %s: %v", path, err)
		}
	}

	// Cleanup
	if _, err := b.SSHClient.RunCommand(fmt.Sprintf("rm -rf %s", restoreDir)); err != nil {
		logger.Log.Printf("Warning: Failed to cleanup restore directory: %v", err)
	}

	return nil
}
