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
	"/etc/ipsec.conf",
	"/etc/openvpn/server.conf",
	"/etc/openvpn/certs",
	"/etc/ipsec.d/cacerts",
	"/etc/ipsec.d/certs",
	"/tmp", // Allow tmp directory for restore operations
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

	// Potential paths to backup (with validation)
	potentialPaths := []string{
		"/etc/openvpn/server.conf",
		"/etc/openvpn/certs",
		"/etc/ipsec.conf",
		"/etc/ipsec.d/cacerts",
		"/etc/ipsec.d/certs",
		"/etc/vpn-configs",
	}

	// Check which paths actually exist and collect them
	var existingPaths []string
	for _, path := range potentialPaths {
		// Validate path first
		if err := ValidatePath(path, allowedBackupPaths); err != nil {
			logger.Log.Printf("Skipping path %s: %v", path, err)
			continue
		}

		// Check if path exists
		checkCmd := fmt.Sprintf("test -e %s && echo 'exists' || echo 'not found'", path)
		output, err := b.SSHClient.RunCommand(checkCmd)
		if err != nil || !strings.Contains(output, "exists") {
			logger.Log.Printf("Path %s does not exist, skipping", path)
			continue
		}

		existingPaths = append(existingPaths, path)
	}

	// Check if we have any paths to backup
	if len(existingPaths) == 0 {
		logger.Log.Println("No backup paths exist, creating minimal backup")
		// Create an empty file to ensure tar doesn't fail
		touchCmd := fmt.Sprintf("touch %s/backup-marker.txt", backupDir)
		if _, err := b.SSHClient.RunCommand(touchCmd); err != nil {
			return "", fmt.Errorf("failed to create backup marker: %v", err)
		}
		existingPaths = append(existingPaths, fmt.Sprintf("%s/backup-marker.txt", backupDir))
	}

	// Create tar command with validated and existing paths
	tarCmd := fmt.Sprintf(
		"tar czf %s --exclude='*.key' --exclude='*.pem' --exclude='*.secrets' %s",
		backupFile,
		strings.Join(existingPaths, " "),
	)

	output, err := b.SSHClient.RunCommand(tarCmd)
	if err != nil {
		logger.Log.Printf("Backup command output: %s", output)
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

		// Check if the source path exists in the extracted backup
		checkCmd := fmt.Sprintf("test -e %s && echo 'exists' || echo 'not found'", srcPath)
		output, err := b.SSHClient.RunCommand(checkCmd)
		if err != nil || !strings.Contains(output, "exists") {
			logger.Log.Printf("Source path %s not found in backup, skipping", srcPath)
			continue
		}

		if err := ValidatePath(srcPath, []string{restoreDir}); err != nil {
			return fmt.Errorf("invalid restore source path: %v", err)
		}

		destPath := path
		if err := ValidatePath(destPath, allowedBackupPaths); err != nil {
			return fmt.Errorf("invalid restore destination path: %v", err)
		}

		// Ensure the destination directory exists
		if _, err := b.SSHClient.RunCommand(fmt.Sprintf("mkdir -p %s", filepath.Dir(destPath))); err != nil {
			logger.Log.Printf("Warning: Failed to create destination directory: %v", err)
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
