package vpn

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

// OpenVPNSetup handles the configuration of the OpenVPN server.
type OpenVPNSetup struct {
	SSHClient *sshclient.SSHClient
	ServerIP  string
}

// Setup configures an OpenVPN server on the given host.
func (o *OpenVPNSetup) Setup() error {
	logger.Log.Println("Starting OpenVPN setup")

	// Check if we're running in Docker
	isDocker := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isDocker = true
		logger.Log.Println("Running in Docker environment")
	}

	// Check if password has expired by running a simple command
	checkCmd := "echo 'Testing connection'"
	if out, err := o.SSHClient.RunCommand(checkCmd); err != nil {
		// Check for expired password error
		if strings.Contains(out, "Your password has expired") || strings.Contains(out, "Password change required") {
			logger.Log.Println("Detected expired password, attempting to reset")
			return fmt.Errorf("password has expired and needs to be reset: %v", err)
		}
	}

	// Check disk space first
	spaceCheckCmd := "df -h / | awk 'NR==2 {print $4}'"
	if out, err := o.SSHClient.RunCommand(spaceCheckCmd); err == nil {
		logger.Log.Printf("Available disk space: %s", out)
	} else {
		// If this command fails with a password expiration message, return early
		if strings.Contains(out, "Your password has expired") || strings.Contains(out, "Password change required") {
			return fmt.Errorf("password has expired and needs to be reset: %v", err)
		}
	}

	// Wait for any existing apt processes to finish
	waitCmd := `while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 1; done`
	if isDocker {
		// In Docker, we likely don't need sudo
		waitCmd = `while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do sleep 1; done`
	}

	if out, err := o.SSHClient.RunCommand(waitCmd); err != nil {
		// Check for specific error about expired password
		if strings.Contains(out, "Your password has expired") || strings.Contains(out, "Password change required") {
			logger.Log.Printf("Warning: Password has expired: %s", out)
			return fmt.Errorf("password has expired and needs to be reset: %v", err)
		}
		logger.Log.Printf("Warning: Wait command failed: %v, output: %s", err, out)
	}

	// Prepare commands based on environment
	var cmds []string
	if isDocker {
		// In Docker, don't use sudo
		cmds = []string{
			"apt-get update",
			"apt-get install -f", // Fix any broken dependencies first
			// Install UFW first
			"DEBIAN_FRONTEND=noninteractive apt-get install -y ufw",
			// Then verify it's installed before continuing
			"ufw status || (echo 'UFW not installed properly' && exit 1)",
			// Then install OpenVPN and other packages
			"DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y openvpn easy-rsa fail2ban openssl",
		}
	} else {
		cmds = []string{
			"sudo apt-get update",
			"sudo apt-get install -f",
			// Install UFW first
			"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ufw",
			// Then verify it's installed
			"sudo ufw status || (echo 'UFW not installed properly' && exit 1)",
			// Then install OpenVPN and other packages
			"sudo DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y openvpn easy-rsa fail2ban openssl",
		}
	}

	// Clear any existing OpenVPN configs and certificates first
	cleanupCmds := []string{
		"systemctl stop openvpn@server || true",
		"rm -rf ~/easy-rsa",
		"rm -rf /etc/openvpn/certs/*",
		"rm -f /etc/openvpn/server.conf",
	}

	if !isDocker {
		for i := range cleanupCmds {
			cleanupCmds[i] = "sudo " + cleanupCmds[i]
		}
	}

	for _, cmd := range cleanupCmds {
		if out, err := o.SSHClient.RunCommand(cmd); err != nil {
			logger.Log.Printf("Cleanup warning: %v, output: %s", err, out)
			// Continue as these might fail if files don't exist
		}
	}

	// Install packages only once
	maxRetries := 3
	success := false
	for attempt := 1; attempt <= maxRetries; attempt++ {
		logger.Log.Printf("Installing packages (attempt %d/%d)", attempt, maxRetries)
		hasErrors := false
		for _, cmd := range cmds {
			if out, err := o.SSHClient.RunCommand(cmd); err != nil {
				logger.Log.Printf("Package installation failed: %v, output: %s", err, out)
				hasErrors = true
				// Wait before retry
				time.Sleep(time.Duration(attempt) * 5 * time.Second)
				break
			}
		}
		if !hasErrors {
			success = true
			break
		}
	}

	if !success {
		return fmt.Errorf("package installation failed after %d attempts", maxRetries)
	}

	// Clean up any existing easy-rsa directory and create new PKI setup
	logger.Log.Println("Step 2/6: Setting up PKI infrastructure...")

	// First, clean up any previous PKI setup
	cleanupCmds = []string{
		"rm -rf ~/easy-rsa",
		"mkdir -p /etc/openvpn/certs",
	}

	if !isDocker {
		cleanupCmds[1] = "sudo " + cleanupCmds[1]
	}

	for _, cmd := range cleanupCmds {
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			logger.Log.Printf("Cleanup warning: %v, output: %s", err, output)
			// Continue anyway as the commands might fail if directories don't exist
		}
	}

	// Execute each step of the PKI setup with proper verification in sequential order
	// This ensures each step completes before proceeding to the next

	// Step 1: Create base easy-rsa directory and initialize PKI
	pkiInitCmds := []string{
		"make-cadir ~/easy-rsa",
		"cd ~/easy-rsa && ./easyrsa init-pki",
		"cd ~/easy-rsa && echo 'set_var EASYRSA_KEY_SIZE 2048' > vars",  // Using 2048 for faster generation
		"cd ~/easy-rsa && echo 'set_var EASYRSA_DIGEST sha256' >> vars", // Using sha256 which is widely supported
	}

	for i, cmd := range pkiInitCmds {
		logger.Log.Printf("PKI initialization %d/%d: %s", i+1, len(pkiInitCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			// Check for password expiry
			if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
				logger.Log.Printf("Password expired during PKI initialization: %s", output)
				return fmt.Errorf("password has expired and needs to be reset before continuing")
			}
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("PKI initialization failed: %v", err)
		}
		// Ensure each command completes
		time.Sleep(500 * time.Millisecond)
	}

	// Step 2: Build CA and server certificates
	certCmds := []string{
		"cd ~/easy-rsa && ./easyrsa --batch build-ca nopass",
		"cd ~/easy-rsa && ./easyrsa --batch gen-req server nopass",
		"cd ~/easy-rsa && ./easyrsa --batch sign-req server server",
		// Generate DH parameters directly with PEM output
		"openssl dhparam -outform PEM -out ~/easy-rsa/dh.pem 2048",
	}

	for i, cmd := range certCmds {
		logger.Log.Printf("Certificate generation %d/%d: %s", i+1, len(certCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
				logger.Log.Printf("Password expired during certificate generation: %s", output)
				return fmt.Errorf("password has expired and needs to be reset before continuing")
			}
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("certificate generation failed: %v", err)
		}
		// Ensure certificate generation completes before moving on
		time.Sleep(1 * time.Second)
	}

	// Verify certificate files exist before copying
	verifyCmd := "ls -la ~/easy-rsa/pki/"
	output, err := o.SSHClient.RunCommand(verifyCmd)
	if err != nil {
		logger.Log.Printf("Failed to verify PKI directory contents: %v", err)
		return fmt.Errorf("PKI directory verification failed: %v", err)
	}
	logger.Log.Printf("PKI directory contents: %s", output)

	// Verify the existence of required files before proceeding
	requiredFiles := []string{
		"~/easy-rsa/pki/ca.crt",
		"~/easy-rsa/pki/issued/server.crt",
		"~/easy-rsa/pki/private/server.key",
		"~/easy-rsa/dh.pem",
	}

	for _, file := range requiredFiles {
		checkCmd := fmt.Sprintf("ls -la %s 2>/dev/null || echo 'NOT_FOUND'", file)
		output, err := o.SSHClient.RunCommand(checkCmd)
		if err != nil || strings.Contains(output, "NOT_FOUND") {
			logger.Log.Printf("Required file %s not found: %s", file, output)

			// Try to diagnose the issue
			diagCmd := fmt.Sprintf("find ~/easy-rsa -type f -name %s 2>/dev/null || echo 'NOT_FOUND'",
				strings.TrimPrefix(file, "~/easy-rsa/"))
			diagOut, _ := o.SSHClient.RunCommand(diagCmd)

			logger.Log.Printf("File search results: %s", diagOut)
			return fmt.Errorf("required file %s not found - PKI setup incomplete", file)
		}
		logger.Log.Printf("Verified existence of required file: %s", file)
	}

	// Step 3: Copy certificates to OpenVPN directory
	copyCmds := []string{
		"mkdir -p /etc/openvpn/certs",
		"chmod -R 700 /etc/openvpn/certs",
	}

	// Add sudo prefix if not in Docker
	if !isDocker {
		for i := range copyCmds {
			copyCmds[i] = "sudo " + copyCmds[i]
		}
	}

	// Execute directory preparation commands
	for i, cmd := range copyCmds {
		logger.Log.Printf("Directory setup %d/%d: %s", i+1, len(copyCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
				logger.Log.Printf("Password expired during directory setup: %s", output)
				return fmt.Errorf("password has expired and needs to be reset before continuing")
			}
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("directory setup failed: %v", err)
		}
	}

	// Now copy the certificate files one by one, checking each carefully
	filesToCopy := []string{
		"$HOME/easy-rsa/pki/ca.crt:/etc/openvpn/certs/ca.crt",
		"$HOME/easy-rsa/pki/issued/server.crt:/etc/openvpn/certs/server.crt",
		"$HOME/easy-rsa/pki/private/server.key:/etc/openvpn/certs/server.key",
		"$HOME/easy-rsa/dh.pem:/etc/openvpn/certs/dh.pem",
	}

	for i, filePair := range filesToCopy {
		parts := strings.Split(filePair, ":")
		src, dst := parts[0], parts[1]

		// Expand environment variables in the source path
		homeDir, err := o.SSHClient.RunCommand("echo $HOME")
		if err != nil {
			logger.Log.Printf("Failed to get home directory: %v", err)
			return fmt.Errorf("failed to determine home directory: %v", err)
		}
		homeDir = strings.TrimSpace(homeDir)
		src = strings.Replace(src, "$HOME", homeDir, 1)

		// First verify source file exists
		checkCmd := fmt.Sprintf("test -f %s && echo 'exists' || echo 'not found'", src)
		output, err := o.SSHClient.RunCommand(checkCmd)
		if err != nil || !strings.Contains(output, "exists") {
			// Try to locate the file in alternate locations
			altSrc := strings.Replace(src, homeDir, "/root", 1)
			altCheckCmd := fmt.Sprintf("test -f %s && echo 'exists' || echo 'not found'", altSrc)
			altOutput, altErr := o.SSHClient.RunCommand(altCheckCmd)
			if altErr == nil && strings.Contains(altOutput, "exists") {
				src = altSrc
				logger.Log.Printf("Found certificate file in alternate location: %s", src)
			} else {
				logger.Log.Printf("Source file %s does not exist: %s", src, output)
				return fmt.Errorf("source file %s not found for copying", src)
			}
		}

		// Now copy the file with sudo if needed
		cpCmd := fmt.Sprintf("cp %s %s", src, dst)
		if !isDocker {
			cpCmd = "sudo " + cpCmd
		}

		logger.Log.Printf("Copying file %d/%d: %s", i+1, len(filesToCopy), cpCmd)
		output, err = o.SSHClient.RunCommand(cpCmd)
		if err != nil {
			if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
				return fmt.Errorf("password has expired and needs to be reset before continuing")
			}
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cpCmd, output, err)
			return fmt.Errorf("copying certificate file failed: %v", err)
		}

		// Verify the file was copied successfully and set permissions
		checkDstCmd := fmt.Sprintf("test -f %s && echo 'exists' || echo 'not found'", dst)
		if !isDocker {
			checkDstCmd = "sudo " + checkDstCmd
		}

		output, err = o.SSHClient.RunCommand(checkDstCmd)
		if err != nil || !strings.Contains(output, "exists") {
			logger.Log.Printf("Destination file %s verification failed: %s", dst, output)
			return fmt.Errorf("destination file %s not found after copying", dst)
		}

		// Set appropriate permissions for the copied file
		chmodCmd := fmt.Sprintf("chmod 600 %s", dst)
		if !isDocker {
			chmodCmd = "sudo " + chmodCmd
		}

		if _, err := o.SSHClient.RunCommand(chmodCmd); err != nil {
			logger.Log.Printf("Setting permissions failed for %s: %v", dst, err)
			// Log but continue as this is not critical
		}
	}

	// Set permissions on certificate files
	permCmd := "chmod -R 600 /etc/openvpn/certs/*"
	if !isDocker {
		permCmd = "sudo " + permCmd
	}

	output, err = o.SSHClient.RunCommand(permCmd)
	if err != nil {
		logger.Log.Printf("Setting permissions failed: %v, output: %s", err, output)
		return fmt.Errorf("setting certificate permissions failed: %v", err)
	}

	// Verify DH parameters after copying
	verifyDhCmd := "openssl dhparam -check -in /etc/openvpn/certs/dh.pem"
	if !isDocker {
		verifyDhCmd = "sudo " + verifyDhCmd
	}

	if dhOut, err := o.SSHClient.RunCommand(verifyDhCmd); err != nil {
		logger.Log.Printf("DH parameter verification failed: %v, output: %s", err, dhOut)
		// Try to regenerate DH params directly
		genDhCmd := "openssl dhparam -out /etc/openvpn/certs/dh.pem 2048"
		if !isDocker {
			genDhCmd = "sudo " + genDhCmd
		}
		if _, err := o.SSHClient.RunCommand(genDhCmd); err != nil {
			return fmt.Errorf("failed to generate DH parameters: %v", err)
		}
	}

	logger.Log.Println("PKI setup completed successfully")

	// Enhanced OpenVPN server configuration
	logger.Log.Println("Step 3/6: Creating OpenVPN server configuration...")
	serverConfig := `port 1194
proto udp
dev tun
ca /etc/openvpn/certs/ca.crt
cert /etc/openvpn/certs/server.crt
key /etc/openvpn/certs/server.key
dh /etc/openvpn/certs/dh.pem
server 10.8.0.0 255.255.255.0
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
push "block-outside-dns"
keepalive 10 120
cipher AES-256-GCM
auth SHA512
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
ncp-ciphers AES-256-GCM:AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
verb 3
mute 20
explicit-exit-notify 1`

	// Write server config
	logger.Log.Println("Writing server configuration...")
	echoCmd := fmt.Sprintf("echo '%s'", serverConfig)
	teeCmd := "tee /etc/openvpn/server.conf"
	if !isDocker {
		teeCmd = "sudo " + teeCmd
	}
	cmd := fmt.Sprintf("%s | %s", echoCmd, teeCmd)

	output, err = o.SSHClient.RunCommand(cmd)
	if err != nil {
		// Check for password expiry
		if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
			return fmt.Errorf("password has expired and needs to be reset before continuing")
		}
		logger.Log.Printf("Command failed: Output: %s, Error: %v", output, err)
		return fmt.Errorf("failed to write server config: %v", err)
	}

	// Create directory for client configs
	logger.Log.Println("Creating directory for client configs...")
	createClientDirCmd := "mkdir -p /etc/vpn-configs && chmod 755 /etc/vpn-configs"
	if !isDocker {
		createClientDirCmd = "sudo " + createClientDirCmd
	}
	output, err = o.SSHClient.RunCommand(createClientDirCmd)
	if err != nil {
		// Check for password expiry
		if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
			return fmt.Errorf("password has expired and needs to be reset before continuing")
		}
		logger.Log.Printf("Warning: Failed to create client config directory: %v, output: %s", err, output)
	}

	// Configure system settings
	logger.Log.Println("Step 5/6: Configuring system settings...")
	systemCmds := []string{
		"mkdir -p /var/log/openvpn",
		"sysctl -w net.ipv4.ip_forward=1",
		"echo 'net.ipv4.ip_forward=1' | tee -a /etc/sysctl.conf",
		"sysctl -p",
		"ufw allow 1194/udp",
	}

	// Add sudo prefix if not in Docker
	if !isDocker {
		for i := range systemCmds {
			systemCmds[i] = "sudo " + systemCmds[i]
		}
	}

	for i, cmd := range systemCmds {
		logger.Log.Printf("System setup %d/%d: %s", i+1, len(systemCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			// Check for password expiry
			if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
				return fmt.Errorf("password has expired and needs to be reset before continuing")
			}
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("system configuration failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(10 * time.Millisecond)
	}

	// Configure iptables with more robustness
	logger.Log.Println("Configuring iptables...")

	// First identify the default interface with more robust command
	getIfaceCmd := "ip route | grep default | awk '{print $5}' | head -n1"
	iface, err := o.SSHClient.RunCommand(getIfaceCmd)
	if err != nil || strings.TrimSpace(iface) == "" {
		logger.Log.Printf("Failed to determine default interface: %v", err)
		iface = "eth0" // Try eth0 first
		// Try to find any available interface
		findIfaceCmd := "ip link show | grep -v lo | grep -oE '^[0-9]+: [^:]+' | cut -d' ' -f2 | head -n1"
		if foundIface, ferr := o.SSHClient.RunCommand(findIfaceCmd); ferr == nil && strings.TrimSpace(foundIface) != "" {
			iface = strings.TrimSpace(foundIface)
		}
		logger.Log.Printf("Using fallback interface: %s", iface)
	} else {
		iface = strings.TrimSpace(iface)
		logger.Log.Printf("Detected default interface: %s", iface)
	}

	// Package installation with apt lock handling
	packageCmd := fmt.Sprintf(`apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent && \
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o %s -j MASQUERADE && \
        netfilter-persistent save && \
        netfilter-persistent reload`, iface)

	// Run the combined command
	if out, err := o.SSHClient.RunCommand(packageCmd); err != nil {
		logger.Log.Printf("Warning: IPTables setup had issues: %v, output: %s", err, out)
		// Try individual commands if combined fails
		iptablesCmds := []string{
			fmt.Sprintf("iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o %s -j MASQUERADE", iface),
			"netfilter-persistent save",
			"netfilter-persistent reload",
		}

		for _, cmd := range iptablesCmds {
			if out, err := o.SSHClient.RunCommand(cmd); err != nil {
				logger.Log.Printf("Warning: Command failed: %s, error: %v, output: %s", cmd, err, out)
				// Continue anyway as some commands might fail if rules already exist
			}
		}
	}

	// Setup OpenVPN service
	logger.Log.Println("Step 6/6: Setting up and starting OpenVPN service...")
	serviceCmds := []string{
		"systemctl enable openvpn@server",
		"systemctl restart openvpn@server",
	}

	// Add sudo prefix if not in Docker
	if !isDocker {
		for i := range serviceCmds {
			serviceCmds[i] = "sudo " + serviceCmds[i]
		}
	}

	for i, cmd := range serviceCmds {
		logger.Log.Printf("Service setup %d/%d: %s", i+1, len(serviceCmds), cmd)
		output, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			// Check if this is a password expiry issue
			if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
				return fmt.Errorf("password has expired and needs to be reset before continuing")
			}
			logger.Log.Printf("Command failed: %s, Output: %s, Error: %v", cmd, output, err)
			return fmt.Errorf("service configuration failed: %v", err)
		}
		// Force immediate flush of logs
		time.Sleep(3 * time.Second) // Longer wait for service restart
	}

	// Verify OpenVPN is running
	logger.Log.Println("Verifying OpenVPN service status...")
	statusCmd := "systemctl is-active openvpn@server"
	if !isDocker {
		statusCmd = "sudo " + statusCmd
	}
	status, err := o.SSHClient.RunCommand(statusCmd)
	if err != nil {
		// Check if this is a password expiry issue
		if strings.Contains(status, "Your password has expired") || strings.Contains(status, "Password change required") {
			return fmt.Errorf("password has expired and needs to be reset before continuing")
		}

		// Try to get more detailed service status information
		journalCmd := "journalctl -u openvpn@server --no-pager -n 50"
		if !isDocker {
			journalCmd = "sudo " + journalCmd
		}

		journalOutput, journalErr := o.SSHClient.RunCommand(journalCmd)
		if journalErr == nil {
			logger.Log.Printf("OpenVPN service logs: %s", journalOutput)
		} else {
			logger.Log.Printf("Failed to retrieve OpenVPN service logs: %v", journalErr)
		}

		// Check config file syntax
		configCheckCmd := "openvpn --config /etc/openvpn/server.conf --verb 0 --show-engines"
		if !isDocker {
			configCheckCmd = "sudo " + configCheckCmd
		}

		checkOutput, checkErr := o.SSHClient.RunCommand(configCheckCmd)
		if checkErr != nil {
			logger.Log.Printf("OpenVPN config check failed: %v, output: %s", checkErr, checkOutput)
		}

		logger.Log.Printf("Service status check failed: %v", err)
		return fmt.Errorf("OpenVPN service failed to start, check logs for details: %v", err)
	}

	trimmedStatus := strings.TrimSpace(status)
	if trimmedStatus != "active" {
		// Get detailed status information to help diagnose the issue
		detailedStatusCmd := "systemctl status openvpn@server --no-pager"
		if !isDocker {
			detailedStatusCmd = "sudo " + detailedStatusCmd
		}

		detailedOutput, _ := o.SSHClient.RunCommand(detailedStatusCmd)
		logger.Log.Printf("Detailed service status: %s", detailedOutput)

		// Check if service exists
		checkServiceCmd := "systemctl list-unit-files | grep openvpn"
		if !isDocker {
			checkServiceCmd = "sudo " + checkServiceCmd
		}

		serviceOutput, _ := o.SSHClient.RunCommand(checkServiceCmd)
		logger.Log.Printf("Available OpenVPN service units: %s", serviceOutput)

		// Try to fix common issues and restart
		fixAndRestartCmds := []string{
			"mkdir -p /var/log/openvpn",
			"chmod 755 /var/log/openvpn",
			"touch /var/log/openvpn/openvpn-status.log",
			"chmod 644 /var/log/openvpn/openvpn-status.log",
			"chown nobody:nogroup /var/log/openvpn/openvpn-status.log",
			"systemctl daemon-reload",
			"systemctl restart openvpn@server",
		}

		if !isDocker {
			for i := range fixAndRestartCmds {
				fixAndRestartCmds[i] = "sudo " + fixAndRestartCmds[i]
			}
		}

		logger.Log.Println("Attempting to fix common OpenVPN service issues and restart...")
		for _, cmd := range fixAndRestartCmds {
			output, err := o.SSHClient.RunCommand(cmd)
			if err != nil {
				logger.Log.Printf("Fix command failed: %s, error: %v, output: %s", cmd, err, output)
			}
		}

		// Check status again after fix attempt
		finalStatusCmd := "systemctl is-active openvpn@server"
		if !isDocker {
			finalStatusCmd = "sudo " + finalStatusCmd
		}

		finalStatus, _ := o.SSHClient.RunCommand(finalStatusCmd)
		finalStatus = strings.TrimSpace(finalStatus)

		if finalStatus == "active" {
			logger.Log.Println("Successfully fixed and restarted OpenVPN service!")
		} else {
			logger.Log.Printf("Service is still not active after fix attempts, status: %s", finalStatus)
			return fmt.Errorf("OpenVPN service is not active after fix attempts, status: %s. Please check system logs for details", finalStatus)
		}
	} else {
		logger.Log.Println("OpenVPN service is active and running")
	}

	// Generate client config
	logger.Log.Println("Generating client configuration...")
	clientConfig := fmt.Sprintf(`client
dev tun
proto udp
remote %s 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
verb 3
key-direction 1`, o.ServerIP)

	clientConfigCmd := fmt.Sprintf("echo '%s' | tee /etc/vpn-configs/openvpn_config.ovpn", clientConfig)
	if !isDocker {
		clientConfigCmd = fmt.Sprintf("echo '%s' | sudo tee /etc/vpn-configs/openvpn_config.ovpn", clientConfig)
	}

	output, err = o.SSHClient.RunCommand(clientConfigCmd)
	if err != nil {
		// Check if this is a password expiry issue
		if strings.Contains(output, "Your password has expired") || strings.Contains(output, "Password change required") {
			return fmt.Errorf("password has expired and needs to be reset before continuing")
		}
		logger.Log.Printf("Warning: Failed to generate client config: %v, output: %s", err, output)
	} else {
		logger.Log.Println("Client configuration created at /etc/vpn-configs/openvpn_config.ovpn")
	}

	logger.Log.Println("OpenVPN setup completed successfully")
	return nil
}
