// Package sshclient provides secure SSH client functionality.
//
// This package handles SSH connections to remote servers with support for
// both password and key-based authentication. It implements secure defaults
// and proper connection lifecycle management.
package sshclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHClient represents a secure SSH connection to a remote server.
type SSHClient struct {
	// Client is the underlying SSH client connection
	Client *ssh.Client

	// RunCommandFunc is the function used to execute commands
	RunCommandFunc func(string) (string, error)

	// CloseFunc is the function used to close the connection
	CloseFunc func()
	mu        sync.Mutex
	password  string
	// Connection information stored for reconnection if needed
	serverIP   string
	username   string
	authMethod string
}

// SSHClientInterface defines the interface for SSH operations
type SSHClientInterface interface {
	// RunCommand executes a command on the remote server
	RunCommand(string) (string, error)

	// Close terminates the SSH connection
	Close()
}

const (
	maxRetries    = 3
	backoffPeriod = 2 * time.Second
)

// insecureIgnoreHostKey returns a function that can be used as ssh.HostKeyCallback
// which accepts any host key. This should only be used in controlled environments
// where security is less critical than connection reliability.
func insecureIgnoreHostKey() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		logger.Log.Printf("SECURITY WARNING: Ignoring host key verification for %s", hostname)
		return nil
	}
}

// NewSSHClient creates a new SSH client with the specified credentials.
// It supports both password and key-based authentication methods.
var NewSSHClient = func(serverIP, username, authMethod, authCredential string) (*SSHClient, error) {
	var auth ssh.AuthMethod

	// Validate inputs
	if serverIP == "" || username == "" || authMethod == "" || authCredential == "" {
		return nil, fmt.Errorf("all parameters are required")
	}

	switch authMethod {
	case "password":
		if len(authCredential) < 8 {
			return nil, fmt.Errorf("password too short")
		}
		auth = ssh.Password(authCredential)

	case "key":
		key, err := os.ReadFile(authCredential)
		if err != nil {
			return nil, fmt.Errorf("unable to read SSH key: %v", err)
		}

		// Hash the key for logging (avoid logging sensitive data)
		keyHash := sha256.Sum256(key)
		logger.Log.Printf("Using SSH key with hash: %s", base64.StdEncoding.EncodeToString(keyHash[:]))

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse SSH key: %v", err)
		}
		auth = ssh.PublicKeys(signer)

	default:
		return nil, fmt.Errorf("unsupported auth method: %s", authMethod)
	}

	// Check if we should disable strict host key checking
	// This is determined by an environment variable for maximum flexibility
	disableHostKeyChecking := os.Getenv("SSH_DISABLE_STRICT_HOST_KEY_CHECKING") == "true"

	var hostKeyCallback ssh.HostKeyCallback
	if disableHostKeyChecking {
		// Use insecure callback that accepts any key when strict checking is disabled
		hostKeyCallback = insecureIgnoreHostKey()
		logger.Log.Printf("Using insecure host key checking for SSH connections to %s", serverIP)
	} else {
		// Normal secure host key verification
		// Ensure .ssh directory exists with proper permissions
		sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create .ssh directory: %v", err)
		}

		knownHostsFile := filepath.Join(sshDir, "known_hosts")
		var err error
		hostKeyCallback, err = knownhosts.New(knownHostsFile)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("could not create hostkey callback: %v", err)
			}
			// Create empty known_hosts file if it doesn't exist
			if err := os.WriteFile(knownHostsFile, []byte{}, 0600); err != nil {
				return nil, fmt.Errorf("could not create known_hosts file: %v", err)
			}
			hostKeyCallback, err = knownhosts.New(knownHostsFile)
			if err != nil {
				return nil, fmt.Errorf("could not create hostkey callback after file creation: %v", err)
			}
		}
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
		ClientVersion:   "SSH-2.0-SecretBayVPN", // Custom version string
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp384",
			},
			Ciphers: []string{
				"chacha20-poly1305@openssh.com",
				"aes256-gcm@openssh.com",
			},
			MACs: []string{
				"hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256-etm@openssh.com",
			},
		},
	}

	addr := fmt.Sprintf("%s:22", serverIP)
	var client *ssh.Client
	var finalErr error

	// Implement retry with exponential backoff
	for i := 0; i < maxRetries; i++ {
		client, finalErr = ssh.Dial("tcp", addr, config)
		if finalErr == nil {
			break
		}

		// If strict host key checking is enabled, handle unknown hosts
		if !disableHostKeyChecking && strings.Contains(finalErr.Error(), "knownhosts: key is unknown") {
			knownHostsFile := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
			if err := handleUnknownHost(serverIP, knownHostsFile); err != nil {
				return nil, fmt.Errorf("failed to handle unknown host: %v", err)
			}
			// Rebuild callback after updating known_hosts
			newHostKeyCallback, err := knownhosts.New(knownHostsFile)
			if err != nil {
				return nil, fmt.Errorf("could not rebuild hostkey callback: %v", err)
			}
			config.HostKeyCallback = newHostKeyCallback
			continue
		}

		// If we're encountering a key mismatch and strict checking is enabled,
		// we might want to update the known_hosts file
		if !disableHostKeyChecking && strings.Contains(finalErr.Error(), "knownhosts: key mismatch") {
			logger.Log.Printf("Detected host key mismatch. Consider setting SSH_DISABLE_STRICT_HOST_KEY_CHECKING=true if in a development environment.")
		}

		if i < maxRetries-1 {
			logger.Log.Printf("SSH connection attempt %d failed: %v. Retrying in %v...", i+1, finalErr, backoffPeriod*time.Duration(i+1))
			time.Sleep(backoffPeriod * time.Duration(i+1))
			continue
		}
	}

	if finalErr != nil {
		return nil, fmt.Errorf("failed to establish SSH connection after %d attempts: %v", maxRetries, finalErr)
	}

	sshClient := &SSHClient{
		Client: client,
		RunCommandFunc: func(cmd string) (string, error) {
			session, err := client.NewSession()
			if err != nil {
				return "", fmt.Errorf("failed to create session: %v", err)
			}
			defer session.Close()

			var b bytes.Buffer
			session.Stdout = &b
			session.Stderr = &b

			if err := session.Run(cmd); err != nil {
				return b.String(), fmt.Errorf("command failed: %v, output: %s", err, b.String())
			}
			return b.String(), nil
		},
		CloseFunc: func() {
			if client != nil {
				client.Close()
			}
		},
		password:   authCredential,
		serverIP:   serverIP,
		username:   username,
		authMethod: authMethod,
	}

	return sshClient, nil
}

// RunCommand executes a command on the remote server and returns its output.
// It handles both stdout and stderr output properly.
func (s *SSHClient) RunCommand(cmd string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Client == nil {
		return "", fmt.Errorf("SSH client is not initialized")
	}

	if s.RunCommandFunc != nil {
		return s.RunCommandFunc(cmd)
	}

	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = &output

	if err := session.Run(cmd); err != nil {
		return output.String(), fmt.Errorf("failed to run command '%s': %v", cmd, err)
	}

	return output.String(), nil
}

// RunCommandWithStdin executes a command on the remote server with input from stdin.
func (s *SSHClient) RunCommandWithStdin(cmd string, stdin io.Reader) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Client == nil {
		return "", fmt.Errorf("SSH client is not initialized")
	}

	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = &output

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to get stdin pipe: %v", err)
	}

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("failed to start command: %v", err)
	}

	go func() {
		defer stdinPipe.Close()
		io.Copy(stdinPipe, stdin)
	}()

	if err := session.Wait(); err != nil {
		return output.String(), fmt.Errorf("command failed: %v, output: %s", err, output.String())
	}

	return output.String(), nil
}

// Close terminates the SSH connection and cleans up resources.
func (s *SSHClient) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.CloseFunc != nil {
		s.CloseFunc()
		return
	}
	if s.Client != nil {
		s.Client.Close()
	}
}

func (c *SSHClient) GetPassword() string {
	return c.password
}

func (c *SSHClient) UpdatePassword(newPassword string) {
	c.password = newPassword
}

// ResetPassword attempts to reset the password using the provided new password.
// This is useful when the current password has expired.
func (c *SSHClient) ResetPassword(newPassword string) error {
	logger.Log.Println("Attempting to reset expired password...")

	// Close the current SSH connection first
	if c.Client != nil {
		c.Client.Close()
		c.Client = nil
	}

	// Create a new SSH client with the new password
	newClient, err := NewSSHClient(c.serverIP, c.username, "password", newPassword)
	if err != nil {
		return fmt.Errorf("failed to create new SSH client with updated password: %v", err)
	}

	// Test the connection with a simple command
	_, err = newClient.RunCommand("echo 'Password reset successful'")
	if err != nil {
		newClient.Close()
		return fmt.Errorf("password reset failed, could not execute test command: %v", err)
	}

	// Update the client with the new connection
	c.Client = newClient.Client
	c.RunCommandFunc = newClient.RunCommandFunc
	c.CloseFunc = newClient.CloseFunc
	c.password = newPassword

	logger.Log.Println("Password reset successful")
	return nil
}

// IsPasswordExpired checks if the current password has expired.
func (c *SSHClient) IsPasswordExpired() bool {
	testCmd := "echo 'Testing connection'"
	out, err := c.RunCommand(testCmd)
	if err != nil {
		return strings.Contains(out, "Your password has expired") ||
			strings.Contains(out, "Password change required")
	}
	return false
}

func (c *SSHClient) WriteFile(path string, content string, mode uint32) error {
	if c.Client == nil {
		return fmt.Errorf("SSH client not connected")
	}

	session, err := c.Client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Create the file with the specified mode
	cmd := fmt.Sprintf("cat > %s && chmod %o %s", path, mode, path)
	pipe, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %v", err)
	}

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("failed to start command: %v", err)
	}

	_, err = pipe.Write([]byte(content))
	if err != nil {
		return fmt.Errorf("failed to write content: %v", err)
	}

	pipe.Close()
	if err := session.Wait(); err != nil {
		return fmt.Errorf("command failed: %v", err)
	}

	return nil
}

func handleUnknownHost(host, knownHostsFile string) error {
	// Use ssh-keyscan to get the host key
	cmd := exec.Command("ssh-keyscan", "-H", "-t", "rsa,ecdsa,ed25519", host)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to scan host key: %v", err)
	}

	// Append the host key to known_hosts file
	f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts file: %v", err)
	}
	defer f.Close()

	if _, err := f.Write(output); err != nil {
		return fmt.Errorf("failed to write to known_hosts file: %v", err)
	}

	return nil
}

// RemoveKnownHost removes a host entry from the known_hosts file
func RemoveKnownHost(host string) error {
	knownHostsFile := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")

	// Check if the file exists
	if _, err := os.Stat(knownHostsFile); os.IsNotExist(err) {
		return nil // Nothing to do if file doesn't exist
	}

	// Use ssh-keygen to remove the host
	cmd := exec.Command("ssh-keygen", "-R", host, "-f", knownHostsFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove host key: %v, output: %s", err, string(output))
	}

	logger.Log.Printf("Removed host key for %s from known_hosts file", host)
	return nil
}
