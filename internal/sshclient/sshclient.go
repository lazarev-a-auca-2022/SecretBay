package sshclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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

// SSHClient wraps an SSH client connection with enhanced security
type SSHClient struct {
	Client         *ssh.Client
	RunCommandFunc func(string) (string, error)
	CloseFunc      func()
	mu             sync.Mutex
}

type SSHClientInterface interface {
	RunCommand(string) (string, error)
	Close()
}

const (
	maxRetries    = 3
	backoffPeriod = 2 * time.Second
)

// NewSSHClient creates a new SSH client instance with enhanced security
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

	// Ensure .ssh directory exists with proper permissions
	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create .ssh directory: %v", err)
	}

	knownHostsFile := filepath.Join(sshDir, "known_hosts")
	hostKeyCallback, err := knownhosts.New(knownHostsFile)
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

	// Implement retry with exponential backoff
	for i := 0; i < maxRetries; i++ {
		client, err = ssh.Dial("tcp", addr, config)
		if err == nil {
			break
		}

		if strings.Contains(err.Error(), "knownhosts: key is unknown") {
			if err := handleUnknownHost(serverIP, knownHostsFile); err != nil {
				return nil, fmt.Errorf("failed to handle unknown host: %v", err)
			}
			// Rebuild callback after updating known_hosts
			hostKeyCallback, err = knownhosts.New(knownHostsFile)
			if err != nil {
				return nil, fmt.Errorf("could not rebuild hostkey callback: %v", err)
			}
			config.HostKeyCallback = hostKeyCallback
			continue
		}

		if i < maxRetries-1 {
			time.Sleep(backoffPeriod * time.Duration(i+1))
			continue
		}
		return nil, fmt.Errorf("failed to establish SSH connection after %d attempts: %v", maxRetries, err)
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
	}

	return sshClient, nil
}

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

func handleUnknownHost(host, knownHostsFile string) error {
	keyScan, err := scanHostKey(host)
	if err != nil {
		return fmt.Errorf("failed to scan host key: %v", err)
	}

	// Validate the key format before adding
	if !strings.HasPrefix(keyScan, host) {
		return fmt.Errorf("invalid host key format")
	}

	return appendToKnownHosts(knownHostsFile, keyScan)
}

func scanHostKey(host string) (string, error) {
	cmd := exec.Command("ssh-keyscan", "-H", "-t", "rsa,ecdsa,ed25519", host)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ssh-keyscan failed: %v", err)
	}
	return string(out), nil
}

func appendToKnownHosts(file, hostKey string) error {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(hostKey + "\n"); err != nil {
		return fmt.Errorf("failed to write to known_hosts: %v", err)
	}
	return nil
}
