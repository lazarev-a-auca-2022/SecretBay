package sshclient

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHClient wraps an SSH client connection
type SSHClient struct {
	Client         *ssh.Client
	RunCommandFunc func(string) (string, error)
	CloseFunc      func()
}

type SSHClientInterface interface {
	RunCommand(string) (string, error)
	Close()
}

// NewSSHClient creates a new SSH client instance
var NewSSHClient = func(serverIP, username, authMethod, authCredential string) (*SSHClient, error) {
	var auth ssh.AuthMethod
	if authMethod == "password" {
		auth = ssh.Password(authCredential)
	} else if authMethod == "key" {
		key, err := os.ReadFile(authCredential)
		if err != nil {
			return nil, fmt.Errorf("unable to read SSH key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse SSH key: %v", err)
		}
		auth = ssh.PublicKeys(signer)
	} else {
		return nil, fmt.Errorf("unsupported auth method")
	}

	knownHostsFile := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("could not create hostkeycallback function: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", serverIP), config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH: %v", err)
	}

	return &SSHClient{Client: client}, nil
}

func (s *SSHClient) RunCommand(cmd string) (string, error) {
	// Use custom implementation if provided
	if s.RunCommandFunc != nil {
		return s.RunCommandFunc(cmd)
	}

	// Create new session for the command
	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Set up output buffer
	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = &output

	// Run the command
	if err := session.Run(cmd); err != nil {
		return output.String(), fmt.Errorf("failed to run command '%s': %v", cmd, err)
	}

	return output.String(), nil
}
func (s *SSHClient) Close() {
	if s.CloseFunc != nil {
		s.CloseFunc()
		return
	}
	if s.Client != nil {
		s.Client.Close()
	}
}
