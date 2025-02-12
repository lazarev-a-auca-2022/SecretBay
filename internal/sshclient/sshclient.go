package sshclient

import (
	"bytes"
	"fmt"
	"os"
	"os/exec" // added import
	"path/filepath"
	"strings" // added import
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

// NewSSHClient creates a new SSH client instance and auto-adds unknown hosts.
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
		return nil, fmt.Errorf("unsupported auth method: %s", authMethod)
	}

	knownHostsFile := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("could not create hostkey callback: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:22", serverIP)
	client, err := ssh.Dial("tcp", addr, config)
	// If the error is due to an unknown host key, scan and add it.
	if err != nil && strings.Contains(err.Error(), "knownhosts: key is unknown") {
		keyScan, scanErr := scanHostKey(serverIP)
		if scanErr != nil {
			return nil, fmt.Errorf("failed to scan host key: %v", scanErr)
		}
		appendErr := appendToKnownHosts(knownHostsFile, keyScan)
		if appendErr != nil {
			return nil, fmt.Errorf("failed to update known_hosts: %v", appendErr)
		}
		// Rebuild the callback after updating known_hosts.
		hostKeyCallback, err = knownhosts.New(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("could not rebuild hostkey callback: %v", err)
		}
		config.HostKeyCallback = hostKeyCallback

		// Retry connection after key update.
		client, err = ssh.Dial("tcp", addr, config)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to dial: %v", err)
	}

	return &SSHClient{
		Client: client,
		RunCommandFunc: func(cmd string) (string, error) {
			session, err := client.NewSession()
			if err != nil {
				return "", err
			}
			defer session.Close()
			var b bytes.Buffer
			session.Stdout = &b
			if err := session.Run(cmd); err != nil {
				return "", err
			}
			return b.String(), nil
		},
		CloseFunc: func() {
			client.Close()
		},
	}, nil
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

func scanHostKey(host string) (string, error) {
	// Use ssh-keyscan to retrieve the host key.
	out, err := exec.Command("ssh-keyscan", "-H", host).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func appendToKnownHosts(file, hostKey string) error {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(hostKey); err != nil {
		return err
	}
	return nil
}
