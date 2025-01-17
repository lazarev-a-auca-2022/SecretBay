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

type SSHClient struct {
	Client *ssh.Client
}

func NewSSHClient(serverIP, username, authMethod, authCredential string) (*SSHClient, error) {
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
	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	if err := session.Run(cmd); err != nil {
		return "", fmt.Errorf("failed to run command: %v", err)
	}

	return stdoutBuf.String(), nil
}

func (s *SSHClient) Close() {
	if s.Client != nil {
		s.Client.Close()
	}
}
