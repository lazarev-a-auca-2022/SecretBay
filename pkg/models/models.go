// Package models defines data structures and validation logic.
//
// This package contains the core data models used throughout the VPN server,
// including request/response structures and their validation logic. All models
// follow strict validation rules to ensure secure operation.
package models

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

// VPNSetupRequest represents a request to set up a VPN server.
// All fields are validated before processing to ensure security.
type VPNSetupRequest struct {
	// ServerIP is the target server's IP address
	ServerIP string `json:"server_ip"`

	// Username for SSH connection, defaults to "root"
	Username string `json:"username"`

	// AuthMethod specifies the SSH authentication method ("password" or "key")
	AuthMethod string `json:"auth_method"`

	// AuthCredential contains either the SSH password or key
	AuthCredential string `json:"auth_credential"`

	// VPNType specifies the VPN implementation ("ios_vpn" or "openvpn")
	VPNType string `json:"vpn_type"`
}

// VPNSetupResponse represents the response after successful VPN setup.
type VPNSetupResponse struct {
	// VPNConfig contains the path to the generated VPN configuration
	VPNConfig string `json:"vpn_config"`

	// NewPassword contains the new root password if it was changed
	NewPassword string `json:"new_password,omitempty"`
}

// Validate performs validation on all VPNSetupRequest fields.
// It ensures all required fields are present and valid.
func (r *VPNSetupRequest) Validate() error {
	// Validate ServerIP
	if r.ServerIP == "" {
		return fmt.Errorf("server_ip is required")
	}
	if ip := net.ParseIP(r.ServerIP); ip == nil {
		return fmt.Errorf("invalid server_ip format")
	}

	// Validate Username
	if r.Username == "" {
		r.Username = "root"
	} else {
		// Check username for valid characters
		for _, char := range r.Username {
			if !unicode.IsLetter(char) && !unicode.IsNumber(char) && char != '_' && char != '-' {
				return fmt.Errorf("username contains invalid characters")
			}
		}
		if len(r.Username) > 32 {
			return fmt.Errorf("username too long (max 32 characters)")
		}
	}

	// Validate AuthMethod
	r.AuthMethod = strings.ToLower(r.AuthMethod)
	if r.AuthMethod != "password" && r.AuthMethod != "key" {
		return fmt.Errorf("auth_method must be 'password' or 'key'")
	}

	// Validate AuthCredential
	if r.AuthCredential == "" {
		return fmt.Errorf("auth_credential is required")
	}
	if len(r.AuthCredential) > 4096 { // Reasonable max length for SSH keys
		return fmt.Errorf("auth_credential too long")
	}

	// Validate VPNType
	r.VPNType = strings.ToLower(r.VPNType)
	if r.VPNType != "openvpn" && r.VPNType != "ios_vpn" {
		return fmt.Errorf("vpn_type must be 'openvpn' or 'ios_vpn'")
	}

	return nil
}
