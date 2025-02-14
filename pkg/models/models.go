package models

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

type VPNSetupRequest struct {
	ServerIP       string `json:"server_ip"`
	Username       string `json:"username"`
	AuthMethod     string `json:"auth_method"`
	AuthCredential string `json:"auth_credential"`
	VPNType        string `json:"vpn_type"`
}

type VPNSetupResponse struct {
	VPNConfig   string `json:"vpn_config"`
	NewPassword string `json:"new_password,omitempty"` // Only included when password is changed
}

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
