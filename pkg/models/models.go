package models

import (
	"fmt"
	"strings"
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
	NewPassword string `json:"new_password"`
}

// validation
func (r *VPNSetupRequest) Validate() error {
	if r.ServerIP == "" {
		return fmt.Errorf("server_ip is required")
	}
	if r.Username == "" {
		r.Username = "root" // default username
	}
	if r.AuthMethod != "password" && r.AuthMethod != "key" {
		return fmt.Errorf("auth_method must be 'password' or 'key'")
	}
	if r.AuthCredential == "" {
		return fmt.Errorf("auth_credential is required")
	}
	// Convert VPNType to lowercase for case-insensitive comparison
	lowerVPNType := strings.ToLower(r.VPNType)
	if lowerVPNType != "openvpn" && lowerVPNType != "ios_vpn" {
		return fmt.Errorf("vpn_type must be 'openvpn' or 'ios_vpn'")
	}
	r.VPNType = lowerVPNType // Normalize to lowercase
	return nil
}
