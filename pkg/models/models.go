package models

import "fmt"

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

// Validate validates the VPNSetupRequest fields
func (r *VPNSetupRequest) Validate() error {
	if r.ServerIP == "" {
		return fmt.Errorf("server_ip is required")
	}
	if r.Username == "" {
		r.Username = "root" // Default username
	}
	if r.AuthMethod != "password" && r.AuthMethod != "key" {
		return fmt.Errorf("auth_method must be 'password' or 'key'")
	}
	if r.AuthCredential == "" {
		return fmt.Errorf("auth_credential is required")
	}
	if r.VPNType != "openvpn" && r.VPNType != "ios_vpn" {
		return fmt.Errorf("vpn_type must be 'openvpn' or 'ios_vpn'")
	}
	return nil
}
