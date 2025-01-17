package vpn

import (
	"fmt"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
)

type StrongSwanSetup struct {
	SSHClient *sshclient.SSHClient
	ServerIP  string
}

func (s *StrongSwanSetup) Setup() error {
	// Update and install StrongSwan
	cmds := []string{
		"sudo apt update && sudo apt upgrade -y",
		"sudo apt install -y strongswan strongswan-pki libcharon-extra-plugins fail2ban ufw",
	}

	for _, cmd := range cmds {
		_, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	// Generate certificates and keys
	cmds = []string{
		"mkdir -p ~/pki/{cacerts,certs,private}",
		"ipsec pki --gen --outform pem > ~/pki/private/ca.key.pem",
		"ipsec pki --self --ca --lifetime 3650 --in ~/pki/private/ca.key.pem --type rsa --dn \"CN=VPN CA\" --outform pem > ~/pki/cacerts/ca.cert.pem",
		"ipsec pki --gen --outform pem > ~/pki/private/server.key.pem",
		"ipsec pki --pub --in ~/pki/private/server.key.pem | ipsec pki --issue --lifetime 1825 --cacert ~/pki/cacerts/ca.cert.pem --cakey ~/pki/private/ca.key.pem --dn \"CN=server.vpn\" --san server.vpn --flag serverAuth --flag ikeIntermediate --outform pem > ~/pki/certs/server.cert.pem",
	}

	for _, cmd := range cmds {
		_, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	// Configure StrongSwan
	strongswanConf := `
config setup
    charondebug="all"

conn %default
    keyexchange=ikev2
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
    dpdaction=clear
    dpddelay=300s
    dpdtimeout=1h
    rekey=no
    left=%any
    leftid=@server.vpn
    leftcert=server.cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8
    eap_identity=%identity

conn ios_vpn
    also=%default
    auto=add
`

	// Write StrongSwan configuration
	cmd := fmt.Sprintf("echo \"%s\" | sudo tee /etc/ipsec.conf", strongswanConf)
	_, err := s.SSHClient.RunCommand(cmd)
	if err != nil {
		return err
	}

	// Restart StrongSwan service
	cmds = []string{
		"sudo systemctl restart strongswan",
		"sudo systemctl enable strongswan",
	}

	for _, cmd := range cmds {
		_, err := s.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// Add more methods for generating client configs, etc.
