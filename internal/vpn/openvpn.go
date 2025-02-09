package vpn

import (
	"fmt"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/sshclient"
)

type OpenVPNSetup struct {
	SSHClient *sshclient.SSHClient
	ServerIP  string
}

func (o *OpenVPNSetup) Setup() error {
	// upd and install required packages
	cmds := []string{
		"sudo apt update && sudo apt upgrade -y",
		"sudo apt install -y openvpn easy-rsa fail2ban ufw",
	}

	for _, cmd := range cmds {
		_, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	// easy-rsa setup
	cmds = []string{
		"make-cadir ~/easy-rsa",
		"cd ~/easy-rsa && ./easyrsa init-pki",
		"cd ~/easy-rsa && echo yes | ./easyrsa build-ca nopass",
		"cd ~/easy-rsa && ./easyrsa gen-req server nopass",
		"cd ~/easy-rsa && ./easyrsa sign-req server server",
		"cd ~/easy-rsa && ./easyrsa gen-dh",
		"sudo cp ~/easy-rsa/pki/ca.crt /etc/openvpn/",
		"sudo cp ~/easy-rsa/pki/issued/server.crt /etc/openvpn/",
		"sudo cp ~/easy-rsa/pki/private/server.key /etc/openvpn/",
		"sudo cp ~/easy-rsa/pki/dh.pem /etc/openvpn/",
	}

	for _, cmd := range cmds {
		_, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	// configure OpenVPN server
	serverConfig := `
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
`

	// Write server config to /etc/openvpn/server.conf
	cmd := fmt.Sprintf("echo \"%s\" | sudo tee /etc/openvpn/server.conf", serverConfig)
	_, err := o.SSHClient.RunCommand(cmd)
	if err != nil {
		return err
	}

	// enable IP forwarding
	cmds = []string{
		"sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf",
		"sudo sysctl -p",
	}

	for _, cmd := range cmds {
		_, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	// configure UFW
	cmds = []string{
		"sudo ufw allow 1194/udp",
		"sudo ufw allow OpenSSH",
		"sudo ufw disable",
		"sudo ufw enable",
	}

	for _, cmd := range cmds {
		_, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	// start and enable OpenVPN service
	cmds = []string{
		"sudo systemctl start openvpn@server",
		"sudo systemctl enable openvpn@server",
	}

	for _, cmd := range cmds {
		_, err := o.SSHClient.RunCommand(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}
