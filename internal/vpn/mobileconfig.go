package vpn

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"text/template"
	"time"
)

const mobileConfigTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>IKEv2</key>
            <dict>
                <key>AuthenticationMethod</key>
                <string>Certificate</string>
                <key>ChildSecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256-GCM</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-384</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>20</integer>
                    <key>LifeTimeInMinutes</key>
                    <integer>1440</integer>
                </dict>
                <key>DeadPeerDetectionRate</key>
                <string>Medium</string>
                <key>DisableMOBIKE</key>
                <integer>0</integer>
                <key>DisableRedirect</key>
                <integer>0</integer>
                <key>EnableCertificateRevocationCheck</key>
                <integer>0</integer>
                <key>EnablePFS</key>
                <integer>1</integer>
                <key>IKESecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256-GCM</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-384</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>20</integer>
                    <key>LifeTimeInMinutes</key>
                    <integer>1440</integer>
                </dict>
                <key>LocalIdentifier</key>
                <string>{{ .Username }}</string>
                <key>RemoteAddress</key>
                <string>{{ .ServerIP }}</string>
                <key>RemoteIdentifier</key>
                <string>{{ .ServerIP }}</string>
                <key>UseConfigurationAttributeInternalIPSubnet</key>
                <integer>0</integer>
            </dict>
            <key>PayloadDescription</key>
            <string>SecretBay VPN Configuration</string>
            <key>PayloadDisplayName</key>
            <string>SecretBay VPN</string>
            <key>PayloadIdentifier</key>
            <string>com.secretbay.vpn.{{ .ConfigID }}</string>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>{{ .UUID }}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>UserDefinedName</key>
            <string>SecretBay VPN</string>
            <key>VPNType</key>
            <string>IKEv2</string>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>SecretBay VPN</string>
    <key>PayloadIdentifier</key>
    <string>com.secretbay.vpn</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{{ .RootUUID }}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`

type MobileConfigData struct {
	ServerIP string
	Username string
	Password string
	ConfigID string
	UUID     string
	RootUUID string
}

func (s *StrongSwanSetup) GenerateMobileConfig(username string) (string, error) {
	// Generate unique IDs
	configID := generateRandomID()
	uuid := generateRandomID()
	rootUUID := generateRandomID()

	// Prepare template data
	data := MobileConfigData{
		ServerIP: s.ServerIP,
		Username: username,
		ConfigID: configID,
		UUID:     uuid,
		RootUUID: rootUUID,
	}

	// Parse and execute template
	tmpl, err := template.New("mobileconfig").Parse(mobileConfigTemplate)
	if err != nil {
		return "", fmt.Errorf("template parsing error: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execution error: %v", err)
	}

	// Save the configuration
	configPath := fmt.Sprintf("/etc/vpn-configs/%s.mobileconfig", configID)
	if _, err := s.SSHClient.RunCommand(fmt.Sprintf("echo '%s' > %s", buf.String(), configPath)); err != nil {
		return "", fmt.Errorf("failed to save mobileconfig: %v", err)
	}

	return configPath, nil
}

func generateRandomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
