package vpn

import (
	"crypto/rand"
	"fmt"
)

// generatePassword generates a secure random password with special characters
func generatePassword() (string, error) {
	const (
		passwordLength  = 16
		chars           = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
		minSpecialChars = 2
	)

	bytes := make([]byte, passwordLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// Ensure password contains special characters
	bytes[0] = "!@#$%^&*"[bytes[0]%8] // First char is special
	bytes[1] = "!@#$%^&*"[bytes[1]%8] // Second char is special

	// Generate remaining characters
	for i := minSpecialChars; i < passwordLength; i++ {
		bytes[i] = chars[bytes[i]%byte(len(chars))]
	}

	return string(bytes), nil
}
