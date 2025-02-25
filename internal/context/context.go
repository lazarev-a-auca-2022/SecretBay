// Package context provides shared context types and keys
package context

// Key is the custom type for context keys to avoid collisions
type Key string

// Context keys used throughout the application
const (
	UsernameKey    Key = "username"
	CSRFTokenKey   Key = "csrf_token"
	AuthEnabledKey Key = "auth_enabled"
)
