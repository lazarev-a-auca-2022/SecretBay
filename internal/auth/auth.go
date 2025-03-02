package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

// Store CSRF tokens with expiration
var (
	csrfTokens = make(map[string]time.Time)
	csrfMutex  sync.RWMutex
)

const (
	csrfTokenExpiration = 1 * time.Hour
)

// Claims represents the JWT claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type TokenError struct {
	Type    string
	Message string
}

func (e *TokenError) Error() string {
	return e.Message
}

type contextKey string

const (
	// UserClaimsKey is the key used to store user claims in the context
	UserClaimsKey contextKey = "user_claims"
)

// AddUserClaimsToContext adds JWT claims to the request context
func AddUserClaimsToContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, UserClaimsKey, claims)
}

// GetUserClaimsFromContext retrieves JWT claims from the request context
func GetUserClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(UserClaimsKey).(*Claims)
	return claims, ok
}

func GenerateJWT(username string, cfg *config.Config) (string, error) {
	if len(cfg.JWTSecret) < 32 {
		logger.Log.Println("Warning: JWT secret key is too short")
	}

	expirationTime := time.Now().Add(24 * time.Hour) // Increased from 1 hour for better UX
	notBefore := time.Now().Add(-1 * time.Minute)    // Small leeway for clock skew

	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(notBefore),
			Issuer:    "vpn-setup-server",
			Subject:   username,
			ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		logger.Log.Printf("Error generating JWT: %v", err)
		return "", fmt.Errorf("failed to generate token")
	}

	return tokenString, nil
}

func ValidateJWT(tokenStr string, cfg *config.Config) (*Claims, error) {
	claims := &Claims{}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logger.Log.Printf("Unexpected signing method: %v", token.Header["alg"])
			return nil, &TokenError{Type: "InvalidMethod", Message: "invalid token signing method"}
		}
		return []byte(cfg.JWTSecret), nil
	}

	token, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		logger.Log.Printf("Error validating JWT: %v", err)

		if err.Error() == "token has expired" {
			return nil, &TokenError{Type: "Expired", Message: "token has expired"}
		} else if err.Error() == "token contains an invalid number of segments" {
			return nil, &TokenError{Type: "Malformed", Message: "token is malformed"}
		} else if err.Error() == "signature is invalid" {
			return nil, &TokenError{Type: "InvalidSignature", Message: "invalid token signature"}
		}
		return nil, &TokenError{Type: "Invalid", Message: "invalid token"}
	}

	if !token.Valid {
		logger.Log.Println("Token validation failed")
		return nil, &TokenError{Type: "Invalid", Message: "invalid token"}
	}

	// Check expiration explicitly but with a 5-minute grace period for clock skew
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Add(5*time.Minute).Before(time.Now()) {
		logger.Log.Println("Token has expired")
		return nil, &TokenError{Type: "Expired", Message: "token has expired"}
	}

	return claims, nil
}

// GenerateCSRFToken generates a secure random token and stores it in memory
func GenerateCSRFToken() (string, error) {
	// Generate 32 bytes of random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		logger.Log.Printf("Error generating random bytes for CSRF token: %v", err)
		return "", err
	}

	// Convert to base64 string
	token := base64.URLEncoding.EncodeToString(bytes)

	// Store the token with expiration
	StoreCSRFToken(token)

	logger.Log.Printf("Generated new CSRF token: %s (truncated)", token[:10])
	return token, nil
}

// VerifyCSRFToken verifies the CSRF token exists and hasn't expired
func VerifyCSRFToken(token string, cfg *config.Config) bool {
	if token == "" {
		logger.Log.Println("CSRF token validation failed: empty token")
		return false
	}

	csrfMutex.RLock()
	expirationTime, exists := csrfTokens[token]
	csrfMutex.RUnlock()

	if !exists {
		logger.Log.Printf("CSRF token validation failed: token not found in store: %s (truncated)", token[:10])
		return false
	}

	// Check if token has expired
	if time.Now().After(expirationTime) {
		csrfMutex.Lock()
		delete(csrfTokens, token)
		csrfMutex.Unlock()
		logger.Log.Printf("CSRF token validation failed: token expired: %s (truncated)", token[:10])
		return false
	}

	logger.Log.Printf("CSRF token validation successful: %s (truncated)", token[:10])
	return true
}

// StoreCSRFToken stores a CSRF token with expiration
func StoreCSRFToken(token string) {
	csrfMutex.Lock()
	defer csrfMutex.Unlock()

	// Store token with expiration time
	expiration := time.Now().Add(csrfTokenExpiration)
	csrfTokens[token] = expiration
	logger.Log.Printf("Stored CSRF token: %s (truncated) with expiration: %v", token[:10], expiration)

	// Schedule cleanup of expired token
	time.AfterFunc(csrfTokenExpiration, func() {
		csrfMutex.Lock()
		delete(csrfTokens, token)
		csrfMutex.Unlock()
	})
}

// CleanupExpiredCSRFTokens removes expired CSRF tokens
func CleanupExpiredCSRFTokens() {
	csrfMutex.Lock()
	defer csrfMutex.Unlock()

	now := time.Now()
	for token, expiration := range csrfTokens {
		if now.After(expiration) {
			logger.Log.Printf("Cleaning up expired CSRF token: %s (truncated)", token[:10])
			delete(csrfTokens, token)
		}
	}
}

// init starts a background goroutine to periodically cleanup expired tokens
func init() {
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			CleanupExpiredCSRFTokens()
		}
	}()
}
