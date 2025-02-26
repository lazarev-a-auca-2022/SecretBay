package auth

import (
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

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
