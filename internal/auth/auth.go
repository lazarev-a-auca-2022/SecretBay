package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/pkg/logger"
)

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateJWT(username string, cfg *config.Config) (string, error) {
	if len(cfg.JWTSecret) < 32 {
		logger.Log.Println("Warning: JWT secret key is too short")
	}

	expirationTime := time.Now().Add(1 * time.Hour) // Reduced from 24 hours for security
	notBefore := time.Now().Add(-1 * time.Minute)   // Small leeway for clock skew

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
			return nil, fmt.Errorf("invalid token signing method")
		}

		// Verify token hasn't expired with custom error message
		if claims, ok := token.Claims.(*Claims); ok {
			if !claims.ExpiresAt.Time.IsZero() && claims.ExpiresAt.Time.Before(time.Now()) {
				return nil, fmt.Errorf("token has expired")
			}
		}

		return []byte(cfg.JWTSecret), nil
	}

	token, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		logger.Log.Printf("Error validating JWT: %v", err)
		return nil, fmt.Errorf("invalid token")
	}

	if !token.Valid {
		logger.Log.Println("Token validation failed")
		return nil, fmt.Errorf("invalid token")
	}

	// Additional validation
	if claims.Issuer != "vpn-setup-server" {
		logger.Log.Printf("Invalid token issuer: %s", claims.Issuer)
		return nil, fmt.Errorf("invalid token issuer")
	}

	if time.Until(claims.ExpiresAt.Time) > 2*time.Hour {
		logger.Log.Println("Token expiration time too long")
		return nil, fmt.Errorf("invalid token expiration")
	}

	return claims, nil
}
