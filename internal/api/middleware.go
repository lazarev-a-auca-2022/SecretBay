package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/auth"
	"github.com/lazarev-a-auca-2022/vpn-setup-server/internal/config"
)

// verify the JWT token and set the username in the request context
func JWTAuthenticationMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "Invalid Authorization Header", http.StatusUnauthorized)
				return
			}

			tokenStr := parts[1]
			claims, err := auth.ValidateJWT(tokenStr, cfg)
			if err != nil {
				http.Error(w, "Invalid Token", http.StatusUnauthorized)
				return
			}

			// set the username in the request context
			ctx := context.WithValue(r.Context(), "username", claims.Username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
