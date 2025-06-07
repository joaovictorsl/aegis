package aegis

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/joaovictorsl/aegis/config"
	"github.com/joaovictorsl/aegis/token"
)

type Middleware func(http.HandlerFunc) http.HandlerFunc

func RequireAuthMiddleware(cfg config.AegisConfig, jwtManager token.JWTManager) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var tok string
			c, err := r.Cookie(cfg.AccessTokenCookie.Name)
			if err != nil {
				authHeader := r.Header.Get(cfg.AccessTokenHeaderKey)
				if authHeader == "" {
					http.Error(w, "No access token provided", http.StatusUnauthorized)
					return
				}

				tokHeader, ok := strings.CutPrefix(authHeader, "Bearer ")
				if !ok {
					http.Error(w, "Authorization header format must be 'Bearer <token>'", http.StatusUnauthorized)
					return
				}

				tok = tokHeader
			} else {
				tok = c.Value
			}

			claims, err := jwtManager.ValidateToken(tok)
			if err != nil {
				fmt.Printf("Token validation error: %v\n", err)
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "user_id", claims.UserId)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		}
	}
}

func GetUserIdFromContext(ctx context.Context) string {
	return ctx.Value("user_id").(string)
}
