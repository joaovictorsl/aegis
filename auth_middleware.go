package aegis

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/joaovictorsl/aegis/token"
)

type Middleware func(http.Handler) http.Handler

func RequireAuthMiddleware(jwtManager token.JWTManager) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tok string
			c, err := r.Cookie("token")
			if err != nil {
				authHeader := r.Header.Get("Authorization")
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
		})
	}
}

func GetUserIdFromContext(ctx context.Context) string {
	return ctx.Value("user_id").(string)
}
