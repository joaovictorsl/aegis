package handlers

import (
	"context"
	"log"
	"net/http"

	"github.com/joaovictorsl/aegis/config"
	"github.com/joaovictorsl/aegis/token"
	"github.com/joaovictorsl/aegis/util"
)

func RefreshHandler(
	log *log.Logger,
	cfg config.AegisConfig,
	jwtManager token.JWTManager,
	tokenRepository token.Repository,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			refreshTok         string
			refreshTokOnHeader = false
		)

		c, err := r.Cookie(cfg.RefreshTokenCookie.Name)
		if err != nil {
			refreshTokHeader := r.Header.Get(cfg.RefreshTokenHeaderKey)
			if refreshTokHeader == "" {
				http.Error(w, "Refresh token not provided", http.StatusUnauthorized)
				log.Println("refresh token not provided")
				return
			}
			refreshTokOnHeader = true
			refreshTok = refreshTokHeader
		} else {
			refreshTok = c.Value
		}

		ctx, cancel := context.WithTimeout(context.Background(), cfg.HandlerTimeout)
		defer cancel()

		claims, err := jwtManager.ValidateToken(refreshTok)
		if err != nil {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			log.Printf("invalid refresh token: %v", err)
			return
		}

		storedTok, err := tokenRepository.SelectToken(ctx, claims.UserId)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.Printf("failed to fetch refresh token from repository: %v", err)
			return
		}

		if storedTok != refreshTok {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			log.Printf("refresh token (%s) does not match stored token (%s)", refreshTok, storedTok)
			return
		}

		newAccessTok, err := jwtManager.GenerateAccessToken(claims.UserId)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.Printf("failed to generate access token: %v", err)
			return
		}
		newRefreshTok, err := jwtManager.GenerateRefreshToken(claims.UserId)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.Printf("failed to generate refresh token: %v", err)
			return
		}

		err = tokenRepository.StoreToken(ctx, claims.UserId, newRefreshTok)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.Printf("failed to store refresh token: %v", err)
			return
		}

		if refreshTokOnHeader {
			w.Header().Set(cfg.AccessTokenHeaderKey, newAccessTok)
			w.Header().Set(cfg.RefreshTokenHeaderKey, newRefreshTok)
		} else {
			util.SetCookie(w, cfg.AccessTokenCookie, newAccessTok)
			util.SetCookie(w, cfg.RefreshTokenCookie, newRefreshTok)
		}

		w.WriteHeader(http.StatusOK)
	}
}
