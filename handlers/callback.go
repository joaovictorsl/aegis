package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/joaovictorsl/aegis/config"
	"github.com/joaovictorsl/aegis/oauth"
	"github.com/joaovictorsl/aegis/token"
	"github.com/joaovictorsl/aegis/util"
)

func CallbackHandler(
	p oauth.Provider,
	log *log.Logger,
	cfg config.AegisConfig,
	jwtManager token.JWTManager,
	tokenRepository token.Repository,
	createUserFn func(ctx context.Context, u oauth.ProviderUser) (string, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.HandlerTimeout)
		defer cancel()

		code := r.URL.Query().Get("code")
		receivedState := r.URL.Query().Get("state")

		stateCookie, err := r.Cookie(cfg.StateCookie.Name)
		if err != nil {
			http.Error(w, "State cookie not found", http.StatusBadRequest)
			log.Printf("State cookie not found: %v", err)
			return
		}
		storedState := stateCookie.Value

		if receivedState != storedState {
			http.Error(w, "State mismatch", http.StatusUnauthorized)
			log.Printf("State mismatch. Received: %q, Stored: %q", receivedState, storedState)
			return
		}
		util.DeleteCookie(w, cfg.StateCookie)

		tok, err := p.ExchangeCodeForToken(ctx, code)
		if err != nil {
			http.Error(w, "Code not valid", http.StatusUnauthorized)
			log.Printf("Failed to exchange code for token: %v", err)
			return
		}

		raw, err := p.GetUserInfo(ctx, tok)
		if err != nil {
			http.Error(w, "Failed to get user info from provider", http.StatusUnauthorized)
			log.Printf("Failed to get user info: %v", err)
			return
		}

		var providerUser oauth.ProviderUser
		if err := json.Unmarshal(raw, &providerUser); err != nil {
			http.Error(w, "Failed to unmarshal provider user", http.StatusInternalServerError)
			log.Printf("Failed to unmarshal provider user: %v", err)
			return
		}
		providerUser.Provider = p.Name()

		userId, err := createUserFn(ctx, providerUser)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			log.Printf("Failed to create user: %v", err)
			return
		}

		accessTok, err := jwtManager.GenerateAccessToken(userId)
		if err != nil {
			http.Error(w, "Failed to create access token", http.StatusInternalServerError)
			log.Printf("Failed to create access token: %v", err)
			return
		}
		refreshTok, err := jwtManager.GenerateRefreshToken(userId)
		if err != nil {
			http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
			log.Printf("Failed to create refresh token: %v", err)
			return
		}

		err = tokenRepository.StoreToken(ctx, userId, refreshTok)
		if err != nil {
			http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
			log.Printf("Failed to store refresh token: %v", err)
			return
		}

		util.SetCookie(w, cfg.AccessTokenCookie, accessTok)
		util.SetCookie(w, cfg.RefreshTokenCookie, refreshTok)
		w.WriteHeader(http.StatusOK)
	}
}
