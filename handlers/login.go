package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/joaovictorsl/aegis/config"
	"github.com/joaovictorsl/aegis/oauth"
	"github.com/joaovictorsl/aegis/util"
)

func generateRandomString(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("unable to generate random string: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func LoginHandler(
	p oauth.Provider,
	log *log.Logger,
	cfg config.AegisConfig,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := generateRandomString(32)
		if err != nil {
			http.Error(w, "Error generating state", http.StatusInternalServerError)
			log.Printf("Error generating state: %v", err)
			return
		}

		util.SetCookie(w, cfg.StateCookie, state)

		authURL := p.GetAuthCodeURL(state)
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	}
}
