package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/joaovictorsl/aegis/oauth"
)

func generateRandomString(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("unable to generate random string: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func LoginHandler(p oauth.Provider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := generateRandomString(32)
		if err != nil {
			http.Error(w, "Error generating state", http.StatusInternalServerError)
			log.Printf("Error generating state: %v", err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     state_cookie,
			Value:    state,
			Path:     p.CallbackHandlerPath(),
			Expires:  time.Now().Add(5 * time.Minute),
			HttpOnly: true,
			Secure:   false, // TODO: set to true once using https
			SameSite: http.SameSiteLaxMode,
		})

		authURL := p.GetAuthCodeURL(state)
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	})
}
