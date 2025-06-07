package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/joaovictorsl/aegis"
	"github.com/joaovictorsl/aegis/config"
	"github.com/joaovictorsl/aegis/oauth"
	"github.com/joaovictorsl/aegis/token"
)

func GET(mux *http.ServeMux, path string, handler http.Handler) {
	pattern := fmt.Sprintf("%s %s", http.MethodGet, path)
	mux.Handle(pattern, handler)
}

func main() {
	jwtManager := token.NewJWTManager("issuer", "mysecret", 10*time.Second, time.Minute)
	a := aegis.New(
		config.DefaultConfig,
		log.Default(),
		jwtManager,
		token.NewInMemoryRepository(),
		func(ctx context.Context, u oauth.ProviderUser) (string, error) {
			return u.Provider + u.Id, nil
		},
	)

	gh, err := a.GoogleHandlers(
		"372817840289-r424kve7a0kc4o9kkqbtnmpusuto9kbg.apps.googleusercontent.com",
		"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",
		"https://loving-deep-loon.ngrok-free.app/auth/google/callback",
	)
	if err != nil {
		panic(err)
	}
	sh, err := a.SpotifyHandlers(
		"c6b7ea09c0c74d9a9f1c34e08b3cf151",
		"d1e7b80495e449fe8fbcfd0b3ee96309",
		"https://loving-deep-loon.ngrok-free.app/auth/spotify/callback",
	)
	if err != nil {
		panic(err)
	}

	requiresAuth := aegis.RequireAuthMiddleware(config.DefaultConfig, jwtManager)

	r := http.NewServeMux()

	GET(r, "/auth/google", gh.Login)
	GET(r, "/auth/google/callback", gh.Callback)

	GET(r, "/auth/spotify", sh.Login)
	GET(r, "/auth/spotify/callback", sh.Callback)

	GET(r, "/auth/refresh", a.RefreshHandler())

	GET(r, "/protected", requiresAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("protected data"))
	}))

	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
