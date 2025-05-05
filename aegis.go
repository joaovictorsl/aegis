package aegis

import (
	"context"
	"net/http"

	"github.com/joaovictorsl/aegis/handlers"
	"github.com/joaovictorsl/aegis/oauth"
	"github.com/joaovictorsl/aegis/token"
	"golang.org/x/oauth2/endpoints"
)

type Aegis struct {
	jwtManager      token.JWTManager
	createUserFn    func(ctx context.Context, u oauth.ProviderUser) (string, error)
	tokenRepository token.Repository
}

func New(
	jwtManager token.JWTManager,
	createUserFn func(ctx context.Context, u oauth.ProviderUser) (string, error),
	tokenRepository token.Repository,
) *Aegis {
	return &Aegis{
		jwtManager:      jwtManager,
		createUserFn:    createUserFn,
		tokenRepository: tokenRepository,
	}
}

type Handlers struct {
	Login    http.Handler
	Callback http.Handler
}

func (a *Aegis) NewGoogleHandlers(clientId, clientSecret, redirectUrl string) (Handlers, error) {
	p, err := oauth.NewProvider(
		"google",
		"https://www.googleapis.com/oauth2/v2/userinfo",
		clientId,
		clientSecret,
		endpoints.Google.AuthURL,
		endpoints.Google.TokenURL,
		redirectUrl,
		"email",
		"openid",
	)
	if err != nil {
		return Handlers{}, err
	}

	return Handlers{
		Login:    handlers.LoginHandler(p),
		Callback: handlers.CallbackHandler(p, a.jwtManager, a.tokenRepository, a.createUserFn),
	}, nil
}

func (a *Aegis) NewSpotifyHandlers(clientId, clientSecret, redirectUrl string) (Handlers, error) {
	p, err := oauth.NewProvider(
		"spotify",
		"https://api.spotify.com/v1/me",
		clientId,
		clientSecret,
		endpoints.Spotify.AuthURL,
		endpoints.Spotify.TokenURL,
		redirectUrl,
		"user-read-email",
	)
	if err != nil {
		return Handlers{}, err
	}

	return Handlers{
		Login:    handlers.LoginHandler(p),
		Callback: handlers.CallbackHandler(p, a.jwtManager, a.tokenRepository, a.createUserFn),
	}, nil
}
