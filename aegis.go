package aegis

import (
	"context"
	"log"
	"net/http"

	"github.com/joaovictorsl/aegis/config"
	"github.com/joaovictorsl/aegis/handlers"
	"github.com/joaovictorsl/aegis/oauth"
	"github.com/joaovictorsl/aegis/token"
	"golang.org/x/oauth2/endpoints"
)

type Aegis struct {
	cfg             config.AegisConfig
	log             *log.Logger
	jwtManager      token.JWTManager
	tokenRepository token.Repository
	createUserFn    func(ctx context.Context, u oauth.ProviderUser) (string, error)
}

func New(
	cfg config.AegisConfig,
	log *log.Logger,
	jwtManager token.JWTManager,
	tokenRepository token.Repository,
	createUserFn func(ctx context.Context, u oauth.ProviderUser) (string, error),
) *Aegis {
	return &Aegis{
		cfg:             cfg,
		log:             log,
		jwtManager:      jwtManager,
		tokenRepository: tokenRepository,
		createUserFn:    createUserFn,
	}
}

func (a *Aegis) RefreshHandler() http.HandlerFunc {
	return handlers.RefreshHandler(
		a.log,
		a.cfg,
		a.jwtManager,
		a.tokenRepository,
	)
}

type Handlers struct {
	Login    http.HandlerFunc
	Callback http.HandlerFunc
}

func (a *Aegis) GoogleHandlers(clientId, clientSecret, redirectUrl string) (Handlers, error) {
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
		Login: handlers.LoginHandler(
			p,
			a.log,
			a.cfg,
		),
		Callback: handlers.CallbackHandler(
			p,
			a.log,
			a.cfg,
			a.jwtManager,
			a.tokenRepository,
			a.createUserFn,
		),
	}, nil
}

func (a *Aegis) SpotifyHandlers(clientId, clientSecret, redirectUrl string) (Handlers, error) {
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
		Login: handlers.LoginHandler(
			p,
			a.log,
			a.cfg,
		),
		Callback: handlers.CallbackHandler(
			p,
			a.log,
			a.cfg,
			a.jwtManager,
			a.tokenRepository,
			a.createUserFn,
		),
	}, nil
}
