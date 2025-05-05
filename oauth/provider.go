package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

// Provider defines the methods needed for an OAuth flow.
type Provider interface {
	// Provider's name
	Name() string

	// Callback handler path
	CallbackHandlerPath() string

	// GetAuthCodeURL generates the URL for the user to authorize the application.
	// It also returns the PKCE verifier to be used later.
	GetAuthCodeURL(state string) (authURL string)

	// ExchangeCodeForToken exchanges the authorization code for an OAuth2 token.
	// It requires the code received in the callback and the PKCE verifier.
	ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error)

	// GetUserInfo fetches user information using the provided OAuth2 token.
	GetUserInfo(ctx context.Context, token *oauth2.Token) (userInfo []byte, err error)
}

func NewProvider(
	name,
	userInfoUrl,
	clientId,
	clientSecret,
	authUrl,
	tokenUrl,
	redirectUrl string,
	scopes ...string,
) (Provider, error) {
	u, err := url.Parse(redirectUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect url: %v", err)
	}
	callbackHandlerPath := u.Path

	return &baseProvider{
		name: name,
		config: &oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			RedirectURL:  redirectUrl,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authUrl,
				TokenURL: tokenUrl,
			},
		},
		callbackHandlerPath: callbackHandlerPath,
		userInfoUrl:         userInfoUrl,
	}, nil
}

type baseProvider struct {
	name                string
	config              *oauth2.Config
	callbackHandlerPath string
	userInfoUrl         string
}

func (p *baseProvider) Name() string {
	return p.name
}

func (p *baseProvider) CallbackHandlerPath() string {
	return p.callbackHandlerPath
}

func (p *baseProvider) GetAuthCodeURL(state string) (authURL string) {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (p *baseProvider) ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	tok, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code for token: %w", err)
	}
	return tok, nil
}

func (p *baseProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) ([]byte, error) {
	client := p.config.Client(ctx, token)
	res, err := client.Get(p.userInfoUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to get user info: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("user info request failed with status: %d and error reading body: %w", res.StatusCode, err)
		}

		return nil, fmt.Errorf("user info request failed with status: %d and body: %s", res.StatusCode, string(raw))
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}

	return raw, nil
}
