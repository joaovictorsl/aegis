package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

type Provider interface {
	Name() string
	CallbackHandlerPath() string
	GetAuthCodeURL(state string) (authURL string)
	ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error)
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
	urls := []string{
		userInfoUrl,
		authUrl,
		tokenUrl,
		redirectUrl,
	}
	for _, u := range urls {
		_, err := url.ParseRequestURI(u)
		if err != nil {
			return nil, err
		}
	}

	return &BaseProvider{
		name: name,
		flow: &oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			RedirectURL:  redirectUrl,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authUrl,
				TokenURL: tokenUrl,
			},
		},
		callbackHandlerPath: redirectUrl,
		userInfoUrl:         userInfoUrl,
	}, nil
}

type BaseProvider struct {
	name                string
	flow                *oauth2.Config
	callbackHandlerPath string
	userInfoUrl         string
}

func (p *BaseProvider) Name() string {
	return p.name
}

func (p *BaseProvider) CallbackHandlerPath() string {
	return p.callbackHandlerPath
}

func (p *BaseProvider) GetAuthCodeURL(state string) (authURL string) {
	return p.flow.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (p *BaseProvider) ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	tok, err := p.flow.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code for token: %w", err)
	}
	return tok, nil
}

func (p *BaseProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) ([]byte, error) {
	client := p.flow.Client(ctx, token)
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
