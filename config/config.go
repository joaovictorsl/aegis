package config

import (
	"net/http"
	"time"
)

type AegisConfig struct {
	StateCookie           http.Cookie
	AccessTokenCookie     http.Cookie
	RefreshTokenCookie    http.Cookie
	RefreshTokenHeaderKey string
	AccessTokenHeaderKey  string
	HandlerTimeout        time.Duration
}

var DefaultConfig = AegisConfig{
	StateCookie: http.Cookie{
		Name:     "oauth_state",
		Path:     "/",
		Domain:   "",
		MaxAge:   int((5 * time.Minute).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	},
	AccessTokenCookie: http.Cookie{
		Name:     "access_token",
		Path:     "/",
		Domain:   "",
		MaxAge:   int((15 * time.Minute).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	},
	RefreshTokenCookie: http.Cookie{
		Name:     "refresh_token",
		Path:     "/",
		Domain:   "",
		MaxAge:   int((30 * 24 * time.Hour).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	},
	AccessTokenHeaderKey:  "Authorization",
	RefreshTokenHeaderKey: "Refresh-Token",
	HandlerTimeout:        5 * time.Second,
}
