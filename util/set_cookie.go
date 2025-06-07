package util

import (
	"net/http"
	"time"
)

func SetCookie(w http.ResponseWriter, c http.Cookie, newValue string) {
	http.SetCookie(w, &http.Cookie{
		Name:        c.Name,
		Value:       newValue,
		Quoted:      c.Quoted,
		Path:        c.Path,
		Domain:      c.Domain,
		MaxAge:      c.MaxAge,
		Secure:      c.Secure,
		HttpOnly:    c.HttpOnly,
		SameSite:    c.SameSite,
		Partitioned: c.Partitioned,
		Raw:         c.Raw,
		Unparsed:    c.Unparsed,
	})
}

func DeleteCookie(w http.ResponseWriter, c http.Cookie) {
	http.SetCookie(w, &http.Cookie{
		Name:        c.Name,
		Value:       "",
		Quoted:      c.Quoted,
		Path:        c.Path,
		Domain:      c.Domain,
		Expires:     time.Now().Add(-24 * time.Hour),
		RawExpires:  c.RawExpires,
		MaxAge:      -1,
		Secure:      c.Secure,
		HttpOnly:    c.HttpOnly,
		SameSite:    c.SameSite,
		Partitioned: c.Partitioned,
		Raw:         c.Raw,
		Unparsed:    c.Unparsed,
	})
}
