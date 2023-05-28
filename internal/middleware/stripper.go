package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"ultra/internal/control"
)

func Stripper(logger control.Logger, prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path, err := url.PathUnescape(r.URL.String())
			if err != nil {
				logger.Warn(`stripper: unescape error: %s`, err)
				next.ServeHTTP(w, r)
				return
			}
			path = strings.TrimPrefix(path, prefix)
			if path == `` {
				path = `/`
			}
			url, err := url.Parse(path)
			if err != nil {
				logger.Warn(`stripper: url error: %s`, err)
				next.ServeHTTP(w, r)
				return
			}
			// FIXME: what is the correct way to smash up a url?
			r.URL = url
			next.ServeHTTP(w, r)
		})
	}
}
