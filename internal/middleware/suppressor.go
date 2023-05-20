package middleware

import (
	"net/http"
	"net/url"
	"strings"
)

func Suppressor(option func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path, err := url.PathUnescape(r.URL.String())
			if err == nil {
				if strings.HasPrefix(path, `/^`) {
					next.ServeHTTP(w, r)
					return
				}
			}
			option(next).ServeHTTP(w, r)
		})
	}
}
