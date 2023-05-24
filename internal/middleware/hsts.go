package middleware

import (
	"fmt"
	"net/http"
	"time"
)

func Hsts(maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add(`Strict-Transport-Security`, fmt.Sprintf(`max-age=%d; includeSubDomains`, int64(maxAge/time.Second)))
			next.ServeHTTP(w, r)
		})
	}
}
