package middleware

import (
	"net/http"
)

func MethodFilter(allowed []string, trash http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, method := range allowed {
				if r.Method == method {
					next.ServeHTTP(w, r)
					return
				}
			}
			trash.ServeHTTP(w, r)
		})
	}
}
