package middleware

import (
	"encoding/hex"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5/middleware"

	"ultra/internal/control"
)

func Trash(label string, logger control.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sig := '.'
			if r.TLS != nil {
				sig = '^'
			}
			reqID := middleware.GetReqID(r.Context())

			keys := make([]string, 0, len(r.Header))
			for k := range r.Header {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			logger.Serve(`%-5s %c %s === headers`, label, sig, reqID)
			for _, key := range keys {
				vals := r.Header[key]
				if len(vals) == 1 {
					logger.Serve(`%-5s %c %s >>> %-20s %s`, label, sig, reqID, key, vals[0])
				} else {
					logger.Serve(`%-5s %c %s >>> %-20s %+v`, label, sig, reqID, key, vals)
				}
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
			if err != nil {
				logger.Error(`%-5s %c %s %s`, label, sig, reqID, err)
			} else if len(body) > 0 {
				logger.Serve(`%-5s %c %s === body %d`, label, sig, reqID, len(body))
				for _, s := range strings.Split(hex.Dump(body), "\n") {
					if len(s) > 0 {
						logger.Serve(`%-5s %c %s >>> %s`, label, sig, reqID, s)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
