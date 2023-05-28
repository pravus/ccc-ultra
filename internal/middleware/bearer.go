package middleware

import (
	"encoding/base64"
	"net/http"
	"strings"

	"ultra/internal/control"
	"ultra/internal/handler"
)

func Bearer(token string, audit bool, fail http.Handler, logger control.Logger) func(http.Handler) http.Handler {
	if fail == nil {
		fail = handler.Cocytus
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if text := r.Header.Get(`authorization`); len(text) <= 0 {
				logger.Audit(`bearer: no authorization token`)
				fail.ServeHTTP(w, r)
			} else if index := strings.Index(text, ` `); index < 0 {
				logger.Audit(`bearer: malformed authorization text`)
				fail.ServeHTTP(w, r)
			} else if strings.ToLower(text[0:index]) != `bearer` {
				logger.Audit(`bearer: invalid authentication type "%s"`, text[0:index])
				fail.ServeHTTP(w, r)
			} else if decoded, err := base64.StdEncoding.DecodeString(text[index+1:]); err != nil {
				logger.Audit(`bearer: base64 error: %s`, err)
				fail.ServeHTTP(w, r)
			} else if string(decoded) != token {
				logger.Audit(`bearer: authentication failed`)
				fail.ServeHTTP(w, r)
			} else {
				if audit {
					logger.Audit(`bearer: authentication success`)
				}
				next.ServeHTTP(w, r)
			}
		})
	}
}
