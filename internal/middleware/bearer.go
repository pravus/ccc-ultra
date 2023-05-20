package middleware

import (
	"fmt"
	"net/http"
	"strings"
)

func Bearer(token string) func(http.Handler) http.Handler {
	return func (next http.Handler) http.Handler {
		return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
			if text := r.Header.Get(`authorization`); len(text) <= 0 {
				fmt.Printf("bearer fail: no authorization token\n")
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			} else if index := strings.Index(text, ` `); index < 0 {
				fmt.Printf("bearer fail: malformed authorization text\n")
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			} else if strings.ToLower(text[0:index]) != `bearer` {
				fmt.Printf("bearer fail: invalid authentication type \"%s\"\n", text[0:index])
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			} else if text[index+1:] != token {
				fmt.Printf("bearer fail: authentication failed\n")
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			} else {
				// TODO: send to audit logger
				//fmt.Printf("bearer pass: token verified\n")
				next.ServeHTTP(w, r)
			}
		})
	}
}
