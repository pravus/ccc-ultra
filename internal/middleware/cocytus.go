package middleware

import (
	"net/http"
)

func Cocytus(http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Ye Who Enter All Hope Abandon", http.StatusNotFound)
	})
}
