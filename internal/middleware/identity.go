package middleware

import (
	"net/http"
)

func Identity(h http.Handler) http.Handler {
	return h
}
