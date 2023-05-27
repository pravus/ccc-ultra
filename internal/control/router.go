package control

import (
	"net/http"
	"net/url"
)

type Router interface {
	AddRoute(string, *url.URL)
	RubRoute(string)
	Handler() func(http.Handler) http.Handler
	Routes() map[string]*url.URL
}
