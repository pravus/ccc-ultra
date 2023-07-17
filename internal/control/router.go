package control

import (
	"net/http"
	"net/url"
)

type Router interface {
	AddProxy(string, *url.URL, func(http.Handler) http.Handler)
	RubProxy(string)
	Proxies() map[string]*url.URL
	Handler() func(http.Handler) http.Handler
}
