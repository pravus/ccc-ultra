package volatile

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"ultra/internal/control"
	"ultra/internal/middleware"
)

type Proxy struct {
	url     *url.URL
	handler http.Handler
}

type Router struct {
	label      string
	logger     control.Logger
	withLogger bool
	proxies    map[string]Proxy
	metrics    func(http.Handler) http.Handler
}

func NewRouter(label string, logger control.Logger, withLogger bool, metrics func(http.Handler) http.Handler) Router {
	router := Router{
		label:      label,
		logger:     logger,
		withLogger: withLogger,
		proxies:    make(map[string]Proxy),
		metrics:    metrics,
	}
	return router
}

func (router Router) AddProxy(prefix string, url *url.URL, wrapper func(http.Handler) http.Handler) {
	if proxy, ok := router.proxies[prefix]; ok {
		router.logger.Audit(`%s.router.eject %s -> %s`, router.label, prefix, proxy.url.String())
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(url)
			r.Out.Host = r.In.Host
			r.Out.Header[`X-Forwarded-For`] = r.In.Header[`X-Forwarded-For`]
			r.SetXForwarded()
		},
	}
	handler := http.Handler(proxy)
	if wrapper != nil {
		handler = wrapper(handler)
	}
	handler = router.metrics(handler)
	handler = middleware.ReverseProxy(handler, router.withLogger, NewLogFormatter(router.label, router.logger))
	router.proxies[prefix] = Proxy{
		url:     url,
		handler: handler,
	}
	router.logger.Audit(`%s.router.add %s -> %s`, router.label, prefix, url.String())
}

func (router Router) RubProxy(prefix string) {
	if proxy, ok := router.proxies[prefix]; ok {
		delete(router.proxies, prefix)
		router.logger.Audit(`router.rub %s %s -> %s`, router.label, prefix, proxy.url.String())
	}
}

func (router Router) Proxies() map[string]*url.URL {
	proxies := map[string]*url.URL{}
	for prefix, proxy := range router.proxies {
		proxies[prefix] = proxy.url
	}
	return proxies
}

func (router Router) Handler() func(http.Handler) http.Handler {
	canProxy := func(prefix string, path string) bool {
		if !strings.HasPrefix(path, prefix) {
			return false
		}
		if len(path) == len(prefix) {
			return true
		}
		check := path[len(prefix)]
		if check == '/' || check == '?' {
			return true
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path, err := url.PathUnescape(r.URL.String())
			if err != nil {
				router.logger.Warn(`%s.unescape error: %s`, router.label, err)
				next.ServeHTTP(w, r)
				return
			}
			for prefix, proxy := range router.proxies {
				if canProxy(prefix, path) {
					proxy.handler.ServeHTTP(w, r)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

