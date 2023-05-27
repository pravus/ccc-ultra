package volatile

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"ultra/internal/control"
	"ultra/internal/middleware"
)

type Route struct {
	url     *url.URL
	handler http.Handler
}

type Router struct {
	label      string
	logger     control.Logger
	withLogger bool
	routes     map[string]Route
	metrics    func(http.Handler) http.Handler
}

func NewRouter(label string, logger control.Logger, withLogger bool) Router {
	router := Router{
		label:      label,
		logger:     logger,
		withLogger: withLogger,
		routes:     make(map[string]Route),
		// FIXME: this is fucking disgusting
		metrics: middleware.Prometheus(label),
	}
	return router
}

func (router Router) AddRoute(prefix string, url *url.URL) {
	if route, ok := router.routes[prefix]; ok {
		router.logger.Audit(`%s.router.eject %s -> %s`, router.label, prefix, route.url.String())
	}
	handler := http.Handler(httputil.NewSingleHostReverseProxy(url))
	handler = router.metrics(handler)
	handler = middleware.ReverseProxy(handler, router.withLogger, NewLogFormatter(router.label, router.logger))
	router.routes[prefix] = Route{
		url:     url,
		handler: handler,
	}
	router.logger.Audit(`%s.router.add %s -> %s`, router.label, prefix, url.String())
}

func (router Router) RubRoute(prefix string) {
	if route, ok := router.routes[prefix]; ok {
		delete(router.routes, prefix)
		router.logger.Audit(`router.rub %s %s -> %s`, router.label, prefix, route.url.String())
	}
}

func (router Router) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for prefix, route := range router.routes {
				path, err := url.PathUnescape(r.URL.String())
				if err != nil {
					router.logger.Warn(`%s.unescape error: %s`, router.label, err)
					next.ServeHTTP(w, r)
					return
				}
				if strings.HasPrefix(path, prefix) {
					route.handler.ServeHTTP(w, r)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (router Router) Routes() map[string]*url.URL {
	routes := map[string]*url.URL{}
	for prefix, route := range router.routes {
		routes[prefix] = route.url
	}
	return routes
}
