package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// FIXME: move stuff like prometheus and bearer token in here?

func Standard(handler http.Handler, withLogger bool, logger middleware.LogFormatter, timeout time.Duration, compress int) http.Handler {
	wares := []func(http.Handler) http.Handler{
		middleware.Recoverer,
	}
	if withLogger {
		wares = append(wares, middleware.RequestLogger(logger))
	}
	wares = append(wares, []func(http.Handler) http.Handler{
		middleware.RealIP,
		middleware.RequestID,
		middleware.CleanPath,
		middleware.Timeout(timeout),
	}...)
	if compress >= 0 {
		wares = append(wares, middleware.Compress(compress))
	}
	for _, wrap := range wares {
		handler = wrap(handler)
	}
	return handler
}

func ReverseProxy(handler http.Handler, withLogger bool, logger middleware.LogFormatter) http.Handler {
	wares := []func(http.Handler) http.Handler{}
	if withLogger {
		wares = append(wares, middleware.RequestLogger(logger))
	}
	wares = append(wares, []func(http.Handler) http.Handler{
		middleware.RealIP,
		middleware.RequestID,
		middleware.CleanPath,
	}...)
	for _, wrap := range wares {
		handler = wrap(handler)
	}
	return handler
}

func Control(handler http.Handler, withLogger bool, logger middleware.LogFormatter) http.Handler {
	wares := []func(http.Handler) http.Handler{
		middleware.Recoverer,
	}
	if withLogger {
		wares = append(wares, middleware.RequestLogger(logger))
	}
	wares = append(wares, []func(http.Handler) http.Handler{
		middleware.RealIP,
		middleware.RequestID,
		middleware.CleanPath,
		middleware.Timeout(15 * time.Second),
		middleware.Compress(10),
	}...)
	for _, wrap := range wares {
		handler = wrap(handler)
	}
	return handler
}
