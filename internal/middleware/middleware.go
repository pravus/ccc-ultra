package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func Standard(label string, handler http.Handler, logger middleware.LogFormatter, timeout time.Duration, compress int) http.Handler {
	wares := []func(http.Handler) http.Handler{
		middleware.Recoverer,
		middleware.RealIP,
		middleware.RequestID,
		middleware.CleanPath,
		middleware.Timeout(timeout),
		middleware.RequestLogger(logger),
	}
	if compress >= 0 {
		wares = append(wares, middleware.Compress(compress))
	}
	for _, wrap := range wares {
		handler = wrap(handler)
	}
	return handler
}

// FIXME: need to be able to configure backend timeout
func ReverseProxy(handler http.Handler, withLogger bool, logger middleware.LogFormatter) http.Handler {
	wares := []func(http.Handler) http.Handler{}
	wares = append(wares, []func(http.Handler) http.Handler{
		middleware.Recoverer,
		middleware.RealIP,
		middleware.RequestID,
		middleware.CleanPath,
		middleware.Timeout(60 * time.Second),
	}...)
	if withLogger {
		wares = append(wares, middleware.RequestLogger(logger))
	}
	for _, wrap := range wares {
		handler = wrap(handler)
	}
	return handler
}

func Control(handler http.Handler, withLogger bool, logger middleware.LogFormatter) http.Handler {
	wares := []func(http.Handler) http.Handler{
		middleware.Recoverer,
	}
	wares = append(wares, []func(http.Handler) http.Handler{
		middleware.Recoverer,
		middleware.RealIP,
		middleware.RequestID,
		middleware.CleanPath,
		middleware.Timeout(15 * time.Second),
		middleware.Compress(10),
	}...)
	if withLogger {
		wares = append(wares, middleware.RequestLogger(logger))
	}
	for _, wrap := range wares {
		handler = wrap(handler)
	}
	return handler
}
