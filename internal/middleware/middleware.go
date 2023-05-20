package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func Always(timeout time.Duration, compress int) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		middleware.CleanPath,
		middleware.RequestID,
		middleware.RealIP,
		middleware.Logger,
		middleware.Recoverer,
		middleware.Timeout(timeout),
		middleware.Compress(compress),
	}
}

func Control() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		middleware.CleanPath,
		middleware.RequestID,
		middleware.RealIP,
		Suppressor(middleware.Logger),
		middleware.Recoverer,
		middleware.Timeout(15 * time.Second),
		middleware.Compress(10),
	}
}
