package handler

import (
	"net/http"

	"ultra/internal/control"
)

func Log(logger control.Logger) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// FIXME: return structured data based on accept header
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(logger.Level().String() + "\r\n"))
		case http.MethodPost:
			// FIXME: return delta record
			// FIXME: level validation?  i like the idea that `default` just smashes to `info`.
			from := logger.Level()
			logger.SetLevelFromString(r.FormValue(`level`))
			logger.Audit(`logging.level %s -> %s`, from.String(), logger.Level().String())
			w.WriteHeader(http.StatusOK)
		default:
			Manus.ServeHTTP(w, r)
		}
	})
}
