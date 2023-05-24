package handler

import (
	"net/http"

	"ultra/internal/control"
)

func Log(logger control.Logger) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from := logger.Level()
		logger.SetLevelFromString(r.FormValue(`level`))
		logger.Audit(`logging.level %s -> %s`, from.String(), logger.Level().String())
	})
}
