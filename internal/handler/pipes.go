package handler

import (
	"encoding/json"
	"net/http"
	"net/url"

	"ultra/internal/control"
)

func Pipes(logger control.Logger, pipes map[string]control.Router) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			res := map[string]map[string]string{}
			for label, router := range pipes {
				res[label] = map[string]string{}
				for path, url := range router.Routes() {
					res[label][path] = url.String()
				}
			}
			if err := json.NewEncoder(w).Encode(res); err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			label := r.FormValue(`label`)
			prefix := r.FormValue(`prefix`)
			formUrl := r.FormValue(`url`)
			if label == `` || prefix == `` || formUrl == `` {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			url, err := url.Parse(formUrl)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			if router, ok := pipes[label]; !ok {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			} else {
				router.AddRoute(prefix, url)
			}
		case http.MethodDelete:
			label := r.FormValue(`label`)
			prefix := r.FormValue(`prefix`)
			if label == `` || prefix == `` {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			} else if router, ok := pipes[label]; !ok {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			} else {
				router.RubRoute(prefix)
			}
		default:
			Manus.ServeHTTP(w, r)
		}
	})
}
