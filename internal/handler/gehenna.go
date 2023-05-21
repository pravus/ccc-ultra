package handler

import (
	"net/http"
)

func Gehenna(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(`Connection`, `close`)
	http.Redirect(w, r, `https://`+r.Host+r.URL.String(), http.StatusMovedPermanently)
}
