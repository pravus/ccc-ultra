package handler

import (
	"net/http"
)

var Gehenna = mummify(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(`Connection`, `close`)
	http.Redirect(w, r, `https://`+r.Host+r.URL.String(), http.StatusMovedPermanently)
})
