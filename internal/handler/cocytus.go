package handler

import (
	"net/http"
)

var Cocytus = mummify(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(`connection`, `close`)
	http.Error(w, `Ye Who Enter All Hope Abandon`, http.StatusNotFound)
})
