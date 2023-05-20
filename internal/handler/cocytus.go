package handler

import (
	"net/http"
)

func Cocytus(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `Ye Who Enter All Hope Abandon`, http.StatusNotFound)
}
