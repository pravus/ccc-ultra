package handler

import (
	"net/http"
)

func mummify(f func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(f)
}
