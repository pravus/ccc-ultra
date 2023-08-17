package handler

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

var RipperTemplate = template.Must(template.New(`ultra-handler-ripper.html`).Parse(strings.TrimSpace(`
<html>
<head>
<title>{{ .Address }}</title>
</head>
<body>
{{ .Address }}
</body>
`)))

var Ripper = mummify(func(w http.ResponseWriter, r *http.Request) {
	address := r.RemoteAddr
	if index := strings.LastIndex(address, `:`); index >= 0 {
		address = address[:index]
	}
	var body []byte
	switch r.Header.Get(`accept`) {
	case `application/json`:
		var err error
		body, err = json.Marshal(map[string]string{`address`: address})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set(`content-type`, `application/json`)
	case ``, `text`, `text/plain`:
		w.Header().Set(`content-type`, `text/plain`)
		body = []byte(address)
	default:
		buffer := bytes.NewBuffer([]byte{})
		if err := RipperTemplate.Execute(buffer, struct {
			Address string
		}{Address: address}); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		body = buffer.Bytes()
		w.Header().Set(`content-type`, `text/html`)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	w.Write([]byte("\r\n"))
})
