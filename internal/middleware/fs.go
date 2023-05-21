package middleware

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"

	"ultra/internal/model"
)

var fsIndex = template.Must(template.New(`node.listing`).Parse(strings.TrimSpace(`
<!doctype html>
<html>
<head>
  <title>{{ .Path }}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
</head>
<body>
{{- $path := .Path }}
{{- range .Nodes }}
<a href="{{ $path }}/{{ .Name }}">{{ .Name }}</a><br>
{{- end }}
</body>
</html>
`) + "\n"))

func NewFs(driver model.FsDriver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path, err := url.PathUnescape(r.URL.String())
			if err != nil {
				fmt.Printf("unescape error: %s\n", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			node, err := driver.Get(path)
			if err != nil {
				fmt.Printf("driver error: %s\n", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			publish(path, node, next, w, r)
		})
	}
}

func publish(path string, node model.FsNode, next http.Handler, w http.ResponseWriter, r *http.Request) {
	if len(node.Nodes) > 0 {
		w.Header().Add(`content-type`, `text/html`)
		w.WriteHeader(http.StatusOK)
		if path == `/` {
			path = path[1:]
		} else if len(path) > 0 && path[len(path)-1] == '/' {
			path = path[:len(path)-1]
		}
		data := struct {
			Path  string
			Nodes []model.FsNode
		}{Path: path, Nodes: node.Nodes}
		if err := fsIndex.Execute(w, data); err != nil {
			fmt.Printf("template error: %s\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else if node.Data != nil {
		w.Header().Add(`content-type`, node.MimeType)
		w.Header().Add(`content-length`, fmt.Sprintf(`%d`, node.Size))
		w.Header().Add(`last-modified`, node.Modified.Format(http.TimeFormat))
		// FIXME: content disposition? with filename?
		w.WriteHeader(http.StatusOK)
		count, err := io.CopyN(w, node.Data, node.Size)
		if err != nil {
			fmt.Printf("copy error: %s\n", err)
		} else if count != node.Size {
			fmt.Printf("copy error: %d written is different than expected amount %d\n", count, node.Size)
		}
		if err := node.Data.Close(); err != nil {
			fmt.Printf("close error: %s\n", err)
		}
	} else {
		next.ServeHTTP(w, r)
	}
}
