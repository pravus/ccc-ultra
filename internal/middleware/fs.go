package middleware

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	_path "path"
	"strings"

	"ultra/internal/control"
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
{{- $prefix := .Prefix }}
{{- $path := .Path }}
{{- range .Nodes }}
<a href="{{ $prefix }}{{ $path }}/{{ .Name }}">{{ .Name }}</a><br>
{{- end }}
</body>
</html>
`) + "\n"))

func NewFs(driver model.FsDriver, urlPrefix string, logger control.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var withBody bool
			switch r.Method {
			case http.MethodGet:
				withBody = true
			case http.MethodHead:
				withBody = false
			default:
				next.ServeHTTP(w, r)
				return
			}
			path, err := url.PathUnescape(r.URL.String())
			if err != nil {
				logger.Warn(`unescape error: %s`, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if index := strings.Index(path, `?`); index >= 0 {
				path = path[:index]
			}
			path = _path.Clean(path)
			node, err := driver.Get(path)
			if err != nil {
				switch err {
				case model.ErrFsNotFound:
					logger.Trace(`driver(%T) error: %s: %s`, driver, path, err)
					next.ServeHTTP(w, r)
				default:
					logger.Error(`driver(%T) error: %s: %s`, driver, path, err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				return
			}
			publish(logger, urlPrefix, path, node, next, withBody, w, r)
		})
	}
}

func NewHome(driver model.FsDriver, prefix string, public string, urlPrefix string, logger control.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var withBody bool
			switch r.Method {
			case http.MethodGet:
				withBody = true
			case http.MethodHead:
				withBody = false
			default:
				next.ServeHTTP(w, r)
				return
			}
			path, err := url.PathUnescape(r.URL.String())
			if err != nil {
				logger.Warn(`unescape error: %s`, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if index := strings.Index(path, `?`); index >= 0 {
				path = path[:index]
			}
			path = _path.Clean(path)
			if !strings.HasPrefix(path, `/`+prefix) {
				next.ServeHTTP(w, r)
				return
			}
			user := path[strings.Index(path, prefix)+len(prefix):]
			if index := strings.Index(user, `/`); index >= 0 {
				user = user[:index]
			}
			if index := strings.Index(path, user); index >= 0 {
				path = path[index+len(user):]
			}
			if path != `` && path[0] == '/' {
				path = path[1:]
			}
			target := `/` + user + `/` + public + `/` + path
			node, err := driver.Get(target)
			if err != nil {
				logger.Warn(`driver(%T) error: %s`, driver, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			publish(logger, urlPrefix, `/`+prefix+user+`/`+path, node, next, withBody, w, r)
		})
	}
}

func publish(logger control.Logger, prefix, path string, node model.FsNode, next http.Handler, withBody bool, w http.ResponseWriter, r *http.Request) {
	if len(node.Nodes) > 0 {
		w.Header().Add(`content-type`, `text/html`)
		w.WriteHeader(http.StatusOK)
		if withBody {
			if path == `/` {
				path = path[1:]
			} else if len(path) > 0 && path[len(path)-1] == '/' {
				path = path[:len(path)-1]
			}
			data := struct {
				Prefix string
				Path   string
				Nodes  []model.FsNode
			}{Prefix: prefix, Path: path, Nodes: node.Nodes}
			if err := fsIndex.Execute(w, data); err != nil {
				logger.Warn(`template error: %s`, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
	} else if node.Data != nil {
		// FIXME: what is "correct" and should this be an option?
		disposition := `inline`
		//disposition := `attachment`
		w.Header().Add(`content-type`, node.MimeType)
		w.Header().Add(`content-length`, fmt.Sprintf(`%d`, node.Size))
		w.Header().Add(`content-disposition`, fmt.Sprintf(`%s; filename="%s"`, disposition, node.Name))
		w.Header().Add(`last-modified`, node.Modified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		if withBody {
			count, err := io.CopyN(w, node.Data, node.Size)
			if err != nil {
				logger.Warn(`copy: %s`, err)
			} else if count != node.Size {
				logger.Warn(`copy: %d written is different than expected amount %d`, count, node.Size)
			}
			if err := node.Data.Close(); err != nil {
				logger.Warn(`close error: %s`, err)
			}
		}
	} else {
		next.ServeHTTP(w, r)
	}
}
