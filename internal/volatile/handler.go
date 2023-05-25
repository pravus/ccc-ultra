package volatile

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ultra/internal/control"
	"ultra/internal/model"
)

func VfsHandler(vfs FsDriver, logger control.Logger) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// FIXME: what to do here?
		case http.MethodDelete:
			path, err := url.PathUnescape(r.URL.String())
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			path = strings.TrimPrefix(path, `/vfs`)
			logger.Audit(`vfs.delete path=%s`, path)
			vfs.Rub(path)
		case http.MethodPost:
			// FIXME: just take in an FsEntry?  or FsNode?
			path, err := url.PathUnescape(r.URL.String())
			if err != nil {
				logger.Error(`vfs.post error: %s`, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			path = strings.TrimPrefix(path, `/vfs`)
			data, err := base64.StdEncoding.DecodeString(r.FormValue(`data`))
			if err != nil {
				logger.Error(`vfs.post error: %s`, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			name := path
			if index := strings.LastIndex(name, `/`); index >= 0 {
				name = name[index:]
			}
			entry := FsEntry{
				node: model.FsNode{
					Name:     name,
					IsDir:    false,
					Modified: time.Now().UTC(),
					MimeType: http.DetectContentType(data),
					Size:     int64(len(data)),
				},
				data: data,
			}
			vfs.Put(path, entry)
			logger.Audit(`vfs.post path=%s size=%d mime-type=%s`, path, entry.node.Size, entry.node.MimeType)
			w.WriteHeader(http.StatusOK)
		}
	})
}
