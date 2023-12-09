package volatile

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
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
			modified := time.Now().UTC()
			if mtime := r.FormValue(`mtime`); mtime != `` {
				if unix, err := strconv.ParseInt(mtime, 10, 64); err != nil {
					logger.Error(`vfs.post error: %s`, err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				} else {
					modified = time.Unix(unix, 0).UTC()
				}
			}
			node := model.FsNode{
				Name:     name,
				IsDir:    false,
				Modified: modified,
				MimeType: http.DetectContentType(data),
				Size:     int64(len(data)),
			}
			vfs.Put(path, data, node)
			logger.Audit(`vfs.post path=%s size=%d mime-type=%s modified=%s`, path, node.Size, node.MimeType, node.Modified.String())
			w.WriteHeader(http.StatusOK)
		}
	})
}
