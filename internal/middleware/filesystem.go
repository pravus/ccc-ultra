package middleware

import (
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"ccc-ultra/internal/volatile"
)

type FilesystemNode struct {
	Name     string
	IsDir    bool
	Modified time.Time
	MimeType string
	Size     int64
	Data     io.ReadCloser
	Nodes    []FilesystemNode
}

type FilesystemDriver interface {
	Get(string) (FilesystemNode, error)
}

var filesystemIndex = template.Must(template.New(`node.listing`).Parse(strings.TrimSpace(`
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
`)+"\n"))

var filesystemMimeTypes = map[string]string{
	`7z`:    `application/x-7z-compressed`,
	`aac`:   `audio/aac`,
	`avi`:   `video/x-msvideo`,
	`bin`:   `application/octet-stream`,
	`bmp`:   `image/bmp`,
	`bz`:    `application/x-bzip`,
	`bz2`:   `application/x-bzip2`,
	`css`:   `text/css`,
	`csv`:   `text/csv`,
	`flac`:  `audio/flac`,
	`gif`:   `image/gif`,
	`gz`:    `application/gzip`,
	`htm`:   `text/html`,
	`html`:  `text/html`,
	`jpeg`:  `image/jpeg`,
	`jpg`:   `image/jpeg`,
	`js`:    `text/javascript`,
	`json`:  `application/json`,
	`md`:    `text/markdown`,
	`mkv`:   `video/x-matroska`,
	`mp3`:   `audio/mpeg`,
	`mp4`:   `video/mp4`,
	`mpeg`:  `video/mpeg`,
	`opus`:  `audio/opus`,
	`pdf`:   `application/pdf`,
	`png`:   `image/png`,
	`rar`:   `application/vnd.rar`,
	`svg`:   `image/svg+xml`,
	`tar`:   `application/x-tar`,
	`tif`:   `image/tiff`,
	`tiff`:  `image/tiff`,
	`ttf`:   `font/ttf`,
	`txt`:   `text/plain`,
	`wav`:   `audio/wav`,
	`weba`:  `audio/webm`,
	`webm`:  `video/webm`,
	`webp`:  `image/webp`,
	`woff`:  `font/woff`,
	`woff2`: `font/woff2`,
	`xhtml`: `application/xhtml+xml`,
	`xml`:   `application/xml`,
	`zip`:   `application/zip`,
}

func NewFilesystem(driver FilesystemDriver) func (http.Handler) http.Handler {
	return func (next http.Handler) http.Handler {
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
			if len(node.Nodes) > 0 {
				w.Header().Add(`content-type`, `text/html`)
				w.WriteHeader(http.StatusOK)
				if path == `/` {
					path = path[1:]
				} else if len(path) > 0 && path[len(path) - 1] == '/' {
					path = path[:len(path)-1]
				}
				data := struct {
					Path  string
					Nodes []FilesystemNode
				}{Path: path, Nodes: node.Nodes}
				if err := filesystemIndex.Execute(w, data); err != nil {
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
		})
	}
}

type OFSDriver struct {
	index string
}
var _ FilesystemDriver = (*OFSDriver)(nil)

func NewOFSDriver(index string) OFSDriver {
	driver := OFSDriver{
		index: index,
	}
	return driver
}

func (driver OFSDriver) Get(path string) (FilesystemNode, error) {
	if index := strings.IndexRune(path, '?'); index >= 0 {
		path = path[0:index]
	}
	cwd, err := os.Getwd()
	if err != nil {
		return FilesystemNode{}, err
	}
	target := cwd
	if path != `/` {
		target += path
	}
	if info, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return FilesystemNode{}, nil
		}
		return FilesystemNode{}, err
	} else if info.IsDir() {
		return driver.dir(target, path, info)
	} else {
		return driver.file(target, path, info)
	}
}

func (driver OFSDriver) dir(target string, rel string, info os.FileInfo) (FilesystemNode, error) {
	if driver.index != `` {
		target := fmt.Sprintf(`%s/%s`, target, driver.index)
		info, err := os.Stat(target)
		if err != nil {
			if !os.IsNotExist(err) {
				return FilesystemNode{}, err
			}
		} else if !info.IsDir() {
			return driver.file(target, rel, info)
		}
	}
	list, err := ioutil.ReadDir(target)
	if err != nil {
		return FilesystemNode{}, err
	}
	size := int64(len(list))
	if rel != `/` {
		size += 1
	}
	node := FilesystemNode{
		Name:     info.Name(),
		IsDir:    true,
		Modified: info.ModTime(),
		Nodes:    make([]FilesystemNode, size),
		Size:     size,
	}
	nodes := node.Nodes
	if rel != `/` {
		nodes[0] = FilesystemNode{
			Name:     `..`,
			IsDir:    true,
			Modified: time.Now().UTC(),
		}
		nodes = nodes[1:]
	}
	for i, info := range list {
		name := info.Name()
		mimeType := ``
		if index := strings.LastIndex(name, `.`); index >= 0 && index < len(name)-1 {
			if text, found := filesystemMimeTypes[name[index+1:]]; found {
				mimeType = text
			}
		}
		nodes[i] = FilesystemNode{
			Name:     name,
			IsDir:    info.IsDir(),
			Modified: info.ModTime(),
			MimeType: mimeType,
			Size:     info.Size(),
		}
	}
	sort.Slice(node.Nodes, func(one int, two int) bool {
		return strings.ToLower(node.Nodes[one].Name) < strings.ToLower(node.Nodes[two].Name)
	})
	return node, nil
}

func (driver OFSDriver) file(target string, _ string, info os.FileInfo) (FilesystemNode, error) {
	file, err := os.Open(target)
	if err != nil {
		return FilesystemNode{}, err
	}
	mimeType := ``
	if index := strings.LastIndex(target, `.`); index >= 0 && index < len(target)-1 {
		if text, found := filesystemMimeTypes[target[index+1:]]; found {
			mimeType = text
		}
	}
	return FilesystemNode{
		Name:     info.Name(),
		Modified: info.ModTime(),
		MimeType: mimeType,
		Size:     info.Size(),
		Data:     file,
	}, nil
}

type VFSDriver struct {
	vfs volatile.Fs
}
var _ FilesystemDriver = (*VFSDriver)(nil)

func NewVFSDriver(vfs volatile.Fs) VFSDriver {
	driver := VFSDriver{
		vfs: vfs,
	}
	return driver
}

func (driver VFSDriver) Get(path string) (FilesystemNode, error) {
	entry, err := driver.vfs.At(path)
	if err != nil {
		// all vfs errors result in a not-found condition
		return FilesystemNode{}, nil
	}
	// vfs entries are always singular filesystem nodes
	return FilesystemNode{
		Name:     entry.Name,
		Modified: entry.When,
		MimeType: entry.Mime,
		Size:     int64(len(entry.Data)),
		Data:     entry.ReadCloser(),
	}, nil
}
