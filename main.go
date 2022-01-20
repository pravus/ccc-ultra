package main

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type Response struct {
	Code    int
	Headers map[string]string
	Body    io.Reader
	Err     error
}

const EOL = "\r\n"

var htmlIndex = template.Must(template.New(`index`).Parse(strings.TrimSpace(`
<!doctype html>

<html>
<head>
  <title>{{ .Path }}</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
</head>
<body>
{{- $path := .Path }}
{{- range .Names }}
<a href="{{ $path }}{{ . }}">{{ . }}</a><br>
{{- end }}
</body>
</html>
`)))

var mimeTypes = map[string]string {
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

func main() {
	flagHttp := flag.String(`http`, ``, `specifies the bind address for the http service`)
	flagIndex := flag.String(`index`, `index.html`, `specifies the name of the default index file`)
	flag.Parse()

	bind := *flagHttp
	if bind == `` {
		bind = os.Getenv(`HTTP_BIND`)
		if bind == `` {
			bind = `localhost:8080`
		}
	}

	connect := bind
	if strings.IndexRune(connect, ':') == 0 {
		if host, err := os.Hostname(); err != nil {
			log.Printf(`hostname: error: %v`, err)
			connect = fmt.Sprintf(`localhost%s`, host, connect)
		} else {
			connect = fmt.Sprintf(`%s%s`, host, connect)
		}
	}
	log.Printf(`go-httpd up: http://%s/`, connect)

	http.ListenAndServe(bind, handler(*flagIndex))
}

func handler(indexName string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodGet {
			end(w, r, start, &Response{Code: http.StatusMethodNotAllowed})
		} else {
			end(w, r, start, serve(r, indexName))
		}
	})
}

func end(w http.ResponseWriter, r *http.Request, start time.Time, response *Response) {
	if response.Headers != nil {
		for key, value := range response.Headers {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.Code)

	if response.Body == nil {
		response.Body = strings.NewReader(fmt.Sprintf(`%d %s%s`, response.Code, http.StatusText(response.Code), EOL))
	}

	written, err := io.Copy(w, response.Body)
	if err != nil {
		if response.Err == nil {
			response.Err = fmt.Errorf(`copy: %v`, err)
		} else {
			response.Err = fmt.Errorf(`copy: %v; %w`, response.Err)
		}
	}

	var result string
	if response.Err == nil {
		result = fmt.Sprintf(`%d %s %d byte(s)`, response.Code, time.Now().Sub(start).String(), written)
	} else {
		result = fmt.Sprintf(`%d %s %d byte(s); error: %v`, response.Code, time.Now().Sub(start).String(), written, response.Err)
	}

	log.Printf("%s %s %s %s\n -> %s", start.Format(time.RFC3339), r.RemoteAddr, r.Method, r.URL.String(), result)
}

func serve(r *http.Request, indexName string) *Response {
	path, err := url.PathUnescape(r.URL.String())
	if err != nil {
		return &Response{Code: http.StatusBadRequest, Err: err}
	}
	path = vpath(path)

	switch path {
	case `favicon.ico`:
	case `robots.txt`:
		return &Response{Code: http.StatusNotFound}
	}

	if index := strings.IndexRune(path, '?'); index >= 0 {
		path = path[0:index]
	}

	if path == `` {
		return serveDir(path, indexName)
	}

	if fileinfo, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return &Response{Code: http.StatusNotFound}
		} else {
			return &Response{Code: http.StatusInternalServerError, Err: err}
		}
	} else if fileinfo.IsDir() {
		return serveDir(path, indexName)
	}

	return serveFile(path)
}

func serveDir(path string, indexName string) *Response {
	dir := path
	if dir == `` {
		dir = `.`
	}

	if indexName != `` {
		name := fmt.Sprintf(`%s/%s`, dir, indexName)

		fileinfo, err := os.Stat(name)
		if err == nil && !fileinfo.IsDir() {
			return serveFile(name)
		}
		if err != nil && !os.IsNotExist(err) {
			return &Response{Code: http.StatusInternalServerError, Err: err}
		}
	}

	list, err := ioutil.ReadDir(dir)
	if err != nil {
		return &Response{Code: http.StatusInternalServerError, Err: err}
	}

	names := []string{}
	if path == `` {
		path = `/`
	} else {
		names = append(names, `..`)
		path = `/` + path + `/`
	}
	for _, info := range list {
		names = append(names, info.Name())
	}
	sort.Strings(names)

	body := bytes.NewBuffer([]byte{})
	if err := htmlIndex.Execute(body, struct {
		Path  string
		Names []string
	}{
		Path:  path,
		Names: names,
	}); err != nil {
		return &Response{Code: http.StatusInternalServerError, Err: err}
	}

	headers := map[string]string{}
	if mimeType, found := mimeTypes[`html`]; found {
		headers[`Content-Type`] = mimeType
	}

	return &Response{Code: http.StatusOK, Headers: headers, Body: body}
}

func serveFile(path string) *Response {
	if file, err := os.Open(path); err != nil {
		return &Response{Code: http.StatusInternalServerError, Err: err}
	} else {
		headers := map[string]string{}
		if index := strings.LastIndex(path, `.`); index >= 0 && index < len(path)-1 {
			if mimeType, found := mimeTypes[path[index+1:]]; found {
				headers[`Content-Type`] = mimeType
			}
		}
		return &Response{Code: http.StatusOK, Headers: headers, Body: file}
	}
}

func vpath(source string) string {
	vpath := []string{}
	for _, name := range strings.Split(source, `/`) {
		switch name {
		case ``:
			continue

		default:
			name = strings.ReplaceAll(name, "\x00", ``)
			if len(name) > 0 {
				vpath = append(vpath, name)
			}
		}
	}
	return strings.Join(vpath, `/`)
}
