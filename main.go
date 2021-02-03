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

	return &Response{Code: http.StatusOK, Body: body}
}

func serveFile(path string) *Response {
	if file, err := os.Open(path); err != nil {
		return &Response{Code: http.StatusInternalServerError, Err: err}
	} else {
		return &Response{Code: http.StatusOK, Body: file}
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
