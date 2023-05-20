package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"ccc-ultra/internal/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Flags struct {
	Compression     *int
	FaviconIco      *string
	faviconBuf      []byte
	faviconType     string
	Hostname        *string
	Http            *string
	httpEnabled     bool
	Https           *string
	httpsEnabled    bool
	HttpsOnly       *bool
	HttpsTlsCert    *string
	HttpsTlsKey     *string
	Index           *string
	indexBuf        []byte
	Prometheus      *bool
	TimeoutIdle     *time.Duration
	TimeoutRead     *time.Duration
	TimeoutRequest  *time.Duration
	TimeoutShutdown *time.Duration
	TimeoutWrite    *time.Duration
	RobotsTxt       *string
	robotsBuf       []byte
	Root            *string
}

type Service struct {
	scheme  string
	address string
	server  *http.Server
}
type Services []Service

type Response struct {
	Code    int
	Headers map[string]string
	Body    io.Reader
	Err     error
}

const (
	defHttpAddress = `localhost:8080`
	envHttpAddress = `ULTRA_HTTP`
)
const (
	defHttpsAddress = `localhost:8443`
	envHttpsAddress = `ULTRA_HTTPS`
)

// FIXME: turn this into a flag
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

// FIXME: turn this into a flag
var mimeTypes = map[string]string{
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
	hostname, err := os.Hostname()
	if err != nil {
		fatal(`hostname: error: %s`, err)
	}
	fmt.Printf("ultra %s\n", hostname)

	flags := Flags{
		Compression:     flag.Int(`compression`, 5, `specifies the compression level`),
		FaviconIco:      flag.String(`favicon-ico`, ``, `specifies the file to use for favicon.ico`),
		Hostname:        flag.String(`hostname`, hostname, `specifies the hostname`),
		Http:            flag.String(`http`, ``, `specifies the bind address for the http service`),
		Https:           flag.String(`https`, ``, `specifies the bind address for the https service`),
		HttpsOnly:       flag.Bool(`https-only`, false, `http requests will be redirected to the https server`),
		HttpsTlsCert:    flag.String(`https-tls-cert`, ``, `specifies the location of the server tls certificate`),
		HttpsTlsKey:     flag.String(`https-tls-key`, ``, `specifies the location of the server tls key`),
		Index:           flag.String(`index`, `index.html`, `specifies the name of the default index file`),
		Prometheus:      flag.Bool(`prometheus`, false, `enable prometheus`),
		TimeoutIdle:     flag.Duration(`timeout-idle`, 5*time.Second, `specifies the request idle timeout duration`),
		TimeoutRead:     flag.Duration(`timeout-read`, 10*time.Second, `specifies the request read timeout duration`),
		TimeoutRequest:  flag.Duration(`timeout-request`, 60*time.Second, `specifies the request timeout duration`),
		TimeoutShutdown: flag.Duration(`timeout-shutdown`, 5*time.Second, `specifies the shutdown timeout`),
		TimeoutWrite:    flag.Duration(`timeout-write`, 60*time.Second, `specifies the request write timeout duration`),
		RobotsTxt:       flag.String(`robots-txt`, ``, `specifies the file to use for robots.txt`),
		Root:            flag.String(`root`, `.`, `specifies the root directory`),
	}
	flag.Parse()

	{
		first := func(list ...string) *string {
			for _, value := range list {
				if value != `` {
					return &value
				}
			}
			return nil
		}
		flags.Http = first(*flags.Http, os.Getenv(envHttpAddress), defHttpAddress)
		flags.Https = first(*flags.Https, os.Getenv(envHttpsAddress), defHttpsAddress)
	}

	// calculate meta flags
	flags.httpEnabled = flags.Http != nil && *flags.Http != ``
	flags.httpsEnabled = flags.Https != nil && *flags.Https != `` && *flags.HttpsTlsCert != `` && *flags.HttpsTlsKey != ``

	// validate settings
	if *flags.Root == `` {
		fatal(`-root must not be empty`)
	}
	if *flags.HttpsOnly {
		if !flags.httpsEnabled {
			fatal(`-https-only requires https to be enabled`)
		}
	}

	// load buffers
	{
		var err error
		if *flags.FaviconIco != `` {
			flags.faviconBuf, err = os.ReadFile(*flags.FaviconIco)
			if err != nil {
				fatal(`load: error: %s`, err)
			}
			image, format, err := image.Decode(bytes.NewBuffer(flags.faviconBuf))
			if err != nil {
				fatal(`decode: error: %s`, err)
			}
			bounds := image.Bounds()
			height := bounds.Max.Y - bounds.Min.Y
			width := bounds.Max.X - bounds.Min.X
			flags.faviconType = `image/` + format
			fmt.Printf("load favicon.ico %s %d (%dx%d; %s)\n", *flags.FaviconIco, len(flags.faviconBuf), width, height, flags.faviconType)
		}
		if *flags.RobotsTxt != `` {
			flags.robotsBuf, err = os.ReadFile(*flags.RobotsTxt)
			if err != nil {
				fatal(`load: error: %s`, err)
			}
			fmt.Printf("load robots.txt %s %d\n", *flags.RobotsTxt, len(flags.robotsBuf))
		}
	}

	// FIXME: add flag to just auto load favicon, index.html, robots.txt from cwd

	// determine root
	if *flags.Root != `.` {
		info, err := os.Stat(*flags.Root)
		if err != nil {
			fatal(`stat: error: %s`, err)
		}
		if info.IsDir() {
			if err := os.Chdir(*flags.Root); err != nil {
				fatal(`chdir: error: %s`, err)
			}
			fmt.Printf("chdir %s\n", *flags.Root)
		} else {
			flags.indexBuf, err = os.ReadFile(*flags.Root)
			if err != nil {
				fatal(`load: error: %s`, err)
			}
			fmt.Printf("load root %s %d\n", *flags.Root, len(flags.indexBuf))
		}
	}

	// services
	var services Services

	// http
	if flags.httpEnabled {
		router := chi.NewRouter().With(middleware.Always(*flags.TimeoutRequest, *flags.Compression)...)
		if *flags.Prometheus {
			router.Use(middleware.Prometheus(`http`))
		}
		var root http.Handler
		if *flags.HttpsOnly {
			root = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(`Connection`, `close`)
				// FIXME: need a solid url generator
				http.Redirect(w, r, `https://`+r.Host+r.URL.String(), http.StatusMovedPermanently)
			})
		} else {
			root = flags.handler()
		}
		router.Mount(`/`, root)
		router.Route(`/^`, func(router chi.Router) {
			if *flags.Prometheus {
				router.Mount(`/metrics`, promhttp.Handler())
			}
		})
		services = append(services, Service{scheme: `http`, server: &http.Server{
			Addr:         *flags.Http,
			Handler:      router,
			IdleTimeout:  *flags.TimeoutIdle,
			ReadTimeout:  *flags.TimeoutRead,
			WriteTimeout: *flags.TimeoutWrite,
		}})
	} else {
		fmt.Printf("http.disabled\n")
	}

	// https
	if flags.httpsEnabled {
		cert, err := tls.LoadX509KeyPair(*flags.HttpsTlsCert, *flags.HttpsTlsKey)
		if err != nil {
			fatal(`load key pair: error: %s`, err)
		}
		tlsConfig := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			Certificates:             []tls.Certificate{cert},
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
		router := chi.NewRouter().With(middleware.Always(*flags.TimeoutRequest, *flags.Compression)...)
		if *flags.Prometheus {
			router.Use(middleware.Prometheus(`https`))
		}
		var root http.Handler
		root = flags.handler()
		router.Mount(`/`, root)
		router.Route(`/^`, func(router chi.Router) {
			if *flags.Prometheus {
				router.Mount(`/metrics`, promhttp.Handler())
			}
		})
		services = append(services, Service{scheme: `https`, server: &http.Server{
			Addr:         *flags.Https,
			Handler:      router,
			TLSConfig:    tlsConfig,
			IdleTimeout:  *flags.TimeoutIdle,
			ReadTimeout:  *flags.TimeoutRead,
			WriteTimeout: *flags.TimeoutWrite,
		}})
	} else {
		fmt.Printf("https.disabled\n")
	}

	// start services
	for _, service := range services {
		service := service
		go func() {
			connect := service.server.Addr
			if strings.IndexRune(connect, ':') == 0 {
				connect = fmt.Sprintf(`%s%s`, hostname, connect)
			}
			features := []string{}
			if service.server.TLSConfig != nil {
				features = append(features, `(tls`)
			}
			if *flags.Prometheus {
				features = append(features, `(prometheus`)
			}
			options := ``
			if len(features) > 0 {
				options = strings.Join(features, ` `)
			}
			fmt.Printf("%s.up %s://%s/ %s\n", service.scheme, service.scheme, connect, options)
			var err error
			if service.server.TLSConfig == nil {
				err = service.server.ListenAndServe()
			} else {
				err = service.server.ListenAndServeTLS(``, ``)
			}
			if err != nil && err != http.ErrServerClosed {
				fmt.Printf("%s.serve: error: %s\n", service.scheme, err)
			} else {
				fmt.Printf("%s.down\n", service.scheme)
			}
		}()
	}

	// into the beyond
	<-func() <-chan os.Signal {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		return signals
	}()

	// stop services
	wg := sync.WaitGroup{}
	for _, service := range services {
		service := service
		wg.Add(1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), *flags.TimeoutShutdown)
			defer cancel()
			if err := service.server.Shutdown(ctx); err != nil {
				fmt.Printf("%s.shutdown: error: %s\n", service.scheme, err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func (flags Flags) handler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			response := flags.handle(w, r)
			if response.Headers != nil {
				for key, value := range response.Headers {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(response.Code)

			if response.Body == nil {
				response.Body = strings.NewReader(fmt.Sprintf("%d %s\r\n", response.Code, http.StatusText(response.Code)))
			}
			_, err := io.Copy(w, response.Body)
			if err != nil {
				if response.Err == nil {
					response.Err = fmt.Errorf(`copy: error: %v`, err)
				} else {
					response.Err = fmt.Errorf(`copy: error: %v; %w`, err, response.Err)
				}
			}
		default:
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
	})
}

func (flags Flags) handle(w http.ResponseWriter, r *http.Request) *Response {
	path, err := url.PathUnescape(r.URL.String())
	if err != nil {
		return &Response{Code: http.StatusBadRequest, Err: err}
	}
	if path[0] == '/' {
		path = path[1:]
	}
	if index := strings.IndexRune(path, '?'); index >= 0 {
		path = path[0:index]
	}
	switch path {
	case ``:
		if flags.indexBuf != nil {
			return &Response{
				Code: http.StatusOK,
				Body: bytes.NewReader(flags.indexBuf),
				Headers: map[string]string{
					`content-type`: `text/html`,
				},
			}
		}
		return flags.dir(path)
	case `favicon.ico`:
		if flags.faviconBuf != nil {
			return &Response{
				Code: http.StatusOK,
				Body: bytes.NewReader(flags.faviconBuf),
				Headers: map[string]string{
					`content-type`: flags.faviconType,
				},
			}
		}
		return &Response{Code: http.StatusNotFound}
	case `robots.txt`:
		if flags.robotsBuf != nil {
			return &Response{
				Code: http.StatusOK,
				Body: bytes.NewReader(flags.robotsBuf),
				Headers: map[string]string{
					`content-type`: `text/plain`,
				},
			}
		}
		return &Response{Code: http.StatusNotFound}
	}
	if flags.indexBuf != nil {
		return &Response{Code: http.StatusNotFound}
	}
	if fileinfo, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return &Response{Code: http.StatusNotFound}
		} else {
			return &Response{Code: http.StatusInternalServerError, Err: err}
		}
	} else if fileinfo.IsDir() {
		return flags.dir(path)
	} else {
		return flags.file(path)
	}
}

func (flags Flags) dir(path string) *Response {
	dir := path
	if dir == `` {
		dir = `.`
	}

	if *flags.Index != `` {
		name := fmt.Sprintf(`%s/%s`, dir, *flags.Index)
		fileinfo, err := os.Stat(name)
		if err == nil && !fileinfo.IsDir() {
			return flags.file(name)
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

func (flags Flags) file(path string) *Response {
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

func fatal(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
	os.Exit(1)
}
