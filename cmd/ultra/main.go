package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"ultra/internal/handler"
	"ultra/internal/middleware"
	"ultra/internal/volatile"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Flags struct {
	BearerToken        *string
	Compression        *int
	Ctrl               *string
	CtrlLogger         *bool
	ctrlEnabled        bool
	FaviconIco         *string
	Hostname           *string
	Http               *string
	httpEnabled        bool
	Https              *string
	httpsEnabled       bool
	HttpsOnly          *bool
	HttpsTlsCert       *string
	HttpsTlsKey        *string
	Index              *string
	LogLevel           *string
	ofsEnabled         bool
	Prometheus         *bool
	ReverseProxies     ReverseProxiesFlag
	ReverseProxyLogger *bool
	TimeoutIdle        *time.Duration
	TimeoutRead        *time.Duration
	TimeoutRequest     *time.Duration
	TimeoutShutdown    *time.Duration
	TimeoutWrite       *time.Duration
	RobotsTxt          *string
	Root               *string
}

type ReverseProxy struct {
	Mount string
	Url   *url.URL
}

type ReverseProxiesFlag []ReverseProxy

func (flag ReverseProxiesFlag) String() string {
	if len(flag) <= 0 {
		return ``
	}
	proxies := make([]string, len(flag))
	for i := 0; i < len(flag); i++ {
		proxies[i] = flag[i].Mount + `=` + flag[i].Url.String()
	}
	return strings.Join(proxies, `, `)
}

func (flag *ReverseProxiesFlag) Set(value string) error {
	if index := strings.Index(value, `=`); value[0] != '/' || index < 1 || len(value[index+1:]) <= 0 {
		return fmt.Errorf(`invalid reverse proxy definition "%s"`, value)
	} else if url, err := url.Parse(value[index+1:]); err != nil {
		return err
	} else {
		*flag = append(*flag, ReverseProxy{Mount: value[0:index], Url: url})
		return nil
	}
}

type Service struct {
	label    string
	scheme   string
	address  string
	features []string
	server   *http.Server
}
type Services []Service

const (
	envBearerToken = `ULTRA_BEARER_TOKEN`
)
const (
	defCtrlAddress = `localhost:8448`
	envCtrlAddress = `ULTRA_CTRL`
)
const (
	defHttpAddress = `localhost:8080`
	envHttpAddress = `ULTRA_HTTP`
)
const (
	defHttpsAddress = `localhost:8443`
	envHttpsAddress = `ULTRA_HTTPS`
)

func main() {
	// logger
	logger := volatile.NewLogger(volatile.LogLevelInfo)

	// boot
	hostname, err := os.Hostname()
	if err != nil {
		logger.Fatal(`hostname: error: %s`, err)
	}
	logger.Info(`ultra %s`, hostname)

	// flags
	flags := Flags{
		BearerToken:        flag.String(`bearer-token`, ``, `specifies the bearer token for authenticated endpoints`),
		Compression:        flag.Int(`compression`, 5, `specifies the compression level`),
		Ctrl:               flag.String(`ctrl`, ``, `specifies the bind address for the ctrl service`),
		CtrlLogger:         flag.Bool(`ctrl-logger`, false, `enable ctrl logging`),
		FaviconIco:         flag.String(`favicon-ico`, ``, `specifies the file to use for favicon.ico`),
		Hostname:           flag.String(`hostname`, hostname, `specifies the hostname`),
		Http:               flag.String(`http`, ``, `specifies the bind address for the http service`),
		Https:              flag.String(`https`, ``, `specifies the bind address for the https service`),
		HttpsOnly:          flag.Bool(`https-only`, false, `http requests will be redirected to the https server`),
		HttpsTlsCert:       flag.String(`https-tls-cert`, ``, `specifies the location of the server tls certificate`),
		HttpsTlsKey:        flag.String(`https-tls-key`, ``, `specifies the location of the server tls key`),
		Index:              flag.String(`index`, `index.html`, `specifies the name of the default index file`),
		LogLevel:           flag.String(`log-level`, `info`, `specifies the logging level`),
		Prometheus:         flag.Bool(`prometheus`, false, `enable prometheus`),
		TimeoutIdle:        flag.Duration(`timeout-idle`, 5*time.Second, `specifies the request idle timeout duration`),
		TimeoutRead:        flag.Duration(`timeout-read`, 10*time.Second, `specifies the request read timeout duration`),
		TimeoutRequest:     flag.Duration(`timeout-request`, 60*time.Second, `specifies the request timeout duration`),
		TimeoutShutdown:    flag.Duration(`timeout-shutdown`, 5*time.Second, `specifies the shutdown timeout`),
		TimeoutWrite:       flag.Duration(`timeout-write`, 60*time.Second, `specifies the response write timeout duration`),
		ReverseProxyLogger: flag.Bool(`reverse-proxy-logger`, false, `enables logging for reverse proxies`),
		RobotsTxt:          flag.String(`robots-txt`, ``, `specifies the file to use for robots.txt`),
		Root:               flag.String(`root`, `.`, `specifies the root directory`),
	}
	flag.Var(&flags.ReverseProxies, `reverse-proxy`, `specifies a reverse proxy`)
	flag.Parse()

	// env
	{
		first := func(list ...string) *string {
			for _, value := range list {
				if value != `` {
					return &value
				}
			}
			return nil
		}

		flags.BearerToken = first(*flags.BearerToken, os.Getenv(envBearerToken))
		flags.Ctrl = first(*flags.Ctrl, os.Getenv(envCtrlAddress), defCtrlAddress)
		flags.Http = first(*flags.Http, os.Getenv(envHttpAddress), defHttpAddress)
		flags.Https = first(*flags.Https, os.Getenv(envHttpsAddress), defHttpsAddress)
	}

	// validate
	flags.ctrlEnabled = flags.Ctrl != nil && *flags.Ctrl != ``
	flags.httpEnabled = flags.Http != nil && *flags.Http != ``
	flags.httpsEnabled = flags.Https != nil && *flags.Https != `` && *flags.HttpsTlsCert != `` && *flags.HttpsTlsKey != ``

	// validate
	if *flags.LogLevel != `` {
		if err := logger.SetLevelFromString(*flags.LogLevel); err != nil {
			logger.Fatal(`log level error: %s`, err)
		}
	}
	if *flags.Root == `` {
		logger.Fatal(`-root must not be empty`)
	}
	if *flags.HttpsOnly {
		if !flags.httpsEnabled {
			logger.Fatal(`-https-only requires https to be enabled`)
		}
	}

	//vfs
	// FIXME: add flag to just auto load favicon, index.html, robots.txt from cwd (-manifest)
	vfs := volatile.NewFs()
	if *flags.FaviconIco != `` {
		if err := vfs.FromFile(`/favicon.ico`, *flags.FaviconIco, func(data []byte) (string, error) {
			image, format, err := image.Decode(bytes.NewBuffer(data))
			if err != nil {
				return ``, err
			}
			bounds := image.Bounds()
			height := bounds.Max.Y - bounds.Min.Y
			width := bounds.Max.X - bounds.Min.X
			logger.Info(`load favicon.ico %s %d (%dx%d; %s)`, *flags.FaviconIco, len(data), width, height, format)
			return `image/` + format, nil
		}); err != nil {
			logger.Fatal(`load error: %s`, err)
		}
	}
	if *flags.RobotsTxt != `` {
		if err := vfs.FromFile(`/robots.txt`, *flags.RobotsTxt, func(data []byte) (string, error) {
			logger.Info(`load robots.txt %s %d`, *flags.RobotsTxt, len(data))
			return `text/plain`, nil
		}); err != nil {
			logger.Fatal(`load error: %s`, err)
		}
	}

	// root
	if *flags.Root == `.` {
		flags.ofsEnabled = true
	} else {
		info, err := os.Stat(*flags.Root)
		if err != nil {
			logger.Fatal(`stat error: %s`, err)
		}
		if info.IsDir() {
			if err := os.Chdir(*flags.Root); err != nil {
				logger.Fatal(`chdir error: %s`, err)
			}
			flags.ofsEnabled = true
			logger.Info(`chdir %s`, *flags.Root)
		} else {
			if err := vfs.FromFile(`/`, *flags.Root, func(data []byte) (string, error) {
				logger.Info(`load root %s %d`, *flags.Root, len(data))
				return `text/html`, nil
			}); err != nil {
				logger.Fatal(`load error: %s`, err)
			}
		}
	}

	// services
	var services Services

	// http
	if flags.httpEnabled {
		features := []string{}
		router := chi.NewRouter().With(middleware.Always(volatile.NewLogFormatter(`http`, logger), *flags.TimeoutRequest, *flags.Compression)...)
		if *flags.Prometheus {
			router.Use(middleware.Prometheus(`http`))
			features = append(features, `prometheus`)
		}
		if vfs.Len() > 0 {
			router.Use(middleware.NewFilesystem(middleware.NewVFSDriver(vfs)))
			features = append(features, `vfs`)
		}
		if flags.ofsEnabled {
			router.Use(middleware.NewFilesystem(middleware.NewOFSDriver(*flags.Index)))
			features = append(features, `ofs`)
		}
		var root http.Handler
		if *flags.HttpsOnly {
			root = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(`Connection`, `close`)
				// FIXME: need a solid url generator
				http.Redirect(w, r, `https://`+r.Host+r.URL.String(), http.StatusMovedPermanently)
			})
			features = append(features, `https-only`)
		} else {
			root = http.HandlerFunc(handler.Cocytus)
		}
		router.Mount(`/`, root)
		if len(flags.ReverseProxies) > 0 {
			for _, proxy := range flags.ReverseProxies {
				router.Mount(proxy.Mount, httputil.NewSingleHostReverseProxy(proxy.Url))
				if !*flags.ReverseProxyLogger {
					logger.Trim(proxy.Mount)
				}
				logger.Info(`http.mount reverse-proxy %s %s`, proxy.Mount, proxy.Url)
			}
			features = append(features, `reverse-proxy`)
		}
		router.NotFound(http.HandlerFunc(handler.Cocytus))
		sort.Strings(features)
		services = append(services, Service{label: `http`, scheme: `http`, features: features, server: &http.Server{
			Addr:         *flags.Http,
			Handler:      router,
			IdleTimeout:  *flags.TimeoutIdle,
			ReadTimeout:  *flags.TimeoutRead,
			WriteTimeout: *flags.TimeoutWrite,
		}})
	} else {
		logger.Info(`http.disabled`)
	}

	// https
	if flags.httpsEnabled {
		features := []string{`tls`}
		cert, err := tls.LoadX509KeyPair(*flags.HttpsTlsCert, *flags.HttpsTlsKey)
		if err != nil {
			logger.Fatal(`load key pair: error: %s`, err)
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
		router := chi.NewRouter().With(middleware.Always(volatile.NewLogFormatter(`https`, logger), *flags.TimeoutRequest, *flags.Compression)...)
		if *flags.Prometheus {
			router.Use(middleware.Prometheus(`https`))
			features = append(features, `prometheus`)
		}
		if vfs.Len() > 0 {
			router.Use(middleware.NewFilesystem(middleware.NewVFSDriver(vfs)))
			features = append(features, `vfs`)
		}
		if flags.ofsEnabled {
			router.Use(middleware.NewFilesystem(middleware.NewOFSDriver(*flags.Index)))
			features = append(features, `ofs`)
		}
		var root http.Handler
		root = http.HandlerFunc(handler.Cocytus)
		router.Mount(`/`, root)
		if len(flags.ReverseProxies) > 0 {
			for _, proxy := range flags.ReverseProxies {
				router.Mount(proxy.Mount, httputil.NewSingleHostReverseProxy(proxy.Url))
				if !*flags.ReverseProxyLogger {
					logger.Trim(proxy.Mount)
				}
				logger.Info(`https.mount reverse-proxy %s %s`, proxy.Mount, proxy.Url)
			}
			features = append(features, `reverse-proxy`)
		}
		router.NotFound(http.HandlerFunc(handler.Cocytus))
		sort.Strings(features)
		services = append(services, Service{label: `https`, scheme: `https`, features: features, server: &http.Server{
			Addr:         *flags.Https,
			Handler:      router,
			TLSConfig:    tlsConfig,
			IdleTimeout:  *flags.TimeoutIdle,
			ReadTimeout:  *flags.TimeoutRead,
			WriteTimeout: *flags.TimeoutWrite,
		}})
	} else {
		logger.Info(`https.disabled`)
	}

	// ctrl
	if flags.ctrlEnabled {
		features := []string{}
		router := chi.NewRouter()
		if flags.BearerToken != nil && *flags.BearerToken != `` {
			router.Use(middleware.Bearer(*flags.BearerToken))
			features = append(features, `bearer`)
		}
		router.Use(middleware.Control(*flags.CtrlLogger)...)
		if *flags.Prometheus {
			router.Use(middleware.Prometheus(`ctrl`))
			features = append(features, `prometheus`)
		}
		router.Route(`/metrics`, func(router chi.Router) {
			if *flags.Prometheus {
				router.Mount(`/prometheus`, promhttp.Handler())
			}
		})
		router.NotFound(http.HandlerFunc(handler.Cocytus))
		sort.Strings(features)
		services = append(services, Service{label: `ctrl`, scheme: `http`, features: features, server: &http.Server{
			Addr:         *flags.Ctrl,
			Handler:      router,
			IdleTimeout:  *flags.TimeoutIdle,
			ReadTimeout:  *flags.TimeoutRead,
			WriteTimeout: *flags.TimeoutWrite,
		}})
	} else {
		logger.Info(`ctrl.disabled`)
	}

	// start
	for _, service := range services {
		service := service
		go func() {
			connect := service.server.Addr
			if strings.IndexRune(connect, ':') == 0 {
				connect = hostname + connect
			}
			features := ``
			if len(service.features) > 0 {
				features = ` ` + strings.Join(service.features, ` `)
			}
			logger.Info(`%s.up %s://%s/%s`, service.label, service.scheme, connect, features)
			var err error
			if service.server.TLSConfig == nil {
				err = service.server.ListenAndServe()
			} else {
				err = service.server.ListenAndServeTLS(``, ``)
			}
			if err != nil && err != http.ErrServerClosed {
				logger.Error(`%s.serve error: %s`, service.label, err)
			} else {
				logger.Info(`%s.down`, service.label)
			}
		}()
	}

	// into the beyond
	<-func(signals chan os.Signal) <-chan os.Signal {
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		return signals
	}(make(chan os.Signal, 1))

	// halt
	wg := sync.WaitGroup{}
	for _, service := range services {
		service := service
		wg.Add(1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), *flags.TimeoutShutdown)
			defer cancel()
			if err := service.server.Shutdown(ctx); err != nil {
				logger.Error(`%s.shutdown error: %s`, service.label, err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
