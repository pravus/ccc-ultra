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
	"log"
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

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ultra/internal/control"
	"ultra/internal/handler"
	"ultra/internal/middleware"
	"ultra/internal/oe"
	"ultra/internal/volatile"
)

// FIXME: add check for ez mode that root is a directory only
// FIXME: implement CtrlTlsCert && CtrlTlsKey
// FIXME: need some way to implement timeouts for reverse proxies
// FIXME: should vfs be optional?
// FIXME: it should be a wrapped interface

const (
	envLogLevel = `ULTRA_LOG_LEVEL`
)
const (
	envBearerToken = `ULTRA_BEARER_TOKEN`
)
const (
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

type Flags struct {
	BearerToken        *string
	Compression        *int
	Croesus            *bool
	Ctrl               *string
	CtrlLogger         *bool
	ctrlEnabled        bool
	Ez                 *bool
	FaviconIco         *string
	Home               *string
	HomeDir            *string
	HomePrefix         *string
	Hostname           *string
	Http               *string
	httpEnabled        bool
	Https              *string
	httpsEnabled       bool
	HttpsHsts          *time.Duration
	HttpsOnly          *bool
	HttpsTlsCert       *string
	HttpsTlsKey        *string
	Index              *string
	LogLevel           *string
	ofsEnabled         bool
	Prometheus         *bool
	ReverseProxies     ReverseProxiesFlag
	ReverseProxiesTls  ReverseProxiesFlag
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

func main() {
	// logger
	logger := control.Logger(volatile.NewLogger(control.LogLevelBoot))

	// boot
	// FIXME: re-scope this to just flags somehow
	hostname, err := os.Hostname()
	if err != nil {
		logger.Fatal(`hostname: error: %s`, err)
	}

	// flags
	flags := Flags{
		BearerToken:        flag.String(`bearer-token`, ``, `specifies the bearer token for authenticated endpoints`),
		Compression:        flag.Int(`compression`, 5, `specifies the compression level`),
		Croesus:            flag.Bool(`croesus`, false, `enable payments`),
		Ctrl:               flag.String(`ctrl`, ``, `specifies the bind address for the ctrl service`),
		CtrlLogger:         flag.Bool(`ctrl-logger`, false, `enable ctrl logging`),
		Ez:                 flag.Bool(`ez`, false, `auto loads the index, favicon.ico, and robots.txt from the root`),
		FaviconIco:         flag.String(`favicon-ico`, ``, `specifies the file to use for favicon.ico`),
		Home:               flag.String(`home`, ``, `specifies the root directory for user homes`),
		HomeDir:            flag.String(`home-dir`, `public_html`, `specifies the public directory for user homes`),
		HomePrefix:         flag.String(`home-prefix`, `@`, `specifies the prefix to use for user homes`),
		Hostname:           flag.String(`hostname`, hostname, `specifies the hostname`),
		Http:               flag.String(`http`, ``, `specifies the bind address for the http service`),
		Https:              flag.String(`https`, ``, `specifies the bind address for the https service`),
		HttpsHsts:          flag.Duration(`https-hsts`, time.Duration(0), `specifies the value used for the max-age parameter in the HSTS header (enables -https-only)`),
		HttpsOnly:          flag.Bool(`https-only`, false, `http requests will be redirected to the https server`),
		HttpsTlsCert:       flag.String(`https-tls-cert`, ``, `specifies the location of the server tls certificate`),
		HttpsTlsKey:        flag.String(`https-tls-key`, ``, `specifies the location of the server tls key`),
		Index:              flag.String(`index`, `index.html`, `specifies the name of the default index file`),
		LogLevel:           flag.String(`log-level`, ``, `specifies the logging level`),
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
	flag.Var(&flags.ReverseProxiesTls, `reverse-proxy-tls`, `specifies a tls reverse proxy`)
	flag.Parse()

	// env
	{
		first := func(list ...string) string {
			for _, value := range list {
				if value != `` {
					return value
				}
			}
			return ``
		}
		*flags.BearerToken = first(*flags.BearerToken, os.Getenv(envBearerToken))
		*flags.Ctrl = first(*flags.Ctrl, os.Getenv(envCtrlAddress))
		*flags.Http = first(*flags.Http, os.Getenv(envHttpAddress), defHttpAddress)
		*flags.Https = first(*flags.Https, os.Getenv(envHttpsAddress), defHttpsAddress)
		*flags.LogLevel = first(*flags.LogLevel, os.Getenv(envHttpsAddress), `info`)
	}

	// inspect
	flags.ctrlEnabled = *flags.Ctrl != ``
	flags.httpEnabled = *flags.Http != ``
	flags.httpsEnabled = *flags.Https != `` && *flags.HttpsTlsCert != `` && *flags.HttpsTlsKey != ``

	// validate
	if *flags.LogLevel != `` {
		logger.SetLevelFromString(*flags.LogLevel)
	}
	if *flags.Root == `` {
		logger.Fatal(`-root must not be empty`)
	}
	if *flags.HttpsHsts > time.Duration(0) {
		*flags.HttpsOnly = true
	}
	if *flags.HttpsOnly {
		if !flags.httpsEnabled {
			logger.Fatal(`-https-only requires https to be enabled`)
		}
		if len(flags.ReverseProxies) > 0 {
			logger.Fatal(`-reverse-proxy cannot be used with -https-only`)
		}
	}
	if len(flags.ReverseProxiesTls) > 0 {
		if !flags.httpsEnabled {
			logger.Fatal(`-reverse-proxy-tls requires https to be enabled`)
		}
	}

	// control plane
	logger.Audit(`ultra.boot %s logging.level=%s`, *flags.Hostname, logger.Level().String())

	// wand
	wand := volatile.Magic()

	// vfs
	vfs := volatile.NewFsDriver()

	// ofs
	ofs := oe.NewFsDriver(*flags.Root, *flags.Index, wand)

	// root
	if *flags.Root == `.` {
		flags.ofsEnabled = true
	} else {
		info, err := os.Stat(*flags.Root)
		if err != nil {
			logger.Fatal(`ofs.stat error: %s`, err)
		}
		if info.IsDir() {
			if err := os.Chdir(*flags.Root); err != nil {
				logger.Fatal(`ofs.chdir error: %s`, err)
			}
			flags.ofsEnabled = true
			logger.Info(`ofs.chdir %s`, *flags.Root)
		} else {
			if err := vfs.Load(`/`, *flags.Root, func(data []byte) (string, error) {
				logger.Info(`vfs.load root %s %d`, *flags.Root, len(data))
				return wand.Zap(*flags.Root), nil
			}); err != nil {
				logger.Fatal(`vfs.load error: %s`, err)
			}
		}
	}

	// other
	if *flags.Ez {
		flags.ofsEnabled = false
		if err := vfs.Load(`/`, *flags.Index, func(data []byte) (string, error) {
			logger.Info(`vfs.load root %s %d`, *flags.Index, len(data))
			return wand.Zap(*flags.Index), nil
		}); err != nil {
			logger.Fatal(`vfs.load error: %s`, err)
		}
		ptr := func(source string) *string {
			return &source
		}
		if *flags.FaviconIco == `` {
			if _, err := os.Stat(`favicon.ico`); err != nil {
				if !os.IsNotExist(err) {
					logger.Fatal(`ofs.stat error: %s`, err)
				}
			} else {
				flags.FaviconIco = ptr(`favicon.ico`)
			}
		}
		if *flags.RobotsTxt == `` {
			if _, err := os.Stat(`robots.txt`); err != nil {
				if !os.IsNotExist(err) {
					logger.Fatal(`ofs.stat error: %s`, err)
				}
			} else {
				flags.RobotsTxt = ptr(`robots.txt`)
			}
		}
	}
	if *flags.FaviconIco != `` {
		if err := vfs.Load(`/favicon.ico`, *flags.FaviconIco, func(data []byte) (string, error) {
			image, format, err := image.Decode(bytes.NewBuffer(data))
			if err != nil {
				return ``, err
			}
			bounds := image.Bounds()
			height := bounds.Max.Y - bounds.Min.Y
			width := bounds.Max.X - bounds.Min.X
			logger.Info(`vfs.load favicon.ico %s %d (%dx%d; %s)`, *flags.FaviconIco, len(data), width, height, format)
			return `image/` + format, nil
		}); err != nil {
			logger.Fatal(`vfs.load error: %s`, err)
		}
	}
	if *flags.RobotsTxt != `` {
		if err := vfs.Load(`/robots.txt`, *flags.RobotsTxt, func(data []byte) (string, error) {
			logger.Info(`vfs.load robots.txt %s %d`, *flags.RobotsTxt, len(data))
			return `text/plain`, nil
		}); err != nil {
			logger.Fatal(`vfs.load error: %s`, err)
		}
	}

	// not found
	_404 := handler.Cocytus
	_405 := handler.Manus
	if *flags.Croesus {
		_404 = handler.Mammon
		_405 = handler.Mammon
	}

	// services
	var services Services

	// http
	{
		label := `http`
		scheme := `http`
		features := []string{}
		if flags.httpEnabled {
			metrics := middleware.Identity
			if *flags.Prometheus {
				features = append(features, `prometheus`)
				metrics = middleware.Prometheus(label)
			}
			formatter := volatile.NewLogFormatter(label, logger)
			router := chi.NewRouter()
			router.NotFound(_404)
			router.Mount(`/`, func() http.Handler {
				if *flags.HttpsOnly {
					features = append(features, `https-only`)
					return http.Handler(handler.Gehenna)
				}
				root := http.Handler(_404)
				if flags.ofsEnabled {
					features = append(features, `ofs`)
					root = middleware.NewFs(ofs, logger)(root)
				}
				{
					features = append(features, `vfs`)
					root = middleware.NewFs(vfs, logger)(root)
				}
				root = middleware.MethodFilter([]string{http.MethodGet}, _405)(root)
				root = metrics(root)
				root = middleware.Standard(label, root, formatter, *flags.TimeoutRequest, *flags.Compression)
				return root
			}())
			if *flags.Home != `` {
				// FIXME: consider redirect if path doesn't end with `/` to force directory mode in browser (relative paths)
				features = append(features, `home`)
				hfs := oe.NewFsDriver(*flags.Home, *flags.Index, wand)
				router.Route(`/`+*flags.HomePrefix+`{user}`, func(router chi.Router) {
					root := http.Handler(_404)
					root = middleware.NewHome(hfs, *flags.HomePrefix, *flags.HomeDir, logger)(root)
					root = middleware.MethodFilter([]string{http.MethodGet}, _405)(root)
					root = metrics(root)
					root = middleware.Standard(label, root, formatter, *flags.TimeoutRequest, *flags.Compression)
					router.Mount(`/`, root)
				})
			}
			if len(flags.ReverseProxies) > 0 {
				features = append(features, `reverse-proxy`)
				for _, proxy := range flags.ReverseProxies {
					handler := http.Handler(httputil.NewSingleHostReverseProxy(proxy.Url))
					handler = metrics(handler)
					handler = middleware.ReverseProxy(handler, *flags.ReverseProxyLogger, formatter)
					router.Mount(proxy.Mount, handler)
					logger.Info(`%s.mount reverse-proxy %s %s`, label, proxy.Mount, proxy.Url)
				}
			}
			sort.Strings(features)
			services = append(services, Service{label: label, scheme: scheme, features: features, server: &http.Server{
				Addr:         *flags.Http,
				Handler:      router,
				IdleTimeout:  *flags.TimeoutIdle,
				ReadTimeout:  *flags.TimeoutRead,
				WriteTimeout: *flags.TimeoutWrite,
				// FIXME: DisableGeneralOptionsHandler?
				ErrorLog: log.New(control.NewHttpLogWriter(logger), ``, 0),
			}})
		} else {
			logger.Info(`%s.disabled`, label)
		}
	}

	// https
	{
		label := `https`
		scheme := `https`
		features := []string{`tls`}
		if flags.httpsEnabled {
			metrics := middleware.Identity
			if *flags.Prometheus {
				features = append(features, `prometheus`)
				metrics = middleware.Prometheus(label)
			}
			formatter := volatile.NewLogFormatter(label, logger)
			cert, err := tls.LoadX509KeyPair(*flags.HttpsTlsCert, *flags.HttpsTlsKey)
			if err != nil {
				logger.Fatal(`https.key-pair: error: %s`, err)
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
			router := chi.NewRouter()
			router.NotFound(_404)
			router.Mount(`/`, func() http.Handler {
				root := http.Handler(_404)
				if flags.ofsEnabled {
					features = append(features, `ofs`)
					root = middleware.NewFs(ofs, logger)(root)
				}
				{
					features = append(features, `vfs`)
					root = middleware.NewFs(vfs, logger)(root)
				}
				root = middleware.MethodFilter([]string{http.MethodGet}, _405)(root)
				root = metrics(root)
				root = middleware.Standard(label, root, formatter, *flags.TimeoutRequest, *flags.Compression)
				if *flags.HttpsHsts > time.Duration(0) {
					features = append(features, `hsts`)
					root = middleware.Hsts(*flags.HttpsHsts)(root)
				}
				return root
			}())
			if *flags.Home != `` {
				// FIXME: consider redirect if path doesn't end with `/` to force directory mode in browser (relative paths)
				features = append(features, `home`)
				hfs := oe.NewFsDriver(*flags.Home, *flags.Index, wand)
				router.Route(`/`+*flags.HomePrefix+`{user}`, func(router chi.Router) {
					root := http.Handler(_404)
					root = middleware.NewHome(hfs, *flags.HomePrefix, *flags.HomeDir, logger)(root)
					root = middleware.MethodFilter([]string{http.MethodGet}, _405)(root)
					root = metrics(root)
					root = middleware.Standard(label, root, formatter, *flags.TimeoutRequest, *flags.Compression)
					router.Mount(`/`, root)
				})
			}
			if len(flags.ReverseProxiesTls) > 0 {
				features = append(features, `reverse-proxy`)
				for _, proxy := range flags.ReverseProxiesTls {
					handler := http.Handler(httputil.NewSingleHostReverseProxy(proxy.Url))
					handler = metrics(handler)
					handler = middleware.ReverseProxy(handler, *flags.ReverseProxyLogger, formatter)
					router.Mount(proxy.Mount, handler)
					logger.Info(`%s.mount reverse-proxy %s %s`, label, proxy.Mount, proxy.Url)
				}
			}
			sort.Strings(features)
			services = append(services, Service{label: label, scheme: scheme, features: features, server: &http.Server{
				Addr:         *flags.Https,
				Handler:      router,
				TLSConfig:    tlsConfig,
				IdleTimeout:  *flags.TimeoutIdle,
				ReadTimeout:  *flags.TimeoutRead,
				WriteTimeout: *flags.TimeoutWrite,
				// FIXME: DisableGeneralOptionsHandler?
				ErrorLog: log.New(control.NewHttpLogWriter(logger), ``, 0),
			}})
		} else {
			logger.Info(`%s.disabled`, label)
		}
	}

	// ctrl
	{
		label := `ctrl`
		scheme := `http`
		features := []string{}
		if flags.ctrlEnabled {
			metrics := middleware.Identity
			if *flags.Prometheus {
				features = append(features, `prometheus`)
				metrics = middleware.Prometheus(label)
			}
			formatter := volatile.NewLogFormatter(label, logger)
			router := chi.NewRouter()
			router.NotFound(_404)
			router.Mount(`/`, func() http.Handler {
				root := http.Handler(_404)
				if *flags.BearerToken != `` {
					features = append(features, `bearer`)
					root = middleware.Bearer(*flags.BearerToken, false, nil, logger)(root)
				}
				root = middleware.Control(root, *flags.CtrlLogger, formatter)
				root = metrics(root)
				return root
			}())
			// NOTE: bearer doesn't get wrapped for paths under here because the router isn't wrapped
			router.Route(`/log`, func(router chi.Router) {
				features = append(features, `log`)
				handler := http.Handler(handler.Log(logger))
				if *flags.BearerToken != `` {
					handler = middleware.Bearer(*flags.BearerToken, false, nil, logger)(handler)
				}
				handler = middleware.Control(handler, *flags.CtrlLogger, formatter)
				handler = metrics(handler)
				router.Mount(`/`, handler)
			})
			router.Route(`/metrics`, func(router chi.Router) {
				features = append(features, `metrics`)
				if *flags.Prometheus {
					handler := http.Handler(promhttp.Handler())
					if *flags.BearerToken != `` {
						handler = middleware.Bearer(*flags.BearerToken, false, nil, logger)(handler)
					}
					handler = middleware.Control(handler, *flags.CtrlLogger, formatter)
					handler = metrics(handler)
					router.Mount(`/prometheus`, handler)
				}
			})
			router.Route(`/vfs`, func(router chi.Router) {
				features = append(features, `vfs`)
				handler := http.Handler(volatile.VfsHandler(vfs, logger))
				if *flags.BearerToken != `` {
					handler = middleware.Bearer(*flags.BearerToken, false, nil, logger)(handler)
				}
				handler = middleware.Control(handler, *flags.CtrlLogger, formatter)
				handler = metrics(handler)
				router.Mount(`/`, handler)
			})
			sort.Strings(features)
			services = append(services, Service{label: label, scheme: scheme, features: features, server: &http.Server{
				Addr:         *flags.Ctrl,
				Handler:      router,
				IdleTimeout:  *flags.TimeoutIdle,
				ReadTimeout:  *flags.TimeoutRead,
				WriteTimeout: *flags.TimeoutWrite,
				// FIXME: DisableGeneralOptionsHandler?
				ErrorLog: log.New(control.NewHttpLogWriter(logger), ``, 0),
			}})
		} else {
			logger.Info(`%s.disabled`, label)
		}
	}

	// start
	for _, service := range services {
		service := service
		go func() {
			connect := service.server.Addr
			if strings.IndexRune(connect, ':') == 0 {
				connect = *flags.Hostname + connect
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
