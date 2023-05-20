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
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"ultra/internal/middleware"
	"ultra/internal/volatile"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Flags struct {
	BearerToken     *string
	Compression     *int
	FaviconIco      *string
	Hostname        *string
	Http            *string
	httpEnabled     bool
	Https           *string
	httpsEnabled    bool
	HttpsOnly       *bool
	HttpsTlsCert    *string
	HttpsTlsKey     *string
	Index           *string
	ofsEnabled      bool
	Prometheus      *bool
	TimeoutIdle     *time.Duration
	TimeoutRead     *time.Duration
	TimeoutRequest  *time.Duration
	TimeoutShutdown *time.Duration
	TimeoutWrite    *time.Duration
	RobotsTxt       *string
	Root            *string
}

type Service struct {
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
	defHttpAddress = `localhost:8080`
	envHttpAddress = `ULTRA_HTTP`
)
const (
	defHttpsAddress = `localhost:8443`
	envHttpsAddress = `ULTRA_HTTPS`
)

func main() {
	// FIXME: initialize logger
	// boot
	hostname, err := os.Hostname()
	if err != nil {
		fatal(`hostname: error: %s`, err)
	}
	fmt.Printf("ultra %s\n", hostname)

	// flags
	flags := Flags{
		BearerToken:     flag.String(`bearer-token`, ``, `specifies the bearer token for authenticated endpoints`),
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
		flags.Http = first(*flags.Http, os.Getenv(envHttpAddress), defHttpAddress)
		flags.Https = first(*flags.Https, os.Getenv(envHttpsAddress), defHttpsAddress)
	}

	// validate
	flags.httpEnabled = flags.Http != nil && *flags.Http != ``
	flags.httpsEnabled = flags.Https != nil && *flags.Https != `` && *flags.HttpsTlsCert != `` && *flags.HttpsTlsKey != ``

	if *flags.Root == `` {
		fatal(`-root must not be empty`)
	}
	if *flags.HttpsOnly {
		if !flags.httpsEnabled {
			fatal(`-https-only requires https to be enabled`)
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
			fmt.Printf("load favicon.ico %s %d (%dx%d; %s)\n", *flags.FaviconIco, len(data), width, height, format)
			return `image/` + format, nil
		}); err != nil {
			fatal(`load error: %s`, err)
		}
	}
	if *flags.RobotsTxt != `` {
		if err := vfs.FromFile(`/robots.txt`, *flags.RobotsTxt, func(data []byte) (string, error) {
			fmt.Printf("load robots.txt %s %d\n", *flags.RobotsTxt, len(data))
			return `text/plain`, nil
		}); err != nil {
			fatal(`load error: %s`, err)
		}
	}

	// root
	if *flags.Root == `.` {
		flags.ofsEnabled = true
	} else {
		info, err := os.Stat(*flags.Root)
		if err != nil {
			fatal(`stat error: %s`, err)
		}
		if info.IsDir() {
			if err := os.Chdir(*flags.Root); err != nil {
				fatal(`chdir error: %s`, err)
			}
			flags.ofsEnabled = true
			fmt.Printf("chdir %s\n", *flags.Root)
		} else {
			if err := vfs.FromFile(`/`, *flags.Root, func(data []byte) (string, error) {
				fmt.Printf("load root %s %d\n", *flags.Root, len(data))
				return `text/html`, nil
			}); err != nil {
				fatal(`load error: %s`, err)
			}
		}
	}

	// services
	var services Services

	// http
	if flags.httpEnabled {
		features := []string{}
		router := chi.NewRouter().With(middleware.Always(*flags.TimeoutRequest, *flags.Compression)...)
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
		if !flags.httpsEnabled && flags.BearerToken != nil && *flags.BearerToken != `` {
			router.Route(`/^`, func(router chi.Router) {
				router.Use(middleware.Bearer(*flags.BearerToken))
				if *flags.Prometheus {
					router.Mount(`/metrics/prometheus`, promhttp.Handler())
				}
			})
			features = append(features, `ctrl`)
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
			root = middleware.Cocytus(nil)
		}
		router.Mount(`/`, root)
		sort.Strings(features)
		services = append(services, Service{scheme: `http`, features: features, server: &http.Server{
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
		features := []string{`tls`}
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
		if flags.BearerToken != nil && *flags.BearerToken != `` {
			router.Route(`/^`, func(router chi.Router) {
				router.Use(middleware.Bearer(*flags.BearerToken))
				if *flags.Prometheus {
					router.Mount(`/metrics/prometheus`, promhttp.Handler())
				}
			})
			features = append(features, `ctrl`)
		}
		var root http.Handler
		root = middleware.Cocytus(nil)
		router.Mount(`/`, root)
		sort.Strings(features)
		services = append(services, Service{scheme: `https`, features: features, server: &http.Server{
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

	// start
	for _, service := range services {
		service := service
		go func() {
			connect := service.server.Addr
			if strings.IndexRune(connect, ':') == 0 {
				connect = fmt.Sprintf(`%s%s`, hostname, connect)
			}
			features := ``
			if len(service.features) > 0 {
				features = ` ` + strings.Join(service.features, ` `)
			}
			fmt.Printf("%s.up %s://%s/%s\n", service.scheme, service.scheme, connect, features)
			var err error
			if service.server.TLSConfig == nil {
				err = service.server.ListenAndServe()
			} else {
				err = service.server.ListenAndServeTLS(``, ``)
			}
			if err != nil && err != http.ErrServerClosed {
				fmt.Printf("%s.serve error: %s\n", service.scheme, err)
			} else {
				fmt.Printf("%s.down\n", service.scheme)
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
				fmt.Printf("%s.shutdown error: %s\n", service.scheme, err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func fatal(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
	os.Exit(1)
}
