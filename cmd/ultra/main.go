package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"log"
	"math/big"
	"net/http"
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
	ctrlEnabled        bool
	CtrlLogger         *bool
	CtrlPipe           *bool
	CtrlSelfSign       *bool
	CtrlTlsCert        *string
	CtrlTlsKey         *string
	CtrlVfs            *bool
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
	HttpsSelfSign      *bool
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
	help     []string
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
		Ctrl:               flag.String(`ctrl`, ``, `specifies the bind address for the controller`),
		CtrlLogger:         flag.Bool(`ctrl-logger`, false, `enable logging for the controller`),
		CtrlPipe:           flag.Bool(`ctrl-pipe`, false, `enable pipe router control`),
		CtrlSelfSign:       flag.Bool(`ctrl-self-sign`, false, `generate a self-signed tls certificate for the controller`),
		CtrlTlsCert:        flag.String(`ctrl-tls-cert`, ``, `specifies the location of the tls certificate for the controller`),
		CtrlTlsKey:         flag.String(`ctrl-tls-key`, ``, `specifies the location of the tls key for the controller`),
		CtrlVfs:            flag.Bool(`ctrl-vfs`, false, `enable vfs control`),
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
		HttpsSelfSign:      flag.Bool(`https-self-sign`, false, `generate a self-signed tls certificate`),
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
	flags.httpsEnabled = *flags.Https != `` && (*flags.HttpsSelfSign || (*flags.HttpsTlsCert != `` && *flags.HttpsTlsKey != ``))

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
	// FIXME: boot summary
	logger.Audit(`%s`, bootAscii)
	logger.Audit(`ultra.boot %s logging.level=%s`, *flags.Hostname, logger.Level().String())
	if *flags.Croesus {
		logger.Audit(`¤ rich as croesus`)
	}

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

	// pipes
	counters := map[string]func(http.Handler) http.Handler{
		`http`:  middleware.Identity,
		`https`: middleware.Identity,
		`ctrl`:  middleware.Identity,
	}
	if *flags.Prometheus {
		for label, _ := range counters {
			counters[label] = middleware.Prometheus(label)
		}
	}

	// pipes
	pipes := map[string]control.Router{
		`http`:  volatile.NewRouter(`http`, logger, *flags.ReverseProxyLogger, counters[`http`]),
		`https`: volatile.NewRouter(`https`, logger, *flags.ReverseProxyLogger, counters[`https`]),
	}

	// services
	var services Services

	// helpers
	buildRootHandler := func(label string, proxies []ReverseProxy, withTls bool, selfSign bool) (http.Handler, []string) {
		features := []string{}
		formatter := volatile.NewLogFormatter(label, logger)
		if !withTls && *flags.HttpsOnly {
			features = append(features, `https-only`)
			return http.Handler(handler.Gehenna), features
		}
		if *flags.Prometheus {
			features = append(features, `prometheus`)
		}
		if withTls {
			features = append(features, `tls`)
		}
		if selfSign {
			features = append(features, `self-sign`)
		}
		root := http.Handler(_404)
		root = middleware.MethodFilter([]string{http.MethodGet}, http.Handler(_405))(root)
		if flags.ofsEnabled {
			features = append(features, `ofs`)
			root = middleware.NewFs(ofs, logger)(root)
		}
		if *flags.Home != `` {
			// FIXME: consider redirect if path doesn't end with `/` to force directory mode in browser (relative paths)
			features = append(features, `home`)
			hfs := oe.NewFsDriver(*flags.Home, *flags.Index, wand)
			root = middleware.NewHome(hfs, *flags.HomePrefix, *flags.HomeDir, logger)(root)
		}
		{
			features = append(features, `vfs`)
			root = middleware.NewFs(vfs, logger)(root)
		}
		root = counters[label](root)
		root = middleware.Standard(label, root, formatter, *flags.TimeoutRequest, *flags.Compression)
		root = pipes[label].Handler()(root)
		if withTls && *flags.HttpsHsts > time.Duration(0) {
			features = append(features, `hsts`)
			root = middleware.Hsts(*flags.HttpsHsts)(root)
		}
		if len(proxies) > 0 {
			features = append(features, `reverse-proxy`)
			for _, proxy := range proxies {
				pipes[label].AddRoute(proxy.Mount, proxy.Url)
			}
		}
		sort.Strings(features)
		router := chi.NewRouter()
		router.NotFound(_404)
		router.MethodNotAllowed(_405)
		router.Mount(`/`, root)
		return router, features
	}

	// http
	{
		label := `http`
		if flags.httpEnabled {
			handler, features := buildRootHandler(label, flags.ReverseProxies, false, false)
			services = append(services, Service{label: label, features: features, server: &http.Server{
				Addr:         *flags.Http,
				Handler:      handler,
				TLSConfig:    nil,
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
		if flags.httpsEnabled {
			tlsConfig, err := buildTlsConfig(*flags.Hostname, *flags.HttpsSelfSign, *flags.HttpsTlsCert, *flags.HttpsTlsKey)
			if err != nil {
				logger.Fatal(`%s.tls-config error: %s`, label, err)
			}
			handler, features := buildRootHandler(label, flags.ReverseProxiesTls, true, *flags.HttpsSelfSign)
			services = append(services, Service{label: label, features: features, server: &http.Server{
				Addr:         *flags.Https,
				Handler:      handler,
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
		if flags.ctrlEnabled {
			tlsConfig, err := buildTlsConfig(*flags.Hostname, *flags.CtrlSelfSign, *flags.CtrlTlsCert, *flags.CtrlTlsKey)
			if err != nil {
				logger.Fatal(`%s.tls-config error: %s`, label, err)
			}

			help := []string{}
			features := []string{}
			{
				for _, method := range []string{`GET`, `POST -d''`, `DELETE`} {
					if *flags.BearerToken != `` {
						features = append(features, `bearer`)
						if *flags.CtrlSelfSign {
							help = append(help, fmt.Sprintf(`# curl --insecure -sX%s -H 'authorization: bearer TOKEN' '%%s'`, method))
						} else {
							help = append(help, fmt.Sprintf(`# curl -sX%s -H 'authorization: bearer TOKEN' '%%s'`, method))
						}
					} else {
						help = append(help, fmt.Sprintf(`# curl -sX%s '%%s'`, method))
					}
				}
			}
			metrics := counters[label]
			if *flags.Prometheus {
				features = append(features, `prometheus`)
			}
			formatter := volatile.NewLogFormatter(label, logger)
			router := chi.NewRouter()
			router.NotFound(_404)
			router.MethodNotAllowed(_405)
			router.Mount(`/`, func() http.Handler {
				root := http.Handler(_404)
				if *flags.BearerToken != `` {
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
			if *flags.CtrlPipe {
				router.Route(`/pipe`, func(router chi.Router) {
					features = append(features, `pipe`)
					handler := http.Handler(handler.Pipes(logger, pipes))
					if *flags.BearerToken != `` {
						handler = middleware.Bearer(*flags.BearerToken, false, nil, logger)(handler)
					}
					handler = middleware.Control(handler, *flags.CtrlLogger, formatter)
					handler = metrics(handler)
					router.Mount(`/`, handler)
				})
			}
			if *flags.CtrlVfs {
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
			}
			if tlsConfig != nil {
				features = append(features, `tls`)
			}
			if *flags.CtrlSelfSign {
				features = append(features, `self-sign`)
			}
			sort.Strings(features)
			services = append(services, Service{label: label, features: features, help: help, server: &http.Server{
				Addr:         *flags.Ctrl,
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
			scheme := `http`
			if service.server.TLSConfig != nil {
				scheme = `https`
			}
			logger.Info(`%s.up %s://%s/%s`, service.label, scheme, connect, features)
			for _, format := range service.help {
				logger.Help(`%s.help %s`, service.label, fmt.Sprintf(format, fmt.Sprintf(`%s://%s/`, scheme, connect)))
			}
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

func buildTlsConfig(hostname string, generate bool, certFile string, keyFile string) (*tls.Config, error) {
	if !generate && certFile == `` && keyFile == `` {
		return nil, nil
	}
	var cert tls.Certificate
	var err error
	if generate {
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{`ultra`},
				// FIXME: what to use for values here?
				/*
					Country:       []string{``},
					Province:      []string{``},
					Locality:      []string{``},
					StreetAddress: []string{``},
					PostalCode:    []string{``},
				*/
			},
			NotBefore:             time.Now().UTC(),
			NotAfter:              time.Now().UTC().AddDate(1, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		caKeyPem := &bytes.Buffer{}
		pem.Encode(caKeyPem, &pem.Block{Type: `RSA PRIVATE KEY`, Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
		caCert, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		caCertPem := &bytes.Buffer{}
		pem.Encode(caCertPem, &pem.Block{Type: `CERTIFICATE`, Bytes: caCert})

		cs := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: hostname,
				// FIXME: what to use for values here?
				/*
					Organization:  []string{`ultra`},
					Country:       []string{``},
					Province:      []string{``},
					Locality:      []string{``},
					StreetAddress: []string{``},
					PostalCode:    []string{``},
				*/
			},
			NotBefore:    time.Now().UTC(),
			NotAfter:     time.Now().UTC().AddDate(1, 0, 0),
			SubjectKeyId: []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			DNSNames:     []string{`localhost`, `127.0.0.1`},
		}
		csKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		csKeyPem := &bytes.Buffer{}
		pem.Encode(csKeyPem, &pem.Block{Type: `RSA PRIVATE KEY`, Bytes: x509.MarshalPKCS1PrivateKey(csKey)})
		csCert, err := x509.CreateCertificate(rand.Reader, cs, ca, &csKey.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		csCertPem := &bytes.Buffer{}
		pem.Encode(csCertPem, &pem.Block{Type: `CERTIFICATE`, Bytes: csCert})

		cert, err = tls.X509KeyPair(csCertPem.Bytes(), csKeyPem.Bytes())
		if err != nil {
			return nil, err
		}
	} else {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
	}
	// FIXME: report cert details (expiration, etc)
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
	return tlsConfig, nil
}

const bootAscii = `
       % @ :%                             8@ 88;
    tSX    X                           %@8    @
  S :       8                        X .       8
 S;         8;                      ::         8S
@;           @X                    :            S:
X             ;:                   S               S
                t8                 8               :@X
.                .8:               8                 .8;
.X                 @               t8                  @;
 XX                  ;8             @8                   8
  88                  . %            ;S                   S
   :                    ;;             S8
     S@                   S@           %S                  S
      .:X                   %t        88                   @
        ;8.                  S%:     ;%    :%S
          8t                   8S   @     ;@  :@         ;.
                                  @      X8    ;       88%
          8;  ..                        @8      :  ;t88
        8 .  %88                       8@       :@S
      @ .   S.   ;@                   .8
    :8:           ;8.                  ;S.
   88     .t        8t                   8@
  ;:      X           .8                    %
 %.        S           .8.                  ;S.
tX         S8            @.                   8;
@           :%             :X                    S
              %@            ;8.                  ;X.
8                %            X                    8t
tX               ;X:            ;8                   :8
 X:                8%            :8.                  ::
  @@                  ;            8:                   X.
   %;                 8X             t8                  X
    .8.                8:             :@:                 :
      SX                                X                 8
       t                ;                 .S              .
         @             ;%                  S@             8
        Xt            :%                    t8           .%
     8%:.            S@                      S          ;t
S@ S;              8:.                       :        ;@%
@8888888888888888S:.                               .:;;`
