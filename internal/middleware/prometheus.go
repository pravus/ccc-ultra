package middleware

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Prometheus(label string) func(http.Handler) http.Handler {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: `ultra_` + label + `_requests`,
		Help: `HTTP Requests`,
	}, []string{`code`, `method`})
	prometheus.MustRegister(counter)
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    `ultra_` + label + `_duration`,
		Help:    `HTTP request duration`,
		Buckets: []float64{.25, .5, 1, 2.5, 5, 10},
	}, []string{`code`, `method`})
	prometheus.MustRegister(duration)
	inFlight := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: `ultra_` + label + `_in_flight`,
		Help: `A gauge of requests currently in flight`,
	})
	prometheus.MustRegister(inFlight)
	requestSize := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    `ultra_` + label + `_request_size`,
		Help:    `HTTP request size`,
		Buckets: []float64{200, 500, 900, 1500},
	}, []string{})
	prometheus.MustRegister(requestSize)
	responseSize := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    `ultra_` + label + `_response_size`,
		Help:    `HTTP response size`,
		Buckets: []float64{200, 500, 900, 1500},
	}, []string{})
	prometheus.MustRegister(responseSize)
	return func(next http.Handler) http.Handler {
		return promhttp.InstrumentHandlerInFlight(inFlight,
			promhttp.InstrumentHandlerDuration(duration,
				promhttp.InstrumentHandlerCounter(counter,
					promhttp.InstrumentHandlerResponseSize(responseSize,
						promhttp.InstrumentHandlerRequestSize(requestSize, next),
					))))
	}
}
