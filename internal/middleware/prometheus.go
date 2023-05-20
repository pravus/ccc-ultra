package middleware

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Prometheus(label string) func(http.Handler) http.Handler {
	return func(
		counter *prometheus.CounterVec,
		duration prometheus.ObserverVec,
		inFlight prometheus.Gauge,
		requestSize prometheus.ObserverVec,
		responseSize prometheus.ObserverVec,
	) func(http.Handler) http.Handler {
		prometheus.MustRegister(counter)
		prometheus.MustRegister(duration)
		prometheus.MustRegister(inFlight)
		prometheus.MustRegister(requestSize)
		prometheus.MustRegister(responseSize)
		return func(next http.Handler) http.Handler {
			return promhttp.InstrumentHandlerInFlight(inFlight,
				promhttp.InstrumentHandlerDuration(duration,
					promhttp.InstrumentHandlerCounter(counter,
						promhttp.InstrumentHandlerResponseSize(responseSize,
							promhttp.InstrumentHandlerRequestSize(requestSize, next),
						))))
		}
	}(
		prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: `ultra_` + label + `_requests`,
			Help: `A counter of total requests`,
		}, []string{`code`, `method`}),
		prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    `ultra_` + label + `_duration`,
			Help:    `A histogram of request duration`,
			Buckets: []float64{.25, .5, 1, 2.5, 5, 10},
		}, []string{`code`, `method`}),
		prometheus.NewGauge(prometheus.GaugeOpts{
			Name: `ultra_` + label + `_in_flight`,
			Help: `A gauge of requests currently in flight`,
		}),
		prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    `ultra_` + label + `_request_size`,
			Help:    `A histogram of request size`,
			Buckets: []float64{200, 500, 900, 1500},
		}, []string{}),
		prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    `ultra_` + label + `_response_size`,
			Help:    `A histogram of response size`,
			Buckets: []float64{200, 500, 900, 1500},
		}, []string{}),
	)
}
