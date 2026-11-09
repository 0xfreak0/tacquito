/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// gauges and counters
	serveReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "serve_received",
		Help:      "total number of packets received within the server",
	})
	serveAccepted = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "tacquito",
		Name:      "serve_accepted",
		Help:      "number of accepted connections within the server that are currently being processed",
	})
	serveAcceptedError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "serve_accepted_error",
		Help:      "number of accepted connection errors within the server",
	})
	handlers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "tacquito",
		Name:      "handle_handlers",
		Help:      "number of handlers running within the server",
	})
	crypterRead = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_read",
		Help:      "number of crypt reads within the server",
	})
	crypterReadError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_read_error",
		Help:      "number of crypt read errors within the server",
	})
	crypterWrite = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_write",
		Help:      "number of crypt writes within the server",
	})
	crypterWriteError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_write_error",
		Help:      "number of crypt write errors within the server",
	})
	crypterBadSecret = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_badSecret",
		Help:      "number of bad secrets",
	})
	// crypterSecretMatch counts which candidate key a multi-key connection
	// selected, by index (0 = primary). During a rotation, once every
	// non-zero index stops increasing, the older keys can be retired.
	crypterSecretMatch = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_secret_match",
		Help:      "number of multi-key connections that selected the key at the given index",
	}, []string{"index"})
	crypterUnmarshalError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_unmarshal_error",
		Help:      "number of errors unmarshalling in crypter",
	})
	crypterCryptError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_crypt_error",
		Help:      "number of errors in crypter crypt()",
	})
	crypterMarshalError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_marshal_error",
		Help:      "number of errors marshalling in crypter",
	})
	crypterReadFlagError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "crypter_tls_read_unencrypt_flag_error",
		Help:      "number of errors the tls unencrypted flag was unset on a conn read",
	})
	waitgroupActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "tacquito",
		Name:      "waitgroup_handle_routines_active",
		Help:      "number of active waitgroup go routines within the server",
	})
	sessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "tacquito",
		Name:      "sessions_active",
		Help:      "number of active sessions within the server",
	})
	sessionsGetHit = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "sessions_get_hit",
		Help:      "number of session cache hits within the server",
	})
	sessionsGetMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "sessions_get_miss",
		Help:      "number of session cache misses within the server",
	})
	sessionsSet = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "sessions_set",
		Help:      "number of session set in the cache",
	})

	// durations
	sessionDurations = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Namespace:  "tacquito",
			Name:       "sessions_duration_milliseconds",
			Help:       "the time a session is a live within tacquito, in milliseconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
	)

	connectionDuration = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Namespace:  "tacquito",
			Name:       "serve_connection_duration_milliseconds",
			Help:       "total time time of a net.Conn, including overhead, in milliseconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
	)
)

func init() {
	// gauges and counters
	prometheus.MustRegister(serveReceived)
	prometheus.MustRegister(serveAccepted)
	prometheus.MustRegister(serveAcceptedError)
	prometheus.MustRegister(handlers)
	prometheus.MustRegister(crypterRead)
	prometheus.MustRegister(crypterReadError)
	prometheus.MustRegister(crypterWrite)
	prometheus.MustRegister(crypterWriteError)
	prometheus.MustRegister(crypterBadSecret)
	prometheus.MustRegister(crypterSecretMatch)
	prometheus.MustRegister(crypterUnmarshalError)
	prometheus.MustRegister(crypterMarshalError)
	prometheus.MustRegister(crypterCryptError)
	prometheus.MustRegister(crypterReadFlagError)
	prometheus.MustRegister(waitgroupActive)
	prometheus.MustRegister(sessionsActive)
	prometheus.MustRegister(sessionsGetHit)
	prometheus.MustRegister(sessionsGetMiss)
	prometheus.MustRegister(sessionsSet)
	// durations
	prometheus.MustRegister(sessionDurations)
	prometheus.MustRegister(connectionDuration)
}

// secretIndexLabel bounds the cardinality of the crypterSecretMatch index
// label; nobody should be rotating through more than a handful of keys.
func secretIndexLabel(i int) string {
	if i > 9 {
		return "10+"
	}
	return strconv.Itoa(i)
}
