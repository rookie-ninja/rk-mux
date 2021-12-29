// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxmetrics is a middleware for mux framework which record prometheus metrics for RPC
package rkmuxmetrics

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
	"time"
)

// Interceptor create a new prometheus metrics interceptor with options.
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName))

			// start timer
			startTime := time.Now()

			next.ServeHTTP(writer, req)

			// end timer
			elapsed := time.Now().Sub(startTime)

			// ignoring /rk/v1/assets, /rk/v1/tv and /sw/ path while logging since these are internal APIs.
			if rkmuxinter.ShouldLog(req) {
				if durationMetrics := GetServerDurationMetrics(req, writer); durationMetrics != nil {
					durationMetrics.Observe(float64(elapsed.Nanoseconds()))
				}

				if resCodeMetrics := GetServerResCodeMetrics(req, writer); resCodeMetrics != nil {
					resCodeMetrics.Inc()
				}
			}
		})
	}
}
