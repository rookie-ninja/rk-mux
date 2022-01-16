// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxmetrics is a middleware for mux framework which record prometheus metrics for RPC
package rkmuxmetrics

import (
	"context"
	"github.com/gorilla/mux"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidmetrics "github.com/rookie-ninja/rk-entry/middleware/metrics"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
	"strconv"
)

// Interceptor create a new prometheus metrics interceptor with options.
func Interceptor(opts ...rkmidmetrics.Option) mux.MiddlewareFunc {
	set := rkmidmetrics.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			next.ServeHTTP(writer, req)

			afterCtx := set.AfterCtx(strconv.Itoa(writer.(*rkmuxinter.RkResponseWriter).Code))
			set.After(beforeCtx, afterCtx)
		})
	}
}
