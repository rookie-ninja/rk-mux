// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxprom is a middleware for mux framework which record prometheus metrics for RPC
package rkmuxprom

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/prom"
	"github.com/rookie-ninja/rk-mux/middleware"
	"net/http"
	"strconv"
)

// Middleware create a new prometheus metrics interceptor with options.
func Middleware(opts ...rkmidprom.Option) mux.MiddlewareFunc {
	set := rkmidprom.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxmid.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			next.ServeHTTP(writer, req)

			afterCtx := set.AfterCtx(strconv.Itoa(writer.(*rkmuxmid.RkResponseWriter).Code))
			set.After(beforeCtx, afterCtx)
		})
	}
}
