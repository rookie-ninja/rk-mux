// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxlog is a middleware for mux framework for logging RPC.
package rkmuxlog

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/log"
	rkmuxmid "github.com/rookie-ninja/rk-mux/middleware"
	"github.com/rookie-ninja/rk-mux/middleware/context"
	"net/http"
	"strconv"
)

// Middleware returns a gin.HandlerFunc (middleware) that logs requests using uber-go/zap.
func Middleware(opts ...rkmidlog.Option) mux.MiddlewareFunc {
	set := rkmidlog.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxmid.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			// call before
			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			ctx = context.WithValue(req.Context(), rkmid.EventKey, beforeCtx.Output.Event)
			req = req.WithContext(ctx)

			ctx = context.WithValue(req.Context(), rkmid.LoggerKey, beforeCtx.Output.Logger)
			req = req.WithContext(ctx)

			next.ServeHTTP(writer, req)

			// call after
			afterCtx := set.AfterCtx(
				rkmuxctx.GetRequestId(writer),
				rkmuxctx.GetTraceId(writer),
				strconv.Itoa(writer.(*rkmuxmid.RkResponseWriter).Code))
			set.After(beforeCtx, afterCtx)
		})
	}
}
