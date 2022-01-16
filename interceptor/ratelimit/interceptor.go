// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxlimit is a middleware of mux framework for adding rate limit in RPC response
package rkmuxlimit

import (
	"context"
	"github.com/gorilla/mux"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidlimit "github.com/rookie-ninja/rk-entry/middleware/ratelimit"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// Interceptor Add rate limit interceptors.
func Interceptor(opts ...rkmidlimit.Option) mux.MiddlewareFunc {
	set := rkmidlimit.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			if beforeCtx.Output.ErrResp != nil {
				rkmuxinter.WriteJson(writer, beforeCtx.Output.ErrResp.Err.Code, beforeCtx.Output.ErrResp)
				return
			}

			next.ServeHTTP(writer, req)
		})
	}
}
