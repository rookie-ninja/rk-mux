// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxlimit is a middleware of mux framework for adding rate limit in RPC response
package rkmuxlimit

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/ratelimit"
	"github.com/rookie-ninja/rk-mux/middleware"
	"net/http"
)

// Middleware Add rate limit interceptors.
func Middleware(opts ...rkmidlimit.Option) mux.MiddlewareFunc {
	set := rkmidlimit.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxmid.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			if beforeCtx.Output.ErrResp != nil {
				rkmuxmid.WriteJson(writer, beforeCtx.Output.ErrResp.Code(), beforeCtx.Output.ErrResp)
				return
			}

			next.ServeHTTP(writer, req)
		})
	}
}
