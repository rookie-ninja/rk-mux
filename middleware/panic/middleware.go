// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxpanic is a middleware of mux framework for recovering from panic
package rkmuxpanic

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/v2/error"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/panic"
	"github.com/rookie-ninja/rk-mux/middleware"
	"github.com/rookie-ninja/rk-mux/middleware/context"
	"net/http"
)

// Middleware returns a rest.Middleware (middleware)
func Middleware(opts ...rkmidpanic.Option) mux.MiddlewareFunc {
	set := rkmidpanic.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxmid.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			handlerFunc := func(resp rkerror.ErrorInterface) {
				rkmuxmid.WriteJson(writer, resp.Code(), resp)
			}
			beforeCtx := set.BeforeCtx(rkmuxctx.GetEvent(req), rkmuxctx.GetLogger(req, writer), handlerFunc)
			set.Before(beforeCtx)

			defer beforeCtx.Output.DeferFunc()

			next.ServeHTTP(writer, req)
		})
	}
}
