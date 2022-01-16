// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxpanic is a middleware of mux framework for recovering from panic
package rkmuxpanic

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-common/error"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidpanic "github.com/rookie-ninja/rk-entry/middleware/panic"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"net/http"
)

// Interceptor returns a rest.Middleware (middleware)
func Interceptor(opts ...rkmidpanic.Option) mux.MiddlewareFunc {
	set := rkmidpanic.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			handlerFunc := func(resp *rkerror.ErrorResp) {
				rkmuxinter.WriteJson(writer, resp.Err.Code, resp)
			}
			beforeCtx := set.BeforeCtx(rkmuxctx.GetEvent(req), rkmuxctx.GetLogger(req, writer), handlerFunc)
			set.Before(beforeCtx)

			defer beforeCtx.Output.DeferFunc()

			next.ServeHTTP(writer, req)
		})
	}
}
