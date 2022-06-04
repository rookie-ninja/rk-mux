// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxcsrf is a middleware for mux framework which validating csrf token for RPC
package rkmuxcsrf

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/csrf"
	rkmuxmid "github.com/rookie-ninja/rk-mux/middleware"
	"net/http"
)

// Middleware Add csrf middleware.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/csrf.go
func Middleware(opts ...rkmidcsrf.Option) mux.MiddlewareFunc {
	set := rkmidcsrf.NewOptionSet(opts...)

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

			for _, v := range beforeCtx.Output.VaryHeaders {
				writer.Header().Add(rkmid.HeaderVary, v)
			}

			if beforeCtx.Output.Cookie != nil {
				http.SetCookie(writer, beforeCtx.Output.Cookie)
			}

			// store token in the context
			ctx = context.WithValue(req.Context(), rkmid.CsrfTokenKey, beforeCtx.Input.Token)
			req = req.WithContext(ctx)

			next.ServeHTTP(writer, req)
		})
	}
}
