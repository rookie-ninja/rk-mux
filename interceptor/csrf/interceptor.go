// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxcsrf is a middleware for mux framework which validating csrf token for RPC
package rkmuxcsrf

import (
	"context"
	"github.com/gorilla/mux"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidcsrf "github.com/rookie-ninja/rk-entry/middleware/csrf"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// Interceptor Add csrf interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/csrf.go
func Interceptor(opts ...rkmidcsrf.Option) mux.MiddlewareFunc {
	set := rkmidcsrf.NewOptionSet(opts...)

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
