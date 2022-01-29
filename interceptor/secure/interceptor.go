// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxsec is a middleware of mux framework for adding secure headers in RPC response
package rkmuxsec

import (
	"context"
	"github.com/gorilla/mux"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidsec "github.com/rookie-ninja/rk-entry/middleware/secure"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// Interceptor Add security interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/secure.go
func Interceptor(opts ...rkmidsec.Option) mux.MiddlewareFunc {
	set := rkmidsec.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			// case 1: return to user if error occur
			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			for k, v := range beforeCtx.Output.HeadersToReturn {
				writer.Header().Set(k, v)
			}

			next.ServeHTTP(writer, req)
		})
	}
}
