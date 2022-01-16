// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxcors is a CORS middleware for mux framework
package rkmuxcors

import (
	"context"
	"github.com/gorilla/mux"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidcors "github.com/rookie-ninja/rk-entry/middleware/cors"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// Interceptor Add cors interceptors.
//
// Mainly copied and modified from bellow.
// https://github.com/labstack/echo/blob/master/middleware/cors.go
func Interceptor(opts ...rkmidcors.Option) mux.MiddlewareFunc {
	set := rkmidcors.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			for k, v := range beforeCtx.Output.HeadersToReturn {
				writer.Header().Set(k, v)
			}

			for _, v := range beforeCtx.Output.HeaderVary {
				writer.Header().Add(rkmid.HeaderVary, v)
			}

			// case 1: with abort
			if beforeCtx.Output.Abort {
				writer.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(writer, req)
		})
	}
}
