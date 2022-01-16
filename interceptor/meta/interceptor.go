// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxmeta is a middleware of mux framework for adding metadata in RPC response
package rkmuxmeta

import (
	"context"
	"github.com/gorilla/mux"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidmeta "github.com/rookie-ninja/rk-entry/middleware/meta"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"net/http"
)

// Interceptor will add common headers as extension style in http response.
func Interceptor(opts ...rkmidmeta.Option) mux.MiddlewareFunc {
	set := rkmidmeta.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(rkmuxctx.GetEvent(req))
			set.Before(beforeCtx)

			ctx = context.WithValue(req.Context(), rkmid.HeaderRequestId, beforeCtx.Output.RequestId)
			req = req.WithContext(ctx)

			for k, v := range beforeCtx.Output.HeadersToReturn {
				writer.Header().Set(k, v)
			}

			next.ServeHTTP(writer, req)
		})
	}
}
