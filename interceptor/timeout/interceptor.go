// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxtimeout is a middleware of mux framework for timing out request in RPC response
package rkmuxtimeout

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// Interceptor Add timeout interceptors.
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName))

			set.Tick(req, writer, next)
		})
	}
}
