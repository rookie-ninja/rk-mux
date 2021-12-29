// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxlimit is a middleware of mux framework for adding rate limit in RPC response
package rkmuxlimit

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"net/http"
)

// Interceptor Add rate limit interceptors.
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName))

			event := rkmuxctx.GetEvent(req)

			if duration, err := set.Wait(req); err != nil {
				event.SetCounter("rateLimitWaitMs", duration.Milliseconds())
				event.AddErr(err)

				rkmuxinter.WriteJson(writer, http.StatusTooManyRequests, rkerror.New(
					rkerror.WithHttpCode(http.StatusTooManyRequests),
					rkerror.WithMessage(err.Error())))
				return
			}

			next.ServeHTTP(writer, req)
		})
	}
}
