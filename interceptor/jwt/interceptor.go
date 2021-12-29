// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxjwt is a middleware for mux framework which validating jwt token for RPC
package rkmuxjwt

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// Interceptor Add jwt interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/jwt.go
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName)
			req = req.WithContext(ctx)

			if set.Skipper(req) {
				next.ServeHTTP(writer, req)
				return
			}

			// extract token from extractor
			var auth string
			var err error
			for _, extractor := range set.extractors {
				// Extract token from extractor, if it's not fail break the loop and
				// set auth
				auth, err = extractor(req)
				if err == nil {
					break
				}
			}

			if err != nil {
				rkmuxinter.WriteJson(writer, http.StatusUnauthorized, rkerror.New(
					rkerror.WithHttpCode(http.StatusUnauthorized),
					rkerror.WithMessage("invalid or expired jwt"),
					rkerror.WithDetails(err)))
				return
			}

			// parse token
			token, err := set.ParseTokenFunc(auth, req)

			if err != nil {
				rkmuxinter.WriteJson(writer, http.StatusUnauthorized, rkerror.New(
					rkerror.WithHttpCode(http.StatusUnauthorized),
					rkerror.WithMessage("invalid or expired jwt"),
					rkerror.WithDetails(err)))
				return
			}

			// insert into context
			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcJwtTokenKey, token))

			next.ServeHTTP(writer, req)
		})
	}
}
