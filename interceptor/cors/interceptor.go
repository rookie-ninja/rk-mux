// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxcors is a CORS middleware for mux framework
package rkmuxcors

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
	"strconv"
	"strings"
)

// Interceptor Add cors interceptors.
//
// Mainly copied and modified from bellow.
// https://github.com/labstack/echo/blob/master/middleware/cors.go
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	allowMethods := strings.Join(set.AllowMethods, ",")
	allowHeaders := strings.Join(set.AllowHeaders, ",")
	exposeHeaders := strings.Join(set.ExposeHeaders, ",")
	maxAge := strconv.Itoa(set.MaxAge)

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

			originHeader := req.Header.Get(headerOrigin)
			preflight := req.Method == http.MethodOptions

			// 1: if no origin header was provided, we will return 204 if request is not a OPTION method
			if originHeader == "" {
				// 1.1: if not a preflight request, then pass through
				if !preflight {
					next.ServeHTTP(writer, req)
					return
				}

				// 1.2: if it is a preflight request, then return with 204
				writer.WriteHeader(http.StatusNoContent)
				return
			}

			// 2: origin not allowed, we will return 204 if request is not a OPTION method
			if !set.isOriginAllowed(originHeader) {
				writer.WriteHeader(http.StatusNoContent)
				return
			}

			// 3: not a OPTION method
			if !preflight {
				writer.Header().Set(headerAccessControlAllowOrigin, originHeader)
				// 3.1: add Access-Control-Allow-Credentials
				if set.AllowCredentials {
					writer.Header().Set(headerAccessControlAllowCredentials, "true")
				}
				// 3.2: add Access-Control-Expose-Headers
				if exposeHeaders != "" {
					writer.Header().Set(headerAccessControlExposeHeaders, exposeHeaders)
				}
				next.ServeHTTP(writer, req)
				return
			}

			// 4: preflight request, return 204
			// add related headers including:
			//
			// - Vary
			// - Access-Control-Allow-Origin
			// - Access-Control-Allow-Methods
			// - Access-Control-Allow-Credentials
			// - Access-Control-Allow-Headers
			// - Access-Control-Max-Age
			writer.Header().Add(headerVary, headerAccessControlRequestMethod)
			writer.Header().Add(headerVary, headerAccessControlRequestHeaders)
			writer.Header().Set(headerAccessControlAllowOrigin, originHeader)
			writer.Header().Set(headerAccessControlAllowMethods, allowMethods)

			// 4.1: Access-Control-Allow-Credentials
			if set.AllowCredentials {
				writer.Header().Set(headerAccessControlAllowCredentials, "true")
			}

			// 4.2: Access-Control-Allow-Headers
			if allowHeaders != "" {
				writer.Header().Set(headerAccessControlAllowHeaders, allowHeaders)
			} else {
				h := req.Header.Get(headerAccessControlRequestHeaders)
				if h != "" {
					writer.Header().Set(headerAccessControlAllowHeaders, h)
				}
			}
			if set.MaxAge > 0 {
				// 4.3: Access-Control-Max-Age
				writer.Header().Set(headerAccessControlMaxAge, maxAge)
			}

			writer.WriteHeader(http.StatusNoContent)
		})
	}
}
