// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxcsrf is a middleware for mux framework which validating csrf token for RPC
package rkmuxcsrf

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-common/common"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
	"time"
)

// Interceptor Add csrf interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/csrf.go
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName)
			req = req.WithContext(ctx)

			// 1: skip csrf check based on skipper
			if set.Skipper(req) {
				next.ServeHTTP(writer, req)
				return
			}

			k, err := req.Cookie(set.CookieName)
			token := ""

			// 2.1: generate token if failed to get cookie from context
			if err != nil {
				token = rkcommon.RandString(set.TokenLength)
			} else {
				// 2.2: reuse token if exists
				token = k.Value
			}

			// 3.1: do not check http methods of GET, HEAD, OPTIONS and TRACE
			switch req.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			default:
				// 3.2: validate token only for requests which are not defined as 'safe' by RFC7231
				clientToken, err := set.extractor(req)
				if err != nil {
					rkmuxinter.WriteJson(writer, http.StatusBadRequest, rkerror.New(
						rkerror.WithHttpCode(http.StatusBadRequest),
						rkerror.WithMessage("failed to extract client token"),
						rkerror.WithDetails(err)))

					return
				}

				// 3.3: return 403 to client if token is not matched
				if !isValidToken(token, clientToken) {
					rkmuxinter.WriteJson(writer, http.StatusForbidden, rkerror.New(
						rkerror.WithHttpCode(http.StatusForbidden),
						rkerror.WithMessage("invalid csrf token")))
					return
				}
			}

			// set CSRF cookie
			cookie := new(http.Cookie)
			cookie.Name = set.CookieName
			cookie.Value = token
			// 4.1
			if set.CookiePath != "" {
				cookie.Path = set.CookiePath
			}
			// 4.2
			if set.CookieDomain != "" {
				cookie.Domain = set.CookieDomain
			}
			// 4.3
			if set.CookieSameSite != http.SameSiteDefaultMode {
				cookie.SameSite = set.CookieSameSite
			}
			cookie.Expires = time.Now().Add(time.Duration(set.CookieMaxAge) * time.Second)
			cookie.Secure = set.CookieSameSite == http.SameSiteNoneMode
			cookie.HttpOnly = set.CookieHTTPOnly
			http.SetCookie(writer, cookie)

			// store token in the context
			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcCsrfTokenKey, token))

			// protect clients from caching the response
			writer.Header().Add(headerVary, headerCookie)

			next.ServeHTTP(writer, req)
		})
	}
}
