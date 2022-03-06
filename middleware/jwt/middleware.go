// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxjwt is a middleware for mux framework which validating jwt token for RPC
package rkmuxjwt

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/jwt"
	"github.com/rookie-ninja/rk-mux/middleware"
	"net/http"
)

// Interceptor Add jwt interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/jwt.go
func Interceptor(opts ...rkmidjwt.Option) mux.MiddlewareFunc {
	set := rkmidjwt.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxmid.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req, nil)
			set.Before(beforeCtx)

			// case 1: error response
			if beforeCtx.Output.ErrResp != nil {
				rkmuxmid.WriteJson(writer, beforeCtx.Output.ErrResp.Err.Code, beforeCtx.Output.ErrResp)
				return
			}

			// insert into context
			ctx = context.WithValue(req.Context(), rkmid.JwtTokenKey, beforeCtx.Output.JwtToken)
			req = req.WithContext(ctx)

			next.ServeHTTP(writer, req)
		})
	}
}
