// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxauth is auth middleware for mux framework
package rkmuxauth

import (
	"context"
	"github.com/gorilla/mux"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidauth "github.com/rookie-ninja/rk-entry/middleware/auth"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// Interceptor validate bellow authorization.
//
// 1: Basic Auth: The client sends HTTP requests with the Authorization header that contains the word Basic, followed by a space and a base64-encoded(non-encrypted) string username: password.
// 2: Bearer Token: Commonly known as token authentication. It is an HTTP authentication scheme that involves security tokens called bearer tokens.
// 3: API key: An API key is a token that a client provides when making API calls. With API key auth, you send a key-value pair to the API in the request headers.
func Interceptor(opts ...rkmidauth.Option) mux.MiddlewareFunc {
	set := rkmidauth.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			// case 1: return to user if error occur
			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			if beforeCtx.Output.ErrResp != nil {
				for k, v := range beforeCtx.Output.HeadersToReturn {
					writer.Header().Set(k, v)
				}
				rkmuxinter.WriteJson(writer, beforeCtx.Output.ErrResp.Err.Code, beforeCtx.Output.ErrResp)
				return
			}

			next.ServeHTTP(writer, req)
		})
	}
}
