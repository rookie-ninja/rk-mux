// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxauth is auth middleware for mux framework
package rkmuxauth

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
	"strings"
)

// Interceptor validate bellow authorization.
//
// 1: Basic Auth: The client sends HTTP requests with the Authorization header that contains the word Basic, followed by a space and a base64-encoded(non-encrypted) string username: password.
// 2: Bearer Token: Commonly known as token authentication. It is an HTTP authentication scheme that involves security tokens called bearer tokens.
// 3: API key: An API key is a token that a client provides when making API calls. With API key auth, you send a key-value pair to the API in the request headers.
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName)
			req = req.WithContext(ctx)

			err := before(req, writer, set)

			if err == nil {
				next.ServeHTTP(writer, req)
			}
		})
	}
}

func before(req *http.Request, writer http.ResponseWriter, set *optionSet) error {
	if !set.ShouldAuth(req) {
		return nil
	}

	authHeader := req.Header.Get(rkmuxinter.RpcAuthorizationHeaderKey)
	apiKeyHeader := req.Header.Get(rkmuxinter.RpcApiKeyHeaderKey)

	if len(authHeader) > 0 {
		// Contains auth header
		// Basic auth type
		tokens := strings.SplitN(authHeader, " ", 2)
		if len(tokens) != 2 {
			resp := rkerror.New(
				rkerror.WithHttpCode(http.StatusUnauthorized),
				rkerror.WithMessage("Invalid Basic Auth format"))

			rkmuxinter.WriteJson(writer, http.StatusUnauthorized, resp)
			return resp.Err
		}
		if !set.Authorized(tokens[0], tokens[1]) {
			if tokens[0] == typeBasic {
				writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s realm="%s"`, typeBasic, set.BasicRealm))
			}

			resp := rkerror.New(
				rkerror.WithHttpCode(http.StatusUnauthorized),
				rkerror.WithMessage("Invalid credential"))

			rkmuxinter.WriteJson(writer, http.StatusUnauthorized, resp)

			return resp.Err
		}
	} else if len(apiKeyHeader) > 0 {
		// Contains api key
		if !set.Authorized(typeApiKey, apiKeyHeader) {
			resp := rkerror.New(
				rkerror.WithHttpCode(http.StatusUnauthorized),
				rkerror.WithMessage("Invalid X-API-Key"))

			rkmuxinter.WriteJson(writer, http.StatusUnauthorized, resp)

			return resp.Err
		}
	} else {
		authHeaders := []string{}
		if len(set.BasicAccounts) > 0 {
			writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s realm="%s"`, typeBasic, set.BasicRealm))
			authHeaders = append(authHeaders, "Basic Auth")
		}
		if len(set.ApiKey) > 0 {
			authHeaders = append(authHeaders, "X-API-Key")
		}

		errMsg := fmt.Sprintf("Missing authorization, provide one of bellow auth header:[%s]", strings.Join(authHeaders, ","))

		resp := rkerror.New(
			rkerror.WithHttpCode(http.StatusUnauthorized),
			rkerror.WithMessage(errMsg))

		rkmuxinter.WriteJson(writer, http.StatusUnauthorized, resp)

		return resp.Err
	}

	return nil
}
