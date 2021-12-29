// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxsec is a middleware of mux framework for adding secure headers in RPC response
package rkmuxsec

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// Interceptor Add security interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/secure.go
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName))

			if set.Skipper(req) {
				next.ServeHTTP(writer, req)
			}

			// Add X-XSS-Protection header
			if set.XSSProtection != "" {
				writer.Header().Set(headerXXSSProtection, set.XSSProtection)
			}

			// Add X-Content-Type-Options header
			if set.ContentTypeNosniff != "" {
				writer.Header().Set(headerXContentTypeOptions, set.ContentTypeNosniff)
			}

			// Add X-Frame-Options header
			if set.XFrameOptions != "" {
				writer.Header().Set(headerXFrameOptions, set.XFrameOptions)
			}

			// Add Strict-Transport-Security header
			if (req.TLS != nil || (req.Header.Get(headerXForwardedProto) == "https")) && set.HSTSMaxAge != 0 {
				subdomains := ""
				if !set.HSTSExcludeSubdomains {
					subdomains = "; includeSubdomains"
				}
				if set.HSTSPreloadEnabled {
					subdomains = fmt.Sprintf("%s; preload", subdomains)
				}
				writer.Header().Set(headerStrictTransportSecurity, fmt.Sprintf("max-age=%d%s", set.HSTSMaxAge, subdomains))
			}

			// Add Content-Security-Policy-Report-Only or Content-Security-Policy header
			if set.ContentSecurityPolicy != "" {
				if set.CSPReportOnly {
					writer.Header().Set(headerContentSecurityPolicyReportOnly, set.ContentSecurityPolicy)
				} else {
					writer.Header().Set(headerContentSecurityPolicy, set.ContentSecurityPolicy)
				}
			}

			// Add Referrer-Policy header
			if set.ReferrerPolicy != "" {
				writer.Header().Set(headerReferrerPolicy, set.ReferrerPolicy)
			}

			next.ServeHTTP(writer, req)
		})
	}
}
