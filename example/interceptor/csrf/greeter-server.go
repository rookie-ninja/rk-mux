// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"github.com/rookie-ninja/rk-mux/interceptor/csrf"
	"net/http"
)

// In this example, we will start a new mux server with csrf interceptor enabled.
// Listen on port of 8080 with GET /v1/greeter.
func main() {
	// ******************************************************
	// ********** Override App name and version *************
	// ******************************************************
	//
	// rkentry.GlobalAppCtx.GetAppInfoEntry().AppName = "demo-app"
	// rkentry.GlobalAppCtx.GetAppInfoEntry().Version = "demo-version"

	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []mux.MiddlewareFunc{
		rkmuxcsrf.Interceptor(
			// Required, entry name and entry type will be used for distinguishing interceptors. Recommended.
			rkmuxcsrf.WithEntryNameAndType("greeter", "mux"),
			//
			// Optional, provide skipper function
			//rkmuxcsrf.WithSkipper(func(*http.Request) bool {
			//	return true
			//}),
			//
			// WithTokenLength the length of the generated token.
			// Optional. Default value 32.
			//rkmuxcsrf.WithTokenLength(10),
			//
			// WithTokenLookup a string in the form of "<source>:<key>" that is used
			// to extract token from the request.
			// Optional. Default value "header:X-CSRF-Token".
			// Possible values:
			// - "header:<name>"
			// - "form:<name>"
			// - "query:<name>"
			// Optional. Default value "header:X-CSRF-Token".
			//rkmuxcsrf.WithTokenLookup("header:X-CSRF-Token"),
			//
			// WithCookieName provide name of the CSRF cookie. This cookie will store CSRF token.
			// Optional. Default value "csrf".
			//rkmuxcsrf.WithCookieName("csrf"),
			//
			// WithCookieDomain provide domain of the CSRF cookie.
			// Optional. Default value "".
			//rkmuxcsrf.WithCookieDomain(""),
			//
			// WithCookiePath provide path of the CSRF cookie.
			// Optional. Default value "".
			//rkmuxcsrf.WithCookiePath(""),
			//
			// WithCookieMaxAge provide max age (in seconds) of the CSRF cookie.
			// Optional. Default value 86400 (24hr).
			//rkmuxcsrf.WithCookieMaxAge(10),
			//
			// WithCookieHTTPOnly indicates if CSRF cookie is HTTP only.
			// Optional. Default value false.
			//rkmuxcsrf.WithCookieHTTPOnly(false),
			//
			// WithCookieSameSite indicates SameSite mode of the CSRF cookie.
			// Optional. Default value SameSiteDefaultMode.
			//rkmuxcsrf.WithCookieSameSite(http.SameSiteStrictMode),
		),
	}

	// 1: Create mux server
	server := startGreeterServer(interceptors...)
	defer server.Shutdown(context.TODO())

	// 2: Wait for ctrl-C to shutdown server
	rkentry.GlobalAppCtx.WaitForShutdownSig()
}

// Start mux server.
func startGreeterServer(interceptors ...mux.MiddlewareFunc) *http.Server {
	router := mux.NewRouter()
	router.Use(interceptors...)
	router.NewRoute().Path("/v1/greeter").HandlerFunc(Greeter)

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: router,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return server
}

// GreeterResponse Response of Greeter.
type GreeterResponse struct {
	Message string
}

// Greeter Handler.
func Greeter(writer http.ResponseWriter, req *http.Request) {
	// ******************************************
	// ********** rpc-scoped logger *************
	// ******************************************
	rkmuxctx.GetLogger(req, writer).Info("Received request from client.")

	rkmuxinter.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("CSRF token:%v", rkmuxctx.GetCsrfToken(req)),
	})
}
