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
	"github.com/rookie-ninja/rk-mux/interceptor/secure"
	"net/http"
)

// In this example, we will start a new mux server with secure interceptor enabled.
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
		rkmuxsec.Interceptor(
			// Required, entry name and entry type will be used for distinguishing interceptors. Recommended.
			rkmuxsec.WithEntryNameAndType("greeter", "mux"),
			//
			// X-XSS-Protection header value.
			// Optional. Default value "1; mode=block".
			//rkmuxsec.WithXSSProtection("my-value"),
			//
			// X-Content-Type-Options header value.
			// Optional. Default value "nosniff".
			//rkmuxsec.WithContentTypeNosniff("my-value"),
			//
			// X-Frame-Options header value.
			// Optional. Default value "SAMEORIGIN".
			//rkmuxsec.WithXFrameOptions("my-value"),
			//
			// Optional, Strict-Transport-Security header value.
			//rkmuxsec.WithHSTSMaxAge(1),
			//
			// Optional, excluding subdomains of HSTS, default is false
			//rkmuxsec.WithHSTSExcludeSubdomains(true),
			//
			// Optional, enabling HSTS preload, default is false
			//rkmuxsec.WithHSTSPreloadEnabled(true),
			//
			// Content-Security-Policy header value.
			// Optional. Default value "".
			//rkmuxsec.WithContentSecurityPolicy("my-value"),
			//
			// Content-Security-Policy-Report-Only header value.
			// Optional. Default value false.
			//rkmuxsec.WithCSPReportOnly(true),
			//
			// Referrer-Policy header value.
			// Optional. Default value "".
			//rkmuxsec.WithReferrerPolicy("my-value"),
			//
			// Ignoring path prefix.
			//rkmuxsec.WithIgnorePrefix("/rk/v1"),
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
	//
	// RequestId will be printed if enabled by bellow codes.
	// 1: Enable rkmuxmeta.Interceptor() in server side.
	// 2: rkmuxctx.SetHeaderToClient(writer, rkmuxctx.RequestIdKey, rkcommon.GenerateRequestId())
	//
	rkmuxctx.GetLogger(req, writer).Info("Received request from client.")

	rkmuxinter.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}
