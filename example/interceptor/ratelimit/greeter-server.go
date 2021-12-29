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
	"github.com/rookie-ninja/rk-mux/interceptor/log/zap"
	"github.com/rookie-ninja/rk-mux/interceptor/ratelimit"
	"net/http"
)

// In this example, we will start a new mux server with rate limit interceptor enabled.
// Listen on port of 8080 with GET /v1/greeter?name=<xxx>.
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
		rkmuxlog.Interceptor(),
		rkmuxlimit.Interceptor(
		// Entry name and entry type will be used for distinguishing interceptors. Recommended.
		//rkmuxmeta.WithEntryNameAndType("greeter", "mux"),
		//
		// Provide algorithm, rkmuxlimit.LeakyBucket and rkmuxlimit.TokenBucket was available, default is TokenBucket.
		//rkmuxlimit.WithAlgorithm(rkmuxlimit.LeakyBucket),
		//
		// Provide request per second, if provide value of zero, then no requests will be pass through and user will receive an error with
		// resource exhausted.
		//rkmuxlimit.WithReqPerSec(10),
		//
		// Provide request per second with path name.
		// The name should be full path name. if provide value of zero,
		// then no requests will be pass through and user will receive an error with resource exhausted.
		//rkmuxlimit.WithReqPerSecByPath("/v1/greeter", 0),
		//
		// Provide user function of limiter. Returns error if you want to limit the request.
		// Please do not try to set response code since it will be overridden by middleware.
		//rkmuxlimit.WithGlobalLimiter(func(req *http.Request) error {
		//	return fmt.Errorf("limited by custom limiter")
		//}),
		//
		// Provide user function of limiter by path name.
		// The name should be full path name.
		//rkmuxlimit.WithLimiterByPath("/v1/greeter", func(*http.Request) error {
		//	 return nil
		//}),
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
