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
	"github.com/rookie-ninja/rk-mux/interceptor/metrics/prom"
	"github.com/rookie-ninja/rk-prom"
	"net/http"
)

// In this example, we will start a new mux server with metrics interceptor enabled.
// Listen on port of 8080 with GET /v1/greeter?name=<xxx>.
func main() {
	// Override app name which would replace namespace value in prometheus.
	// rkentry.GlobalAppCtx.GetAppInfoEntry().AppName = "newApp"

	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []mux.MiddlewareFunc{
		rkmuxmetrics.Interceptor(
			// Entry name and entry type will be used for distinguishing interceptors. Recommended.
			rkmuxmetrics.WithEntryNameAndType("greeter", "mux"),
			//
			// Provide new prometheus registerer.
			// Default value is prometheus.DefaultRegisterer
			//rkmuxmetrics.WithRegisterer(prometheus.NewRegistry()),
		),
	}

	// 1: Start prometheus client
	// By default, we will start prometheus client at localhost:1608/metrics
	promEntry := rkprom.RegisterPromEntry()
	promEntry.Bootstrap(context.Background())
	defer promEntry.Interrupt(context.Background())

	// 2: Create mux server
	server := startGreeterServer(interceptors...)
	defer server.Shutdown(context.TODO())

	// 3: Wait for ctrl-C to shutdown server
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
