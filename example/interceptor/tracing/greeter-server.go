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
	"github.com/rookie-ninja/rk-mux/interceptor/tracing/telemetry"
	"net/http"
)

// In this example, we will start a new mux server with tracing interceptor enabled.
// Listen on port of 8080 with GET /v1/greeter?name=<xxx>.
func main() {
	// ****************************************
	// ********** Create Exporter *************
	// ****************************************

	// Export trace to stdout
	exporter := rkmuxtrace.CreateFileExporter("stdout")

	// Export trace to local file system
	//exporter := rkmuxtrace.CreateFileExporter("logs/trace.log")

	// Export trace to jaeger agent
	//exporter := rkmuxtrace.CreateJaegerExporter(jaeger.WithAgentEndpoint())

	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []mux.MiddlewareFunc{
		rkmuxlog.Interceptor(),
		rkmuxtrace.Interceptor(
			// Entry name and entry type will be used for distinguishing interceptors. Recommended.
			//rkmuxtrace.WithEntryNameAndType("greeter", "mux"),
			//
			// Provide an exporter.
			rkmuxtrace.WithExporter(exporter),
			//
			// Provide propagation.TextMapPropagator
			// rkmuxtrace.WithPropagator(<propagator>),
			//
			// Provide SpanProcessor
			// rkmuxtrace.WithSpanProcessor(<span processor>),
			//
			// Provide TracerProvider
			// rkmuxtrace.WithTracerProvider(<trace provider>),
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
