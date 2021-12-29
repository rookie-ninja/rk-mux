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
	"net/http"
)

// In this example, we will start a new mux server with log interceptor enabled.
// Listen on port of 8080 with GET /v1/greeter?name=<xxx>.
func main() {
	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []mux.MiddlewareFunc{
		//rkmuxmeta.Interceptor(),
		rkmuxlog.Interceptor(
		// Entry name and entry type will be used for distinguishing interceptors. Recommended.
		// rkmuxlog.WithEntryNameAndType("greeter", "mux"),
		//
		// Zap logger would be logged as JSON format.
		//rkmuxlog.WithZapLoggerEncoding(rkmuxlog.ENCODING_JSON),
		//
		// Event logger would be logged as JSON format.
		//rkmuxlog.WithEventLoggerEncoding(rkmuxlog.ENCODING_JSON),
		//
		// Zap logger would be logged to specified path.
		//rkmuxlog.WithZapLoggerOutputPaths("logs/server-zap.log"),
		//
		// Event logger would be logged to specified path.
		//rkmuxlog.WithEventLoggerOutputPaths("logs/server-event.log"),
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

// Greeter Handler for greeter.
func Greeter(writer http.ResponseWriter, req *http.Request) {
	// ******************************************
	// ********** rpc-scoped logger *************
	// ******************************************
	//
	// RequestId will be printed if enabled by bellow codes.
	// 1: Enable rkmuxmeta.Interceptor() in server side.
	// 2: rkmuxctx.SetHeaderToClient(ctx, rkmuxctx.RequestIdKey, rkcommon.GenerateRequestId())
	//
	rkmuxctx.GetLogger(req, writer).Info("Received request from client.")

	// *******************************************
	// ********** rpc-scoped event  *************
	// *******************************************
	//
	// Get rkquery.Event which would be printed as soon as request finish.
	// User can call any Add/Set/Get functions on rkquery.Event
	//
	// rkmuxctx.GetEvent(req).AddPair("rk-key", "rk-value")

	// *********************************************
	// ********** Get incoming headers *************
	// *********************************************
	//
	// Read headers sent from client.
	//
	//for k, v := range rkmuxctx.GetIncomingHeaders(req) {
	//	 fmt.Println(fmt.Sprintf("%s: %s", k, v))
	//}

	// *********************************************************
	// ********** Add headers will send to client **************
	// *********************************************************
	//
	// Send headers to client with this function
	//
	//rkmuxctx.AddHeaderToClient(writer, "from-server", "value")

	// ***********************************************
	// ********** Get and log request id *************
	// ***********************************************
	//
	// RequestId will be printed on both client and server side.
	//
	//rkmuxctx.SetHeaderToClient(writer, rkmuxctx.RequestIdKey, rkcommon.GenerateRequestId())

	rkmuxinter.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}
