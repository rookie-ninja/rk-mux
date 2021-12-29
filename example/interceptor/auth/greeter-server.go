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
	"github.com/rookie-ninja/rk-mux/interceptor/auth"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"github.com/rookie-ninja/rk-mux/interceptor/log/zap"
	"net/http"
)

// In this example, we will start a new mux server with auth interceptor enabled.
// Listen on port of 8080 with GET /v1/greeter?name=<xxx>.
func main() {
	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []mux.MiddlewareFunc{
		rkmuxlog.Interceptor(),
		rkmuxauth.Interceptor(
			// rkmuxauth.WithIgnorePrefix("/rk/v1/greeter"),
			rkmuxauth.WithBasicAuth("", "rk-user:rk-pass"),
			rkmuxauth.WithApiKeyAuth("rk-api-key"),
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
	router.NewRoute().Methods(http.MethodGet).Path("/v1/greeter").HandlerFunc(Greeter)

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
	validateCtx(writer, req)

	rkmuxinter.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}

func validateCtx(writer http.ResponseWriter, req *http.Request) {
	// 1: get incoming headers
	printIndex("[1]: get incoming headers")
	prettyHeader(rkmuxctx.GetIncomingHeaders(req))

	// 2: add header to client
	printIndex("[2]: add header to client")
	rkmuxctx.AddHeaderToClient(writer, "add-key", "add-value")

	// 3: set header to client
	printIndex("[3]: set header to client")
	rkmuxctx.SetHeaderToClient(writer, "set-key", "set-value")

	// 4: get event
	printIndex("[4]: get event")
	rkmuxctx.GetEvent(req).SetCounter("my-counter", 1)

	// 5: get logger
	printIndex("[5]: get logger")
	rkmuxctx.GetLogger(req, writer).Info("error msg")

	// 6: get request id
	printIndex("[6]: get request id")
	fmt.Println(rkmuxctx.GetRequestId(writer))

	// 7: get trace id
	printIndex("[7]: get trace id")
	fmt.Println(rkmuxctx.GetTraceId(writer))

	// 8: get entry name
	printIndex("[8]: get entry name")
	fmt.Println(rkmuxctx.GetEntryName(req))

	// 9: get trace span
	printIndex("[9]: get trace span")
	fmt.Println(rkmuxctx.GetTraceSpan(req))

	// 10: get tracer
	printIndex("[10]: get tracer")
	fmt.Println(rkmuxctx.GetTracer(req))

	// 11: get trace provider
	printIndex("[11]: get trace provider")
	fmt.Println(rkmuxctx.GetTracerProvider(req))

	// 12: get tracer propagator
	printIndex("[12]: get tracer propagator")
	fmt.Println(rkmuxctx.GetTracerPropagator(req))

	// 13: inject span
	printIndex("[13]: inject span")
	rkmuxctx.InjectSpanToHttpRequest(req, &http.Request{})

	// 14: new trace span
	printIndex("[14]: new trace span")
	fmt.Println(rkmuxctx.NewTraceSpan(req, "my-span"))

	// 15: end trace span
	printIndex("[15]: end trace span")
	_, span := rkmuxctx.NewTraceSpan(req, "my-span")
	rkmuxctx.EndTraceSpan(span, true)
}

func printIndex(key string) {
	fmt.Println(fmt.Sprintf("%s", key))
}

func prettyHeader(header http.Header) {
	for k, v := range header {
		fmt.Println(fmt.Sprintf("%s:%s", k, v))
	}
}
