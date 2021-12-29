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
	"github.com/rookie-ninja/rk-mux/interceptor/log/zap"
	"github.com/rookie-ninja/rk-mux/interceptor/panic"
	"net/http"
)

// In this example, we will start a new mux server with panic interceptor enabled.
// Listen on port of 8080 with GET /v1/greeter?name=<xxx>.
func main() {
	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []mux.MiddlewareFunc{
		rkmuxlog.Interceptor(),
		rkmuxpanic.Interceptor(),
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
	// All bellow panic case should return same error response.
	// {"error":{"code":500,"status":"Internal Server Error","message":"Panic manually!","details":[]}}

	// Panic interceptor will wrap error with standard RK style error.
	// Please refer to rkerror.ErrorResp.
	// panic(errors.New("Panic manually!"))

	// Please refer to rkerror.ErrorResp.
	// panic(rkerror.FromError(errors.New("Panic manually!")))

	// Please refer to rkerror.ErrorResp.
	panic("Panic manually!")

	rkmuxinter.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}
