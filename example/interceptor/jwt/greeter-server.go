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
	"github.com/rookie-ninja/rk-mux/interceptor/jwt"
	"net/http"
)

// In this example, we will start a new mux server with jwt interceptor enabled.
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
		//rkmuxlog.Interceptor(),
		rkmuxjwt.Interceptor(
			// Required, entry name and entry type will be used for distinguishing interceptors. Recommended.
			//rkmuxjwt.WithEntryNameAndType("greeter", "mux"),
			//
			// Required, provide signing key.
			rkmuxjwt.WithSigningKey([]byte("my-secret")),
			//
			// Optional, provide skipper function
			//rkmuxjwt.WithSkipper(func(*http.Request) bool {
			//	return true
			//}),
			//
			// Optional, provide token parse function, default one will be assigned.
			//rkmuxjwt.WithParseTokenFunc(func(auth string, req *http.Request) (*jwt.Token, error) {
			//	return nil, nil
			//}),
			//
			// Optional, provide key function, default one will be assigned.
			//rkmuxjwt.WithKeyFunc(func(token *jwt.Token) (interface{}, error) {
			//	return nil, nil
			//}),
			//
			// Optional, default is Bearer
			//rkmuxjwt.WithAuthScheme("Bearer"),
			//
			// Optional
			//rkmuxjwt.WithTokenLookup("header:my-jwt-header-key"),
			//
			// Optional, default is HS256
			//rkmuxjwt.WithSigningAlgorithm(rkmuxjwt.AlgorithmHS256),
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
		Message: fmt.Sprintf("Is token valid:%v!", rkmuxctx.GetJwtToken(req).Valid),
	})
}
