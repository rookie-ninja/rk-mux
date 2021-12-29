// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	"fmt"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-mux/boot"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"net/http"
)

// @title RK Swagger for Mux
// @version 1.0
// @description This is a greeter service with rk-boot.
func main() {
	// Bootstrap basic entries from boot config.
	rkentry.RegisterInternalEntriesFromConfig("example/boot/simple/boot.yaml")

	// Bootstrap mux entry from boot config
	res := rkmux.RegisterMuxEntriesWithConfig("example/boot/simple/boot.yaml")

	// Get MuxEntry
	muxEntry := res["greeter"].(*rkmux.MuxEntry)
	// Use *mux.Router adding handler.
	muxEntry.Router.NewRoute().Path("/v1/greeter").HandlerFunc(Greeter)

	// Bootstrap mux entry
	muxEntry.Bootstrap(context.Background())

	// Wait for shutdown signal
	rkentry.GlobalAppCtx.WaitForShutdownSig()

	// Interrupt mux entry
	muxEntry.Interrupt(context.Background())
}

// @Summary Greeter service
// @Id 1
// @version 1.0
// @produce application/json
// @Param name query string true "Input name"
// @Success 200 {object} GreeterResponse
// @Router /v1/greeter [get]
func Greeter(writer http.ResponseWriter, req *http.Request) {
	rkmuxinter.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}

// Response.
type GreeterResponse struct {
	Message string
}
