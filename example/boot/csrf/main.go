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
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"net/http"
)

func main() {
	// Bootstrap basic entries from boot config.
	rkentry.RegisterInternalEntriesFromConfig("example/boot/csrf/boot.yaml")

	// Bootstrap echo entry from boot config
	res := rkmux.RegisterMuxEntriesWithConfig("example/boot/csrf/boot.yaml")

	// Register GET and POST method of /rk/v1/greeter
	entry := res["greeter"].(*rkmux.MuxEntry)
	entry.Router.NewRoute().Path("/v1/greeter").HandlerFunc(Greeter)

	// Bootstrap echo entry
	res["greeter"].Bootstrap(context.Background())

	// Wait for shutdown signal
	rkentry.GlobalAppCtx.WaitForShutdownSig()

	// Interrupt echo entry
	res["greeter"].Interrupt(context.Background())
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
