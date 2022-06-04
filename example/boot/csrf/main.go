// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/rookie-ninja/rk-entry/v2/entry"
	"github.com/rookie-ninja/rk-mux/boot"
	rkmuxmid "github.com/rookie-ninja/rk-mux/middleware"
	"github.com/rookie-ninja/rk-mux/middleware/context"
	"net/http"
)

//go:embed boot.yaml
var boot []byte

func main() {
	// Bootstrap preload entries
	rkentry.BootstrapBuiltInEntryFromYAML(boot)
	rkentry.BootstrapPluginEntryFromYAML(boot)

	// Bootstrap gin entry from boot config
	res := rkmux.RegisterMuxEntryYAML(boot)

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

	rkmuxmid.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("CSRF token:%v", rkmuxctx.GetCsrfToken(req)),
	})
}
