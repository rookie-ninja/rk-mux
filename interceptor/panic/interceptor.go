// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxpanic is a middleware of mux framework for recovering from panic
package rkmuxpanic

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"go.uber.org/zap"
	"net/http"
	"runtime/debug"
)

// Interceptor returns a rest.Middleware (middleware)
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName))

			defer func() {
				if recv := recover(); recv != nil {
					var res *rkerror.ErrorResp

					if se, ok := recv.(*rkerror.ErrorResp); ok {
						res = se
					} else if re, ok := recv.(error); ok {
						res = rkerror.FromError(re)
					} else {
						res = rkerror.New(rkerror.WithMessage(fmt.Sprintf("%v", recv)))
					}

					rkmuxctx.GetEvent(req).SetCounter("panic", 1)
					rkmuxctx.GetEvent(req).AddErr(res.Err)
					rkmuxctx.GetLogger(req, writer).Error(fmt.Sprintf("panic occurs:\n%s", string(debug.Stack())), zap.Error(res.Err))

					rkmuxinter.WriteJson(writer, http.StatusInternalServerError, res)
				}
			}()

			next.ServeHTTP(writer, req)
		})
	}
}
