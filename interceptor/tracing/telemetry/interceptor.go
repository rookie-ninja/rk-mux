// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxtrace is aa middleware of mux framework for recording trace info of RPC
package rkmuxtrace

import (
	"context"
	"github.com/gorilla/mux"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidtrace "github.com/rookie-ninja/rk-entry/middleware/tracing"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"net/http"
)

// Interceptor create a interceptor with opentelemetry.
func Interceptor(opts ...rkmidtrace.Option) mux.MiddlewareFunc {
	set := rkmidtrace.NewOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			ctx = context.WithValue(req.Context(), rkmid.TracerKey, set.GetTracer())
			req = req.WithContext(ctx)

			ctx = context.WithValue(req.Context(), rkmid.TracerProviderKey, set.GetProvider())
			req = req.WithContext(ctx)

			ctx = context.WithValue(req.Context(), rkmid.PropagatorKey, set.GetPropagator())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req, false)
			set.Before(beforeCtx)

			// create request with new context
			req = req.WithContext(beforeCtx.Output.NewCtx)

			// add to context
			if beforeCtx.Output.Span != nil {
				traceId := beforeCtx.Output.Span.SpanContext().TraceID().String()
				rkmuxctx.GetEvent(req).SetTraceId(traceId)
				writer.Header().Set(rkmid.HeaderTraceId, traceId)
				ctx = context.WithValue(req.Context(), rkmid.SpanKey, beforeCtx.Output.Span)
				req = req.WithContext(ctx)
			}

			next.ServeHTTP(writer, req)

			afterCtx := set.AfterCtx(writer.(*rkmuxinter.RkResponseWriter).Code, "")
			set.After(beforeCtx, afterCtx)
		})
	}
}
