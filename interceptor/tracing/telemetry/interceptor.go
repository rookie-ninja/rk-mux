// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxtrace is aa middleware of mux framework for recording trace info of RPC
package rkmuxtrace

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"net/http"
)

// Interceptor create a interceptor with opentelemetry.
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName))
			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcTracerKey, set.Tracer))
			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcTracerProviderKey, set.Provider))
			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcPropagatorKey, set.Propagator))

			span, newReq := before(req, writer, set)
			defer span.End()

			next.ServeHTTP(writer, newReq)

			after(writer.(*rkmuxinter.RkResponseWriter), span)
		})
	}
}

func before(req *http.Request, writer http.ResponseWriter, set *optionSet) (oteltrace.Span, *http.Request) {
	opts := []oteltrace.SpanStartOption{
		oteltrace.WithAttributes(semconv.NetAttributesFromHTTPRequest("tcp", req)...),
		oteltrace.WithAttributes(semconv.EndUserAttributesFromHTTPRequest(req)...),
		oteltrace.WithAttributes(semconv.HTTPServerAttributesFromHTTPRequest(rkentry.GlobalAppCtx.GetAppInfoEntry().AppName, req.URL.Path, req)...),
		oteltrace.WithAttributes(localeToAttributes()...),
		oteltrace.WithSpanKind(oteltrace.SpanKindServer),
	}

	// 1: extract tracing info from request header
	spanCtx := oteltrace.SpanContextFromContext(
		set.Propagator.Extract(req.Context(), propagation.HeaderCarrier(req.Header)))

	spanName := req.URL.Path
	if len(spanName) < 1 {
		spanName = "rk-span-default"
	}

	// 2: start new span
	newRequestCtx, span := set.Tracer.Start(
		oteltrace.ContextWithRemoteSpanContext(req.Context(), spanCtx),
		spanName, opts...)
	// 2.1: pass the span through the request context
	req = req.WithContext(newRequestCtx)

	// 3: read trace id, tracer, traceProvider, propagator and logger into event data and request context
	rkmuxctx.GetEvent(req).SetTraceId(span.SpanContext().TraceID().String())
	writer.Header().Set(rkmuxctx.TraceIdKey, span.SpanContext().TraceID().String())

	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcSpanKey, span))
	return span, req
}

func after(writer *rkmuxinter.RkResponseWriter, span oteltrace.Span) {
	attrs := semconv.HTTPAttributesFromHTTPStatusCode(writer.Code)
	spanStatus, spanMessage := semconv.SpanStatusFromHTTPStatusCode(writer.Code)
	span.SetAttributes(attrs...)
	span.SetStatus(spanStatus, spanMessage)
}

// Convert locale information into attributes.
func localeToAttributes() []attribute.KeyValue {
	res := []attribute.KeyValue{
		attribute.String(rkmuxinter.Realm.Key, rkmuxinter.Realm.String),
		attribute.String(rkmuxinter.Region.Key, rkmuxinter.Region.String),
		attribute.String(rkmuxinter.AZ.Key, rkmuxinter.AZ.String),
		attribute.String(rkmuxinter.Domain.Key, rkmuxinter.Domain.String),
	}

	return res
}
