// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxctx defines utility functions and variables used by gorilla/mux middleware
package rkmuxctx

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	rkcursor "github.com/rookie-ninja/rk-entry/v2/cursor"
	rkmid "github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-logger"
	"github.com/rookie-ninja/rk-query"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

var (
	noopTracerProvider = trace.NewNoopTracerProvider()
	noopEvent          = rkquery.NewEventFactory().CreateEventNoop()
	pointerCreator     rkcursor.PointerCreator
)

// GetIncomingHeaders extract call-scoped incoming headers
func GetIncomingHeaders(req *http.Request) http.Header {
	return req.Header
}

// AddHeaderToClient headers that would be sent to client.
// Values would be merged.
func AddHeaderToClient(writer http.ResponseWriter, key, value string) {
	if writer == nil {
		return
	}

	writer.Header().Add(key, value)
}

// SetHeaderToClient headers that would be sent to client.
// Values would be overridden.
func SetHeaderToClient(writer http.ResponseWriter, key, value string) {
	if writer == nil {
		return
	}
	writer.Header().Set(key, value)
}

// SetPointerCreator override  rkcursor.PointerCreator
func SetPointerCreator(creator rkcursor.PointerCreator) {
	pointerCreator = creator
}

// GetCursor create rkcursor.Cursor instance
func GetCursor(req *http.Request, writer http.ResponseWriter) *rkcursor.Cursor {
	res := rkcursor.NewCursor(
		rkcursor.WithLogger(GetLogger(req, writer)),
		rkcursor.WithEvent(GetEvent(req)),
		rkcursor.WithEntryNameAndType(GetEntryName(req), "MuxEntry"))

	if pointerCreator != nil {
		res.Creator = pointerCreator
	}

	return res
}

// GetEvent extract takes the call-scoped EventData from middleware.
func GetEvent(req *http.Request) rkquery.Event {
	if req == nil {
		return noopEvent
	}

	if event := req.Context().Value(rkmid.EventKey); event != nil {
		return event.(rkquery.Event)
	}

	return noopEvent
}

// GetLogger extract takes the call-scoped zap logger from middleware.
func GetLogger(req *http.Request, writer http.ResponseWriter) *zap.Logger {
	if req == nil {
		return rklogger.NoopLogger
	}

	if logger := req.Context().Value(rkmid.LoggerKey); logger != nil {
		requestId := GetRequestId(writer)
		traceId := GetTraceId(writer)
		fields := make([]zap.Field, 0)
		if len(requestId) > 0 {
			fields = append(fields, zap.String("requestId", requestId))
		}
		if len(traceId) > 0 {
			fields = append(fields, zap.String("traceId", traceId))
		}

		return logger.(*zap.Logger).With(fields...)
	}

	return rklogger.NoopLogger
}

func GormCtx(req *http.Request, writer http.ResponseWriter) context.Context {
	res := context.Background()
	res = context.WithValue(res, rkmid.LoggerKey.String(), GetLogger(req, writer))
	res = context.WithValue(res, rkmid.EventKey.String(), GetEvent(req))
	return res
}

// GetRequestId extract request id from ResponseWriter.
// If user enabled meta interceptor, then a random request Id would e assigned and set to ResponseWriter as value.
// If user called AddHeaderToClient() with key of RequestIdKey, then a new request id would be updated.
func GetRequestId(w http.ResponseWriter) string {
	if w == nil {
		return ""
	}

	return w.Header().Get(rkmid.HeaderRequestId)
}

// GetTraceId extract trace id from ResponseWriter.
func GetTraceId(w http.ResponseWriter) string {
	if w == nil {
		return ""
	}

	return w.Header().Get(rkmid.HeaderTraceId)
}

// GetEntryName extract entry name from Request.
func GetEntryName(req *http.Request) string {
	if req == nil {
		return ""
	}

	if raw := req.Context().Value(rkmid.EntryNameKey); raw != nil {
		return raw.(string)
	}

	return ""
}

// GetTraceSpan extract the call-scoped span from Request.
func GetTraceSpan(req *http.Request) trace.Span {
	_, span := noopTracerProvider.Tracer("rk-trace-noop").Start(context.TODO(), "noop-span")

	if req == nil {
		return span
	}

	_, span = noopTracerProvider.Tracer("rk-trace-noop").Start(req.Context(), "noop-span")

	if raw := req.Context().Value(rkmid.SpanKey); raw != nil {
		return raw.(trace.Span)
	}

	return span
}

// GetTracer extract the call-scoped tracer from Request.
func GetTracer(req *http.Request) trace.Tracer {
	if req == nil {
		return noopTracerProvider.Tracer("rk-trace-noop")
	}

	if raw := req.Context().Value(rkmid.TracerKey); raw != nil {
		return raw.(trace.Tracer)
	}

	return noopTracerProvider.Tracer("rk-trace-noop")
}

// GetTracerProvider extract the call-scoped tracer provider from Request.
func GetTracerProvider(req *http.Request) trace.TracerProvider {
	if req == nil {
		return noopTracerProvider
	}

	if raw := req.Context().Value(rkmid.TracerProviderKey); raw != nil {
		return raw.(trace.TracerProvider)
	}

	return noopTracerProvider
}

// GetTracerPropagator extract takes the call-scoped propagator from middleware.
func GetTracerPropagator(req *http.Request) propagation.TextMapPropagator {
	if req == nil {
		return nil
	}

	if raw := req.Context().Value(rkmid.PropagatorKey); raw != nil {
		return raw.(propagation.TextMapPropagator)
	}

	return nil
}

// InjectSpanToHttpRequest inject span to http request
func InjectSpanToHttpRequest(src *http.Request, dest *http.Request) {
	if src == nil || dest == nil {
		return
	}

	newCtx := trace.ContextWithRemoteSpanContext(src.Context(), GetTraceSpan(src).SpanContext())

	if propagator := GetTracerPropagator(src); propagator != nil {
		propagator.Inject(newCtx, propagation.HeaderCarrier(dest.Header))
	}
}

// NewTraceSpan start a new span
func NewTraceSpan(req *http.Request, name string) (*http.Request, trace.Span) {
	tracer := GetTracer(req)
	newCtx, span := tracer.Start(req.Context(), name)

	GetEvent(req).StartTimer(name)

	return req.WithContext(newCtx), span
}

// EndTraceSpan end span
func EndTraceSpan(span trace.Span, success bool) {
	if success {
		span.SetStatus(otelcodes.Ok, otelcodes.Ok.String())
	}

	span.End()
}

// GetJwtToken return jwt.Token if exists
func GetJwtToken(req *http.Request) *jwt.Token {
	if req == nil {
		return nil
	}

	if raw := req.Context().Value(rkmid.JwtTokenKey); raw != nil {
		if res, ok := raw.(*jwt.Token); ok {
			return res
		}
	}

	return nil
}

// GetCsrfToken return csrf token if exists
func GetCsrfToken(req *http.Request) string {
	if req == nil {
		return ""
	}

	if raw := req.Context().Value(rkmid.CsrfTokenKey); raw != nil {
		if res, ok := raw.(string); ok {
			return res
		}
	}

	return ""
}
