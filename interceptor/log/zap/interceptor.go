// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmuxlog is a middleware for mux framework for logging RPC.
package rkmuxlog

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"github.com/rookie-ninja/rk-query"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"time"
)

// Interceptor returns a gin.HandlerFunc (middleware) that logs requests using uber-go/zap.
func Interceptor(opts ...Option) mux.MiddlewareFunc {
	set := newOptionSet(opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkmuxinter.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, set.EntryName))

			req = before(req, set)

			next.ServeHTTP(writer, req)

			after(req, writer, set)
		})
	}
}

func before(req *http.Request, set *optionSet) *http.Request {
	var event rkquery.Event
	if rkmuxinter.ShouldLog(req) {
		event = set.eventLoggerEntry.GetEventFactory().CreateEvent(
			rkquery.WithZapLogger(set.eventLoggerOverride),
			rkquery.WithEncoding(set.eventLoggerEncoding),
			rkquery.WithAppName(rkentry.GlobalAppCtx.GetAppInfoEntry().AppName),
			rkquery.WithAppVersion(rkentry.GlobalAppCtx.GetAppInfoEntry().Version),
			rkquery.WithEntryName(set.EntryName),
			rkquery.WithEntryType(set.EntryType))
	} else {
		event = set.eventLoggerEntry.GetEventFactory().CreateEventNoop()
	}

	event.SetStartTime(time.Now())

	remoteIp, remotePort := rkmuxinter.GetRemoteAddressSet(req)
	// handle remote address
	event.SetRemoteAddr(remoteIp + ":" + remotePort)

	payloads := []zap.Field{
		zap.String("apiPath", req.URL.Path),
		zap.String("apiMethod", req.Method),
		zap.String("apiQuery", req.URL.RawQuery),
		zap.String("apiProtocol", req.Proto),
		zap.String("userAgent", req.UserAgent()),
	}

	// handle payloads
	event.AddPayloads(payloads...)

	// handle operation
	event.SetOperation(req.URL.Path)

	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEventKey, event))
	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcLoggerKey, set.ZapLogger))

	return req
}

func after(req *http.Request, writer http.ResponseWriter, set *optionSet) {
	event := rkmuxctx.GetEvent(req)

	if requestId := rkmuxctx.GetRequestId(writer); len(requestId) > 0 {
		event.SetEventId(requestId)
		event.SetRequestId(requestId)
	}

	if traceId := rkmuxctx.GetTraceId(writer); len(traceId) > 0 {
		event.SetTraceId(traceId)
	}

	// writer must be RkResponseWriter
	event.SetResCode(strconv.Itoa(writer.(*rkmuxinter.RkResponseWriter).Code))
	event.SetEndTime(time.Now())
	event.Finish()
}
