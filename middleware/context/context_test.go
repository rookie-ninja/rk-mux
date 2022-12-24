// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxctx

import (
	"context"
	rkcursor "github.com/rookie-ninja/rk-entry/v2/cursor"
	rkmid "github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-logger"
	"github.com/rookie-ninja/rk-query"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/ut-path", nil)
	writer := httptest.NewRecorder()
	return req, writer
}

func TestGormCtx(t *testing.T) {
	req, w := newReqAndWriter()
	assert.NotNil(t, GormCtx(req, w))
}

func TestGetIncomingHeaders(t *testing.T) {
	req, _ := newReqAndWriter()
	req.Header.Set("ut-key", "ut-value")

	assert.Len(t, GetIncomingHeaders(req), 1)
	assert.Equal(t, "ut-value", GetIncomingHeaders(req).Get("ut-key"))
}

func TestAddHeaderToClient(t *testing.T) {
	defer assertNotPanic(t)

	_, writer := newReqAndWriter()

	// With nil writer
	AddHeaderToClient(writer, "", "")

	// Happy case
	AddHeaderToClient(writer, "ut-key", "ut-value")
	assert.Equal(t, "ut-value", writer.Header().Get("ut-key"))
}

func TestSetHeaderToClient(t *testing.T) {
	defer assertNotPanic(t)

	_, writer := newReqAndWriter()

	// With nil writer
	SetHeaderToClient(writer, "", "")

	// Happy case
	SetHeaderToClient(writer, "ut-key", "ut-value")
	assert.Equal(t, "ut-value", writer.Header().Get("ut-key"))
}

func TestGetEvent(t *testing.T) {
	// With no event in context
	req, _ := newReqAndWriter()
	assert.Equal(t, noopEvent, GetEvent(req))

	// Happy case
	event := rkquery.NewEventFactory().CreateEventNoop()
	req = req.WithContext(context.WithValue(req.Context(), rkmid.EventKey, event))
	assert.Equal(t, event, GetEvent(req))
}

func TestGetLogger(t *testing.T) {
	req, writer := newReqAndWriter()

	// With no logger in context
	assert.Equal(t, rklogger.NoopLogger, GetLogger(req, writer))

	// Happy case
	// Add request id and trace id
	writer.Header().Set(rkmid.HeaderRequestId, "ut-request-id")
	writer.Header().Set(rkmid.HeaderTraceId, "ut-trace-id")

	req = req.WithContext(context.WithValue(req.Context(), rkmid.LoggerKey, rklogger.NoopLogger))

	assert.Equal(t, rklogger.NoopLogger, GetLogger(req, writer))
}

func TestGetRequestId(t *testing.T) {
	_, writer := newReqAndWriter()

	// With no requestId in context
	assert.Empty(t, GetRequestId(writer))

	// Happy case
	writer.Header().Set(rkmid.HeaderRequestId, "ut-request-id")
	assert.Equal(t, "ut-request-id", GetRequestId(writer))
}

func TestGetTraceId(t *testing.T) {
	_, writer := newReqAndWriter()

	// With no traceId in context
	assert.Empty(t, GetTraceId(writer))

	// Happy case
	writer.Header().Set(rkmid.HeaderTraceId, "ut-trace-id")
	assert.Equal(t, "ut-trace-id", GetTraceId(writer))
}

func TestGetEntryName(t *testing.T) {
	req, _ := newReqAndWriter()

	// With no entry name in context
	assert.Empty(t, GetEntryName(req))

	// Happy case
	req = req.WithContext(context.WithValue(req.Context(), rkmid.EntryNameKey, "ut-entry-name"))
	assert.Equal(t, "ut-entry-name", GetEntryName(req))
}

func TestGetTraceSpan(t *testing.T) {
	req, _ := newReqAndWriter()

	// With no span in context
	assert.NotNil(t, GetTraceSpan(req))

	// Happy case
	_, span := noopTracerProvider.Tracer("ut-trace").Start(req.Context(), "noop-span")
	req = req.WithContext(context.WithValue(req.Context(), rkmid.SpanKey, span))
	assert.Equal(t, span, GetTraceSpan(req))
}

func TestGetTracer(t *testing.T) {
	req, _ := newReqAndWriter()

	// With no tracer in context
	assert.NotNil(t, GetTracer(req))

	// Happy case
	tracer := noopTracerProvider.Tracer("ut-trace")
	req = req.WithContext(context.WithValue(req.Context(), rkmid.TracerKey, tracer))
	assert.Equal(t, tracer, GetTracer(req))
}

func TestGetTracerProvider(t *testing.T) {
	req, _ := newReqAndWriter()

	// With no tracer provider in context
	assert.NotNil(t, GetTracerProvider(req))

	// Happy case
	provider := trace.NewNoopTracerProvider()
	req = req.WithContext(context.WithValue(req.Context(), rkmid.TracerProviderKey, provider))
	assert.Equal(t, provider, GetTracerProvider(req))
}

func TestGetTracerPropagator(t *testing.T) {
	req, _ := newReqAndWriter()

	// With no tracer propagator in context
	assert.Nil(t, GetTracerPropagator(req))

	// Happy case
	prop := propagation.NewCompositeTextMapPropagator()
	req = req.WithContext(context.WithValue(req.Context(), rkmid.PropagatorKey, prop))
	assert.Equal(t, prop, GetTracerPropagator(req))
}

func TestInjectSpanToHttpRequest(t *testing.T) {
	defer assertNotPanic(t)

	// Happy case
	req, _ := newReqAndWriter()

	prop := propagation.NewCompositeTextMapPropagator()
	req = req.WithContext(context.WithValue(req.Context(), rkmid.PropagatorKey, prop))

	InjectSpanToHttpRequest(req, &http.Request{
		Header: http.Header{},
	})
}

func TestNewTraceSpan(t *testing.T) {
	req, _ := newReqAndWriter()

	_, span := NewTraceSpan(req, "ut-span")
	assert.NotNil(t, span)
}

func TestEndTraceSpan(t *testing.T) {
	defer assertNotPanic(t)

	req, _ := newReqAndWriter()

	// With success
	span := GetTraceSpan(req)
	EndTraceSpan(span, true)

	// With failure
	span = GetTraceSpan(req)
	EndTraceSpan(span, false)
}

func TestSetPointerCreator(t *testing.T) {
	assert.Nil(t, pointerCreator)

	SetPointerCreator(createFakePointer)

	assert.NotNil(t, pointerCreator)
}

func createFakePointer(p *rkcursor.CursorPayload) rkcursor.Pointer {
	return &fakePointer{}
}

type fakePointer struct{}

func (f fakePointer) PrintError(err error) {
	//TODO implement me
	panic("implement me")
}

func (f fakePointer) ObserveError(err error) error {
	//TODO implement me
	panic("implement me")
}

func (f fakePointer) Release() {
	//TODO implement me
	panic("implement me")
}

func assertNotPanic(t *testing.T) {
	if r := recover(); r != nil {
		// Expect panic to be called with non nil error
		assert.True(t, false)
	} else {
		// This should never be called in case of a bug
		assert.True(t, true)
	}
}
