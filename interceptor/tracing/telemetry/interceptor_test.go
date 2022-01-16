// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxtrace

import (
	"context"
	rkmidtrace "github.com/rookie-ninja/rk-entry/middleware/tracing"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)

	beforeCtx := rkmidtrace.NewBeforeCtx()
	afterCtx := rkmidtrace.NewAfterCtx()
	mock := rkmidtrace.NewOptionSetMock(beforeCtx, afterCtx, nil, nil, nil)
	beforeCtx.Output.NewCtx = context.TODO()

	// case 1: with error response
	inter := Interceptor(rkmidtrace.WithMockOptionSet(mock))
	req, w := newReqAndWriter()

	inter(userHandler).ServeHTTP(w, req)

	// case 2: happy case
	req, w = newReqAndWriter()
	noopTracerProvider := trace.NewNoopTracerProvider()
	_, span := noopTracerProvider.Tracer("rk-trace-noop").Start(req.Context(), "noop-span")
	beforeCtx.Output.Span = span

	inter(userHandler).ServeHTTP(w, req)
}

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/ut-path", nil)
	req.Header = http.Header{}
	writer := httptest.NewRecorder()
	return req, writer
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