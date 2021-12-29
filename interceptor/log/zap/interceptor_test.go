// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxlog

import (
	"bytes"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"github.com/rookie-ninja/rk-query"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userFunc = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	var buf bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "/ut-path", &buf)
	writer := httptest.NewRecorder()
	return req, writer
}

func TestInterceptor_WithShouldNotLog(t *testing.T) {
	defer assertNotPanic(t)

	req, writer := newReqAndWriter()
	req.URL.Path = "/rk/v1/assets"

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithZapLoggerEntry(rkentry.NoopZapLoggerEntry()),
		WithEventLoggerEntry(rkentry.NoopEventLoggerEntry()))

	f := handler(userFunc)
	f.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
}

func TestInterceptor_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	req, writer := newReqAndWriter()

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithZapLoggerEntry(rkentry.NoopZapLoggerEntry()),
		WithEventLoggerEntry(rkentry.NoopEventLoggerEntry()))

	writer.Header().Set(rkmuxctx.RequestIdKey, "ut-request-id")
	writer.Header().Set(rkmuxctx.TraceIdKey, "ut-trace-id")

	f := handler(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		req = request
		w.WriteHeader(http.StatusOK)
	}))

	f.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)

	event := rkmuxctx.GetEvent(req)

	assert.NotEmpty(t, event.GetRemoteAddr())
	assert.NotEmpty(t, event.ListPayloads())
	assert.NotEmpty(t, event.GetOperation())
	assert.NotEmpty(t, event.GetRequestId())
	assert.NotEmpty(t, event.GetTraceId())
	assert.NotEmpty(t, event.GetResCode())
	assert.Equal(t, rkquery.Ended, event.GetEventStatus())
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
