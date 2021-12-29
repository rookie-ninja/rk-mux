// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxtrace

import (
	"bytes"
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

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)
	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithExporter(&NoopExporter{}))

	req, writer := newReqAndWriter()

	f := handler(userFunc)
	f.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
}
