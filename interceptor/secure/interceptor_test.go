// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxsec

import (
	rkmidsec "github.com/rookie-ninja/rk-entry/middleware/secure"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)

	beforeCtx := rkmidsec.NewBeforeCtx()
	mock := rkmidsec.NewOptionSetMock(beforeCtx)

	// case 1: with error response
	inter := Interceptor(rkmidsec.WithMockOptionSet(mock))
	req, w := newReqAndWriter()
	// assign any of error response
	beforeCtx.Output.HeadersToReturn["key"] = "value"
	inter(userHandler).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "value", w.Header().Get("key"))
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

