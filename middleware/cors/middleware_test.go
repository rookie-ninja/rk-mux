// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package rkmuxcors

import (
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/cors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

const originHeaderValue = "http://ut-origin"

var userHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestMiddleware(t *testing.T) {
	defer assertNotPanic(t)

	beforeCtx := rkmidcors.NewBeforeCtx()
	beforeCtx.Output.HeadersToReturn["key"] = "value"
	beforeCtx.Output.HeaderVary = []string{"vary"}
	mock := rkmidcors.NewOptionSetMock(beforeCtx)

	// case 1: abort
	inter := Middleware(rkmidcors.WithMockOptionSet(mock))
	req, w := newReqAndWriter()
	beforeCtx.Output.Abort = true
	inter(userHandler).ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "value", w.Header().Get("key"))
	assert.Equal(t, "vary", w.Header().Get(rkmid.HeaderVary))

	// case 2: happy case
	req, w = newReqAndWriter()
	beforeCtx.Output.Abort = false
	inter(userHandler).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
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
