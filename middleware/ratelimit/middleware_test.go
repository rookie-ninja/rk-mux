// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxlimit

import (
	rkmid "github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/ratelimit"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestMiddleware(t *testing.T) {
	defer assertNotPanic(t)

	beforeCtx := rkmidlimit.NewBeforeCtx()
	mock := rkmidlimit.NewOptionSetMock(beforeCtx)

	// case 1: with error response
	inter := Middleware(rkmidlimit.WithMockOptionSet(mock))
	req, w := newReqAndWriter()
	// assign any of error response
	beforeCtx.Output.ErrResp = rkmid.GetErrorBuilder().New(http.StatusTooManyRequests, "")
	inter(userHandler).ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// case 2: happy case
	req, w = newReqAndWriter()
	beforeCtx.Output.ErrResp = nil
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
