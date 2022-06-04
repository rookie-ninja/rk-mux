// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxcsrf

import (
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/csrf"
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

	beforeCtx := rkmidcsrf.NewBeforeCtx()
	mock := rkmidcsrf.NewOptionSetMock(beforeCtx)

	// case 1: with error response
	inter := Middleware(rkmidcsrf.WithMockOptionSet(mock))
	req, w := newReqAndWriter()

	// assign any of error response
	beforeCtx.Output.ErrResp = rkmid.GetErrorBuilder().New(http.StatusForbidden, "")
	inter(userHandler).ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// case 2: happy case
	beforeCtx.Output.ErrResp = nil
	beforeCtx.Output.VaryHeaders = []string{"value"}
	beforeCtx.Output.Cookie = &http.Cookie{}
	req, w = newReqAndWriter()
	inter(userHandler).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get(rkmid.HeaderVary))
	assert.NotNil(t, w.Header().Get("Set-Cookie"))
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
