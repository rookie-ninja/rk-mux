// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxjwt

import (
	rkerror "github.com/rookie-ninja/rk-entry/v2/error"
	"github.com/rookie-ninja/rk-entry/v2/middleware/jwt"
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

	beforeCtx := rkmidjwt.NewBeforeCtx()
	mock := rkmidjwt.NewOptionSetMock(beforeCtx)
	inter := Interceptor(rkmidjwt.WithMockOptionSet(mock))

	// case 1: error response
	beforeCtx.Output.ErrResp = rkerror.NewUnauthorized("")
	req, w := newReqAndWriter()
	inter(userHandler).ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// case 2: happy case
	beforeCtx.Output.ErrResp = nil
	req, w = newReqAndWriter()
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
