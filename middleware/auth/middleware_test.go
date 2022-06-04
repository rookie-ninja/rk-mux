// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxauth

import (
	rkmid "github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/auth"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userFunc = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestInterceptor(t *testing.T) {
	beforeCtx := rkmidauth.NewBeforeCtx()
	mock := rkmidauth.NewOptionSetMock(beforeCtx)

	// case 1: with error response
	inter := Middleware(rkmidauth.WithMockOptionSet(mock))
	req := httptest.NewRequest(http.MethodGet, "/ut-ignore-path", nil)
	w := httptest.NewRecorder()

	// assign any of error response
	beforeCtx.Output.ErrResp = rkmid.GetErrorBuilder().New(http.StatusUnauthorized, "")
	beforeCtx.Output.HeadersToReturn["key"] = "value"
	inter(userFunc).ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "value", w.Header().Get("key"))

	// case 2: happy case
	beforeCtx.Output.ErrResp = nil
	req = httptest.NewRequest(http.MethodGet, "/ut-ignore-path", nil)
	w = httptest.NewRecorder()
	inter(userFunc).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
