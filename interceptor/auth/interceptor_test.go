// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxauth

import (
	"fmt"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userFunc = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestInterceptor_WithIgnoringPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ut-ignore-path", nil)
	w := httptest.NewRecorder()

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithBasicAuth("ut-realm", "user:pass"),
		WithApiKeyAuth("ut-api-key"),
		WithIgnorePrefix("/ut-ignore-path"))

	f := handler(userFunc)
	f.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
}

func TestInterceptor_WithBasicAuth_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ut-path", nil)
	w := httptest.NewRecorder()

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithBasicAuth("ut-realm", "user:pass"))

	// set invalid auth header
	req.Header.Set(rkmuxinter.RpcAuthorizationHeaderKey, "invalid")

	f := handler(userFunc)
	f.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestInterceptor_WithBasicAuth_InvalidBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ut-path", nil)
	w := httptest.NewRecorder()

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithBasicAuth("ut-realm", "user:pass"))

	// set invalid auth header
	req.Header.Set(rkmuxinter.RpcAuthorizationHeaderKey, fmt.Sprintf("%s invalid", typeBasic))

	f := handler(userFunc)
	f.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestInterceptor_WithApiKey_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ut-path", nil)
	w := httptest.NewRecorder()

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithApiKeyAuth("ut-api-key"))

	// set invalid auth header
	req.Header.Set(rkmuxinter.RpcApiKeyHeaderKey, "invalid")

	f := handler(userFunc)
	f.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestInterceptor_MissingAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ut-path", nil)
	w := httptest.NewRecorder()

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithApiKeyAuth("ut-api-key"))

	f := handler(userFunc)
	f.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestInterceptor_HappyCase(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ut-ignore-path", nil)
	w := httptest.NewRecorder()

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		//WithBasicAuth("ut-realm", "user:pass"),
		WithApiKeyAuth("ut-api-key"))

	req.Header.Set(rkmuxinter.RpcApiKeyHeaderKey, "ut-api-key")

	f := handler(userFunc)
	f.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
}
