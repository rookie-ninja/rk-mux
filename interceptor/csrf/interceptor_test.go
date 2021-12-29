// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxcsrf

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userFunc = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)

	// match 1
	req, writer := newReqAndWriter(http.MethodGet)
	handler := Interceptor(WithSkipper(func(r *http.Request) bool {
		return true
	}))
	f := handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)

	// match 2.1
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Contains(t, writer.Header().Get("Set-Cookie"), "_csrf")

	// match 2.2
	req, writer = newReqAndWriter(http.MethodGet)
	req.AddCookie(&http.Cookie{
		Name:  "_csrf",
		Value: "ut-csrf-token",
	})
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Contains(t, writer.Header().Get("Set-Cookie"), "_csrf")

	// match 3.1
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)

	// match 3.2
	req, writer = newReqAndWriter(http.MethodPost)
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusBadRequest, writer.Result().StatusCode)

	// match 3.3
	req, writer = newReqAndWriter(http.MethodPost)
	req.Header.Set(headerXCSRFToken, "ut-csrf-token")
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusForbidden, writer.Result().StatusCode)

	// match 4.1
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor(
		WithCookiePath("ut-path"))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Contains(t, writer.Header().Get("Set-Cookie"), "ut-path")

	// match 4.2
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor(
		WithCookieDomain("ut-domain"))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Contains(t, writer.Header().Get("Set-Cookie"), "ut-domain")

	// match 4.3
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor(
		WithCookieSameSite(http.SameSiteStrictMode))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Contains(t, writer.Header().Get("Set-Cookie"), "Strict")
}

func newReqAndWriter(method string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, "/ut-path", nil)
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
