// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package rkmuxcors

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

const originHeaderValue = "http://ut-origin"

var userFunc = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)

	// with skipper
	req, writer := newReqAndWriter(http.MethodGet)
	handler := Interceptor(WithSkipper(func(r *http.Request) bool {
		return true
	}))
	f := handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)

	// with empty option, all request will be passed
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)

	// match 1.1
	req, writer = newReqAndWriter(http.MethodGet)
	req.Header.Del(headerOrigin)
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)

	// match 1.2
	req, writer = newReqAndWriter(http.MethodOptions)
	req.Header.Del(headerOrigin)
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusNoContent, writer.Result().StatusCode)

	// match 2
	req, writer = newReqAndWriter(http.MethodOptions)
	handler = Interceptor(WithAllowOrigins("http://do-not-pass-through"))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusNoContent, writer.Result().StatusCode)

	// match 3
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Equal(t, originHeaderValue, writer.Header().Get(headerAccessControlAllowOrigin))

	// match 3.1
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor(WithAllowCredentials(true))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Equal(t, originHeaderValue, writer.Header().Get(headerAccessControlAllowOrigin))
	assert.Equal(t, "true", writer.Header().Get(headerAccessControlAllowCredentials))

	// match 3.2
	req, writer = newReqAndWriter(http.MethodGet)
	handler = Interceptor(
		WithAllowCredentials(true),
		WithExposeHeaders("expose"))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Equal(t, originHeaderValue, writer.Header().Get(headerAccessControlAllowOrigin))
	assert.Equal(t, "true", writer.Header().Get(headerAccessControlAllowCredentials))
	assert.Equal(t, "expose", writer.Header().Get(headerAccessControlExposeHeaders))

	// match 4
	req, writer = newReqAndWriter(http.MethodOptions)
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusNoContent, writer.Result().StatusCode)
	assert.Equal(t, []string{
		headerAccessControlRequestMethod,
		headerAccessControlRequestHeaders,
	}, writer.Header().Values(headerVary))
	assert.Equal(t, originHeaderValue, writer.Header().Get(headerAccessControlAllowOrigin))
	assert.NotEmpty(t, writer.Header().Get(headerAccessControlAllowMethods))

	// match 4.1
	req, writer = newReqAndWriter(http.MethodOptions)
	handler = Interceptor(WithAllowCredentials(true))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusNoContent, writer.Result().StatusCode)
	assert.Equal(t, []string{
		headerAccessControlRequestMethod,
		headerAccessControlRequestHeaders,
	}, writer.Header().Values(headerVary))
	assert.Equal(t, originHeaderValue, writer.Header().Get(headerAccessControlAllowOrigin))
	assert.NotEmpty(t, writer.Header().Get(headerAccessControlAllowMethods))
	assert.Equal(t, "true", writer.Header().Get(headerAccessControlAllowCredentials))

	// match 4.2
	req, writer = newReqAndWriter(http.MethodOptions)
	handler = Interceptor(WithAllowHeaders("ut-header"))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusNoContent, writer.Result().StatusCode)
	assert.Equal(t, []string{
		headerAccessControlRequestMethod,
		headerAccessControlRequestHeaders,
	}, writer.Header().Values(headerVary))
	assert.Equal(t, originHeaderValue, writer.Header().Get(headerAccessControlAllowOrigin))
	assert.NotEmpty(t, writer.Header().Get(headerAccessControlAllowMethods))
	assert.Equal(t, "ut-header", writer.Header().Get(headerAccessControlAllowHeaders))

	// match 4.3
	req, writer = newReqAndWriter(http.MethodOptions)
	handler = Interceptor(WithMaxAge(1))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusNoContent, writer.Result().StatusCode)
	assert.Equal(t, []string{
		headerAccessControlRequestMethod,
		headerAccessControlRequestHeaders,
	}, writer.Header().Values(headerVary))
	assert.Equal(t, originHeaderValue, writer.Header().Get(headerAccessControlAllowOrigin))
	assert.NotEmpty(t, writer.Header().Get(headerAccessControlAllowMethods))
	assert.Equal(t, "1", writer.Header().Get(headerAccessControlMaxAge))
}

func newReqAndWriter(method string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, "/ut-path", nil)
	req.Header = http.Header{}
	req.Header.Set(headerOrigin, originHeaderValue)

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
