// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxlimit

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestInterceptor_WithoutOptions(t *testing.T) {
	defer assertNotPanic(t)

	handler := Interceptor()

	req, writer := newReqAndWriter()
	req.URL.Path = "/ut-path"
	f := handler(userFunc)
	f.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
}

func TestInterceptor_WithTokenBucket(t *testing.T) {
	defer assertNotPanic(t)

	handler := Interceptor(
		WithAlgorithm(TokenBucket),
		WithReqPerSec(1),
		WithReqPerSecByPath("ut-path", 1))

	req, writer := newReqAndWriter()
	req.URL.Path = "/ut-path"

	f := handler(userFunc)
	f.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
}

func TestInterceptor_WithLeakyBucket(t *testing.T) {
	defer assertNotPanic(t)

	handler := Interceptor(
		WithAlgorithm(LeakyBucket),
		WithReqPerSec(1),
		WithReqPerSecByPath("ut-path", 1))

	req, writer := newReqAndWriter()
	req.URL.Path = "/ut-path"

	f := handler(userFunc)
	f.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
}

func TestInterceptor_WithUserLimiter(t *testing.T) {
	defer assertNotPanic(t)

	handler := Interceptor(
		WithGlobalLimiter(func(*http.Request) error {
			return fmt.Errorf("ut-error")
		}),
		WithLimiterByPath("/ut-path", func(*http.Request) error {
			return fmt.Errorf("ut-error")
		}))

	req, writer := newReqAndWriter()
	req.URL.Path = "/ut-path"

	f := handler(userFunc)
	f.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusTooManyRequests, writer.Result().StatusCode)
}
