// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxlimit

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userFunc = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	var buf bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "/ut-path", &buf)
	writer := httptest.NewRecorder()
	return req, writer
}

func TestWithEntryNameAndType(t *testing.T) {
	defer assertNotPanic(t)

	set := newOptionSet(
		WithEntryNameAndType("ut-entry", "ut-type"))

	assert.Equal(t, "ut-entry", set.EntryName)
	assert.Equal(t, "ut-type", set.EntryType)
	assert.Len(t, set.limiter, 1)

	// Should be noop limiter
	req, _ := newReqAndWriter()
	req.URL.Path = "/ut-path"

	set.getLimiter("")(req)
}

func TestWithReqPerSec(t *testing.T) {
	// With non-zero
	set := newOptionSet(
		WithReqPerSec(1))

	assert.Equal(t, 1, set.reqPerSec)
	assert.Len(t, set.limiter, 1)

	// Should be token based limiter
	req, _ := newReqAndWriter()
	req.URL.Path = "/ut-path"
	set.getLimiter("")(req)

	// With zero
	set = newOptionSet(
		WithReqPerSec(0))

	assert.Equal(t, 0, set.reqPerSec)
	assert.Len(t, set.limiter, 1)

	// should be zero rate limiter which returns error
	req, _ = newReqAndWriter()
	req.URL.Path = "/ut-path"
	assert.NotNil(t, set.getLimiter("")(req))
}

func TestWithReqPerSecByPath(t *testing.T) {
	// with non-zero
	set := newOptionSet(
		WithReqPerSecByPath("/ut-path", 1))

	assert.Equal(t, 1, set.reqPerSecByPath["/ut-path"])
	assert.NotNil(t, set.limiter["/ut-path"])

	// Should be token based limiter
	req, _ := newReqAndWriter()
	req.URL.Path = "/ut-path"
	set.getLimiter("/ut-path")(req)

	// With zero
	set = newOptionSet(
		WithReqPerSecByPath("/ut-path", 0))

	assert.Equal(t, 0, set.reqPerSecByPath["/ut-path"])
	assert.NotNil(t, set.limiter["/ut-path"])

	// should be zero rate limiter which returns error
	req, _ = newReqAndWriter()
	req.URL.Path = "/ut-path"
	assert.NotNil(t, set.getLimiter("/ut-path")(req))
}

func TestWithAlgorithm(t *testing.T) {
	defer assertNotPanic(t)

	// With invalid algorithm
	set := newOptionSet(
		WithAlgorithm("invalid-algo"))

	// should be noop limiter
	assert.Len(t, set.limiter, 1)
	set.getLimiter("")

	// With leaky bucket non zero
	set = newOptionSet(
		WithAlgorithm(LeakyBucket),
		WithReqPerSec(1),
		WithReqPerSecByPath("ut-method", 1))

	// should be leaky bucket
	assert.Len(t, set.limiter, 2)
	req, _ := newReqAndWriter()
	req.URL.Path = "/ut-path"
	set.getLimiter("")(req)
	set.getLimiter("ut-path")(req)
}

func TestWithGlobalLimiter(t *testing.T) {
	set := newOptionSet(
		WithGlobalLimiter(func(*http.Request) error {
			return fmt.Errorf("ut error")
		}))

	assert.Len(t, set.limiter, 1)
	req, _ := newReqAndWriter()
	req.URL.Path = "/ut-path"
	assert.NotNil(t, set.getLimiter("")(req))
}

func TestWithLimiterByPath(t *testing.T) {
	set := newOptionSet(
		WithLimiterByPath("/ut-path", func(*http.Request) error {
			return fmt.Errorf("ut error")
		}))

	assert.Len(t, set.limiter, 2)

	req, _ := newReqAndWriter()
	req.URL.Path = "/ut-path"
	assert.NotNil(t, set.getLimiter("/ut-path")(req))
}

func TestOptionSet_Wait(t *testing.T) {
	defer assertNotPanic(t)

	// With user limiter
	set := newOptionSet(
		WithGlobalLimiter(func(*http.Request) error {
			return nil
		}))

	req, _ := newReqAndWriter()
	req.URL.Path = "/ut-path"
	set.Wait(req)

	// With token bucket and global limiter
	set = newOptionSet(
		WithAlgorithm(TokenBucket))

	set.Wait(req)

	// With token bucket and limiter by method
	set = newOptionSet(
		WithAlgorithm(TokenBucket),
		WithReqPerSecByPath("/ut-path", 100))

	set.Wait(req)

	// With leaky bucket and global limiter
	set = newOptionSet(
		WithAlgorithm(LeakyBucket))

	set.Wait(req)

	// With leaky bucket and limiter by method
	set = newOptionSet(
		WithAlgorithm(LeakyBucket),
		WithReqPerSecByPath("/ut-path", 100))

	set.Wait(req)

	// Without any configuration
	set = newOptionSet()
	set.Wait(req)
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
