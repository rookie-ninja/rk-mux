// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)

	handler := Interceptor(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithRegisterer(prometheus.NewRegistry()))

	// With ignoring case
	req, writer := newReqAndWriter()
	req.URL.Path = "/rk/v1/assets"

	// Happy case
	f := handler(userFunc)
	f.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
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
