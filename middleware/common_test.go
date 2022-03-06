// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxmid

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrapResponseWriter(t *testing.T) {
	defer assertNotPanic(t)

	// with same type
	rkWriter := &RkResponseWriter{}
	assert.Equal(t, rkWriter, WrapResponseWriter(rkWriter))

	// happy case
	oldW := httptest.NewRecorder()
	rkWriter = WrapResponseWriter(oldW)

	_, err := rkWriter.Write([]byte{})
	assert.Nil(t, err)

	rkWriter.WriteHeader(http.StatusOK)
	assert.Equal(t, http.StatusOK, oldW.Code)

	_, _, err = rkWriter.Hijack()
	assert.Nil(t, err)

	assert.NotNil(t, rkWriter.Header())

	rkWriter.Flush()
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
