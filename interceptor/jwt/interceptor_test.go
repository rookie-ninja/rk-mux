// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxjwt

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
)

var userFunc = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)

	// with skipper
	req, writer := newReqAndWriter()
	handler := Interceptor(WithSkipper(func(*http.Request) bool {
		return true
	}))
	f := handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)

	// without options
	req, writer = newReqAndWriter()
	handler = Interceptor()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusUnauthorized, writer.Result().StatusCode)

	// with parse token error
	parseTokenErrFunc := func(auth string, req *http.Request) (*jwt.Token, error) {
		return nil, errors.New("ut-error")
	}
	req, writer = newReqAndWriter()
	req.Header.Set(headerAuthorization, strings.Join([]string{"Bearer", "ut-auth"}, " "))
	handler = Interceptor(
		WithParseTokenFunc(parseTokenErrFunc))
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusUnauthorized, writer.Result().StatusCode)

	// happy case
	parseTokenErrFunc = func(auth string, req *http.Request) (*jwt.Token, error) {
		return &jwt.Token{}, nil
	}
	req, writer = newReqAndWriter()
	req.Header.Set(headerAuthorization, strings.Join([]string{"Bearer", "ut-auth"}, " "))
	handler = Interceptor(
		WithParseTokenFunc(parseTokenErrFunc))
	f = handler(userFunc)
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
