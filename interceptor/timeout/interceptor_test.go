// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxtimeout

import (
	"bytes"
	"fmt"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func sleepHandler(writer http.ResponseWriter, req *http.Request) {
	time.Sleep(time.Second)
	rkmuxinter.WriteJson(writer, http.StatusOK, "{}")
}

func panicHandler(writer http.ResponseWriter, req *http.Request) {
	panic(fmt.Errorf("ut panic"))
}

func returnHandler(writer http.ResponseWriter, req *http.Request) {
	rkmuxinter.WriteJson(writer, http.StatusOK, "{}")
}

var customResponse = func(writer http.ResponseWriter, req *http.Request) {
	writer.Write([]byte("this is custom response!"))
}

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	var buf bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "/ut-path", &buf)
	writer := httptest.NewRecorder()
	return req, writer
}

func TestInterceptor_WithTimeout(t *testing.T) {
	// with global timeout response
	handler := Interceptor(
		WithTimeoutAndResp(time.Nanosecond, nil))
	req, writer := newReqAndWriter()
	f := handler(http.HandlerFunc(sleepHandler))
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusRequestTimeout, writer.Code)

	// with path
	handler = Interceptor(
		WithTimeoutAndRespByPath("/ut-path", time.Nanosecond, nil))
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/ut-path",
	}
	f = handler(http.HandlerFunc(sleepHandler))
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusRequestTimeout, writer.Code)

	// with custom response
	handler = Interceptor(
		WithTimeoutAndRespByPath("/", time.Nanosecond, customResponse))
	req, writer = newReqAndWriter()
	f = handler(http.HandlerFunc(sleepHandler))
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusRequestTimeout, writer.Code)
	assert.NotEmpty(t, writer.Body.String())
}

func TestInterceptor_WithPanic(t *testing.T) {
	defer assertPanic(t)

	handler := Interceptor(
		WithTimeoutAndResp(time.Minute, nil))
	req, writer := newReqAndWriter()
	f := handler(http.HandlerFunc(panicHandler))
	f.ServeHTTP(writer, req)
}

func TestInterceptor_HappyCase(t *testing.T) {
	// Let's add two routes /timeout and /happy
	// We expect interceptor acts as the name describes
	handler := Interceptor(
		WithTimeoutAndRespByPath("/timeout", time.Nanosecond, nil),
		WithTimeoutAndRespByPath("/happy", time.Minute, nil))

	// timeout on /timeout
	req, writer := newReqAndWriter()
	req.URL = &url.URL{
		Path: "/timeout",
	}
	f := handler(http.HandlerFunc(sleepHandler))
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusRequestTimeout, writer.Code)

	// OK on /happy
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/happy",
	}
	f = handler(http.HandlerFunc(returnHandler))
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Code)
}

func assertPanic(t *testing.T) {
	if r := recover(); r != nil {
		// Expect panic to be called with non nil error
		assert.True(t, true)
	} else {
		// This should never be called in case of a bug
		assert.True(t, false)
	}
}
