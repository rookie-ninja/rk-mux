// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxsec

import (
	"bytes"
	"crypto/tls"
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
	req := httptest.NewRequest(http.MethodPost, "/ut-path", &buf)
	writer := httptest.NewRecorder()
	return req, writer
}

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)

	// with skipper
	handler := Interceptor(WithSkipper(func(*http.Request) bool {
		return true
	}))
	req, writer := newReqAndWriter()
	f := handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)

	// without options
	handler = Interceptor()
	req, writer = newReqAndWriter()
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	containsHeader(t, writer,
		headerXXSSProtection,
		headerXContentTypeOptions,
		headerXFrameOptions)

	// with options
	handler = Interceptor(
		WithXSSProtection("ut-xss"),
		WithContentTypeNosniff("ut-sniff"),
		WithXFrameOptions("ut-frame"),
		WithHSTSMaxAge(10),
		WithHSTSExcludeSubdomains(true),
		WithHSTSPreloadEnabled(true),
		WithContentSecurityPolicy("ut-policy"),
		WithCSPReportOnly(true),
		WithReferrerPolicy("ut-ref"),
		WithIgnorePrefix("ut-prefix"))
	req, writer = newReqAndWriter()
	req.TLS = &tls.ConnectionState{}
	f = handler(userFunc)
	f.ServeHTTP(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	containsHeader(t, writer,
		headerXXSSProtection,
		headerXContentTypeOptions,
		headerXFrameOptions,
		headerStrictTransportSecurity,
		headerContentSecurityPolicyReportOnly,
		headerReferrerPolicy)
}

func containsHeader(t *testing.T, writer http.ResponseWriter, headers ...string) {
	for _, v := range headers {
		assert.Contains(t, writer.Header(), v)
	}
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
