// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxinter

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestGetRemoteAddressSet(t *testing.T) {
	// With nil request
	ip, port := GetRemoteAddressSet(nil)
	assert.Equal(t, "0.0.0.0", ip)
	assert.Equal(t, "0", port)

	// With x-forwarded-for equals to ::1
	req := &http.Request{
		RemoteAddr: "1.1.1.1:1",
		Header:     http.Header{},
	}
	req.Header.Set("x-forwarded-for", "::1")
	ip, port = GetRemoteAddressSet(req)

	assert.Equal(t, "localhost", ip)
	assert.Equal(t, "1", port)

	// Happy case
	req = &http.Request{
		RemoteAddr: "1.1.1.1:1",
		Header:     http.Header{},
	}
	ip, port = GetRemoteAddressSet(req)

	assert.Equal(t, "1.1.1.1", ip)
	assert.Equal(t, "1", port)
}

func TestShouldLog(t *testing.T) {
	// With nil context
	assert.False(t, ShouldLog(nil))

	// With ignoring path
	req := &http.Request{
		URL: &url.URL{
			Path: "/rk/v1/assets",
		},
	}
	assert.False(t, ShouldLog(req))

	req = &http.Request{
		URL: &url.URL{
			Path: "/rk/v1/tv",
		},
	}
	assert.False(t, ShouldLog(req))

	req = &http.Request{
		URL: &url.URL{
			Path: "/sw/",
		},
	}
	assert.False(t, ShouldLog(req))

	// Expect true
	req = &http.Request{
		URL: &url.URL{
			Path: "ut-path",
		},
	}
	assert.True(t, ShouldLog(req))
}
