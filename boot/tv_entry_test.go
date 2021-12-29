// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmux

import (
	"context"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func TestNewTvEntry(t *testing.T) {
	entry := NewTvEntry(
		WithEventLoggerEntryTv(rkentry.NoopEventLoggerEntry()),
		WithZapLoggerEntryTv(rkentry.NoopZapLoggerEntry()))

	assert.Equal(t, TvEntryNameDefault, entry.GetName())
	assert.Equal(t, TvEntryType, entry.GetType())
	assert.Equal(t, TvEntryDescription, entry.GetDescription())
	assert.NotEmpty(t, entry.String())
	assert.Nil(t, entry.UnmarshalJSON(nil))
}

func TestTvEntry_Bootstrap(t *testing.T) {
	entry := NewTvEntry(
		WithEventLoggerEntryTv(rkentry.NoopEventLoggerEntry()),
		WithZapLoggerEntryTv(rkentry.NoopZapLoggerEntry()))

	entry.Bootstrap(context.TODO())
}

func TestTvEntry_Interrupt(t *testing.T) {
	entry := NewTvEntry(
		WithEventLoggerEntryTv(rkentry.NoopEventLoggerEntry()),
		WithZapLoggerEntryTv(rkentry.NoopZapLoggerEntry()))

	entry.Interrupt(context.TODO())
}

func TestTvEntry_TV(t *testing.T) {
	entry := NewTvEntry(
		WithEventLoggerEntryTv(rkentry.NoopEventLoggerEntry()),
		WithZapLoggerEntryTv(rkentry.NoopZapLoggerEntry()))
	entry.Bootstrap(context.TODO())

	defer assertNotPanic(t)

	// With all paths
	req, writer := newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/",
	}

	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// apis
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/apis",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// entries
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/entries",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// configs
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/configs",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// certs
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/certs",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// os
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/os",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// env
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/env",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// logs
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/logs",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// deps
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/deps",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// license
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/license",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// info
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/info",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// git
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/git",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())

	// unknown
	req, writer = newReqAndWriter()
	req.URL = &url.URL{
		Path: "/rk/v1/tv/unknown",
	}
	entry.TV(writer, req)
	assert.NotEmpty(t, writer.Body.String())
}
