// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxmetrics

import (
	"bytes"
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rookie-ninja/rk-mux/interceptor"
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
	set := newOptionSet(
		WithEntryNameAndType("ut-entry", "ut-type"))

	assert.Equal(t, "ut-entry", set.EntryName)
	assert.Equal(t, "ut-type", set.EntryType)

	defer clearAllMetrics()
}

func TestWithRegisterer(t *testing.T) {
	reg := prometheus.NewRegistry()
	set := newOptionSet(
		WithRegisterer(reg))

	assert.Equal(t, reg, set.registerer)

	defer clearAllMetrics()
}

func TestGetOptionSet(t *testing.T) {
	// With nil context
	assert.Nil(t, getOptionSet(nil))

	req, _ := newReqAndWriter()

	// Happy case
	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, "ut-entry"))
	set := newOptionSet()
	optionsMap["ut-entry"] = set
	assert.Equal(t, set, getOptionSet(req))

	defer clearAllMetrics()
}

func TestGetServerMetricsSet(t *testing.T) {
	reg := prometheus.NewRegistry()
	set := newOptionSet(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithRegisterer(reg))

	req, _ := newReqAndWriter()

	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, "ut-entry"))
	assert.Equal(t, set.MetricsSet, GetServerMetricsSet(req))

	defer clearAllMetrics()
}

func TestListServerMetricsSets(t *testing.T) {
	reg := prometheus.NewRegistry()
	newOptionSet(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithRegisterer(reg))

	req, _ := newReqAndWriter()
	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, "ut-entry"))
	assert.Len(t, ListServerMetricsSets(), 1)

	defer clearAllMetrics()
}

func TestGetServerResCodeMetrics(t *testing.T) {
	// With nil context
	assert.Nil(t, GetServerResCodeMetrics(nil, nil))

	// Happy case
	reg := prometheus.NewRegistry()
	newOptionSet(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithRegisterer(reg))

	req, writer := newReqAndWriter()
	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, "ut-entry"))

	assert.NotNil(t, GetServerResCodeMetrics(req, writer))

	defer clearAllMetrics()
}

func TestGetServerErrorMetrics(t *testing.T) {
	// With nil context
	assert.Nil(t, GetServerErrorMetrics(nil, nil))

	req, writer := newReqAndWriter()

	// Happy case
	reg := prometheus.NewRegistry()
	newOptionSet(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithRegisterer(reg))

	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, "ut-entry"))

	assert.NotNil(t, GetServerErrorMetrics(req, writer))

	defer clearAllMetrics()
}

func TestGetServerDurationMetrics(t *testing.T) {
	// With nil context
	assert.Nil(t, GetServerDurationMetrics(nil, nil))

	// Happy case
	reg := prometheus.NewRegistry()
	newOptionSet(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithRegisterer(reg))

	req, writer := newReqAndWriter()
	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, "ut-entry"))

	assert.NotNil(t, GetServerDurationMetrics(req, writer))

	defer clearAllMetrics()
}
