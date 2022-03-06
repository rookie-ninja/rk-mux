// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmuxlog

import (
	rkentry "github.com/rookie-ninja/rk-entry/v2/entry"
	"github.com/rookie-ninja/rk-entry/v2/middleware/log"
	"github.com/rookie-ninja/rk-mux/middleware/context"
	"github.com/rookie-ninja/rk-query"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestMiddleware(t *testing.T) {
	defer assertNotPanic(t)

	beforeCtx := rkmidlog.NewBeforeCtx()
	afterCtx := rkmidlog.NewAfterCtx()
	mock := rkmidlog.NewOptionSetMock(beforeCtx, afterCtx)
	inter := Middleware(rkmidlog.WithMockOptionSet(mock))
	req, w := newReqAndWriter()

	// happy case
	event := rkentry.EventEntryNoop.CreateEventNoop()
	logger := rkentry.LoggerEntryNoop.Logger
	beforeCtx.Output.Event = event
	beforeCtx.Output.Logger = logger

	var eventFromCtx rkquery.Event
	var loggerFromCtx *zap.Logger
	inter(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		eventFromCtx = rkmuxctx.GetEvent(req)
		loggerFromCtx = rkmuxctx.GetLogger(req, w)
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, req)

	assert.Equal(t, event, eventFromCtx)
	assert.Equal(t, logger, loggerFromCtx)

	assert.Equal(t, http.StatusOK, w.Code)
}

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/ut-path", nil)
	req.Header = http.Header{}
	writer := httptest.NewRecorder()
	return req, writer
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
