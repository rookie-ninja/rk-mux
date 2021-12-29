// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmux

import (
	"bytes"
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rookie-ninja/rk-common/common"
	"github.com/rookie-ninja/rk-entry/entry"
	rkmuxinter "github.com/rookie-ninja/rk-mux/interceptor"
	rkmuxmetrics "github.com/rookie-ninja/rk-mux/interceptor/metrics/prom"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	var buf bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "/ut-path", &buf)
	writer := httptest.NewRecorder()
	return req, writer
}

func TestWithNameCommonService_WithEmptyString(t *testing.T) {
	entry := NewCommonServiceEntry(
		WithNameCommonService(""))

	assert.NotEmpty(t, entry.GetName())
}

func TestWithNameCommonService_HappyCase(t *testing.T) {
	entry := NewCommonServiceEntry(
		WithNameCommonService("unit-test"))

	assert.Equal(t, "unit-test", entry.GetName())
}

func TestWithEventLoggerEntryCommonService_WithNilParam(t *testing.T) {
	entry := NewCommonServiceEntry(
		WithEventLoggerEntryCommonService(nil))

	assert.NotNil(t, entry.EventLoggerEntry)
}

func TestWithEventLoggerEntryCommonService_HappyCase(t *testing.T) {
	eventLoggerEntry := rkentry.NoopEventLoggerEntry()
	entry := NewCommonServiceEntry(
		WithEventLoggerEntryCommonService(eventLoggerEntry))

	assert.Equal(t, eventLoggerEntry, entry.EventLoggerEntry)
}

func TestWithZapLoggerEntryCommonService_WithNilParam(t *testing.T) {
	entry := NewCommonServiceEntry(
		WithZapLoggerEntryCommonService(nil))

	assert.NotNil(t, entry.ZapLoggerEntry)
}

func TestWithZapLoggerEntryCommonService_HappyCase(t *testing.T) {
	zapLoggerEntry := rkentry.NoopZapLoggerEntry()
	entry := NewCommonServiceEntry(
		WithZapLoggerEntryCommonService(zapLoggerEntry))

	assert.Equal(t, zapLoggerEntry, entry.ZapLoggerEntry)
}

func TestNewCommonServiceEntry_WithoutOptions(t *testing.T) {
	entry := NewCommonServiceEntry()

	assert.NotNil(t, entry.ZapLoggerEntry)
	assert.NotNil(t, entry.EventLoggerEntry)
	assert.NotEmpty(t, entry.GetName())
	assert.NotEmpty(t, entry.GetType())
}

func TestNewCommonServiceEntry_HappyCase(t *testing.T) {
	zapLoggerEntry := rkentry.NoopZapLoggerEntry()
	eventLoggerEntry := rkentry.NoopEventLoggerEntry()

	entry := NewCommonServiceEntry(
		WithZapLoggerEntryCommonService(zapLoggerEntry),
		WithEventLoggerEntryCommonService(eventLoggerEntry),
		WithNameCommonService("ut"))

	assert.Equal(t, zapLoggerEntry, entry.ZapLoggerEntry)
	assert.Equal(t, eventLoggerEntry, entry.EventLoggerEntry)
	assert.Equal(t, "ut", entry.GetName())
	assert.NotEmpty(t, entry.GetType())
}

func TestCommonServiceEntry_Bootstrap_WithoutRouter(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			// expect panic to be called with non nil error
			assert.True(t, false)
		} else {
			// this should never be called in case of a bug
			assert.True(t, true)
		}
	}()

	entry := NewCommonServiceEntry(
		WithZapLoggerEntryCommonService(rkentry.NoopZapLoggerEntry()),
		WithEventLoggerEntryCommonService(rkentry.NoopEventLoggerEntry()))
	entry.Bootstrap(context.Background())
}

func TestCommonServiceEntry_Bootstrap_HappyCase(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			// expect panic to be called with non nil error
			assert.True(t, false)
		} else {
			// this should never be called in case of a bug
			assert.True(t, true)
		}
	}()

	entry := NewCommonServiceEntry(
		WithZapLoggerEntryCommonService(rkentry.NoopZapLoggerEntry()),
		WithEventLoggerEntryCommonService(rkentry.NoopEventLoggerEntry()))
	entry.Bootstrap(context.Background())
}

func TestCommonServiceEntry_Interrupt_HappyCase(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			// expect panic to be called with non nil error
			assert.True(t, false)
		} else {
			// this should never be called in case of a bug
			assert.True(t, true)
		}
	}()

	entry := NewCommonServiceEntry(
		WithZapLoggerEntryCommonService(rkentry.NoopZapLoggerEntry()),
		WithEventLoggerEntryCommonService(rkentry.NoopEventLoggerEntry()))
	entry.Interrupt(context.Background())
}

func TestCommonServiceEntry_GetName_HappyCase(t *testing.T) {
	entry := NewCommonServiceEntry(
		WithNameCommonService("ut"))

	assert.Equal(t, "ut", entry.GetName())
}

func TestCommonServiceEntry_GetType_HappyCase(t *testing.T) {
	entry := NewCommonServiceEntry()

	assert.Equal(t, "CommonServiceEntry", entry.GetType())
}

func TestCommonServiceEntry_String_HappyCase(t *testing.T) {
	entry := NewCommonServiceEntry()

	assert.NotEmpty(t, entry.String())
}

func TestCommonServiceEntry_Healthy_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()
	entry.Healthy(writer, req)

	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.Equal(t, `{"healthy":true}`, strings.TrimSuffix(writer.Body.String(), "\n"))
}

func TestCommonServiceEntry_GC_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	entry.Gc(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Info_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	entry.Info(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Config_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	vp := viper.New()
	vp.Set("unit-test-key", "unit-test-value")

	viperEntry := rkentry.RegisterConfigEntry(
		rkentry.WithNameConfig("unit-test"),
		rkentry.WithViperInstanceConfig(vp))

	rkentry.GlobalAppCtx.AddConfigEntry(viperEntry)
	defer rkentry.GlobalAppCtx.RemoveConfigEntry(viperEntry.EntryName)

	entry.Configs(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
	assert.Contains(t, writer.Body.String(), "unit-test-key")
	assert.Contains(t, writer.Body.String(), "unit-test-value")
}

func TestCommonServiceEntry_Sys_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	entry.Sys(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Entries_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)
	defer rkentry.GlobalAppCtx.RemoveEntry(muxEntry.EntryName)

	entry.Entries(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Certs_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)
	rkentry.RegisterCertEntry(rkentry.WithNameCert("ut-cert"))
	certEntry := rkentry.GlobalAppCtx.GetCertEntry("ut-cert")
	certEntry.Retriever = &rkentry.CredRetrieverLocalFs{}
	certEntry.Store = &rkentry.CertStore{}

	defer rkentry.GlobalAppCtx.RemoveCertEntry(certEntry.EntryName)

	entry.Certs(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Logs_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)
	defer rkentry.GlobalAppCtx.RemoveEntry(muxEntry.EntryName)

	entry.Logs(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Deps_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)
	defer rkentry.GlobalAppCtx.RemoveEntry(muxEntry.EntryName)

	entry.Deps(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_License_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)
	defer rkentry.GlobalAppCtx.RemoveEntry(muxEntry.EntryName)

	entry.License(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Readme_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)
	defer rkentry.GlobalAppCtx.RemoveEntry(muxEntry.EntryName)

	entry.Readme(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Git_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	req, writer := newReqAndWriter()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)
	rkentry.GlobalAppCtx.SetRkMetaEntry(&rkentry.RkMetaEntry{
		RkMeta: &rkcommon.RkMeta{
			Git: &rkcommon.Git{
				Commit: &rkcommon.Commit{
					Committer: &rkcommon.Committer{},
				},
			},
		},
	})

	entry.Git(writer, req)
	assert.Equal(t, http.StatusOK, writer.Result().StatusCode)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_APIs_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)

	req, writer := newReqAndWriter()
	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, "unit-test-mux"))

	muxEntry.Router.NewRoute().Methods(http.MethodGet).Path("/ut-test")

	entry.Apis(writer, req)
	assert.Equal(t, http.StatusOK, writer.Code)
	assert.NotEmpty(t, writer.Body.String())
}

func TestCommonServiceEntry_Req_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := NewCommonServiceEntry()

	muxEntry := RegisterMuxEntry(
		WithCommonServiceEntryMux(entry),
		WithNameMux("unit-test-mux"))
	rkentry.GlobalAppCtx.AddEntry(muxEntry)

	muxEntry.AddInterceptor(rkmuxmetrics.Interceptor(
		rkmuxmetrics.WithRegisterer(prometheus.NewRegistry())))

	req, writer := newReqAndWriter()
	req = req.WithContext(context.WithValue(req.Context(), rkmuxinter.RpcEntryNameKey, "unit-test-mux"))

	entry.Req(writer, req)
	assert.Equal(t, http.StatusOK, writer.Code)
	assert.NotEmpty(t, writer.Body.String())
}
