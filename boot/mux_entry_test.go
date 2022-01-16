// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmux

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rookie-ninja/rk-entry/entry"
	rkmidmetrics "github.com/rookie-ninja/rk-entry/middleware/metrics"
	"github.com/rookie-ninja/rk-mux/interceptor/meta"
	rkmuxmetrics "github.com/rookie-ninja/rk-mux/interceptor/metrics/prom"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const (
	defaultBootConfigStr = `
---
mux:
 - name: greeter
   port: 1949
   enabled: true
   sw:
     enabled: true
     path: "sw"
   commonService:
     enabled: true
   tv:
     enabled: true
   prom:
     enabled: true
     pusher:
       enabled: false
   interceptors:
     loggingZap:
       enabled: true
     metricsProm:
       enabled: true
     auth:
       enabled: true
       basic:
         - "user:pass"
     meta:
       enabled: true
     tracingTelemetry:
       enabled: true
     ratelimit:
       enabled: true
     timeout:
       enabled: true
     cors:
       enabled: true
     jwt:
       enabled: true
     secure:
       enabled: true
     csrf:
       enabled: true
     gzip:
       enabled: true
 - name: greeter2
   port: 2008
   enabled: true
   sw:
     enabled: true
     path: "sw"
   commonService:
     enabled: true
   tv:
     enabled: true
   interceptors:
     loggingZap:
       enabled: true
     metricsProm:
       enabled: true
     auth:
       enabled: true
       basic:
         - "user:pass"
 - name: greeter3
   port: 2022
   enabled: false
`
)

//func TestWithZapLoggerEntryMux_HappyCase(t *testing.T) {
//	loggerEntry := rkentry.NoopZapLoggerEntry()
//	entry := RegisterMuxEntry()
//
//	option := WithZapLoggerEntryMux(loggerEntry)
//	option(entry)
//
//	assert.Equal(t, loggerEntry, entry.ZapLoggerEntry)
//}
//
//func TestWithEventLoggerEntryMux_HappyCase(t *testing.T) {
//	entry := RegisterMuxEntry()
//
//	eventLoggerEntry := rkentry.NoopEventLoggerEntry()
//
//	option := WithEventLoggerEntryMux(eventLoggerEntry)
//	option(entry)
//
//	assert.Equal(t, eventLoggerEntry, entry.EventLoggerEntry)
//}
//
//func TestWithInterceptorsMux_WithNilInterceptorList(t *testing.T) {
//	entry := RegisterMuxEntry()
//
//	option := WithInterceptorsMux(nil)
//	option(entry)
//
//	assert.NotNil(t, entry.Interceptors)
//}
//
//func TestWithInterceptorsMux_HappyCase(t *testing.T) {
//	entry := RegisterMuxEntry()
//
//	loggingInterceptor := rkmuxlog.Interceptor()
//	metricsInterceptor := rkmuxmetrics.Interceptor()
//
//	interceptors := []mux.MiddlewareFunc{
//		loggingInterceptor,
//		metricsInterceptor,
//	}
//
//	option := WithInterceptorsMux(interceptors...)
//	option(entry)
//
//	assert.NotNil(t, entry.Interceptors)
//	// should contains logging, metrics and panic interceptor
//	// where panic interceptor is inject by default
//	assert.Len(t, entry.Interceptors, 3)
//}
//
//func TestWithCommonServiceEntryMux_WithEntry(t *testing.T) {
//	entry := RegisterMuxEntry()
//
//	option := WithCommonServiceEntryMux(NewCommonServiceEntry())
//	option(entry)
//
//	assert.NotNil(t, entry.CommonServiceEntry)
//}
//
//func TestWithCommonServiceEntryMux_WithoutEntry(t *testing.T) {
//	entry := RegisterMuxEntry()
//
//	assert.Nil(t, entry.CommonServiceEntry)
//}
//
//func TestWithTVEntryMux_WithEntry(t *testing.T) {
//	entry := RegisterMuxEntry()
//
//	option := WithTVEntryMux(NewTvEntry())
//	option(entry)
//
//	assert.NotNil(t, entry.TvEntry)
//}
//
//func TestWithTVEntry_WithoutEntry(t *testing.T) {
//	entry := RegisterMuxEntry()
//
//	assert.Nil(t, entry.TvEntry)
//}
//
//func TestWithCertEntryMux_HappyCase(t *testing.T) {
//	entry := RegisterMuxEntry()
//	certEntry := &rkentry.CertEntry{}
//
//	option := WithCertEntryMux(certEntry)
//	option(entry)
//
//	assert.Equal(t, entry.CertEntry, certEntry)
//}
//
//func TestWithSWEntryMux_HappyCase(t *testing.T) {
//	entry := RegisterMuxEntry()
//	sw := NewSwEntry()
//
//	option := WithSwEntryMux(sw)
//	option(entry)
//
//	assert.Equal(t, entry.SwEntry, sw)
//}
//
//func TestWithPortMux_HappyCase(t *testing.T) {
//	entry := RegisterMuxEntry()
//	port := uint64(1111)
//
//	option := WithPortMux(port)
//	option(entry)
//
//	assert.Equal(t, entry.Port, port)
//}
//
//func TestWithNameMux_HappyCase(t *testing.T) {
//	entry := RegisterMuxEntry()
//	name := "unit-test-entry"
//
//	option := WithNameMux(name)
//	option(entry)
//
//	assert.Equal(t, entry.EntryName, name)
//}
//
//func TestRegisterMuxEntriesWithConfig_WithInvalidConfigFilePath(t *testing.T) {
//	defer assertPanic(t)
//
//	RegisterMuxEntriesWithConfig("/invalid-path")
//}
//
//func TestRegisterMuxEntriesWithConfig_WithNilFactory(t *testing.T) {
//	defer assertNotPanic(t)
//
//	// write config file in unit test temp directory
//	tempDir := path.Join(t.TempDir(), "boot.yaml")
//	assert.Nil(t, ioutil.WriteFile(tempDir, []byte(defaultBootConfigStr), os.ModePerm))
//	entries := RegisterMuxEntriesWithConfig(tempDir)
//	assert.NotNil(t, entries)
//	assert.Len(t, entries, 2)
//	for _, entry := range entries {
//		entry.Interrupt(context.TODO())
//	}
//}
//
//func TestRegisterMuxEntriesWithConfig_HappyCase(t *testing.T) {
//	defer assertNotPanic(t)
//
//	// write config file in unit test temp directory
//	tempDir := path.Join(t.TempDir(), "boot.yaml")
//	assert.Nil(t, ioutil.WriteFile(tempDir, []byte(defaultBootConfigStr), os.ModePerm))
//	entries := RegisterMuxEntriesWithConfig(tempDir)
//	assert.NotNil(t, entries)
//	assert.Len(t, entries, 2)
//
//	// validate entry element based on boot.yaml config defined in defaultBootConfigStr
//	greeter := entries["greeter"].(*MuxEntry)
//	assert.NotNil(t, greeter)
//	assert.Equal(t, uint64(8080), greeter.Port)
//	assert.NotNil(t, greeter.SwEntry)
//	assert.NotNil(t, greeter.CommonServiceEntry)
//	assert.NotNil(t, greeter.TvEntry)
//	// logging, metrics, auth and panic interceptor should be included
//	assert.True(t, len(greeter.Interceptors) > 0)
//
//	greeter2 := entries["greeter2"].(*MuxEntry)
//	assert.NotNil(t, greeter2)
//	assert.Equal(t, uint64(2008), greeter2.Port)
//	assert.NotNil(t, greeter2.SwEntry)
//	assert.NotNil(t, greeter2.CommonServiceEntry)
//	assert.NotNil(t, greeter2.TvEntry)
//	// logging, metrics, auth and panic interceptor should be included
//	assert.Len(t, greeter2.Interceptors, 4)
//
//	for _, entry := range entries {
//		entry.Interrupt(context.TODO())
//	}
//}
//
//func TestRegisterMuxEntry_WithZapLoggerEntry(t *testing.T) {
//	loggerEntry := rkentry.NoopZapLoggerEntry()
//	entry := RegisterMuxEntry(WithZapLoggerEntryMux(loggerEntry))
//	assert.Equal(t, loggerEntry, entry.ZapLoggerEntry)
//}
//
//func TestRegisterMuxEntry_WithEventLoggerEntry(t *testing.T) {
//	loggerEntry := rkentry.NoopEventLoggerEntry()
//
//	entry := RegisterMuxEntry(WithEventLoggerEntryMux(loggerEntry))
//	assert.Equal(t, loggerEntry, entry.EventLoggerEntry)
//}
//
//func TestNewMuxEntry_WithInterceptors(t *testing.T) {
//	loggingInterceptor := rkmuxlog.Interceptor()
//	entry := RegisterMuxEntry(WithInterceptorsMux(loggingInterceptor))
//	assert.Len(t, entry.Interceptors, 2)
//}
//
//func TestNewMuxEntry_WithCommonServiceEntry(t *testing.T) {
//	entry := RegisterMuxEntry(WithCommonServiceEntryMux(NewCommonServiceEntry()))
//	assert.NotNil(t, entry.CommonServiceEntry)
//}
//
//func TestNewMuxEntry_WithTVEntry(t *testing.T) {
//	entry := RegisterMuxEntry(WithTVEntryMux(NewTvEntry()))
//	assert.NotNil(t, entry.TvEntry)
//}
//
//func TestNewMuxEntry_WithCertStore(t *testing.T) {
//	certEntry := &rkentry.CertEntry{}
//
//	entry := RegisterMuxEntry(WithCertEntryMux(certEntry))
//	assert.Equal(t, certEntry, entry.CertEntry)
//}
//
//func TestNewMuxEntry_WithSWEntry(t *testing.T) {
//	sw := NewSwEntry()
//	entry := RegisterMuxEntry(WithSwEntryMux(sw))
//	assert.Equal(t, sw, entry.SwEntry)
//}
//
//func TestNewMuxEntry_WithPort(t *testing.T) {
//	entry := RegisterMuxEntry(WithPortMux(8080))
//	assert.Equal(t, uint64(8080), entry.Port)
//}
//
//func TestNewMuxEntry_WithName(t *testing.T) {
//	entry := RegisterMuxEntry(WithNameMux("unit-test-greeter"))
//	assert.Equal(t, "unit-test-greeter", entry.GetName())
//}
//
//func TestNewMuxEntry_WithDefaultValue(t *testing.T) {
//	entry := RegisterMuxEntry()
//	assert.True(t, strings.HasPrefix(entry.GetName(), "MuxServer-"))
//	assert.NotNil(t, entry.ZapLoggerEntry)
//	assert.NotNil(t, entry.EventLoggerEntry)
//	assert.Len(t, entry.Interceptors, 1)
//	assert.NotNil(t, entry.Server)
//	assert.Nil(t, entry.SwEntry)
//	assert.Nil(t, entry.CertEntry)
//	assert.False(t, entry.IsSwEnabled())
//	assert.False(t, entry.IsTlsEnabled())
//	assert.Nil(t, entry.CommonServiceEntry)
//	assert.Nil(t, entry.TvEntry)
//	assert.Equal(t, "MuxEntry", entry.GetType())
//}
//
//func TestMuxEntry_GetName_HappyCase(t *testing.T) {
//	entry := RegisterMuxEntry(WithNameMux("unit-test-entry"))
//	assert.Equal(t, "unit-test-entry", entry.GetName())
//}
//
//func TestMuxEntry_GetType_HappyCase(t *testing.T) {
//	assert.Equal(t, "MuxEntry", RegisterMuxEntry().GetType())
//}
//
//func TestMuxEntry_String_HappyCase(t *testing.T) {
//	assert.NotEmpty(t, RegisterMuxEntry().String())
//}
//
//func TestMuxEntry_IsSwEnabled_ExpectTrue(t *testing.T) {
//	sw := NewSwEntry()
//	entry := RegisterMuxEntry(WithSwEntryMux(sw))
//	assert.True(t, entry.IsSwEnabled())
//}
//
//func TestMuxEntry_IsSwEnabled_ExpectFalse(t *testing.T) {
//	entry := RegisterMuxEntry()
//	assert.False(t, entry.IsSwEnabled())
//}
//
//func TestMuxEntry_IsTlsEnabled_ExpectTrue(t *testing.T) {
//	certEntry := &rkentry.CertEntry{
//		Store: &rkentry.CertStore{},
//	}
//
//	entry := RegisterMuxEntry(WithCertEntryMux(certEntry))
//	assert.True(t, entry.IsTlsEnabled())
//}
//
//func TestMuxEntry_IsTlsEnabled_ExpectFalse(t *testing.T) {
//	entry := RegisterMuxEntry()
//	assert.False(t, entry.IsTlsEnabled())
//}
//
//func TestMuxEntry_GetServer_HappyCase(t *testing.T) {
//	entry := RegisterMuxEntry()
//	assert.NotNil(t, entry.Server)
//}
//
//func TestMuxEntry_Bootstrap_WithSwagger(t *testing.T) {
//	sw := NewSwEntry(
//		WithPathSw("sw"),
//		WithZapLoggerEntrySw(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntrySw(rkentry.NoopEventLoggerEntry()))
//	entry := RegisterMuxEntry(
//		WithNameMux("unit-test-entry"),
//		WithPortMux(8080),
//		WithZapLoggerEntryMux(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryMux(rkentry.NoopEventLoggerEntry()),
//		WithSwEntryMux(sw))
//
//	go entry.Bootstrap(context.Background())
//	time.Sleep(time.Second)
//	// endpoint should be accessible with 8080 port
//	validateServerIsUp(t, entry.Port)
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because mux do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}
//
//func TestMuxEntry_Bootstrap_WithoutSwagger(t *testing.T) {
//	entry := RegisterMuxEntry(
//		WithNameMux("unit-test-entry"),
//		WithPortMux(8080),
//		WithZapLoggerEntryMux(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryMux(rkentry.NoopEventLoggerEntry()))
//
//	go entry.Bootstrap(context.Background())
//	time.Sleep(time.Second)
//	// endpoint should be accessible with 8080 port
//	validateServerIsUp(t, entry.Port)
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because mux do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}
//
//func TestMuxEntry_Bootstrap_WithoutTLS(t *testing.T) {
//	entry := RegisterMuxEntry(
//		WithNameMux("unit-test-entry"),
//		WithPortMux(8080),
//		WithZapLoggerEntryMux(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryMux(rkentry.NoopEventLoggerEntry()))
//
//	go entry.Bootstrap(context.Background())
//	time.Sleep(time.Second)
//	// endpoint should be accessible with 8080 port
//	validateServerIsUp(t, entry.Port)
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because mux do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}
//
//func TestMuxEntry_Shutdown_WithBootstrap(t *testing.T) {
//	defer assertNotPanic(t)
//
//	entry := RegisterMuxEntry(
//		WithNameMux("unit-test-entry"),
//		WithPortMux(8080),
//		WithZapLoggerEntryMux(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryMux(rkentry.NoopEventLoggerEntry()))
//
//	go entry.Bootstrap(context.Background())
//	time.Sleep(time.Second)
//	// endpoint should be accessible with 8080 port
//	validateServerIsUp(t, entry.Port)
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because mux do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}
//
//func TestMuxEntry_Shutdown_WithoutBootstrap(t *testing.T) {
//	defer assertNotPanic(t)
//
//	entry := RegisterMuxEntry(
//		WithNameMux("unit-test-entry"),
//		WithPortMux(8080),
//		WithZapLoggerEntryMux(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryMux(rkentry.NoopEventLoggerEntry()))
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because mux do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}

func TestGetMuxEntry(t *testing.T) {
	// expect nil
	assert.Nil(t, GetMuxEntry("entry-name"))

	// happy case
	echoEntry := RegisterMuxEntry(WithName("ut"))
	assert.Equal(t, echoEntry, GetMuxEntry("ut"))

	rkentry.GlobalAppCtx.RemoveEntry("ut")
}

func TestRegisterMuxEntry(t *testing.T) {
	// without options
	entry := RegisterMuxEntry()
	assert.NotNil(t, entry)
	assert.NotEmpty(t, entry.GetName())
	assert.NotEmpty(t, entry.GetType())
	assert.NotEmpty(t, entry.GetDescription())
	assert.NotEmpty(t, entry.String())
	rkentry.GlobalAppCtx.RemoveEntry(entry.GetName())

	// with options
	entry = RegisterMuxEntry(
		WithZapLoggerEntry(nil),
		WithEventLoggerEntry(nil),
		WithCommonServiceEntry(rkentry.RegisterCommonServiceEntry()),
		WithTvEntry(rkentry.RegisterTvEntry()),
		WithSwEntry(rkentry.RegisterSwEntry()),
		WithPort(8083),
		WithName("ut-entry"),
		WithDescription("ut-desc"),
		WithPromEntry(rkentry.RegisterPromEntry()),
		WithStaticFileHandlerEntry(rkentry.RegisterStaticFileHandlerEntry()))

	assert.NotEmpty(t, entry.GetName())
	assert.NotEmpty(t, entry.GetType())
	assert.NotEmpty(t, entry.GetDescription())
	assert.NotEmpty(t, entry.String())
	assert.True(t, entry.IsSwEnabled())
	assert.True(t, entry.IsPromEnabled())
	assert.True(t, entry.IsCommonServiceEnabled())
	assert.True(t, entry.IsTvEnabled())
	assert.False(t, entry.IsTlsEnabled())
	assert.True(t, entry.IsStaticFileHandlerEnabled())

	bytes, err := entry.MarshalJSON()
	assert.NotEmpty(t, bytes)
	assert.Nil(t, err)
	assert.Nil(t, entry.UnmarshalJSON([]byte{}))
}

func TestMuxEntry_AddInterceptor(t *testing.T) {
	defer assertNotPanic(t)
	entry := RegisterMuxEntry()
	inter := rkmuxmeta.Interceptor()
	entry.AddInterceptor(inter)
}

func TestMuxEntry_Bootstrap(t *testing.T) {
	defer assertNotPanic(t)

	// without enable sw, static, prom, common, tv, tls
	entry := RegisterMuxEntry(WithPort(8080))
	go entry.Bootstrap(context.Background())
	time.Sleep(time.Second)
	validateServerIsUp(t, 8080, entry.IsTlsEnabled())
	entry.Interrupt(context.Background())
	time.Sleep(time.Second)
	entry.Interrupt(context.TODO())
	// force to kill it because go-zero do not stop server with stop() call
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	entry = RegisterMuxEntry(
		WithPort(8081),
		WithCommonServiceEntry(rkentry.RegisterCommonServiceEntry()),
		WithTvEntry(rkentry.RegisterTvEntry()),
		WithSwEntry(rkentry.RegisterSwEntry()),
		WithPromEntry(rkentry.RegisterPromEntry()))
	go entry.Bootstrap(context.Background())
	time.Sleep(time.Second)
	entry.Interrupt(context.TODO())
	// force to kill it because go-zero do not stop server with stop() call
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
}

func TestRegisterMuxEntriesWithConfig(t *testing.T) {
	defer assertNotPanic(t)

	// write config file in unit test temp directory
	tempDir := path.Join(t.TempDir(), "boot.yaml")
	assert.Nil(t, ioutil.WriteFile(tempDir, []byte(defaultBootConfigStr), os.ModePerm))
	entries := RegisterMuxEntriesWithConfig(tempDir)
	assert.NotNil(t, entries)
	assert.Len(t, entries, 2)

	// validate entry element based on boot.yaml config defined in defaultBootConfigStr
	greeter := entries["greeter"].(*MuxEntry)
	assert.NotNil(t, greeter)

	greeter2 := entries["greeter2"].(*MuxEntry)
	assert.NotNil(t, greeter2)

	greeter3 := entries["greeter3"]
	assert.Nil(t, greeter3)
}

func TestMuxEntry_constructSwUrl(t *testing.T) {
	// happy case
	req := &http.Request{
		Host: "8.8.8.8:1111",
	}

	path := "ut-sw"
	port := 1111

	sw := rkentry.RegisterSwEntry(rkentry.WithPathSw(path), rkentry.WithPortSw(uint64(port)))
	entry := RegisterMuxEntry(WithSwEntry(sw), WithPort(uint64(port)))

	assert.Equal(t, fmt.Sprintf("http://8.8.8.8:%s/%s/", strconv.Itoa(port), path), entry.constructSwUrl(req))

	// with tls
	req.TLS = &tls.ConnectionState{}
	assert.Equal(t, fmt.Sprintf("https://8.8.8.8:%s/%s/", strconv.Itoa(port), path), entry.constructSwUrl(req))

	// without swagger
	entry = RegisterMuxEntry(WithPort(uint64(port)))
	assert.Equal(t, "N/A", entry.constructSwUrl(req))
}

func TestMuxEntry_API(t *testing.T) {
	defer assertNotPanic(t)

	entry := RegisterMuxEntry(
		WithPort(8080),
		WithCommonServiceEntry(rkentry.RegisterCommonServiceEntry()),
		WithName("unit-test"))

	entry.Bootstrap(context.TODO())

	req := httptest.NewRequest(http.MethodGet, "/rk/v1/apis", nil)
	w := httptest.NewRecorder()

	entry.Apis(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	entry.Interrupt(context.TODO())
}

func TestMuxEntry_Req_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	entry := RegisterMuxEntry(
		WithPort(8080),
		WithCommonServiceEntry(rkentry.RegisterCommonServiceEntry()),
		WithName("unit-test-req"))

	entry.Bootstrap(context.TODO())

	req := httptest.NewRequest(http.MethodGet, "/rk/v1/req", nil)
	w := httptest.NewRecorder()

	entry.Req(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	entry.Interrupt(context.TODO())
}

func TestMuxEntry_Req_WithEmpty(t *testing.T) {
	defer assertNotPanic(t)

	entry := RegisterMuxEntry(
		WithPort(8080),
		WithCommonServiceEntry(rkentry.RegisterCommonServiceEntry()),
		WithName("unit-test-req-empty"))

	entry.Bootstrap(context.TODO())

	entry.AddInterceptor(rkmuxmetrics.Interceptor(
		rkmidmetrics.WithRegisterer(prometheus.NewRegistry())))

	req := httptest.NewRequest(http.MethodGet, "/rk/v1/req", nil)
	w := httptest.NewRecorder()
	entry.Req(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	entry.Interrupt(context.TODO())
}

func TestMuxEntry_TV(t *testing.T) {
	defer assertNotPanic(t)

	entry := RegisterMuxEntry(
		WithCommonServiceEntry(rkentry.RegisterCommonServiceEntry()),
		WithTvEntry(rkentry.RegisterTvEntry()),
		WithPort(8080),
		WithName("ut-gf"))

	entry.AddInterceptor(rkmuxmetrics.Interceptor(
		rkmidmetrics.WithEntryNameAndType("ut-gf", "Gf")))

	entry.Bootstrap(context.TODO())

	// for /api
	req := httptest.NewRequest(http.MethodGet, "/rk/v1/tv/apis", nil)
	w := httptest.NewRecorder()
	entry.TV(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// for default
	req = httptest.NewRequest(http.MethodGet, "/rk/v1/tv/other", nil)
	w = httptest.NewRecorder()
	entry.TV(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	entry.Interrupt(context.TODO())
}

func validateServerIsUp(t *testing.T, port uint64, isTls bool) {
	// sleep for 2 seconds waiting server startup
	time.Sleep(2 * time.Second)

	if !isTls {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("0.0.0.0", strconv.FormatUint(port, 10)), time.Second)
		assert.Nil(t, err)
		assert.NotNil(t, conn)
		if conn != nil {
			assert.Nil(t, conn.Close())
		}
		return
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}

	tlsConn, err := tls.Dial("tcp", net.JoinHostPort("0.0.0.0", strconv.FormatUint(port, 10)), tlsConf)
	assert.Nil(t, err)
	assert.NotNil(t, tlsConn)
	if tlsConn != nil {
		assert.Nil(t, tlsConn.Close())
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

func assertPanic(t *testing.T) {
	if r := recover(); r != nil {
		// Expect panic to be called with non nil error
		assert.True(t, true)
	} else {
		// This should never be called in case of a bug
		assert.True(t, false)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
