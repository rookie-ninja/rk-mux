// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkmux

import (
	"context"
	"crypto/tls"
	"github.com/rookie-ninja/rk-entry/v2/entry"
	"github.com/rookie-ninja/rk-mux/middleware/meta"
	"github.com/stretchr/testify/assert"
	"net"
	"os"
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
   prom:
     enabled: true
     pusher:
       enabled: false
   middleware:
     logging:
       enabled: true
     prom:
       enabled: true
     auth:
       enabled: true
       basic:
         - "user:pass"
     meta:
       enabled: true
     trace:
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
   middleware:
     logging:
       enabled: true
     prom:
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

func TestGetMuxEntry(t *testing.T) {
	// expect nil
	assert.Nil(t, GetMuxEntry("entry-name"))

	// happy case
	muxEntry := RegisterMuxEntry(WithName("ut"))
	assert.Equal(t, muxEntry, GetMuxEntry("ut"))

	rkentry.GlobalAppCtx.RemoveEntry(muxEntry)
}

func TestRegisterMuxEntry(t *testing.T) {
	// without options
	entry := RegisterMuxEntry()
	assert.NotNil(t, entry)
	assert.NotEmpty(t, entry.GetName())
	assert.NotEmpty(t, entry.GetType())
	assert.NotEmpty(t, entry.GetDescription())
	assert.NotEmpty(t, entry.String())
	rkentry.GlobalAppCtx.RemoveEntry(entry)

	// with options
	commonServiceEntry := rkentry.RegisterCommonServiceEntry(&rkentry.BootCommonService{
		Enabled: true,
	})
	staticEntry := rkentry.RegisterStaticFileHandlerEntry(&rkentry.BootStaticFileHandler{
		Enabled: true,
	})
	certEntry := rkentry.RegisterCertEntry(&rkentry.BootCert{
		Cert: []*rkentry.BootCertE{
			{
				Name: "ut-cert",
			},
		},
	})
	swEntry := rkentry.RegisterSWEntry(&rkentry.BootSW{
		Enabled: true,
	})
	promEntry := rkentry.RegisterPromEntry(&rkentry.BootProm{
		Enabled: true,
	})

	// with options
	entry = RegisterMuxEntry(
		WithLoggerEntry(rkentry.LoggerEntryNoop),
		WithEventEntry(rkentry.EventEntryNoop),
		WithCommonServiceEntry(commonServiceEntry),
		WithCertEntry(certEntry[0]),
		WithSwEntry(swEntry),
		WithPort(8083),
		WithName("ut-entry"),
		WithDescription("ut-desc"),
		WithPromEntry(promEntry),
		WithStaticFileHandlerEntry(staticEntry))

	assert.NotEmpty(t, entry.GetName())
	assert.NotEmpty(t, entry.GetType())
	assert.NotEmpty(t, entry.GetDescription())
	assert.NotEmpty(t, entry.String())
	assert.True(t, entry.IsSwEnabled())
	assert.True(t, entry.IsPromEnabled())
	assert.True(t, entry.IsCommonServiceEnabled())
	assert.False(t, entry.IsDocsEnabled())
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
	inter := rkmuxmeta.Middleware()
	entry.AddMiddleware(inter)
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

	commonServiceEntry := rkentry.RegisterCommonServiceEntry(&rkentry.BootCommonService{
		Enabled: true,
	})
	swEntry := rkentry.RegisterSWEntry(&rkentry.BootSW{
		Enabled: true,
	})
	promEntry := rkentry.RegisterPromEntry(&rkentry.BootProm{
		Enabled: true,
	})

	entry = RegisterMuxEntry(
		WithPort(8081),
		WithCommonServiceEntry(commonServiceEntry),
		WithSwEntry(swEntry),
		WithPromEntry(promEntry))
	go entry.Bootstrap(context.Background())
	time.Sleep(time.Second)
	entry.Interrupt(context.TODO())
	// force to kill it because go-zero do not stop server with stop() call
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
}

func TestRegisterMuxEntriesWithConfig(t *testing.T) {
	defer assertNotPanic(t)

	// write config file in unit test temp directory
	entries := RegisterMuxEntryYAML([]byte(defaultBootConfigStr))
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
