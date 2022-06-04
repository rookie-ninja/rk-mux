// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkmux an implementation of rkentry.Entry which could be used start restful server with rkmux framework
package rkmux

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rookie-ninja/rk-entry/v2/entry"
	rkerror "github.com/rookie-ninja/rk-entry/v2/error"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/auth"
	"github.com/rookie-ninja/rk-entry/v2/middleware/cors"
	"github.com/rookie-ninja/rk-entry/v2/middleware/csrf"
	"github.com/rookie-ninja/rk-entry/v2/middleware/jwt"
	"github.com/rookie-ninja/rk-entry/v2/middleware/log"
	"github.com/rookie-ninja/rk-entry/v2/middleware/meta"
	"github.com/rookie-ninja/rk-entry/v2/middleware/panic"
	"github.com/rookie-ninja/rk-entry/v2/middleware/prom"
	"github.com/rookie-ninja/rk-entry/v2/middleware/ratelimit"
	"github.com/rookie-ninja/rk-entry/v2/middleware/secure"
	"github.com/rookie-ninja/rk-entry/v2/middleware/tracing"
	"github.com/rookie-ninja/rk-mux/middleware/auth"
	"github.com/rookie-ninja/rk-mux/middleware/cors"
	"github.com/rookie-ninja/rk-mux/middleware/csrf"
	"github.com/rookie-ninja/rk-mux/middleware/jwt"
	"github.com/rookie-ninja/rk-mux/middleware/log"
	"github.com/rookie-ninja/rk-mux/middleware/meta"
	"github.com/rookie-ninja/rk-mux/middleware/panic"
	"github.com/rookie-ninja/rk-mux/middleware/prom"
	"github.com/rookie-ninja/rk-mux/middleware/ratelimit"
	"github.com/rookie-ninja/rk-mux/middleware/secure"
	"github.com/rookie-ninja/rk-mux/middleware/tracing"
	"github.com/rookie-ninja/rk-query"
	"go.uber.org/zap"
	"net"
	"net/http"
	"net/http/pprof"
	"path"
	"strconv"
	"strings"
	"sync"
)

const (
	// MuxEntryType type of entry
	MuxEntryType = "MuxEntry"
)

// This must be declared in order to register registration function into rk context
// otherwise, rk-boot won't able to bootstrap Mux entry automatically from boot config file
func init() {
	rkentry.RegisterWebFrameRegFunc(RegisterMuxEntryYAML)
}

// BootMux boot config which is for Mux entry.
type BootMux struct {
	Mux []struct {
		Enabled       bool                          `yaml:"enabled" json:"enabled"`
		Name          string                        `yaml:"name" json:"name"`
		Port          uint64                        `yaml:"port" json:"port"`
		Description   string                        `yaml:"description" json:"description"`
		SW            rkentry.BootSW                `yaml:"sw" json:"sw"`
		Docs          rkentry.BootDocs              `yaml:"docs" json:"docs"`
		CommonService rkentry.BootCommonService     `yaml:"commonService" json:"commonService"`
		Prom          rkentry.BootProm              `yaml:"prom" json:"prom"`
		CertEntry     string                        `yaml:"certEntry" json:"certEntry"`
		LoggerEntry   string                        `yaml:"loggerEntry" json:"loggerEntry"`
		EventEntry    string                        `yaml:"eventEntry" json:"eventEntry"`
		Static        rkentry.BootStaticFileHandler `yaml:"static" json:"static"`
		PProf         rkentry.BootPProf             `yaml:"pprof" json:"pprof"`
		Middleware    struct {
			Ignore     []string              `yaml:"ignore" json:"ignore"`
			ErrorModel string                `yaml:"errorModel" json:"errorModel"`
			Logging    rkmidlog.BootConfig   `yaml:"logging" json:"logging"`
			Prom       rkmidprom.BootConfig  `yaml:"prom" json:"prom"`
			Auth       rkmidauth.BootConfig  `yaml:"auth" json:"auth"`
			Cors       rkmidcors.BootConfig  `yaml:"cors" json:"cors"`
			Meta       rkmidmeta.BootConfig  `yaml:"meta" json:"meta"`
			Jwt        rkmidjwt.BootConfig   `yaml:"jwt" json:"jwt"`
			Secure     rkmidsec.BootConfig   `yaml:"secure" json:"secure"`
			RateLimit  rkmidlimit.BootConfig `yaml:"rateLimit" json:"rateLimit"`
			Csrf       rkmidcsrf.BootConfig  `yaml:"csrf" yaml:"csrf"`
			Trace      rkmidtrace.BootConfig `yaml:"trace" json:"trace"`
		} `yaml:"middleware" json:"middleware"`
	} `yaml:"mux" json:"mux"`
}

// MuxEntry implements rkentry.Entry interface.
type MuxEntry struct {
	entryName          string                          `json:"-" yaml:"-"`
	entryType          string                          `json:"-" yaml:"-"`
	entryDescription   string                          `json:"-" yaml:"-"`
	Port               uint64                          `json:"-" yaml:"-"`
	LoggerEntry        *rkentry.LoggerEntry            `json:"-" yaml:"-"`
	EventEntry         *rkentry.EventEntry             `json:"-" yaml:"-"`
	CertEntry          *rkentry.CertEntry              `json:"-" yaml:"-"`
	SwEntry            *rkentry.SWEntry                `json:"-" yaml:"-"`
	CommonServiceEntry *rkentry.CommonServiceEntry     `json:"-" yaml:"-"`
	Router             *mux.Router                     `json:"-" yaml:"-"`
	Server             *http.Server                    `json:"-" yaml:"-"`
	TlsConfig          *tls.Config                     `json:"-" yaml:"-"`
	Middlewares        []mux.MiddlewareFunc            `json:"-" yaml:"-"`
	PromEntry          *rkentry.PromEntry              `json:"-" yaml:"-"`
	DocsEntry          *rkentry.DocsEntry              `json:"-" yaml:"-"`
	StaticFileEntry    *rkentry.StaticFileHandlerEntry `json:"-" yaml:"-"`
	PProfEntry         *rkentry.PProfEntry             `json:"-" yaml:"-"`

	bootstrapLogOnce sync.Once `json:"-" yaml:"-"`
}

// RegisterMuxEntryYAML register Mux entries with provided config file (Must YAML file).
//
// Currently, support two ways to provide config file path.
// 1: With function parameters
// 2: With command line flag "--rkboot" described in rkcommon.BootConfigPathFlagKey (Will override function parameter if exists)
// Command line flag has high priority which would override function parameter
//
// Error handling:
// Process will shutdown if any errors occur with rkcommon.ShutdownWithError function
//
// Override elements in config file:
// We learned from HELM source code which would override elements in YAML file with "--set" flag followed with comma
// separated key/value pairs.
//
// We are using "--rkset" described in rkcommon.BootConfigOverrideKey in order to distinguish with user flags
// Example of common usage: ./binary_file --rkset "key1=val1,key2=val2"
// Example of nested map:   ./binary_file --rkset "outer.inner.key=val"
// Example of slice:        ./binary_file --rkset "outer[0].key=val"
func RegisterMuxEntryYAML(raw []byte) map[string]rkentry.Entry {
	res := make(map[string]rkentry.Entry)

	// 1: Decode config map into boot config struct
	config := &BootMux{}
	rkentry.UnmarshalBootYAML(raw, config)

	// 2: Init Mux entries with boot config
	for i := range config.Mux {
		element := config.Mux[i]
		if !element.Enabled {
			continue
		}

		name := element.Name

		// logger entry
		loggerEntry := rkentry.GlobalAppCtx.GetLoggerEntry(element.LoggerEntry)
		if loggerEntry == nil {
			loggerEntry = rkentry.LoggerEntryStdout
		}

		// event entry
		eventEntry := rkentry.GlobalAppCtx.GetEventEntry(element.EventEntry)
		if eventEntry == nil {
			eventEntry = rkentry.EventEntryStdout
		}

		// cert entry
		certEntry := rkentry.GlobalAppCtx.GetCertEntry(element.CertEntry)

		// Register swagger entry
		swEntry := rkentry.RegisterSWEntry(&element.SW, rkentry.WithNameSWEntry(element.Name))

		// Register docs entry
		docsEntry := rkentry.RegisterDocsEntry(&element.Docs, rkentry.WithNameDocsEntry(element.Name))

		// Register prometheus entry
		promRegistry := prometheus.NewRegistry()
		promEntry := rkentry.RegisterPromEntry(&element.Prom, rkentry.WithRegistryPromEntry(promRegistry))

		// Register common service entry
		commonServiceEntry := rkentry.RegisterCommonServiceEntry(&element.CommonService)

		// Register static file handler
		staticEntry := rkentry.RegisterStaticFileHandlerEntry(&element.Static, rkentry.WithNameStaticFileHandlerEntry(element.Name))

		// Register pprof entry
		pprofEntry := rkentry.RegisterPProfEntry(&element.PProf, rkentry.WithNamePProfEntry(element.Name))

		inters := make([]mux.MiddlewareFunc, 0)

		// add global path ignorance
		rkmid.AddPathToIgnoreGlobal(element.Middleware.Ignore...)

		switch strings.ToLower(element.Middleware.ErrorModel) {
		case "", "google":
			rkmid.SetErrorBuilder(rkerror.NewErrorBuilderGoogle())
		case "amazon":
			rkmid.SetErrorBuilder(rkerror.NewErrorBuilderAMZN())
		}

		// logging middlewares
		if element.Middleware.Logging.Enabled {
			inters = append(inters, rkmuxlog.Middleware(
				rkmidlog.ToOptions(&element.Middleware.Logging, element.Name, MuxEntryType,
					loggerEntry, eventEntry)...))

		}

		// Default interceptor should be placed after logging middleware, we should make sure interceptors never panic
		// insert panic interceptor
		inters = append(inters, rkmuxpanic.Middleware(
			rkmidpanic.WithEntryNameAndType(element.Name, MuxEntryType)))

		// metrics middleware
		if element.Middleware.Prom.Enabled {
			inters = append(inters, rkmuxprom.Middleware(
				rkmidprom.ToOptions(&element.Middleware.Prom, element.Name, MuxEntryType,
					promRegistry, rkmidprom.LabelerTypeHttp)...))
		}

		// tracing middleware
		if element.Middleware.Trace.Enabled {
			inters = append(inters, rkmuxtrace.Middleware(
				rkmidtrace.ToOptions(&element.Middleware.Trace, element.Name, MuxEntryType)...))
		}

		// jwt middleware
		if element.Middleware.Jwt.Enabled {
			inters = append(inters, rkmuxjwt.Interceptor(
				rkmidjwt.ToOptions(&element.Middleware.Jwt, element.Name, MuxEntryType)...))
		}

		// secure middleware
		if element.Middleware.Secure.Enabled {
			inters = append(inters, rkmuxsec.Middleware(
				rkmidsec.ToOptions(&element.Middleware.Secure, element.Name, MuxEntryType)...))
		}

		// csrf middleware
		if element.Middleware.Csrf.Enabled {
			inters = append(inters, rkmuxcsrf.Middleware(
				rkmidcsrf.ToOptions(&element.Middleware.Csrf, element.Name, MuxEntryType)...))
		}

		// cors middleware
		if element.Middleware.Cors.Enabled {
			inters = append(inters, rkmuxcors.Middleware(
				rkmidcors.ToOptions(&element.Middleware.Cors, element.Name, MuxEntryType)...))
		}

		// meta middleware
		if element.Middleware.Meta.Enabled {
			inters = append(inters, rkmuxmeta.Middleware(
				rkmidmeta.ToOptions(&element.Middleware.Meta, element.Name, MuxEntryType)...))
		}

		// auth middlewares
		if element.Middleware.Auth.Enabled {
			inters = append(inters, rkmuxauth.Middleware(
				rkmidauth.ToOptions(&element.Middleware.Auth, element.Name, MuxEntryType)...))
		}

		// rate limit middleware
		if element.Middleware.RateLimit.Enabled {
			inters = append(inters, rkmuxlimit.Middleware(
				rkmidlimit.ToOptions(&element.Middleware.RateLimit, element.Name, MuxEntryType)...))
		}

		entry := RegisterMuxEntry(
			WithName(name),
			WithDescription(element.Description),
			WithPort(element.Port),
			WithLoggerEntry(loggerEntry),
			WithEventEntry(eventEntry),
			WithCertEntry(certEntry),
			WithPromEntry(promEntry),
			WithDocsEntry(docsEntry),
			WithCommonServiceEntry(commonServiceEntry),
			WithSwEntry(swEntry),
			WithPProfEntry(pprofEntry),
			WithStaticFileHandlerEntry(staticEntry))

		entry.AddMiddleware(inters...)

		res[name] = entry
	}

	return res
}

// RegisterMuxEntry register MuxEntry with options.
func RegisterMuxEntry(opts ...MuxEntryOption) *MuxEntry {
	entry := &MuxEntry{
		entryType:        MuxEntryType,
		entryDescription: "Internal RK entry which helps to bootstrap with mux framework.",
		LoggerEntry:      rkentry.NewLoggerEntryStdout(),
		EventEntry:       rkentry.NewEventEntryStdout(),
		Port:             80,
	}

	for i := range opts {
		opts[i](entry)
	}

	if len(entry.entryName) < 1 {
		entry.entryName = "mux-" + strconv.FormatUint(entry.Port, 10)
	}

	if entry.Router == nil {
		entry.Router = mux.NewRouter()
	}

	// add entry name and entry type into loki syncer if enabled
	entry.LoggerEntry.AddEntryLabelToLokiSyncer(entry)
	entry.EventEntry.AddEntryLabelToLokiSyncer(entry)

	// Init TLS config
	if entry.IsTlsEnabled() {
		entry.TlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{*entry.CertEntry.Certificate},
		}
	}

	entry.Server = &http.Server{
		Addr: "0.0.0.0:" + strconv.FormatUint(entry.Port, 10),
	}

	rkentry.GlobalAppCtx.AddEntry(entry)

	return entry
}

// Bootstrap MuxEntry.
func (entry *MuxEntry) Bootstrap(ctx context.Context) {
	event, logger := entry.logBasicInfo("Bootstrap", ctx)

	// Is common service enabled?
	if entry.IsCommonServiceEnabled() {
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.ReadyPath).HandlerFunc(entry.CommonServiceEntry.Ready)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.AlivePath).HandlerFunc(entry.CommonServiceEntry.Alive)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.GcPath).HandlerFunc(entry.CommonServiceEntry.Gc)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.InfoPath).HandlerFunc(entry.CommonServiceEntry.Info)

		// Bootstrap common service entry.
		entry.CommonServiceEntry.Bootstrap(ctx)
	}

	// Is swagger enabled?
	if entry.IsSwEnabled() {
		redirect := func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Location", entry.SwEntry.Path)
			writer.WriteHeader(http.StatusTemporaryRedirect)
		}

		entry.Router.NewRoute().Methods(http.MethodGet).Path(strings.TrimSuffix(entry.SwEntry.Path, "/")).HandlerFunc(redirect)
		entry.Router.NewRoute().Methods(http.MethodGet).PathPrefix(entry.SwEntry.Path).HandlerFunc(entry.SwEntry.ConfigFileHandler())

		// Bootstrap swagger entry.
		entry.SwEntry.Bootstrap(ctx)
	}

	// Is Docs enabled?
	if entry.IsDocsEnabled() {
		// Bootstrap TV entry.
		redirect := func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Location", entry.DocsEntry.Path)
			writer.WriteHeader(http.StatusTemporaryRedirect)
		}

		entry.Router.NewRoute().Methods(http.MethodGet).Path(strings.TrimSuffix(entry.DocsEntry.Path, "/")).HandlerFunc(redirect)
		entry.Router.NewRoute().Methods(http.MethodGet).PathPrefix(entry.DocsEntry.Path).HandlerFunc(entry.DocsEntry.ConfigFileHandler())

		entry.DocsEntry.Bootstrap(ctx)
	}

	// Is static file handler enabled?
	if entry.IsStaticFileHandlerEnabled() {
		// Register path into Router.
		entry.Router.NewRoute().Methods(http.MethodGet).Path(strings.TrimSuffix(entry.StaticFileEntry.Path, "/")).HandlerFunc(
			func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Location", entry.StaticFileEntry.Path)
				writer.WriteHeader(http.StatusTemporaryRedirect)
			})

		entry.Router.NewRoute().Methods(http.MethodGet).PathPrefix(entry.StaticFileEntry.Path).HandlerFunc(entry.StaticFileEntry.GetFileHandler())

		// Register path into Router.
		entry.StaticFileEntry.Bootstrap(ctx)
	}

	// Is pprof enabled?
	if entry.IsPProfEnabled() {
		entry.Router.NewRoute().Methods(http.MethodGet).Path(strings.TrimSuffix(entry.PProfEntry.Path, "/")).HandlerFunc(
			func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Location", entry.PProfEntry.Path)
				writer.WriteHeader(http.StatusTemporaryRedirect)
			})

		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.PProfEntry.Path).HandlerFunc(pprof.Index)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "cmdline")).HandlerFunc(pprof.Cmdline)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "profile")).HandlerFunc(pprof.Profile)
		entry.Router.NewRoute().Methods(http.MethodGet, http.MethodPost).Path(path.Join(entry.PProfEntry.Path, "symbol")).HandlerFunc(pprof.Symbol)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "trace")).HandlerFunc(pprof.Trace)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "allocs")).HandlerFunc(pprof.Handler("allocs").ServeHTTP)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "block")).HandlerFunc(pprof.Handler("block").ServeHTTP)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "goroutine")).HandlerFunc(pprof.Handler("goroutine").ServeHTTP)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "heap")).HandlerFunc(pprof.Handler("heap").ServeHTTP)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "mutex")).HandlerFunc(pprof.Handler("mutex").ServeHTTP)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.PProfEntry.Path, "threadcreate")).HandlerFunc(pprof.Handler("threadcreate").ServeHTTP)
		entry.PProfEntry.Bootstrap(ctx)
	}

	// Is prometheus enabled?
	if entry.IsPromEnabled() {
		// Register prom path into Router.
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.PromEntry.Path).Handler(promhttp.HandlerFor(entry.PromEntry.Gatherer, promhttp.HandlerOpts{}))

		// don't start with http handler, we will handle it by ourselves
		entry.PromEntry.Bootstrap(ctx)
	}

	go entry.startServer(event, logger)

	entry.bootstrapLogOnce.Do(func() {
		// Print link and logging message
		scheme := "http"
		if entry.IsTlsEnabled() {
			scheme = "https"
		}

		if entry.IsSwEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("SwaggerEntry: %s://localhost:%d%s", scheme, entry.Port, entry.SwEntry.Path))
		}
		if entry.IsDocsEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("DocsEntry: %s://localhost:%d%s", scheme, entry.Port, entry.DocsEntry.Path))
		}
		if entry.IsPromEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("PromEntry: %s://localhost:%d%s", scheme, entry.Port, entry.PromEntry.Path))
		}
		if entry.IsStaticFileHandlerEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("StaticFileHandlerEntry: %s://localhost:%d%s", scheme, entry.Port, entry.StaticFileEntry.Path))
		}
		if entry.IsCommonServiceEnabled() {
			handlers := []string{
				fmt.Sprintf("%s://localhost:%d%s", scheme, entry.Port, entry.CommonServiceEntry.ReadyPath),
				fmt.Sprintf("%s://localhost:%d%s", scheme, entry.Port, entry.CommonServiceEntry.AlivePath),
				fmt.Sprintf("%s://localhost:%d%s", scheme, entry.Port, entry.CommonServiceEntry.InfoPath),
			}

			entry.LoggerEntry.Info(fmt.Sprintf("CommonSreviceEntry: %s", strings.Join(handlers, ", ")))
		}
		if entry.IsPProfEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("PProfEntry: %s://localhost:%d%s", scheme, entry.Port, entry.PProfEntry.Path))
		}
		entry.EventEntry.Finish(event)
	})
}

// Interrupt MuxEntry.
func (entry *MuxEntry) Interrupt(ctx context.Context) {
	event, logger := entry.logBasicInfo("Interrupt", ctx)

	if entry.IsSwEnabled() {
		// Interrupt swagger entry
		entry.SwEntry.Interrupt(ctx)
	}

	if entry.IsPromEnabled() {
		// Interrupt prometheus entry
		entry.PromEntry.Interrupt(ctx)
	}

	if entry.IsCommonServiceEnabled() {
		// Interrupt common service entry
		entry.CommonServiceEntry.Interrupt(ctx)
	}

	if entry.IsDocsEnabled() {
		// Interrupt common service entry
		entry.DocsEntry.Interrupt(ctx)
	}

	if entry.IsPProfEnabled() {
		entry.PProfEntry.Interrupt(ctx)
	}

	if entry.Server != nil {
		if err := entry.Server.Shutdown(context.Background()); err != nil {
			event.AddErr(err)
			logger.Warn("Error occurs while stopping http server")
		}
	}

	entry.EventEntry.Finish(event)
}

// GetName Get entry name.
func (entry *MuxEntry) GetName() string {
	return entry.entryName
}

// GetType Get entry type.
func (entry *MuxEntry) GetType() string {
	return entry.entryType
}

// GetDescription Get description of entry.
func (entry *MuxEntry) GetDescription() string {
	return entry.entryDescription
}

// String Stringfy entry.
func (entry *MuxEntry) String() string {
	bytes, _ := json.Marshal(entry)
	return string(bytes)
}

// ***************** Stringfy *****************

// MarshalJSON Marshal entry.
func (entry *MuxEntry) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"name":                   entry.entryName,
		"type":                   entry.entryType,
		"description":            entry.entryDescription,
		"port":                   entry.Port,
		"swEntry":                entry.SwEntry,
		"docsEntry":              entry.DocsEntry,
		"commonServiceEntry":     entry.CommonServiceEntry,
		"promEntry":              entry.PromEntry,
		"staticFileHandlerEntry": entry.StaticFileEntry,
		"pprofEntry":             entry.PProfEntry,
	}

	if entry.CertEntry != nil {
		m["certEntry"] = entry.CertEntry.GetName()
	}

	return json.Marshal(&m)
}

// UnmarshalJSON Not supported.
func (entry *MuxEntry) UnmarshalJSON([]byte) error {
	return nil
}

// ***************** Public functions *****************

// GetMuxEntry Get MuxEntry from rkentry.GlobalAppCtx.
func GetMuxEntry(name string) *MuxEntry {
	entryRaw := rkentry.GlobalAppCtx.GetEntry(MuxEntryType, name)
	if entryRaw == nil {
		return nil
	}

	entry, _ := entryRaw.(*MuxEntry)
	return entry
}

// AddMiddleware Add middlewares.
// This function should be called before Bootstrap() called.
func (entry *MuxEntry) AddMiddleware(inters ...mux.MiddlewareFunc) {
	entry.Router.Use(inters...)
}

// IsTlsEnabled Is TLS enabled?
func (entry *MuxEntry) IsTlsEnabled() bool {
	return entry.CertEntry != nil && entry.CertEntry.Certificate != nil
}

// IsSwEnabled Is swagger entry enabled?
func (entry *MuxEntry) IsSwEnabled() bool {
	return entry.SwEntry != nil
}

// IsCommonServiceEnabled Is common service entry enabled?
func (entry *MuxEntry) IsCommonServiceEnabled() bool {
	return entry.CommonServiceEntry != nil
}

// IsDocsEnabled Is Docs entry enabled?
func (entry *MuxEntry) IsDocsEnabled() bool {
	return entry.DocsEntry != nil
}

// IsPromEnabled Is prometheus entry enabled?
func (entry *MuxEntry) IsPromEnabled() bool {
	return entry.PromEntry != nil
}

// IsStaticFileHandlerEnabled Is static file handler entry enabled?
func (entry *MuxEntry) IsStaticFileHandlerEnabled() bool {
	return entry.StaticFileEntry != nil
}

// IsPProfEnabled Is pprof entry enabled?
func (entry *MuxEntry) IsPProfEnabled() bool {
	return entry.PProfEntry != nil
}

// ***************** Helper function *****************

// Start server
// We move the code here for testability
func (entry *MuxEntry) startServer(event rkquery.Event, logger *zap.Logger) {
	if entry.Server != nil {
		entry.Server.Handler = entry.Router

		lis, err := net.Listen("tcp4", ":"+strconv.FormatUint(entry.Port, 10))
		if err != nil {
			entry.bootstrapLogOnce.Do(func() {
				entry.EventEntry.FinishWithCond(event, false)
			})
			rkentry.ShutdownWithError(err)
		}

		if entry.IsTlsEnabled() {
			lis = tls.NewListener(lis, entry.TlsConfig)
		}

		if err := entry.Server.Serve(lis); err != nil && !strings.Contains(err.Error(), "http: Server closed") {
			logger.Error("Error occurs while serving gateway-server.", zap.Error(err))
			entry.bootstrapLogOnce.Do(func() {
				entry.EventEntry.FinishWithCond(event, false)
			})
			rkentry.ShutdownWithError(err)
		}
	}
}

// Add basic fields into event.
func (entry *MuxEntry) logBasicInfo(operation string, ctx context.Context) (rkquery.Event, *zap.Logger) {
	event := entry.EventEntry.Start(
		operation,
		rkquery.WithEntryName(entry.GetName()),
		rkquery.WithEntryType(entry.GetType()))

	// extract eventId if exists
	if val := ctx.Value("eventId"); val != nil {
		if id, ok := val.(string); ok {
			event.SetEventId(id)
		}
	}

	logger := entry.LoggerEntry.With(
		zap.String("eventId", event.GetEventId()),
		zap.String("entryName", entry.entryName),
		zap.String("entryType", entry.entryType))

	// add general info
	event.AddPayloads(
		zap.Uint64("muxPort", entry.Port))

	// add SwEntry info
	if entry.IsSwEnabled() {
		event.AddPayloads(
			zap.Bool("swEnabled", true),
			zap.String("swPath", entry.SwEntry.Path))
	}

	// add CommonServiceEntry info
	if entry.IsCommonServiceEnabled() {
		event.AddPayloads(
			zap.Bool("commonServiceEnabled", true),
			zap.String("commonServicePathPrefix", "/rk/v1/"))
	}

	// add DocsEntry info
	if entry.IsDocsEnabled() {
		event.AddPayloads(
			zap.Bool("docsEnabled", true),
			zap.String("docsPath", entry.DocsEntry.Path))
	}

	// add pprofEntry info
	if entry.IsPProfEnabled() {
		event.AddPayloads(
			zap.Bool("pprofEnabled", true),
			zap.String("pprofPath", entry.PProfEntry.Path))
	}

	// add PromEntry info
	if entry.IsPromEnabled() {
		event.AddPayloads(
			zap.Bool("promEnabled", true),
			zap.Uint64("promPort", entry.Port),
			zap.String("promPath", entry.PromEntry.Path))
	}

	// add tls info
	if entry.IsTlsEnabled() {
		event.AddPayloads(
			zap.Bool("tlsEnabled", true))
	}

	logger.Info(fmt.Sprintf("%s muxEntry", operation))

	return event, logger

}

// ***************** Options *****************

// MuxEntryOption Mux entry option.
type MuxEntryOption func(*MuxEntry)

// WithName provide name.
func WithName(name string) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.entryName = name
	}
}

// WithDescription provide name.
func WithDescription(description string) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.entryDescription = description
	}
}

// WithPort provide port.
func WithPort(port uint64) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.Port = port
	}
}

// WithLoggerEntry provide rkentry.LoggerEntry.
func WithLoggerEntry(zapLogger *rkentry.LoggerEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.LoggerEntry = zapLogger
	}
}

// WithEventEntry provide rkentry.EventEntry.
func WithEventEntry(eventLogger *rkentry.EventEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.EventEntry = eventLogger
	}
}

// WithCertEntry provide rkentry.CertEntry.
func WithCertEntry(certEntry *rkentry.CertEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.CertEntry = certEntry
	}
}

// WithSwEntry provide SwEntry.
func WithSwEntry(sw *rkentry.SWEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.SwEntry = sw
	}
}

// WithPProfEntry provide rkentry.PProfEntry.
func WithPProfEntry(p *rkentry.PProfEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.PProfEntry = p
	}
}

// WithCommonServiceEntry provide CommonServiceEntry.
func WithCommonServiceEntry(commonServiceEntry *rkentry.CommonServiceEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.CommonServiceEntry = commonServiceEntry
	}
}

// WithPromEntry provide PromEntry.
func WithPromEntry(prom *rkentry.PromEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.PromEntry = prom
	}
}

// WithDocsEntry provide DocsEntry.
func WithDocsEntry(docsEntry *rkentry.DocsEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.DocsEntry = docsEntry
	}
}

// WithStaticFileHandlerEntry provide StaticFileHandlerEntry.
func WithStaticFileHandlerEntry(staticEntry *rkentry.StaticFileHandlerEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.StaticFileEntry = staticEntry
	}
}
