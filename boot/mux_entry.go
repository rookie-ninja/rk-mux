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
	"github.com/rookie-ninja/rk-common/common"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-entry/middleware/auth"
	"github.com/rookie-ninja/rk-entry/middleware/cors"
	"github.com/rookie-ninja/rk-entry/middleware/csrf"
	"github.com/rookie-ninja/rk-entry/middleware/jwt"
	"github.com/rookie-ninja/rk-entry/middleware/log"
	"github.com/rookie-ninja/rk-entry/middleware/meta"
	"github.com/rookie-ninja/rk-entry/middleware/metrics"
	"github.com/rookie-ninja/rk-entry/middleware/panic"
	"github.com/rookie-ninja/rk-entry/middleware/ratelimit"
	"github.com/rookie-ninja/rk-entry/middleware/secure"
	"github.com/rookie-ninja/rk-entry/middleware/tracing"
	"github.com/rookie-ninja/rk-mux/interceptor"
	"github.com/rookie-ninja/rk-mux/interceptor/auth"
	"github.com/rookie-ninja/rk-mux/interceptor/context"
	"github.com/rookie-ninja/rk-mux/interceptor/cors"
	"github.com/rookie-ninja/rk-mux/interceptor/csrf"
	"github.com/rookie-ninja/rk-mux/interceptor/jwt"
	"github.com/rookie-ninja/rk-mux/interceptor/log/zap"
	"github.com/rookie-ninja/rk-mux/interceptor/meta"
	"github.com/rookie-ninja/rk-mux/interceptor/metrics/prom"
	"github.com/rookie-ninja/rk-mux/interceptor/panic"
	"github.com/rookie-ninja/rk-mux/interceptor/ratelimit"
	"github.com/rookie-ninja/rk-mux/interceptor/secure"
	"github.com/rookie-ninja/rk-mux/interceptor/tracing/telemetry"
	"github.com/rookie-ninja/rk-query"
	"go.uber.org/zap"
	"net"
	"net/http"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
)

const (
	// MuxEntryType type of entry
	MuxEntryType = "MuxEntry"
	// MuxEntryDescription description of entry
	MuxEntryDescription = "Internal RK entry which helps to bootstrap with mux framework."
)

// This must be declared in order to register registration function into rk context
// otherwise, rk-boot won't able to bootstrap Mux entry automatically from boot config file
func init() {
	rkentry.RegisterEntryRegFunc(RegisterMuxEntriesWithConfig)
}

// BootConfigMux boot config which is for Mux entry.
//
// 1: Mux.Enabled: Enable Mux entry, default is true.
// 2: Mux.Name: Name of Mux entry, should be unique globally.
// 3: Mux.Port: Port of Mux entry.
// 4: Mux.Cert.Ref: Reference of rkentry.CertEntry.
// 5: Mux.SW: See BootConfigSW for details.
// 6: Mux.CommonService: See BootConfigCommonService for details.
// 7: Mux.TV: See BootConfigTv for details.
// 8: Mux.Prom: See BootConfigProm for details.
// 9: Mux.Interceptors.LoggingZap.Enabled: Enable zap logging interceptor.
// 10: Mux.Interceptors.MetricsProm.Enable: Enable prometheus interceptor.
// 11: Mux.Interceptors.auth.Enabled: Enable basic auth.
// 12: Mux.Interceptors.auth.Basic: Credential for basic auth, scheme: <user:pass>
// 13: Mux.Interceptors.auth.ApiKey: Credential for X-API-Key.
// 14: Mux.Interceptors.auth.igorePrefix: List of paths that will be ignored.
// 15: Mux.Interceptors.Extension.Enabled: Enable extension interceptor.
// 16: Mux.Interceptors.Extension.Prefix: Prefix of extension header key.
// 17: Mux.Interceptors.TracingTelemetry.Enabled: Enable tracing interceptor with opentelemetry.
// 18: Mux.Interceptors.TracingTelemetry.Exporter.File.Enabled: Enable file exporter which support type of stdout and local file.
// 19: Mux.Interceptors.TracingTelemetry.Exporter.File.OutputPath: Output path of file exporter, stdout and file path is supported.
// 20: Mux.Interceptors.TracingTelemetry.Exporter.Jaeger.Enabled: Enable jaeger exporter.
// 21: Mux.Interceptors.TracingTelemetry.Exporter.Jaeger.AgentEndpoint: Specify jeager agent endpoint, localhost:6832 would be used by default.
// 22: Mux.Interceptors.RateLimit.Enabled: Enable rate limit interceptor.
// 23: Mux.Interceptors.RateLimit.Algorithm: Algorithm of rate limiter.
// 24: Mux.Interceptors.RateLimit.ReqPerSec: Request per second.
// 25: Mux.Interceptors.RateLimit.Paths.path: Name of full path.
// 26: Mux.Interceptors.RateLimit.Paths.ReqPerSec: Request per second by path.
// 27: Mux.Interceptors.Timeout.Enabled: Enable timeout interceptor.
// 28: Mux.Interceptors.Timeout.TimeoutMs: Timeout in milliseconds.
// 29: Mux.Interceptors.Timeout.Paths.path: Name of full path.
// 30: Mux.Interceptors.Timeout.Paths.TimeoutMs: Timeout in milliseconds by path.
// 31: Mux.Logger.ZapLogger.Ref: Zap logger reference, see rkentry.ZapLoggerEntry for details.
// 32: Mux.Logger.EventLogger.Ref: Event logger reference, see rkentry.EventLoggerEntry for details.
type BootConfig struct {
	Mux []struct {
		Enabled     bool   `yaml:"enabled" json:"enabled"`
		Name        string `yaml:"name" json:"name"`
		Port        uint64 `yaml:"port" json:"port"`
		Description string `yaml:"description" json:"description"`
		Cert        struct {
			Ref string `yaml:"ref" json:"ref"`
		} `yaml:"cert" json:"cert"`
		SW            rkentry.BootConfigSw            `yaml:"sw" json:"sw"`
		CommonService rkentry.BootConfigCommonService `yaml:"commonService" json:"commonService"`
		TV            rkentry.BootConfigTv            `yaml:"tv" json:"tv"`
		Prom          rkentry.BootConfigProm          `yaml:"prom" json:"prom"`
		Static        rkentry.BootConfigStaticHandler `yaml:"static" json:"static"`
		Interceptors  struct {
			LoggingZap       rkmidlog.BootConfig     `yaml:"loggingZap" json:"loggingZap"`
			MetricsProm      rkmidmetrics.BootConfig `yaml:"metricsProm" json:"metricsProm"`
			Auth             rkmidauth.BootConfig    `yaml:"auth" json:"auth"`
			Cors             rkmidcors.BootConfig    `yaml:"cors" json:"cors"`
			Meta             rkmidmeta.BootConfig    `yaml:"meta" json:"meta"`
			Jwt              rkmidjwt.BootConfig     `yaml:"jwt" json:"jwt"`
			Secure           rkmidsec.BootConfig     `yaml:"secure" json:"secure"`
			RateLimit        rkmidlimit.BootConfig   `yaml:"rateLimit" json:"rateLimit"`
			Csrf             rkmidcsrf.BootConfig    `yaml:"csrf" yaml:"csrf"`
			TracingTelemetry rkmidtrace.BootConfig   `yaml:"tracingTelemetry" json:"tracingTelemetry"`
		} `yaml:"interceptors" json:"interceptors"`
		Logger struct {
			ZapLogger struct {
				Ref string `yaml:"ref" json:"ref"`
			} `yaml:"zapLogger" json:"zapLogger"`
			EventLogger struct {
				Ref string `yaml:"ref" json:"ref"`
			} `yaml:"eventLogger" json:"eventLogger"`
		} `yaml:"logger" json:"logger"`
	} `yaml:"mux" json:"mux"`
}

// MuxEntry implements rkentry.Entry interface.
type MuxEntry struct {
	EntryName          string                          `json:"entryName" yaml:"entryName"`
	EntryType          string                          `json:"entryType" yaml:"entryType"`
	EntryDescription   string                          `json:"-" yaml:"-"`
	ZapLoggerEntry     *rkentry.ZapLoggerEntry         `json:"-" yaml:"-"`
	EventLoggerEntry   *rkentry.EventLoggerEntry       `json:"-" yaml:"-"`
	Port               uint64                          `json:"port" yaml:"port"`
	CertEntry          *rkentry.CertEntry              `json:"-" yaml:"-"`
	SwEntry            *rkentry.SwEntry                `json:"-" yaml:"-"`
	CommonServiceEntry *rkentry.CommonServiceEntry     `json:"-" yaml:"-"`
	Router             *mux.Router                     `json:"-" yaml:"-"`
	Server             *http.Server                    `json:"-" yaml:"-"`
	TlsConfig          *tls.Config                     `json:"-" yaml:"-"`
	Interceptors       []mux.MiddlewareFunc            `json:"-" yaml:"-"`
	PromEntry          *rkentry.PromEntry              `json:"-" yaml:"-"`
	TvEntry            *rkentry.TvEntry                `json:"-" yaml:"-"`
	StaticFileEntry    *rkentry.StaticFileHandlerEntry `json:"-" yaml:"-"`
}

// RegisterMuxEntriesWithConfig register Mux entries with provided config file (Must YAML file).
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
func RegisterMuxEntriesWithConfig(configFilePath string) map[string]rkentry.Entry {
	res := make(map[string]rkentry.Entry)

	// 1: Decode config map into boot config struct
	config := &BootConfig{}
	rkcommon.UnmarshalBootConfig(configFilePath, config)

	// 2: Init Mux entries with boot config
	for i := range config.Mux {
		element := config.Mux[i]
		if !element.Enabled {
			continue
		}

		name := element.Name

		zapLoggerEntry := rkentry.GlobalAppCtx.GetZapLoggerEntry(element.Logger.ZapLogger.Ref)
		if zapLoggerEntry == nil {
			zapLoggerEntry = rkentry.GlobalAppCtx.GetZapLoggerEntryDefault()
		}

		eventLoggerEntry := rkentry.GlobalAppCtx.GetEventLoggerEntry(element.Logger.EventLogger.Ref)
		if eventLoggerEntry == nil {
			eventLoggerEntry = rkentry.GlobalAppCtx.GetEventLoggerEntryDefault()
		}

		// Register swagger entry
		swEntry := rkentry.RegisterSwEntryWithConfig(&element.SW, element.Name, element.Port,
			zapLoggerEntry, eventLoggerEntry, element.CommonService.Enabled)

		// Register prometheus entry
		promRegistry := prometheus.NewRegistry()
		promEntry := rkentry.RegisterPromEntryWithConfig(&element.Prom, element.Name, element.Port,
			zapLoggerEntry, eventLoggerEntry, promRegistry)

		// Register common service entry
		commonServiceEntry := rkentry.RegisterCommonServiceEntryWithConfig(&element.CommonService, element.Name,
			zapLoggerEntry, eventLoggerEntry)

		// Register TV entry
		tvEntry := rkentry.RegisterTvEntryWithConfig(&element.TV, element.Name,
			zapLoggerEntry, eventLoggerEntry)

		// Register static file handler
		staticEntry := rkentry.RegisterStaticFileHandlerEntryWithConfig(&element.Static, element.Name,
			zapLoggerEntry, eventLoggerEntry)

		inters := make([]mux.MiddlewareFunc, 0)

		// logging middlewares
		if element.Interceptors.LoggingZap.Enabled {
			inters = append(inters, rkmuxlog.Interceptor(
				rkmidlog.ToOptions(&element.Interceptors.LoggingZap, element.Name, MuxEntryType,
					zapLoggerEntry, eventLoggerEntry)...))
		}

		// metrics middleware
		if element.Interceptors.MetricsProm.Enabled {
			inters = append(inters, rkmuxmetrics.Interceptor(
				rkmidmetrics.ToOptions(&element.Interceptors.MetricsProm, element.Name, MuxEntryType,
					promRegistry, rkmidmetrics.LabelerTypeHttp)...))
		}

		// tracing middleware
		if element.Interceptors.TracingTelemetry.Enabled {
			inters = append(inters, rkmuxtrace.Interceptor(
				rkmidtrace.ToOptions(&element.Interceptors.TracingTelemetry, element.Name, MuxEntryType)...))
		}

		// jwt middleware
		if element.Interceptors.Jwt.Enabled {
			inters = append(inters, rkmuxjwt.Interceptor(
				rkmidjwt.ToOptions(&element.Interceptors.Jwt, element.Name, MuxEntryType)...))
		}

		// secure middleware
		if element.Interceptors.Secure.Enabled {
			inters = append(inters, rkmuxsec.Interceptor(
				rkmidsec.ToOptions(&element.Interceptors.Secure, element.Name, MuxEntryType)...))
		}

		// csrf middleware
		if element.Interceptors.Csrf.Enabled {
			inters = append(inters, rkmuxcsrf.Interceptor(
				rkmidcsrf.ToOptions(&element.Interceptors.Csrf, element.Name, MuxEntryType)...))
		}

		// cors middleware
		if element.Interceptors.Cors.Enabled {
			inters = append(inters, rkmuxcors.Interceptor(
				rkmidcors.ToOptions(&element.Interceptors.Cors, element.Name, MuxEntryType)...))
		}

		// meta middleware
		if element.Interceptors.Meta.Enabled {
			inters = append(inters, rkmuxmeta.Interceptor(
				rkmidmeta.ToOptions(&element.Interceptors.Meta, element.Name, MuxEntryType)...))
		}

		// auth middlewares
		if element.Interceptors.Auth.Enabled {
			inters = append(inters, rkmuxauth.Interceptor(
				rkmidauth.ToOptions(&element.Interceptors.Auth, element.Name, MuxEntryType)...))
		}

		// rate limit middleware
		if element.Interceptors.RateLimit.Enabled {
			inters = append(inters, rkmuxlimit.Interceptor(
				rkmidlimit.ToOptions(&element.Interceptors.RateLimit, element.Name, MuxEntryType)...))
		}

		certEntry := rkentry.GlobalAppCtx.GetCertEntry(element.Cert.Ref)

		entry := RegisterMuxEntry(
			WithName(name),
			WithDescription(element.Description),
			WithPort(element.Port),
			WithZapLoggerEntry(zapLoggerEntry),
			WithEventLoggerEntry(eventLoggerEntry),
			WithCertEntry(certEntry),
			WithPromEntry(promEntry),
			WithTvEntry(tvEntry),
			WithCommonServiceEntry(commonServiceEntry),
			WithSwEntry(swEntry),
			WithStaticFileHandlerEntry(staticEntry))

		entry.AddInterceptor(inters...)

		res[name] = entry
	}

	return res
}

// RegisterMuxEntry register MuxEntry with options.
func RegisterMuxEntry(opts ...MuxEntryOption) *MuxEntry {
	entry := &MuxEntry{
		EntryType:        MuxEntryType,
		EntryDescription: MuxEntryDescription,
		Port:             8080,
	}

	for i := range opts {
		opts[i](entry)
	}

	if entry.ZapLoggerEntry == nil {
		entry.ZapLoggerEntry = rkentry.GlobalAppCtx.GetZapLoggerEntryDefault()
	}

	if entry.EventLoggerEntry == nil {
		entry.EventLoggerEntry = rkentry.GlobalAppCtx.GetEventLoggerEntryDefault()
	}

	if len(entry.EntryName) < 1 {
		entry.EntryName = "MuxServer-" + strconv.FormatUint(entry.Port, 10)
	}

	if entry.Router == nil {
		entry.Router = mux.NewRouter()
	}

	// Init TLS config
	if entry.IsTlsEnabled() {
		var cert tls.Certificate
		var err error
		if cert, err = tls.X509KeyPair(entry.CertEntry.Store.ServerCert, entry.CertEntry.Store.ServerKey); err != nil {
			entry.ZapLoggerEntry.GetLogger().Error("Error occurs while parsing TLS.", zap.String("cert", entry.CertEntry.String()))
		} else {
			entry.TlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			}
		}
	}

	entry.Server = &http.Server{
		Addr: "0.0.0.0:" + strconv.FormatUint(entry.Port, 10),
	}

	entry.Router.Use(rkmuxpanic.Interceptor(
		rkmidpanic.WithEntryNameAndType(entry.EntryName, entry.EntryType)))

	rkentry.GlobalAppCtx.AddEntry(entry)

	return entry
}

// Bootstrap MuxEntry.
func (entry *MuxEntry) Bootstrap(ctx context.Context) {
	event, logger := entry.logBasicInfo("Bootstrap")

	// Is swagger enabled?
	if entry.IsSwEnabled() {
		redirect := func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Location", entry.SwEntry.Path)
			writer.WriteHeader(http.StatusTemporaryRedirect)
		}

		entry.Router.NewRoute().Methods(http.MethodGet).Path(strings.TrimSuffix(entry.SwEntry.Path, "/")).HandlerFunc(redirect)

		// Register swagger path into Router.
		entry.Router.NewRoute().Methods(http.MethodGet).PathPrefix(entry.SwEntry.Path).HandlerFunc(entry.SwEntry.ConfigFileHandler())
		entry.Router.NewRoute().Methods(http.MethodGet).PathPrefix(entry.SwEntry.AssetsFilePath).HandlerFunc(entry.SwEntry.AssetsFileHandler())

		// Bootstrap swagger entry.
		entry.SwEntry.Bootstrap(ctx)
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

	// Is prometheus enabled?
	if entry.IsPromEnabled() {
		// Register prom path into Router.
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.PromEntry.Path).Handler(promhttp.HandlerFor(entry.PromEntry.Gatherer, promhttp.HandlerOpts{}))

		// don't start with http handler, we will handle it by ourselves
		entry.PromEntry.Bootstrap(ctx)
	}

	// Is common service enabled?
	if entry.IsCommonServiceEnabled() {
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.HealthyPath).HandlerFunc(entry.CommonServiceEntry.Healthy)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.GcPath).HandlerFunc(entry.CommonServiceEntry.Gc)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.InfoPath).HandlerFunc(entry.CommonServiceEntry.Info)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.ConfigsPath).HandlerFunc(entry.CommonServiceEntry.Configs)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.SysPath).HandlerFunc(entry.CommonServiceEntry.Sys)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.EntriesPath).HandlerFunc(entry.CommonServiceEntry.Entries)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.CertsPath).HandlerFunc(entry.CommonServiceEntry.Certs)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.LogsPath).HandlerFunc(entry.CommonServiceEntry.Logs)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.DepsPath).HandlerFunc(entry.CommonServiceEntry.Deps)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.LicensePath).HandlerFunc(entry.CommonServiceEntry.License)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.ReadmePath).HandlerFunc(entry.CommonServiceEntry.Readme)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.GitPath).HandlerFunc(entry.CommonServiceEntry.Git)

		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.ApisPath).HandlerFunc(entry.Apis)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.CommonServiceEntry.ReqPath).HandlerFunc(entry.Req)

		// Bootstrap common service entry.
		entry.CommonServiceEntry.Bootstrap(ctx)
	}

	// Is TV enabled?
	if entry.IsTvEnabled() {
		// Bootstrap TV entry.
		redirect := func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Location", "/rk/v1/tv/overview")
			writer.WriteHeader(http.StatusTemporaryRedirect)
		}

		entry.Router.NewRoute().Methods(http.MethodGet).Path(strings.TrimSuffix(entry.TvEntry.BasePath, "/")).HandlerFunc(redirect)
		entry.Router.NewRoute().Methods(http.MethodGet).Path(entry.TvEntry.BasePath).HandlerFunc(redirect)

		entry.Router.NewRoute().Methods(http.MethodGet).Path(path.Join(entry.TvEntry.BasePath, "{item}")).HandlerFunc(entry.TV)
		entry.Router.NewRoute().Methods(http.MethodGet).PathPrefix(entry.TvEntry.AssetsFilePath).HandlerFunc(entry.TvEntry.AssetsFileHandler())

		entry.TvEntry.Bootstrap(ctx)
	}

	go entry.startServer(event, logger)

	entry.EventLoggerEntry.GetEventHelper().Finish(event)
}

// Interrupt MuxEntry.
func (entry *MuxEntry) Interrupt(ctx context.Context) {
	event, logger := entry.logBasicInfo("Interrupt")

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

	if entry.IsTvEnabled() {
		// Interrupt common service entry
		entry.TvEntry.Interrupt(ctx)
	}

	if entry.Server != nil {
		if err := entry.Server.Shutdown(context.Background()); err != nil {
			event.AddErr(err)
			logger.Warn("Error occurs while stopping http server")
		}
	}

	entry.EventLoggerEntry.GetEventHelper().Finish(event)
}

// GetName Get entry name.
func (entry *MuxEntry) GetName() string {
	return entry.EntryName
}

// GetType Get entry type.
func (entry *MuxEntry) GetType() string {
	return entry.EntryType
}

// GetDescription Get description of entry.
func (entry *MuxEntry) GetDescription() string {
	return entry.EntryDescription
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
		"entryName":          entry.EntryName,
		"entryType":          entry.EntryType,
		"entryDescription":   entry.EntryDescription,
		"eventLoggerEntry":   entry.EventLoggerEntry.GetName(),
		"zapLoggerEntry":     entry.ZapLoggerEntry.GetName(),
		"port":               entry.Port,
		"swEntry":            entry.SwEntry,
		"commonServiceEntry": entry.CommonServiceEntry,
		"promEntry":          entry.PromEntry,
		"tvEntry":            entry.TvEntry,
	}

	if entry.CertEntry != nil {
		m["certEntry"] = entry.CertEntry.GetName()
	}

	interceptorsStr := make([]string, 0)
	m["interceptors"] = &interceptorsStr

	for i := range entry.Interceptors {
		element := entry.Interceptors[i]
		interceptorsStr = append(interceptorsStr,
			path.Base(runtime.FuncForPC(reflect.ValueOf(element).Pointer()).Name()))
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
	entryRaw := rkentry.GlobalAppCtx.GetEntry(name)
	if entryRaw == nil {
		return nil
	}

	entry, _ := entryRaw.(*MuxEntry)
	return entry
}

// AddInterceptor Add interceptors.
// This function should be called before Bootstrap() called.
func (entry *MuxEntry) AddInterceptor(inters ...mux.MiddlewareFunc) {
	entry.Router.Use(inters...)
}

// IsTlsEnabled Is TLS enabled?
func (entry *MuxEntry) IsTlsEnabled() bool {
	return entry.CertEntry != nil && entry.CertEntry.Store != nil
}

// IsSwEnabled Is swagger entry enabled?
func (entry *MuxEntry) IsSwEnabled() bool {
	return entry.SwEntry != nil
}

// IsCommonServiceEnabled Is common service entry enabled?
func (entry *MuxEntry) IsCommonServiceEnabled() bool {
	return entry.CommonServiceEntry != nil
}

// IsTvEnabled Is TV entry enabled?
func (entry *MuxEntry) IsTvEnabled() bool {
	return entry.TvEntry != nil
}

// IsPromEnabled Is prometheus entry enabled?
func (entry *MuxEntry) IsPromEnabled() bool {
	return entry.PromEntry != nil
}

// IsStaticFileHandlerEnabled Is static file handler entry enabled?
func (entry *MuxEntry) IsStaticFileHandlerEnabled() bool {
	return entry.StaticFileEntry != nil
}

// ***************** Helper function *****************

// Start server
// We move the code here for testability
func (entry *MuxEntry) startServer(event rkquery.Event, logger *zap.Logger) {
	if entry.Server != nil {
		entry.Server.Handler = entry.Router

		lis, err := net.Listen("tcp4", ":"+strconv.FormatUint(entry.Port, 10))
		if err != nil {
			entry.EventLoggerEntry.GetEventHelper().FinishWithError(event, err)
			rkcommon.ShutdownWithError(err)
		}

		if entry.IsTlsEnabled() {
			lis = tls.NewListener(lis, entry.TlsConfig)
		}

		if err := entry.Server.Serve(lis); err != nil && !strings.Contains(err.Error(), "http: Server closed") {
			logger.Error("Error occurs while serving gateway-server.", zap.Error(err))
			rkcommon.ShutdownWithError(err)
		}
	}
}

// Add basic fields into event.
func (entry *MuxEntry) logBasicInfo(operation string) (rkquery.Event, *zap.Logger) {
	event := entry.EventLoggerEntry.GetEventHelper().Start(
		operation,
		rkquery.WithEntryName(entry.GetName()),
		rkquery.WithEntryType(entry.GetType()))
	logger := entry.ZapLoggerEntry.GetLogger().With(
		zap.String("eventId", event.GetEventId()),
		zap.String("entryName", entry.EntryName))

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

	// add TvEntry info
	if entry.IsTvEnabled() {
		event.AddPayloads(
			zap.Bool("tvEnabled", true),
			zap.String("tvPath", "/rk/v1/tv/"))
	}

	// add PromEntry info
	if entry.IsPromEnabled() {
		event.AddPayloads(
			zap.Bool("promEnabled", true),
			zap.Uint64("promPort", entry.PromEntry.Port),
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

// ***************** Common Service Extension API *****************

// Apis list apis
func (entry *MuxEntry) Apis(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")

	rkmuxinter.WriteJson(writer, http.StatusOK, entry.doApis(req))
}

// Req handler
func (entry *MuxEntry) Req(writer http.ResponseWriter, req *http.Request) {
	rkmuxinter.WriteJson(writer, http.StatusOK, entry.doReq(req))
}

// TV handler
func (entry *MuxEntry) TV(writer http.ResponseWriter, req *http.Request) {
	logger := rkmuxctx.GetLogger(req, writer)
	param := mux.Vars(req)

	writer.Header().Set("Content-Type", "text/html;charset=UTF-8")

	switch item := param["item"]; item {
	case "apis":
		buf := entry.TvEntry.ExecuteTemplate("apis", entry.doApis(req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	default:
		buf := entry.TvEntry.Action(item, logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	}
}

// Construct swagger URL based on IP and scheme
func (entry *MuxEntry) constructSwUrl(req *http.Request) string {
	if entry == nil || entry.SwEntry == nil {
		return "N/A"
	}

	originalURL := fmt.Sprintf("localhost:%d", entry.Port)
	if req != nil && len(req.Host) > 0 {
		originalURL = req.Host
	}

	scheme := "http"
	if req != nil && req.TLS != nil {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s%s", scheme, originalURL, entry.SwEntry.Path)
}

// Helper function for APIs call
func (entry *MuxEntry) doApis(req *http.Request) *rkentry.ApisResponse {
	res := &rkentry.ApisResponse{
		Entries: make([]*rkentry.ApisResponseElement, 0),
	}

	entry.Router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemp, _ := route.GetPathTemplate()
		rawMethods, _ := route.GetMethods()
		methods := strings.Join(rawMethods, ",")

		entry := &rkentry.ApisResponseElement{
			EntryName: entry.GetName(),
			Method:    methods,
			Path:      pathTemp,
			Port:      entry.Port,
			SwUrl:     entry.constructSwUrl(req),
		}
		res.Entries = append(res.Entries, entry)

		return nil
	})

	return res
}

// Is metrics from prometheus contains particular api?
func (entry *MuxEntry) containsMetrics(api string, metrics []*rkentry.ReqMetricsRK) bool {
	for i := range metrics {
		if metrics[i].RestPath == api {
			return true
		}
	}

	return false
}

// Helper function for Req call
func (entry *MuxEntry) doReq(req *http.Request) *rkentry.ReqResponse {
	metricsSet := rkmidmetrics.GetServerMetricsSet(entry.GetName())
	if metricsSet == nil {
		return &rkentry.ReqResponse{
			Metrics: make([]*rkentry.ReqMetricsRK, 0),
		}
	}

	vector := metricsSet.GetSummary(rkmidmetrics.MetricsNameElapsedNano)
	if vector == nil {
		return &rkentry.ReqResponse{
			Metrics: make([]*rkentry.ReqMetricsRK, 0),
		}
	}

	reqMetrics := rkentry.NewPromMetricsInfo(vector)

	// Fill missed metrics
	apis := make([]string, 0)

	entry.Router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemp, _ := route.GetPathTemplate()
		apis = append(apis, pathTemp)
		return nil
	})

	// Add empty metrics into result
	for i := range apis {
		if !entry.containsMetrics(apis[i], reqMetrics) {
			reqMetrics = append(reqMetrics, &rkentry.ReqMetricsRK{
				RestPath: apis[i],
				ResCode:  make([]*rkentry.ResCodeRK, 0),
			})
		}
	}

	return &rkentry.ReqResponse{
		Metrics: reqMetrics,
	}
}

// ***************** Options *****************

// MuxEntryOption Mux entry option.
type MuxEntryOption func(*MuxEntry)

// WithName provide name.
func WithName(name string) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.EntryName = name
	}
}

// WithDescription provide name.
func WithDescription(description string) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.EntryDescription = description
	}
}

// WithPort provide port.
func WithPort(port uint64) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.Port = port
	}
}

// WithZapLoggerEntry provide rkentry.ZapLoggerEntry.
func WithZapLoggerEntry(zapLogger *rkentry.ZapLoggerEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.ZapLoggerEntry = zapLogger
	}
}

// WithEventLoggerEntry provide rkentry.EventLoggerEntry.
func WithEventLoggerEntry(eventLogger *rkentry.EventLoggerEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.EventLoggerEntry = eventLogger
	}
}

// WithCertEntry provide rkentry.CertEntry.
func WithCertEntry(certEntry *rkentry.CertEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.CertEntry = certEntry
	}
}

// WithSwEntry provide SwEntry.
func WithSwEntry(sw *rkentry.SwEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.SwEntry = sw
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

// WithTvEntry provide TvEntry.
func WithTvEntry(tvEntry *rkentry.TvEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.TvEntry = tvEntry
	}
}

// WithStaticFileHandlerEntry provide StaticFileHandlerEntry.
func WithStaticFileHandlerEntry(staticEntry *rkentry.StaticFileHandlerEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.StaticFileEntry = staticEntry
	}
}
