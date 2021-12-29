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
	"github.com/rookie-ninja/rk-mux/interceptor/auth"
	"github.com/rookie-ninja/rk-mux/interceptor/cors"
	"github.com/rookie-ninja/rk-mux/interceptor/csrf"
	"github.com/rookie-ninja/rk-mux/interceptor/jwt"
	"github.com/rookie-ninja/rk-mux/interceptor/log/zap"
	"github.com/rookie-ninja/rk-mux/interceptor/meta"
	"github.com/rookie-ninja/rk-mux/interceptor/metrics/prom"
	"github.com/rookie-ninja/rk-mux/interceptor/panic"
	"github.com/rookie-ninja/rk-mux/interceptor/ratelimit"
	"github.com/rookie-ninja/rk-mux/interceptor/secure"
	"github.com/rookie-ninja/rk-mux/interceptor/timeout"
	"github.com/rookie-ninja/rk-mux/interceptor/tracing/telemetry"
	"github.com/rookie-ninja/rk-prom"
	"github.com/rookie-ninja/rk-query"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
	"net"
	"net/http"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
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
type BootConfigMux struct {
	Mux []struct {
		Enabled     bool   `yaml:"enabled" json:"enabled"`
		Name        string `yaml:"name" json:"name"`
		Port        uint64 `yaml:"port" json:"port"`
		Description string `yaml:"description" json:"description"`
		Cert        struct {
			Ref string `yaml:"ref" json:"ref"`
		} `yaml:"cert" json:"cert"`
		SW            BootConfigSw            `yaml:"sw" json:"sw"`
		CommonService BootConfigCommonService `yaml:"commonService" json:"commonService"`
		TV            BootConfigTv            `yaml:"tv" json:"tv"`
		Prom          BootConfigProm          `yaml:"prom" json:"prom"`
		Interceptors  struct {
			LoggingZap struct {
				Enabled                bool     `yaml:"enabled" json:"enabled"`
				ZapLoggerEncoding      string   `yaml:"zapLoggerEncoding" json:"zapLoggerEncoding"`
				ZapLoggerOutputPaths   []string `yaml:"zapLoggerOutputPaths" json:"zapLoggerOutputPaths"`
				EventLoggerEncoding    string   `yaml:"eventLoggerEncoding" json:"eventLoggerEncoding"`
				EventLoggerOutputPaths []string `yaml:"eventLoggerOutputPaths" json:"eventLoggerOutputPaths"`
			} `yaml:"loggingZap" json:"loggingZap"`
			MetricsProm struct {
				Enabled bool `yaml:"enabled" json:"enabled"`
			} `yaml:"metricsProm" json:"metricsProm"`
			Auth struct {
				Enabled      bool     `yaml:"enabled" json:"enabled"`
				IgnorePrefix []string `yaml:"ignorePrefix" json:"ignorePrefix"`
				Basic        []string `yaml:"basic" json:"basic"`
				ApiKey       []string `yaml:"apiKey" json:"apiKey"`
			} `yaml:"auth" json:"auth"`
			Cors struct {
				Enabled          bool     `yaml:"enabled" json:"enabled"`
				AllowOrigins     []string `yaml:"allowOrigins" json:"allowOrigins"`
				AllowCredentials bool     `yaml:"allowCredentials" json:"allowCredentials"`
				AllowHeaders     []string `yaml:"allowHeaders" json:"allowHeaders"`
				AllowMethods     []string `yaml:"allowMethods" json:"allowMethods"`
				ExposeHeaders    []string `yaml:"exposeHeaders" json:"exposeHeaders"`
				MaxAge           int      `yaml:"maxAge" json:"maxAge"`
			} `yaml:"cors" json:"cors"`
			Meta struct {
				Enabled bool   `yaml:"enabled" json:"enabled"`
				Prefix  string `yaml:"prefix" json:"prefix"`
			} `yaml:"meta" json:"meta"`
			Jwt struct {
				Enabled      bool     `yaml:"enabled" json:"enabled"`
				IgnorePrefix []string `yaml:"ignorePrefix" json:"ignorePrefix"`
				SigningKey   string   `yaml:"signingKey" json:"signingKey"`
				SigningKeys  []string `yaml:"signingKeys" json:"signingKeys"`
				SigningAlgo  string   `yaml:"signingAlgo" json:"signingAlgo"`
				TokenLookup  string   `yaml:"tokenLookup" json:"tokenLookup"`
				AuthScheme   string   `yaml:"authScheme" json:"authScheme"`
			} `yaml:"jwt" json:"jwt"`
			Secure struct {
				Enabled               bool     `yaml:"enabled" json:"enabled"`
				IgnorePrefix          []string `yaml:"ignorePrefix" json:"ignorePrefix"`
				XssProtection         string   `yaml:"xssProtection" json:"xssProtection"`
				ContentTypeNosniff    string   `yaml:"contentTypeNosniff" json:"contentTypeNosniff"`
				XFrameOptions         string   `yaml:"xFrameOptions" json:"xFrameOptions"`
				HstsMaxAge            int      `yaml:"hstsMaxAge" json:"hstsMaxAge"`
				HstsExcludeSubdomains bool     `yaml:"hstsExcludeSubdomains" json:"hstsExcludeSubdomains"`
				HstsPreloadEnabled    bool     `yaml:"hstsPreloadEnabled" json:"hstsPreloadEnabled"`
				ContentSecurityPolicy string   `yaml:"contentSecurityPolicy" json:"contentSecurityPolicy"`
				CspReportOnly         bool     `yaml:"cspReportOnly" json:"cspReportOnly"`
				ReferrerPolicy        string   `yaml:"referrerPolicy" json:"referrerPolicy"`
			} `yaml:"secure" json:"secure"`
			Csrf struct {
				Enabled        bool     `yaml:"enabled" json:"enabled"`
				IgnorePrefix   []string `yaml:"ignorePrefix" json:"ignorePrefix"`
				TokenLength    int      `yaml:"tokenLength" json:"tokenLength"`
				TokenLookup    string   `yaml:"tokenLookup" json:"tokenLookup"`
				CookieName     string   `yaml:"cookieName" json:"cookieName"`
				CookieDomain   string   `yaml:"cookieDomain" json:"cookieDomain"`
				CookiePath     string   `yaml:"cookiePath" json:"cookiePath"`
				CookieMaxAge   int      `yaml:"cookieMaxAge" json:"cookieMaxAge"`
				CookieHttpOnly bool     `yaml:"cookieHttpOnly" json:"cookieHttpOnly"`
				CookieSameSite string   `yaml:"cookieSameSite" json:"cookieSameSite"`
			} `yaml:"csrf" yaml:"csrf"`
			Gzip struct {
				Enabled bool   `yaml:"enabled" json:"enabled"`
				Level   string `yaml:"level" json:"level"`
			} `yaml:"gzip" json:"gzip"`
			RateLimit struct {
				Enabled   bool   `yaml:"enabled" json:"enabled"`
				Algorithm string `yaml:"algorithm" json:"algorithm"`
				ReqPerSec int    `yaml:"reqPerSec" json:"reqPerSec"`
				Paths     []struct {
					Path      string `yaml:"path" json:"path"`
					ReqPerSec int    `yaml:"reqPerSec" json:"reqPerSec"`
				} `yaml:"paths" json:"paths"`
			} `yaml:"rateLimit" json:"rateLimit"`
			Timeout struct {
				Enabled   bool `yaml:"enabled" json:"enabled"`
				TimeoutMs int  `yaml:"timeoutMs" json:"timeoutMs"`
				Paths     []struct {
					Path      string `yaml:"path" json:"path"`
					TimeoutMs int    `yaml:"timeoutMs" json:"timeoutMs"`
				} `yaml:"paths" json:"paths"`
			} `yaml:"timeout" json:"timeout"`
			TracingTelemetry struct {
				Enabled  bool `yaml:"enabled" json:"enabled"`
				Exporter struct {
					File struct {
						Enabled    bool   `yaml:"enabled" json:"enabled"`
						OutputPath string `yaml:"outputPath" json:"outputPath"`
					} `yaml:"file" json:"file"`
					Jaeger struct {
						Agent struct {
							Enabled bool   `yaml:"enabled" json:"enabled"`
							Host    string `yaml:"host" json:"host"`
							Port    int    `yaml:"port" json:"port"`
						} `yaml:"agent" json:"agent"`
						Collector struct {
							Enabled  bool   `yaml:"enabled" json:"enabled"`
							Endpoint string `yaml:"endpoint" json:"endpoint"`
							Username string `yaml:"username" json:"username"`
							Password string `yaml:"password" json:"password"`
						} `yaml:"collector" json:"collector"`
					} `yaml:"jaeger" json:"jaeger"`
				} `yaml:"exporter" json:"exporter"`
			} `yaml:"tracingTelemetry" json:"tracingTelemetry"`
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
	EntryName          string                    `json:"entryName" yaml:"entryName"`
	EntryType          string                    `json:"entryType" yaml:"entryType"`
	EntryDescription   string                    `json:"-" yaml:"-"`
	ZapLoggerEntry     *rkentry.ZapLoggerEntry   `json:"-" yaml:"-"`
	EventLoggerEntry   *rkentry.EventLoggerEntry `json:"-" yaml:"-"`
	Port               uint64                    `json:"port" yaml:"port"`
	CertEntry          *rkentry.CertEntry        `json:"-" yaml:"-"`
	SwEntry            *SwEntry                  `json:"-" yaml:"-"`
	CommonServiceEntry *CommonServiceEntry       `json:"-" yaml:"-"`
	Router             *mux.Router               `json:"-" yaml:"-"`
	Server             *http.Server              `json:"-" yaml:"-"`
	TlsConfig          *tls.Config               `json:"-" yaml:"-"`
	Interceptors       []mux.MiddlewareFunc      `json:"-" yaml:"-"`
	PromEntry          *PromEntry                `json:"-" yaml:"-"`
	TvEntry            *TvEntry                  `json:"-" yaml:"-"`
}

// MuxEntryOption Mux entry option.
type MuxEntryOption func(*MuxEntry)

// WithNameMux provide name.
func WithNameMux(name string) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.EntryName = name
	}
}

// WithDescriptionMux provide name.
func WithDescriptionMux(description string) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.EntryDescription = description
	}
}

// WithPortMux provide port.
func WithPortMux(port uint64) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.Port = port
	}
}

// WithZapLoggerEntryMux provide rkentry.ZapLoggerEntry.
func WithZapLoggerEntryMux(zapLogger *rkentry.ZapLoggerEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.ZapLoggerEntry = zapLogger
	}
}

// WithEventLoggerEntryMux provide rkentry.EventLoggerEntry.
func WithEventLoggerEntryMux(eventLogger *rkentry.EventLoggerEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.EventLoggerEntry = eventLogger
	}
}

// WithCertEntryMux provide rkentry.CertEntry.
func WithCertEntryMux(certEntry *rkentry.CertEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.CertEntry = certEntry
	}
}

// WithSwEntryMux provide SwEntry.
func WithSwEntryMux(sw *SwEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.SwEntry = sw
	}
}

// WithCommonServiceEntryMux provide CommonServiceEntry.
func WithCommonServiceEntryMux(commonServiceEntry *CommonServiceEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.CommonServiceEntry = commonServiceEntry
	}
}

// WithInterceptorsMux provide user interceptors.
func WithInterceptorsMux(inters ...mux.MiddlewareFunc) MuxEntryOption {
	return func(entry *MuxEntry) {
		if entry.Interceptors == nil {
			entry.Interceptors = make([]mux.MiddlewareFunc, 0)
		}

		entry.Interceptors = append(entry.Interceptors, inters...)
	}
}

// WithPromEntryMux provide PromEntry.
func WithPromEntryMux(prom *PromEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.PromEntry = prom
	}
}

// WithTVEntryMux provide TvEntry.
func WithTVEntryMux(tvEntry *TvEntry) MuxEntryOption {
	return func(entry *MuxEntry) {
		entry.TvEntry = tvEntry
	}
}

// GetMuxEntry Get MuxEntry from rkentry.GlobalAppCtx.
func GetMuxEntry(name string) *MuxEntry {
	entryRaw := rkentry.GlobalAppCtx.GetEntry(name)
	if entryRaw == nil {
		return nil
	}

	entry, _ := entryRaw.(*MuxEntry)
	return entry
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
	config := &BootConfigMux{}
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

		promRegistry := prometheus.NewRegistry()
		// Did we enabled swagger?
		var swEntry *SwEntry
		if element.SW.Enabled {
			// Init swagger custom headers from config
			headers := make(map[string]string, 0)
			for i := range element.SW.Headers {
				header := element.SW.Headers[i]
				tokens := strings.Split(header, ":")
				if len(tokens) == 2 {
					headers[tokens[0]] = tokens[1]
				}
			}

			swEntry = NewSwEntry(
				WithNameSw(fmt.Sprintf("%s-sw", element.Name)),
				WithZapLoggerEntrySw(zapLoggerEntry),
				WithEventLoggerEntrySw(eventLoggerEntry),
				WithEnableCommonServiceSw(element.CommonService.Enabled),
				WithPortSw(element.Port),
				WithPathSw(element.SW.Path),
				WithJsonPathSw(element.SW.JsonPath),
				WithHeadersSw(headers))
		}

		// Did we enabled prometheus?
		var promEntry *PromEntry
		if element.Prom.Enabled {
			var pusher *rkprom.PushGatewayPusher
			if element.Prom.Pusher.Enabled {
				certEntry := rkentry.GlobalAppCtx.GetCertEntry(element.Prom.Pusher.Cert.Ref)
				var certStore *rkentry.CertStore

				if certEntry != nil {
					certStore = certEntry.Store
				}

				pusher, _ = rkprom.NewPushGatewayPusher(
					rkprom.WithIntervalMSPusher(time.Duration(element.Prom.Pusher.IntervalMs)*time.Millisecond),
					rkprom.WithRemoteAddressPusher(element.Prom.Pusher.RemoteAddress),
					rkprom.WithJobNamePusher(element.Prom.Pusher.JobName),
					rkprom.WithBasicAuthPusher(element.Prom.Pusher.BasicAuth),
					rkprom.WithZapLoggerEntryPusher(zapLoggerEntry),
					rkprom.WithEventLoggerEntryPusher(eventLoggerEntry),
					rkprom.WithCertStorePusher(certStore))
			}

			promRegistry.Register(prometheus.NewGoCollector())
			promEntry = NewPromEntry(
				WithNameProm(fmt.Sprintf("%s-prom", element.Name)),
				WithPortProm(element.Port),
				WithPathProm(element.Prom.Path),
				WithZapLoggerEntryProm(zapLoggerEntry),
				WithPromRegistryProm(promRegistry),
				WithEventLoggerEntryProm(eventLoggerEntry),
				WithPusherProm(pusher))

			if promEntry.Pusher != nil {
				promEntry.Pusher.SetGatherer(promEntry.Gatherer)
			}
		}

		inters := make([]mux.MiddlewareFunc, 0)

		// Did we enabled logging interceptor?
		if element.Interceptors.LoggingZap.Enabled {
			opts := []rkmuxlog.Option{
				rkmuxlog.WithEntryNameAndType(element.Name, MuxEntryType),
				rkmuxlog.WithEventLoggerEntry(eventLoggerEntry),
				rkmuxlog.WithZapLoggerEntry(zapLoggerEntry),
			}

			if strings.ToLower(element.Interceptors.LoggingZap.ZapLoggerEncoding) == "json" {
				opts = append(opts, rkmuxlog.WithZapLoggerEncoding(rkmuxlog.ENCODING_JSON))
			}

			if strings.ToLower(element.Interceptors.LoggingZap.EventLoggerEncoding) == "json" {
				opts = append(opts, rkmuxlog.WithEventLoggerEncoding(rkmuxlog.ENCODING_JSON))
			}

			if len(element.Interceptors.LoggingZap.ZapLoggerOutputPaths) > 0 {
				opts = append(opts, rkmuxlog.WithZapLoggerOutputPaths(element.Interceptors.LoggingZap.ZapLoggerOutputPaths...))
			}

			if len(element.Interceptors.LoggingZap.EventLoggerOutputPaths) > 0 {
				opts = append(opts, rkmuxlog.WithEventLoggerOutputPaths(element.Interceptors.LoggingZap.EventLoggerOutputPaths...))
			}

			inters = append(inters, rkmuxlog.Interceptor(opts...))
		}

		// Did we enabled metrics interceptor?
		if element.Interceptors.MetricsProm.Enabled {
			opts := []rkmuxmetrics.Option{
				rkmuxmetrics.WithRegisterer(promRegistry),
				rkmuxmetrics.WithEntryNameAndType(element.Name, MuxEntryType),
			}

			inters = append(inters, rkmuxmetrics.Interceptor(opts...))
		}

		// Did we enabled tracing interceptor?
		if element.Interceptors.TracingTelemetry.Enabled {
			var exporter trace.SpanExporter

			if element.Interceptors.TracingTelemetry.Exporter.File.Enabled {
				exporter = rkmuxtrace.CreateFileExporter(element.Interceptors.TracingTelemetry.Exporter.File.OutputPath)
			}

			if element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Enabled {
				opts := make([]jaeger.AgentEndpointOption, 0)
				if len(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Host) > 0 {
					opts = append(opts,
						jaeger.WithAgentHost(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Host))
				}
				if element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Port > 0 {
					opts = append(opts,
						jaeger.WithAgentPort(
							fmt.Sprintf("%d", element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Port)))
				}

				exporter = rkmuxtrace.CreateJaegerExporter(jaeger.WithAgentEndpoint(opts...))
			}

			if element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Enabled {
				opts := []jaeger.CollectorEndpointOption{
					jaeger.WithUsername(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Username),
					jaeger.WithPassword(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Password),
				}

				if len(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Endpoint) > 0 {
					opts = append(opts, jaeger.WithEndpoint(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Endpoint))
				}

				exporter = rkmuxtrace.CreateJaegerExporter(jaeger.WithCollectorEndpoint(opts...))
			}

			opts := []rkmuxtrace.Option{
				rkmuxtrace.WithEntryNameAndType(element.Name, MuxEntryType),
				rkmuxtrace.WithExporter(exporter),
			}

			inters = append(inters, rkmuxtrace.Interceptor(opts...))
		}

		// Did we enabled jwt interceptor?
		if element.Interceptors.Jwt.Enabled {
			var signingKey []byte
			if len(element.Interceptors.Jwt.SigningKey) > 0 {
				signingKey = []byte(element.Interceptors.Jwt.SigningKey)
			}

			opts := []rkmuxjwt.Option{
				rkmuxjwt.WithEntryNameAndType(element.Name, MuxEntryType),
				rkmuxjwt.WithSigningKey(signingKey),
				rkmuxjwt.WithSigningAlgorithm(element.Interceptors.Jwt.SigningAlgo),
				rkmuxjwt.WithTokenLookup(element.Interceptors.Jwt.TokenLookup),
				rkmuxjwt.WithAuthScheme(element.Interceptors.Jwt.AuthScheme),
				rkmuxjwt.WithIgnorePrefix(element.Interceptors.Jwt.IgnorePrefix...),
			}

			for _, v := range element.Interceptors.Jwt.SigningKeys {
				tokens := strings.SplitN(v, ":", 2)
				if len(tokens) == 2 {
					opts = append(opts, rkmuxjwt.WithSigningKeys(tokens[0], tokens[1]))
				}
			}

			inters = append(inters, rkmuxjwt.Interceptor(opts...))
		}

		// Did we enabled secure interceptor?
		if element.Interceptors.Secure.Enabled {
			opts := []rkmuxsec.Option{
				rkmuxsec.WithEntryNameAndType(element.Name, MuxEntryType),
				rkmuxsec.WithXSSProtection(element.Interceptors.Secure.XssProtection),
				rkmuxsec.WithContentTypeNosniff(element.Interceptors.Secure.ContentTypeNosniff),
				rkmuxsec.WithXFrameOptions(element.Interceptors.Secure.XFrameOptions),
				rkmuxsec.WithHSTSMaxAge(element.Interceptors.Secure.HstsMaxAge),
				rkmuxsec.WithHSTSExcludeSubdomains(element.Interceptors.Secure.HstsExcludeSubdomains),
				rkmuxsec.WithHSTSPreloadEnabled(element.Interceptors.Secure.HstsPreloadEnabled),
				rkmuxsec.WithContentSecurityPolicy(element.Interceptors.Secure.ContentSecurityPolicy),
				rkmuxsec.WithCSPReportOnly(element.Interceptors.Secure.CspReportOnly),
				rkmuxsec.WithReferrerPolicy(element.Interceptors.Secure.ReferrerPolicy),
				rkmuxsec.WithIgnorePrefix(element.Interceptors.Secure.IgnorePrefix...),
			}

			inters = append(inters, rkmuxsec.Interceptor(opts...))
		}

		// Did we enabled csrf interceptor?
		if element.Interceptors.Csrf.Enabled {
			opts := []rkmuxcsrf.Option{
				rkmuxcsrf.WithEntryNameAndType(element.Name, MuxEntryType),
				rkmuxcsrf.WithTokenLength(element.Interceptors.Csrf.TokenLength),
				rkmuxcsrf.WithTokenLookup(element.Interceptors.Csrf.TokenLookup),
				rkmuxcsrf.WithCookieName(element.Interceptors.Csrf.CookieName),
				rkmuxcsrf.WithCookieDomain(element.Interceptors.Csrf.CookieDomain),
				rkmuxcsrf.WithCookiePath(element.Interceptors.Csrf.CookiePath),
				rkmuxcsrf.WithCookieMaxAge(element.Interceptors.Csrf.CookieMaxAge),
				rkmuxcsrf.WithCookieHTTPOnly(element.Interceptors.Csrf.CookieHttpOnly),
				rkmuxcsrf.WithIgnorePrefix(element.Interceptors.Csrf.IgnorePrefix...),
			}

			// convert to string to cookie same sites
			sameSite := http.SameSiteDefaultMode

			switch strings.ToLower(element.Interceptors.Csrf.CookieSameSite) {
			case "lax":
				sameSite = http.SameSiteLaxMode
			case "strict":
				sameSite = http.SameSiteStrictMode
			case "none":
				sameSite = http.SameSiteNoneMode
			default:
				sameSite = http.SameSiteDefaultMode
			}

			opts = append(opts, rkmuxcsrf.WithCookieSameSite(sameSite))

			inters = append(inters, rkmuxcsrf.Interceptor(opts...))
		}

		// Did we enabled cors interceptor?
		if element.Interceptors.Cors.Enabled {
			opts := []rkmuxcors.Option{
				rkmuxcors.WithEntryNameAndType(element.Name, MuxEntryType),
				rkmuxcors.WithAllowOrigins(element.Interceptors.Cors.AllowOrigins...),
				rkmuxcors.WithAllowCredentials(element.Interceptors.Cors.AllowCredentials),
				rkmuxcors.WithExposeHeaders(element.Interceptors.Cors.ExposeHeaders...),
				rkmuxcors.WithMaxAge(element.Interceptors.Cors.MaxAge),
				rkmuxcors.WithAllowHeaders(element.Interceptors.Cors.AllowHeaders...),
				rkmuxcors.WithAllowMethods(element.Interceptors.Cors.AllowMethods...),
			}

			inters = append(inters, rkmuxcors.Interceptor(opts...))
		}

		// Did we enabled meta interceptor?
		if element.Interceptors.Meta.Enabled {
			opts := []rkmuxmeta.Option{
				rkmuxmeta.WithEntryNameAndType(element.Name, MuxEntryType),
				rkmuxmeta.WithPrefix(element.Interceptors.Meta.Prefix),
			}

			inters = append(inters, rkmuxmeta.Interceptor(opts...))
		}

		// Did we enabled auth interceptor?
		if element.Interceptors.Auth.Enabled {
			opts := make([]rkmuxauth.Option, 0)
			opts = append(opts,
				rkmuxauth.WithEntryNameAndType(element.Name, MuxEntryType),
				rkmuxauth.WithBasicAuth(element.Name, element.Interceptors.Auth.Basic...),
				rkmuxauth.WithApiKeyAuth(element.Interceptors.Auth.ApiKey...))

			// Add exceptional path
			if swEntry != nil {
				opts = append(opts, rkmuxauth.WithIgnorePrefix(strings.TrimSuffix(swEntry.Path, "/")))
			}

			opts = append(opts, rkmuxauth.WithIgnorePrefix("/rk/v1/assets"))
			opts = append(opts, rkmuxauth.WithIgnorePrefix(element.Interceptors.Auth.IgnorePrefix...))

			inters = append(inters, rkmuxauth.Interceptor(opts...))
		}

		// Did we enabled timeout interceptor?
		// This should be in front of rate limit interceptor since rate limit may block over the threshold of timeout.
		if element.Interceptors.Timeout.Enabled {
			opts := make([]rkmuxtimeout.Option, 0)
			opts = append(opts,
				rkmuxtimeout.WithEntryNameAndType(element.Name, MuxEntryType))

			timeout := time.Duration(element.Interceptors.Timeout.TimeoutMs) * time.Millisecond
			opts = append(opts, rkmuxtimeout.WithTimeoutAndResp(timeout, nil))

			for i := range element.Interceptors.Timeout.Paths {
				e := element.Interceptors.Timeout.Paths[i]
				timeout := time.Duration(e.TimeoutMs) * time.Millisecond
				opts = append(opts, rkmuxtimeout.WithTimeoutAndRespByPath(e.Path, timeout, nil))
			}

			inters = append(inters, rkmuxtimeout.Interceptor(opts...))
		}

		// Did we enabled rate limit interceptor?
		if element.Interceptors.RateLimit.Enabled {
			opts := make([]rkmuxlimit.Option, 0)
			opts = append(opts,
				rkmuxlimit.WithEntryNameAndType(element.Name, MuxEntryType))

			if len(element.Interceptors.RateLimit.Algorithm) > 0 {
				opts = append(opts, rkmuxlimit.WithAlgorithm(element.Interceptors.RateLimit.Algorithm))
			}
			opts = append(opts, rkmuxlimit.WithReqPerSec(element.Interceptors.RateLimit.ReqPerSec))

			for i := range element.Interceptors.RateLimit.Paths {
				e := element.Interceptors.RateLimit.Paths[i]
				opts = append(opts, rkmuxlimit.WithReqPerSecByPath(e.Path, e.ReqPerSec))
			}

			inters = append(inters, rkmuxlimit.Interceptor(opts...))
		}

		// Did we enabled common service?
		var commonServiceEntry *CommonServiceEntry
		if element.CommonService.Enabled {
			commonServiceEntry = NewCommonServiceEntry(
				WithNameCommonService(fmt.Sprintf("%s-commonService", element.Name)),
				WithZapLoggerEntryCommonService(zapLoggerEntry),
				WithEventLoggerEntryCommonService(eventLoggerEntry))
		}

		// Did we enabled tv?
		var tvEntry *TvEntry
		if element.TV.Enabled {
			tvEntry = NewTvEntry(
				WithNameTv(fmt.Sprintf("%s-tv", element.Name)),
				WithZapLoggerEntryTv(zapLoggerEntry),
				WithEventLoggerEntryTv(eventLoggerEntry))
		}

		certEntry := rkentry.GlobalAppCtx.GetCertEntry(element.Cert.Ref)

		entry := RegisterMuxEntry(
			WithNameMux(name),
			WithDescriptionMux(element.Description),
			WithPortMux(element.Port),
			WithZapLoggerEntryMux(zapLoggerEntry),
			WithEventLoggerEntryMux(eventLoggerEntry),
			WithCertEntryMux(certEntry),
			WithPromEntryMux(promEntry),
			WithTVEntryMux(tvEntry),
			WithCommonServiceEntryMux(commonServiceEntry),
			WithSwEntryMux(swEntry),
			WithInterceptorsMux(inters...))

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

	// insert panic interceptor
	entry.Interceptors = append(entry.Interceptors, rkmuxpanic.Interceptor(
		rkmuxpanic.WithEntryNameAndType(entry.EntryName, entry.EntryType)))

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
		entry.Router.NewRoute().Methods(http.MethodGet).PathPrefix("/rk/v1/assets/sw/").HandlerFunc(entry.SwEntry.AssetsFileHandler())

		// Bootstrap swagger entry.
		entry.SwEntry.Bootstrap(ctx)
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
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/healthy").HandlerFunc(entry.CommonServiceEntry.Healthy)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/gc").HandlerFunc(entry.CommonServiceEntry.Gc)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/info").HandlerFunc(entry.CommonServiceEntry.Info)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/configs").HandlerFunc(entry.CommonServiceEntry.Configs)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/apis").HandlerFunc(entry.CommonServiceEntry.Apis)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/sys").HandlerFunc(entry.CommonServiceEntry.Sys)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/req").HandlerFunc(entry.CommonServiceEntry.Req)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/entries").HandlerFunc(entry.CommonServiceEntry.Entries)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/certs").HandlerFunc(entry.CommonServiceEntry.Certs)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/logs").HandlerFunc(entry.CommonServiceEntry.Logs)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/deps").HandlerFunc(entry.CommonServiceEntry.Deps)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/license").HandlerFunc(entry.CommonServiceEntry.License)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/readme").HandlerFunc(entry.CommonServiceEntry.Readme)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/git").HandlerFunc(entry.CommonServiceEntry.Git)

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

		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/tv").HandlerFunc(redirect)
		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/tv/").HandlerFunc(redirect)

		entry.Router.NewRoute().Methods(http.MethodGet).Path("/rk/v1/tv/{item}").HandlerFunc(entry.TvEntry.TV)
		entry.Router.NewRoute().Methods(http.MethodGet).PathPrefix("/rk/v1/assets/tv/").HandlerFunc(entry.TvEntry.AssetsFileHandler())

		entry.TvEntry.Bootstrap(ctx)
	}

	// Default interceptor should be at front
	entry.Router.Use(entry.Interceptors...)

	go func(muxEntry *MuxEntry) {
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
	}(entry)

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

// AddInterceptor Add interceptors.
// This function should be called before Bootstrap() called.
func (entry *MuxEntry) AddInterceptor(inters ...mux.MiddlewareFunc) {
	entry.Interceptors = append(entry.Interceptors, inters...)
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
