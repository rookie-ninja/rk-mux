# Trace middleware
In this example, we will try to create mux server with trace middleware enabled.

Trace interceptor has bellow options currently while exporting tracing information.

| Exporter | Description |
| ---- | ---- |
| Stdout | Export as JSON style. |
| Local file | Export as JSON style. |
| Jaeger | Export to jaeger collector or agent. |

**Please make sure panic interceptor to be added at last in chain of interceptors.**

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
- [Options](#options)
  - [Exporter](#exporter)
    - [Stdout exporter](#stdout-exporter)
    - [File exporter](#file-exporter)
    - [Jaeger exporter](#jaeger-exporter)
- [Example](#example)
  - [Start server and client](#start-server-and-client)
  - [Output](#output)
    - [Stdout exporter](#stdout-exporter-1)
    - [Jaeger exporter](#jaeger-exporter-1)
  - [Code](#code)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Quick start
Get rk-mux package from the remote repository.

```go
go get -u github.com/rookie-ninja/rk-mux
```
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []mux.MiddlewareFunc{
		rkmuxtrace.Interceptor(
		// Entry name and entry type will be used for distinguishing interceptors. Recommended.
		//rkmuxtrace.WithEntryNameAndType("greeter", "mux"),
		//
		// Provide an exporter.
		//rkmuxtrace.WithExporter(exporter),
		//
		// Provide propagation.TextMapPropagator
		// rkmuxtrace.WithPropagator(<propagator>),
		//
		// Provide SpanProcessor
		// rkmuxtrace.WithSpanProcessor(<span processor>),
		//
		// Provide TracerProvider
		// rkmuxtrace.WithTracerProvider(<trace provider>),
		),
	}
```

## Options
If client didn't enable trace interceptor, then server will create a new trace span by itself. If client sends a tracemeta to server, 
then server will use the same traceId.

| Name | Description | Default |
| ---- | ---- | ---- |
| WithEntryNameAndType(entryName, entryType string) | Provide entryName and entryType, recommended. | entryName=mux, entryType=mux |
| WithExporter(exporter sdktrace.SpanExporter) | User defined exporter. | [Stdout exporter](https://pkg.go.dev/go.opentelemetry.io/otel/exporters/stdout) with pretty print and disabled metrics |
| WithSpanProcessor(processor sdktrace.SpanProcessor) | User defined span processor. | [NewBatchSpanProcessor](https://pkg.go.dev/go.opentelemetry.io/otel/sdk/trace#NewBatchSpanProcessor) |
| WithPropagator(propagator propagation.TextMapPropagator) | User defined propagator. | [NewCompositeTextMapPropagator](https://pkg.go.dev/go.opentelemetry.io/otel/propagation#TextMapPropagator) |

![arch](img/arch.png)

### Exporter
#### Stdout exporter
```go
    // ****************************************
    // ********** Create Exporter *************
    // ****************************************

    // Export trace to stdout with utility function
    //
    // Bellow function would be while creation
    // set.Exporter, _ = stdout.NewExporter(
    //     stdout.WithPrettyPrint(),
    //     stdout.WithoutMetricExport())
    exporter := rkmuxtrace.CreateFileExporter("stdout")

    // Users can define own stdout exporter by themselves.
	exporter, _ := stdouttrace.New(stdouttrace.WithPrettyPrint())
```

#### File exporter
```go
    // ****************************************
    // ********** Create Exporter *************
    // ****************************************

    // Export trace to local file system
    exporter := rkmuxtrace.CreateFileExporter("logs/trace.log")
```

#### Jaeger exporter
```go
    // ****************************************
    // ********** Create Exporter *************
    // ****************************************

	// Export trace to jaeger agent
	exporter := rkmuxtrace.CreateJaegerExporter(jaeger.WithAgentEndpoint())
```

## Example
### Start server and client
```shell script
$ go run greeter-server.go
```

### Output
#### Stdout exporter
If logger interceptor enabled, then traceId would be attached to event and zap logger.

- Server side trace log
```shell script
{
        "Name": "/v1/greeter",
        "SpanContext": {
                "TraceID": "e7d6b7e287fc747e2750edcdbac270a6",
                "SpanID": "dd319d7d6193fc5b",
                "TraceFlags": "01",
                "TraceState": "",
                "Remote": false
        },
        ...
```

- Server side log (zap & event)
```shell script
2021-12-30T03:02:22.466+0800    INFO    tracing/greeter-server.go:101   Received request from client.   {"traceId": "e7d6b7e287fc747e2750edcdbac270a6"}
```

```shell script
------------------------------------------------------------------------
endTime=2021-12-30T03:02:22.466143+08:00
startTime=2021-12-30T03:02:22.46592+08:00
elapsedNano=223006
timezone=CST
ids={"eventId":"4d709e90-fa6b-4562-85d1-33418fb7a642","traceId":"e7d6b7e287fc747e2750edcdbac270a6"}
app={"appName":"rk","appVersion":"","entryName":"mux","entryType":"mux"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"name=rk-dev","userAgent":"curl/7.64.1"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost:55289
operation=/v1/greeter
resCode=200
eventStatus=Ended
EOE
```

- Client side
```shell script
$ curl -vs "localhost:8080/v1/greeter?name=rk-dev"
...
< X-Trace-Id: e7d6b7e287fc747e2750edcdbac270a6
```

#### Jaeger exporter
![Jaeger](img/jaeger.png)

### Code
- [greeter-server.go](greeter-server.go)
