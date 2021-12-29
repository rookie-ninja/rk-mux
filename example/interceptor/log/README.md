# Log middleware
In this example, we will try to create mux server with log middleware enabled.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
  - [Code](#code)
- [Options](#options)
  - [Encoding](#encoding)
  - [OutputPath](#outputpath)
  - [Context Usage](#context-usage)
- [Example](#example)
    - [Start server](#start-server)
    - [Output](#output)
  - [Code](#code-1)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Quick start
Get rk-mux package from the remote repository.

```go
go get -u github.com/rookie-ninja/rk-mux
```

### Code
```go
import     "github.com/rookie-ninja/rk-mux/interceptor/log/zap"
```

```go
	interceptors := []mux.MiddlewareFunc{
        rkmuxlog.Interceptor(),
    }
```

## Options
Log interceptor will init rkquery.Event, zap.Logger and entryName which will be injected into request context before user function.
As soon as user function returns, interceptor will write the event into files.

![arch](img/arch.png)

| Name | Default | Description |
| ---- | ---- | ---- |
| WithEntryNameAndType(entryName, entryType string) | entryName=mux, entryType=mux | entryName and entryType will be used to distinguish options if there are multiple interceptors in single process. |
| WithZapLoggerEntry(zapLoggerEntry *rkentry.ZapLoggerEntry) | [rkentry.GlobalAppCtx.GetZapLoggerEntryDefault()](https://github.com/rookie-ninja/rk-entry/blob/master/entry/context.go) | Zap logger would print to stdout with console encoding type. |
| WithEventLoggerEntry(eventLoggerEntry *rkentry.EventLoggerEntry) | [rkentry.GlobalAppCtx.GetEventLoggerEntryDefault()](https://github.com/rookie-ninja/rk-entry/blob/master/entry/context.go) | Event logger would print to stdout with console encoding type. |
| WithZapLoggerEncoding(ec int) | rkmuxlog.ENCODING_CONSOLE | rkmuxlog.ENCODING_CONSOLE and rkmuxlog.ENCODING_JSON are available options. |
| WithZapLoggerOutputPaths(path ...string) | stdout | Both absolute path and relative path is acceptable. Current working directory would be used if path is relative. |
| WithEventLoggerEncoding(ec int) | rkmuxlog.ENCODING_CONSOLE | rkmuxlog.ENCODING_CONSOLE and rkmuxlog.ENCODING_JSON are available options. |
| WithEventLoggerOutputPaths(path ...string) | stdout | Both absolute path and relative path is acceptable. Current working directory would be used if path is relative. |

```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []mux.MiddlewareFunc{
		rkmuxlog.Interceptor(
		// Entry name and entry type will be used for distinguishing interceptors. Recommended.
		// rkmuxlog.WithEntryNameAndType("greeter", "mux"),
		//
		// Zap logger would be logged as JSON format.
		// rkmuxlog.WithZapLoggerEncoding(rkmuxlog.ENCODING_JSON),
		//
		// Event logger would be logged as JSON format.
		// rkmuxlog.WithEventLoggerEncoding(rkmuxlog.ENCODING_JSON),
		//
		// Zap logger would be logged to specified path.
		// rkmuxlog.WithZapLoggerOutputPaths("logs/server-zap.log"),
		//
		// Event logger would be logged to specified path.
		// rkmuxlog.WithEventLoggerOutputPaths("logs/server-event.log"),
		),
	}
```

### Encoding
- CONSOLE
No options needs to be provided. 
```shell script
2021-12-30T01:36:31.535+0800    INFO    log/greeter-server.go:88        Received request from client.
```

```shell script
------------------------------------------------------------------------
endTime=2021-12-30T01:36:31.53557+08:00
startTime=2021-12-30T01:36:31.535428+08:00
elapsedNano=142132
timezone=CST
ids={"eventId":"3c7cd5f4-87f3-42c8-b50e-bb77199b859c"}
app={"appName":"rk","appVersion":"","entryName":"mux","entryType":"mux"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"","userAgent":"curl/7.64.1"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost:59678
operation=/v1/greeter
resCode=200
eventStatus=Ended
EOE
```

- JSON
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []mux.MiddlewareFunc{
        rkmuxlog.Interceptor(
            // Zap logger would be logged as JSON format.
            rkmuxlog.WithZapLoggerEncoding(rkmuxlog.ENCODING_JSON),
            //
            // Event logger would be logged as JSON format.
            rkmuxlog.WithEventLoggerEncoding(rkmuxlog.ENCODING_JSON),
        ),
    }
```
```json
{"level":"INFO","ts":"2021-12-30T01:37:21.974+0800","msg":"Received request from client."}
```
```json
{"endTime": "2021-12-30T01:37:21.974+0800", "startTime": "2021-12-30T01:37:21.974+0800", "elapsedNano": 91958, "timezone": "CST", "ids": {"eventId":"9d1fed61-2368-464b-bfa7-d7935d48e37d"}, "app": {"appName":"rk","appVersion":"","entryName":"mux","entryType":"mux"}, "env": {"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}, "payloads": {"apiMethod":"GET","apiPath":"/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"name=rk-dev","userAgent":"curl/7.64.1"}, "error": {}, "counters": {}, "pairs": {}, "timing": {}, "remoteAddr": "localhost:63010", "operation": "/v1/greeter", "eventStatus": "Ended", "resCode": "200"}
```

### OutputPath
- Stdout
No options needs to be provided. 

- Files
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []mux.MiddlewareFunc{
        rkmuxlog.Interceptor(
            // Zap logger would be logged to specified path.
            rkmuxlog.WithZapLoggerOutputPaths("logs/server-zap.log"),
            //
            // Event logger would be logged to specified path.
            rkmuxlog.WithEventLoggerOutputPaths("logs/server-event.log"),
        ),
    }
```

### Context Usage
| Name | Functionality |
| ------ | ------ |
| rkmuxctx.GetLogger(req, writer) | Get logger generated by log interceptor. If there are X-Request-Id or X-Trace-Id as headers in incoming and outgoing metadata, then loggers will has requestId and traceId attached by default. |
| rkmuxctx.GetEvent(req) | Get event generated by log interceptor. Event would be printed as soon as RPC finished. |
| rkmuxctx.GetIncomingHeaders(req) | Get incoming header. |
| rkmuxctx.AddHeaderToClient(writer, "k", "v") | Add k/v to headers which would be sent to client. This is append operation. |
| rkmuxctx.SetHeaderToClient(writer, "k", "v") | Set k/v to headers which would be sent to client. |
| rkmuxctx.GetJwtToken(req) | Get jwt token if exists |
| rkmuxctx.GetCsrfToken(req) | Get csrf token if exists |

## Example
In this example, we enable log interceptor.

#### Start server
```shell script
$ go run greeter-server.go
```

#### Output
- Server side (zap & event)
```shell script
2021-12-30T01:45:08.009+0800    INFO    log/greeter-server.go:88        Received request from client.
```

```shell script
------------------------------------------------------------------------
endTime=2021-12-30T01:45:08.009794+08:00
startTime=2021-12-30T01:45:08.009611+08:00
elapsedNano=182842
timezone=CST
ids={"eventId":"b9d5bd80-29d6-4cef-9e4c-0dee0ec72c0d"}
app={"appName":"rk","appVersion":"","entryName":"mux","entryType":"mux"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"name=rk-dev","userAgent":"curl/7.64.1"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost:61026
operation=/v1/greeter
resCode=200
eventStatus=Ended
EOE
```

- Client side
```shell script
$ curl "localhost:8080/v1/greeter?name=rk-dev"
{"Message":"Hello rk-dev!"}
```

### Code
- [greeter-server.go](greeter-server.go)
