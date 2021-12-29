# Panic middleware
In this example, we will try to create mux server with panic middleware enabled.

Panic interceptor will add do the bellow actions.
- Recover from panic
- Convert interface to standard rkerror.ErrorResp style of error
- Set resCode to 500
- Print stacktrace
- Set [panic:1] into event as counters
- Add error into event

**Please make sure panic interceptor to be added at last in chain of interceptors.**

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
  - [Code](#code)
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
import     "github.com/rookie-ninja/rk-mux/interceptor/panic"
```
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []mux.MiddlewareFunc{
        rkmuxpanic.Interceptor(),
    }
```

## Example
We will enable log interceptor to monitor RPC.

### Start server
```shell script
$ go run greeter-server.go
```

### Output
- Server side log (zap & event)
```shell script
2021-12-30T02:46:17.985+0800    ERROR   panic/interceptor.go:46 panic occurs:
goroutine 51 [running]:
runtime/debug.Stack(0xc000258a00, 0x4b307f0, 0xc0001201e0)
        /usr/local/Cellar/go/1.16.3/libexec/src/runtime/debug/stack.go:24 +0x9f
github.com/rookie-ninja/rk-mux/interceptor/panic.Interceptor.func1.1.1(0xc000258a00, 0x4b307f0, 0xc0001201e0)
        /Users/dongxuny/workspace/rk/rk-mux/interceptor/panic/interceptor.go:46 +0x13f
...
        {"error": "[Internal Server Error] Panic manually!"}
```
```shell script
------------------------------------------------------------------------
endTime=2021-12-30T02:46:17.986451+08:00
startTime=2021-12-30T02:46:17.985752+08:00
elapsedNano=699112
timezone=CST
ids={"eventId":"5b72a821-5621-42df-accb-f2883409efdb"}
app={"appName":"rk","appVersion":"","entryName":"mux","entryType":"mux"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"name=rk-dev","userAgent":"curl/7.64.1"}
error={"[Internal Server Error] Panic manually!":1}
counters={"panic":1}
pairs={}
timing={}
remoteAddr=localhost:57104
operation=/v1/greeter
resCode=500
eventStatus=Ended
EOE
```
- Client side
```shell script
$ curl "localhost:8080/v1/greeter?name=rk-dev"
{"error":{"code":500,"status":"Internal Server Error","message":"Panic manually!","details":[]}}
```

### Code
- [greeter-server.go](greeter-server.go)
