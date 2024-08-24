package main

// http+gRPC prpxy server
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>

import (
	"flag"
	"log"

	_ "expvar"         // to be used for monitoring, see https://github.com/divan/expvarmon
	_ "net/http/pprof" // profiler, see https://golang.org/pkg/net/http/pprof/

	"github.com/dmwm/auth-proxy-server/auth"
	"github.com/dmwm/auth-proxy-server/logging"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
)

// main function
func main() {
	var config string
	flag.StringVar(&config, "config", "", "configuration file")
	flag.Parse()
	err := parseConfig(config)
	if err != nil {
		log.Fatalf("Unable to parse config file %s, error: %v", config, err)
	}

	// configure logger with log time, filename, and line number
	log.SetFlags(0)
	if Config.Verbose > 0 {
		log.SetFlags(log.Lshortfile)
	}
	log.SetOutput(new(logging.LogWriter))
	if Config.LogFile != "" {
		rl, err := rotatelogs.New(Config.LogFile + "-%Y%m%d")
		if err == nil {
			rotlogs := logging.RotateLogWriter{RotateLogs: rl}
			log.SetOutput(rotlogs)
		}
	}
	if Config.Verbose > 0 {
		log.Printf("%+v\n", Config)
	}

	// initialize all particiapted providers
	auth.Init(Config.Providers, Config.Verbose)

	// start proxy server
	if Config.HttpServer {
		// client -> (Http) ProxyServer -> (gRPC) -> gRPC backend
		grpcHttpServer()
	} else {
		// client -> (gRPC) ProxyServer -> (gRPC) -> gRPC backend
		grpcServer()
	}
}
