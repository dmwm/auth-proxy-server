package main

// auth-proxy-server - Go implementation of reverse proxy server
//                     with CERN SSO OAuth2 OICD and x509 support
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
	// _ "expvar"         // to be used for monitoring, see https://github.com/divan/expvarmon
	// _ "net/http/pprof" // profiler, see https://golang.org/pkg/net/http/pprof/
)

// gitVersion of the code shows git hash
var gitVersion string

// tagVersion of the code shows git tag
var tagVersion string

// helper function to return version string of the server
func info() string {
	goVersion := runtime.Version()
	tstamp := time.Now().Format("2006-02-01")
	return fmt.Sprintf("auth-proxy-server tag=%s git=%s go=%s date=%s", tagVersion, gitVersion, goVersion, tstamp)
}

func main() {
	var config string
	flag.StringVar(&config, "config", "", "configuration file")
	var port int
	flag.IntVar(&port, "port", 0, "server port number")
	var metricsPort int
	flag.IntVar(&metricsPort, "metricsPort", 0, "server metrics port number")
	var logFile string
	flag.StringVar(&logFile, "logFile", "", "log file")
	var useX509 bool
	flag.BoolVar(&useX509, "useX509", false, "start X509 auth server")
	var useX509middleware bool
	flag.BoolVar(&useX509middleware, "useX509middleware", false, "start X509middleware auth server")
	var scitokens bool
	flag.BoolVar(&scitokens, "scitokens", false, "start scitokens server")
	var rules bool
	flag.BoolVar(&rules, "rules", false, "print APS redirect rules")
	var testRule string
	flag.StringVar(&testRule, "testRule", "", "url path")
	var version bool
	flag.BoolVar(&version, "version", false, "print version information about the server")
	flag.Parse()
	if version {
		fmt.Println(info())
		os.Exit(0)
	}
	if testRule != "" {
		testRedirectRule(config, testRule)
		os.Exit(0)
	}
	Server(config, port, metricsPort, logFile, useX509, useX509middleware, scitokens, rules)
}
