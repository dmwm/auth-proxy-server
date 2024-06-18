package main

// auth-proxy-server - Go implementation of reverse proxy server
//                     with CERN SSO OAuth2 OICD and x509 support
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

/*
The code is implemented as the following modules:
- config.go provides server configuration methods
- cric.go provides CMS CRIC service functionality
- data.go holds all data structures used in the package
- logging.go provides logging functionality
- oauth.go provides implementation of oathProxyServer
- x509.go provides implementation of x509ProxyServer
- utils.go provides various utils used in a code

Both server implementations (oauthProxyServer and x509ProxyServer) support
/server end-point which can be used to update server settings, e.g.
curl -X POST -H"Content-type: application/json" -d '{"verbose":true}' https://a.b.com/server

This codebase is based on different examples taken from:
   https://hackernoon.com/writing-a-reverse-proxy-in-just-one-line-with-go-c1edfa78c84b
   https://github.com/bechurch/reverse-proxy-demo/blob/master/main.go
   https://imti.co/golang-reverse-proxy/
   https://itnext.io/capturing-metrics-with-gos-reverse-proxy-5c36cb20cb20
   https://www.integralist.co.uk/posts/golang-reverse-proxy/
*/

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	_ "expvar"         // to be used for monitoring, see https://github.com/divan/expvarmon
	_ "net/http/pprof" // profiler, see https://golang.org/pkg/net/http/pprof/

	"github.com/dmwm/cmsauth"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/shirou/gopsutil/cpu"
	"github.com/vkuznet/auth-proxy-server/auth"
	"github.com/vkuznet/auth-proxy-server/cric"
	"github.com/vkuznet/auth-proxy-server/logging"
)

// StartTime of the server
var StartTime time.Time

// NumPhysicalCores represents number of cores in our node
var NumPhysicalCores int

// NumLogicalCores represents number of cores in our node
var NumLogicalCores int

// CMSAuth structure to create CMS Auth headers
var CMSAuth cmsauth.CMSAuth

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
	var scitokens bool
	flag.BoolVar(&scitokens, "scitokens", false, "start scitokens server")
	var version bool
	flag.BoolVar(&version, "version", false, "print version information about the server")
	flag.Parse()
	if version {
		fmt.Println(info())
		os.Exit(0)
	}
	err := parseConfig(config)
	if err != nil {
		log.Fatalf("unable to parse config %s, error %v\n", config, err)
	}

	// configure logger with log time, filename, and line number
	log.SetFlags(0)
	if Config.Verbose > 0 {
		log.SetFlags(log.Lshortfile)
	}
	log.SetOutput(new(logging.LogWriter))
	if Config.LogFile != "" {
		rl, err := rotatelogs.New(LogName())
		if err == nil {
			rotlogs := logging.RotateLogWriter{RotateLogs: rl}
			log.SetOutput(rotlogs)
		}
	}
	// initialize logging module
	logging.CMSMonitType = Config.MonitType
	logging.CMSMonitProducer = Config.MonitProducer

	if port > 0 {
		log.Println("overwrite server port number to", port)
		Config.Port = port
	}
	if metricsPort > 0 {
		log.Println("overwrite server metrics port number to", metricsPort)
		Config.MetricsPort = metricsPort
	}
	if logFile != "" {
		log.Println("overwrite server log file to", logFile)
		Config.LogFile = logFile
	}
	if Config.Verbose > 0 {
		log.Printf("%+v\n", Config.String())
	}

	// read RootCAs once
	_rootCAs = RootCAs()

	// initialize ingress rules only once
	_ingressMap, _ingressRules = readIngressRules()

	// setup StartTime and metrics last update time
	StartTime = time.Now()
	MetricsLastUpdateTime = time.Now()
	NumPhysicalCores, err = cpu.Counts(false)
	if err != nil {
		log.Printf("unable to get number of physical cores, error %v\n", err)
		NumPhysicalCores = 0
	}
	NumLogicalCores, err = cpu.Counts(true)
	if err != nil {
		log.Printf("unable to get number of logical cores, error %v\n", err)
		NumLogicalCores = 0
	}

	// initialize all particiapted providers
	auth.Init(Config.Providers, Config.Verbose)

	// initialize cmsauth module
	CMSAuth.Init(Config.Hmac)

	// start our servers
	if useX509 {
		if Config.CricURL != "" || Config.CricFile != "" {
			go cric.UpdateCricRecords("dn", Config.CricFile, Config.CricURL, Config.UpdateCricInterval, Config.CricVerbose)
		}
		x509ProxyServer()
		return
	} else if scitokens {
		if Config.CricURL != "" || Config.CricFile != "" {
			go cric.UpdateCricRecords("dn", Config.CricFile, Config.CricURL, Config.UpdateCricInterval, Config.CricVerbose)
		}
		scitokensServer()
		return
	}
	if Config.CricURL != "" || Config.CricFile != "" {
		// Get CRIC records
		go cric.UpdateCricRecords("id", Config.CricFile, Config.CricURL, Config.UpdateCricInterval, Config.CricVerbose)
	}
	// Get AIM records
	go getIAMInfo()
	// start OAuth server
	oauthProxyServer()
}
