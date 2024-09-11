package main

import (
	"log"
	"time"

	"github.com/dmwm/auth-proxy-server/auth"
	"github.com/dmwm/auth-proxy-server/cric"
	"github.com/dmwm/auth-proxy-server/logging"
	"github.com/dmwm/cmsauth"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/shirou/gopsutil/cpu"
)

// StartTime of the server
var StartTime time.Time

// NumPhysicalCores represents number of cores in our node
var NumPhysicalCores int

// NumLogicalCores represents number of cores in our node
var NumLogicalCores int

// CMSAuth structure to create CMS Auth headers
var CMSAuth cmsauth.CMSAuth

// Server starts APS server
func Server(config string, port, metricsPort int, logFile string, useX509, scitokens, rules bool) {
	err := parseConfig(config)
	if err != nil {
		log.Fatalf("unable to parse config %s, error %v\n", config, err)
	}
	if rules {
		printRules()
		return
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
	if Config.ZapLogger != "" {
		log.Printf("Use zap logger with %s format", Config.ZapLogger)
		logging.ZapLogger = Config.ZapLogger
	}

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

	// initialize log collector attributes
	logging.CollectorURL = Config.CollectorURL
	logging.CollectorLogin = Config.CollectorLogin
	logging.CollectorPassword = Config.CollectorPassword
	logging.CollectorSize = Config.CollectorSize

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
