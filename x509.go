package main

// x509 module provides x509 implementation of reverse proxy with
// CMS headers based on CRIC service
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmwm/auth-proxy-server/cric"
	"github.com/dmwm/auth-proxy-server/logging"
	_ "github.com/thomasdarimont/go-kc-example/session_memory"
)

// TotalX509GetRequests counts total number of GET requests received by the server
var TotalX509GetRequests uint64

// TotalX509PostRequests counts total number of POST requests received by the server
var TotalX509PostRequests uint64

// TotalX509PutRequests counts total number of PUT requests received by the server
var TotalX509PutRequests uint64

// TotalX509HeadRequests counts total number of HEAD requests received by the server
var TotalX509HeadRequests uint64

// TotalX509DeleteRequests counts total number of DELETE requests received by the server
var TotalX509DeleteRequests uint64

// TotalX509Requests counts total number of all requests received by the server
var TotalX509Requests uint64

// x509RequestHandler handle requests for x509 clients
func x509RequestHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// increment requests counters
	if r.Method == "GET" {
		atomic.AddUint64(&TotalX509GetRequests, 1)
	} else if r.Method == "POST" {
		atomic.AddUint64(&TotalX509PostRequests, 1)
	} else if r.Method == "PUT" {
		atomic.AddUint64(&TotalX509PutRequests, 1)
	} else if r.Method == "DELETE" {
		atomic.AddUint64(&TotalX509DeleteRequests, 1)
	} else if r.Method == "HEAD" {
		atomic.AddUint64(&TotalX509HeadRequests, 1)
	}
	atomic.AddUint64(&TotalX509Requests, 1)
	defer getRPS(start)

	// check if user provides valid credentials
	status := http.StatusOK
	tstamp := int64(start.UnixNano() / 1000000) // use milliseconds for MONIT
	userData := getUserData(r)
	mapMutex := sync.RWMutex{}
	if Config.Verbose > 0 {
		log.Println("userData", userData)
	}

	// set CMS headers based on provided user certificate
	level := false
	if Config.Verbose > 3 {
		level = true
	}
	mapMutex.RLock()
	CMSAuth.SetCMSHeaders(r, userData, cric.CricRecords, level)
	mapMutex.RUnlock()
	if Config.Verbose > 1 {
		printHTTPRequest(r, "cms headers")
	}

	// Use the custom response writer to capture number of bytes written back by BE
	crw := &logging.CustomResponseWriter{ResponseWriter: w}
	// collect how much bytes we consume and write out with every HTTP request
	defer func() {
		DataIn += float64(r.ContentLength) / float64(TotalX509Requests)
		DataOut += float64(crw.BytesWritten) / float64(TotalX509Requests)
	}()

	// add LogRequest after we set cms headers in HTTP request
	defer logging.LogRequest(crw, r, start, "x509", &status, tstamp, 0)
	mapMutex.RLock()
	_, ok := userData["name"]
	mapMutex.RUnlock()
	if !ok {
		log.Println("unauthorized access, user not found in CRIC DB")
		status = http.StatusUnauthorized
		w.WriteHeader(status)
		return
	}

	// check CMS headers
	authStatus := CMSAuth.CheckAuthnAuthz(r.Header)
	if Config.Verbose > 1 {
		log.Println("x509RequestHandler", r.Header, authStatus)
	}
	if authStatus {
		redirect(crw, r)
		return
	}
	status = http.StatusUnauthorized
	crw.WriteHeader(status)

}

// helper function to start x509 proxy server
func x509ProxyServer() {
	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", Config.Base), metricsHandler)
	// rules handler
	http.HandleFunc(fmt.Sprintf("%s/rules", Config.Base), rulesHandler)

	// start http server to serve metrics only
	if Config.MetricsPort > 0 {
		log.Println("Start x509 server metrics on port", Config.MetricsPort)
		go http.ListenAndServe(fmt.Sprintf(":%d", Config.MetricsPort), nil)
	}

	// the server settings handler
	http.HandleFunc(fmt.Sprintf("%s/server", Config.Base), settingsHandler)

	// Only expose debug endpoints (pprof, expvar) if the client IP is allowed
	http.HandleFunc("/debug/", debugHandler)

	// the request handler
	http.HandleFunc("/", x509RequestHandler)

	// start HTTPS server
	if Config.LetsEncrypt {
		server := LetsEncryptServer(Config.DomainNames...)
		log.Println("Start X509 HTTPs server with LetsEncrypt", Config.DomainNames)
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		// check if provided crt/key files exists
		serverCrt := checkFile(Config.ServerCrt)
		serverKey := checkFile(Config.ServerKey)

		server, err := getServer(serverCrt, serverKey, true)
		if err != nil {
			log.Fatalf("unable to start x509 server, error %v\n", err)
		}
		log.Println("Start X509 HTTPs server with", serverCrt, serverKey)
		log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
	}
}
