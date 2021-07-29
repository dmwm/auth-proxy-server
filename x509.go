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
	"sync/atomic"
	"time"

	_ "github.com/thomasdarimont/go-kc-example/session_memory"
	"github.com/vkuznet/auth-proxy-server/cric"
	"github.com/vkuznet/auth-proxy-server/logging"
)

// TotalX509GetRequests counts total number of GET requests received by the server
var TotalX509GetRequests uint64

// TotalX509PostRequests counts total number of POST requests received by the server
var TotalX509PostRequests uint64

// x509RequestHandler handle requests for x509 clients
func x509RequestHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// increment GET/POST counters
	if r.Method == "GET" {
		atomic.AddUint64(&TotalX509GetRequests, 1)
	}
	if r.Method == "POST" {
		atomic.AddUint64(&TotalX509PostRequests, 1)
	}
	defer getRPS(start)

	// check if user provides valid credentials
	status := http.StatusOK
	tstamp := int64(start.UnixNano() / 1000000) // use milliseconds for MONIT
	userData := getUserData(r)
	// set CMS headers based on provided user certificate
	level := false
	if Config.Verbose > 3 {
		level = true
	}
	CMSAuth.SetCMSHeaders(r, userData, cric.CricRecords, level)
	if r.Header.Get("Cms-Auth-Cert") == "" {
		if dn, ok := userData["dn"]; ok {
			r.Header.Set("Cms-Auth-Cert", dn.(string))
		}
	}
	if Config.Verbose > 0 {
		printHTTPRequest(r, "cms headers")
	}
	// add LogRequest after we set cms headers in HTTP request
	defer logging.LogRequest(w, r, start, "x509", &status, tstamp)
	if _, ok := userData["name"]; !ok {
		log.Println("unauthorized access, user not found in CRIC DB")
		status = http.StatusUnauthorized
		w.WriteHeader(status)
		return
	}

	// check CMS headers
	authStatus := CMSAuth.CheckAuthnAuthz(r.Header)
	if Config.Verbose > 0 {
		log.Println("x509RequestHandler", r.Header, authStatus)
	}
	if authStatus {
		redirect(w, r)
		return
	}
	status = http.StatusUnauthorized
	w.WriteHeader(status)
}

// helper function to start x509 proxy server
func x509ProxyServer() {
	// check if provided crt/key files exists
	serverCrt := checkFile(Config.ServerCrt)
	serverKey := checkFile(Config.ServerKey)

	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", Config.Base), metricsHandler)

	// start http server to serve metrics only
	if Config.MetricsPort > 0 {
		go http.ListenAndServe(fmt.Sprintf(":%d", Config.MetricsPort), nil)
	}

	// the server settings handler
	http.HandleFunc(fmt.Sprintf("%s/server", Config.Base), settingsHandler)

	// the request handler
	http.HandleFunc("/", x509RequestHandler)

	// start HTTPS server
	server, err := getServer(serverCrt, serverKey, true)
	if err != nil {
		log.Fatalf("unable to start x509 server, error %v\n", err)
	}
	log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
}
