package main

// logging module provides various logging methods
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
)

// helper function to produce UTC time prefixed output
func utcMsg(data []byte) string {
	var msg string
	// UTC record
	//         msg = fmt.Sprintf("[" + time.Now().UTC().String() + "] " + string(data))
	msg = fmt.Sprintf("[" + time.Now().String() + "] " + string(data))
	return msg
}

// custom rotate logger
type rotateLogWriter struct {
	RotateLogs *rotatelogs.RotateLogs
}

func (w rotateLogWriter) Write(data []byte) (int, error) {
	return w.RotateLogs.Write([]byte(utcMsg(data)))
}

// custom logger
type logWriter struct {
}

func (writer logWriter) Write(data []byte) (int, error) {
	return fmt.Print(utcMsg(data))
}

// LogRecord represents data we can send to StompAMQ or HTTP endpoint
type LogRecord struct {
	Method         string  `json:"method"`           // http.Request HTTP method
	URI            string  `json:"uri"`              // http.RequestURI
	API            string  `json:"api"`              // http service API being used
	System         string  `json:"system"`           // cmsweb service name
	ClientIP       string  `json:"clientip"`         // client IP address
	BytesSend      int64   `json:"bytes_send"`       // number of bytes send with HTTP request
	BytesReceived  int64   `json:"bytes_received"`   // number of bytes received with HTTP request
	Proto          string  `json:"proto"`            // http.Request protocol
	Status         int64   `json:"status"`           // http.Request status code
	ContentLength  int64   `json:"content_length"`   // http.Request content-length
	AuthProto      string  `json:"auth_proto"`       // authentication protocol
	Cipher         string  `json:"cipher"`           // TLS cipher name
	CmsAuthCert    string  `json:"cms_auth_cert"`    // cms auth certificate, user DN
	CmsLoginName   string  `json:"cms_login_name"`   // cms login name, user DN
	CmsAuth        string  `json:"cms_auth"`         // cms auth method
	Referer        string  `json:"referer"`          // http referer
	UserAgent      string  `json:"user_agent"`       // http user-agent field
	XForwardedHost string  `json:"x_forwarded_host"` // http.Request X-Forwarded-Host
	XForwardedFor  string  `json:"x_forwarded_for"`  // http.Request X-Forwarded-For
	RemoteAddr     string  `json:"remote_addr"`      // http.Request remote address
	ResponseStatus string  `json:"response_status"`  // http.Response status
	ResponseTime   float64 `json:"response_time"`    // http response time
	RequestTime    float64 `json:"request_time"`     // http request time
	Timestamp      int64   `json:"timestamp"`        // record timestamp
	RecTimestamp   int64   `json:"rec_timestamp"`    // timestamp for backward compatibility with apache
	RecDate        string  `json:"rec_date"`         // timestamp for backward compatibility with apache
}

// helper function to log every single user request, here we pass pointer to status code
// as it may change through the handler while we use defer logRequest
func logRequest(w http.ResponseWriter, r *http.Request, start time.Time, cauth string, status *int, tstamp int64) {
	// our apache configuration
	// CustomLog "||@APACHE2_ROOT@/bin/rotatelogs -f @LOGDIR@/access_log_%Y%m%d.txt 86400" \
	//   "%t %v [client: %a] [backend: %h] \"%r\" %>s [data: %I in %O out %b body %D us ] [auth: %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%{SSL_CLIENT_S_DN}x\" \"%{cms-auth}C\" ] [ref: \"%{Referer}i\" \"%{User-Agent}i\" ]"
	//     status := http.StatusOK
	var aproto, cipher string
	if r != nil && r.TLS != nil {
		if r.TLS.Version == tls.VersionTLS10 {
			aproto = "TLS10"
		} else if r.TLS.Version == tls.VersionTLS11 {
			aproto = "TLS11"
		} else if r.TLS.Version == tls.VersionTLS12 {
			aproto = "TLS12"
		} else if r.TLS.Version == tls.VersionTLS13 {
			aproto = "TLS13"
		} else if r.TLS.Version == tls.VersionSSL30 {
			aproto = "SSL30"
		} else {
			aproto = fmt.Sprintf("TLS version: %+v", r.TLS.Version)
		}
		cipher = tls.CipherSuiteName(r.TLS.CipherSuite)
	} else {
		aproto = fmt.Sprintf("No TLS")
		cipher = "None"
	}
	if cauth == "" {
		cauth = fmt.Sprintf("%v", r.Header.Get("Cms-Authn-Method"))
	}
	cmsAuthCert := r.Header.Get("Cms-Auth-Cert")
	if cmsAuthCert == "" {
		cmsAuthCert = "NA"
	}
	cmsLoginName := r.Header.Get("Cms-Authn-Login")
	if cmsLoginName == "" {
		cmsLoginName = "NA"
	}
	authMsg := fmt.Sprintf("[auth: %v %v \"%v\" %v %v]", aproto, cipher, cmsAuthCert, cmsLoginName, cauth)
	respHeader := w.Header()
	dataMsg := fmt.Sprintf("[data: %v in %v out]", r.ContentLength, respHeader.Get("Content-Length"))
	referer := r.Referer()
	if referer == "" {
		referer = "-"
	}
	xff := r.Header.Get("X-Forwarded-For")
	var clientip string
	if xff != "" {
		clientip = strings.Split(xff, ":")[0]
	} else if r.RemoteAddr != "" {
		clientip = strings.Split(r.RemoteAddr, ":")[0]
	}
	addr := fmt.Sprintf("[X-Forwarded-For: %v] [X-Forwarded-Host: %v] [remoteAddr: %v]", xff, r.Header.Get("X-Forwarded-Host"), r.RemoteAddr)
	refMsg := fmt.Sprintf("[ref: \"%s\" \"%v\"]", referer, r.Header.Get("User-Agent"))
	respMsg := fmt.Sprintf("[req: %v resp: %v]", time.Since(start), respHeader.Get("Response-Time"))
	log.Printf("%s %s %s %s %d %s %s %s %s\n", addr, r.Method, r.RequestURI, r.Proto, *status, dataMsg, authMsg, refMsg, respMsg)
	rTime, _ := strconv.ParseFloat(respHeader.Get("Response-Time-Seconds"), 10)
	var bytesSend, bytesRecv int64
	bytesSend = r.ContentLength
	bytesRecv, _ = strconv.ParseInt(respHeader.Get("Content-Length"), 10, 64)
	rec := LogRecord{
		Method:         r.Method,
		URI:            r.RequestURI,
		API:            getAPI(r.RequestURI),
		BytesSend:      bytesSend,
		BytesReceived:  bytesRecv,
		Proto:          r.Proto,
		Status:         int64(*status),
		ContentLength:  r.ContentLength,
		AuthProto:      aproto,
		Cipher:         cipher,
		CmsAuthCert:    cmsAuthCert,
		CmsLoginName:   cmsLoginName,
		CmsAuth:        cauth,
		Referer:        referer,
		UserAgent:      r.Header.Get("User-Agent"),
		XForwardedHost: r.Header.Get("X-Forwarded-Host"),
		XForwardedFor:  xff,
		ClientIP:       clientip,
		RemoteAddr:     r.RemoteAddr,
		ResponseStatus: respHeader.Get("Response-Status"),
		ResponseTime:   rTime,
		RequestTime:    time.Since(start).Seconds(),
		Timestamp:      tstamp,
		RecTimestamp:   int64(time.Now().Unix()),
		RecDate:        time.Now().Format(time.RFC3339),
	}
	log.Println(rec)
}

// helper function to extract service API from the record URI
func getAPI(uri string) string {
	// /httpgo?test=bla
	arr := strings.Split(uri, "/")
	last := arr[len(arr)-1]
	arr = strings.Split(last, "?")
	return arr[0]
}
