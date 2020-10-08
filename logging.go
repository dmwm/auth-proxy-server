package main

// logging module provides various logging methods
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
)

// helper function to produce UTC time prefixed output
func utcMsg(data []byte) string {
	var msg string
	if Config.UTC {
		msg = fmt.Sprintf("[" + time.Now().UTC().String() + "] " + string(data))
	} else {
		msg = fmt.Sprintf("[" + time.Now().String() + "] " + string(data))
		//     msg = fmt.Sprintf("[" + time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " UTC] " + string(data))
	}
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

// helper function to log every single user request
func logRequest(w http.ResponseWriter, r *http.Request, start time.Time, cauth string, status int, logChannel chan LogRecord) {
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
	authMsg := fmt.Sprintf("[auth: %v %v \"%v\" %v]", aproto, cipher, cmsAuthCert, cauth)
	respHeader := w.Header()
	dataMsg := fmt.Sprintf("[data: %v in %v out]", r.ContentLength, respHeader.Get("Content-Length"))
	referer := r.Referer()
	if referer == "" {
		referer = "-"
	}
	realIP := r.Header.Get("X-Real-IP")
	clientIP := r.Header.Get("X-Forwarded-For")
	origIP := r.Header.Get("X-Original-Forwarded-For")
	addr := fmt.Sprintf("[X-Original-Forwarded-For: %v] [X-Real-IP: %v] [X-Forwarded-For: %v] [X-Forwarded-Host: %v] [remoteAddr: %v]", origIP, realIP, clientIP, r.Header.Get("X-Forwarded-Host"), r.RemoteAddr)
	refMsg := fmt.Sprintf("[ref: \"%s\" \"%v\"]", referer, r.Header.Get("User-Agent"))
	respMsg := fmt.Sprintf("[req: %v resp: %v]", time.Since(start), respHeader.Get("Response-Time"))
	log.Printf("%s %s %s %s %d %s %s %s %s\n", addr, r.Method, r.RequestURI, r.Proto, status, dataMsg, authMsg, refMsg, respMsg)
	rTime, _ := strconv.ParseFloat(respHeader.Get("Response-Time-Seconds"), 10)
	var bytesSend, bytesRecv int64
	bytesSend = r.ContentLength
	bytesRecv, _ = strconv.ParseInt(respHeader.Get("Content-Length"), 10, 64)
	rec := LogRecord{
		Method:         r.Method,
		URI:            r.RequestURI,
		API:            getAPI(r.RequestURI),
		System:         getSystem(r.RequestURI),
		ClientIP:       clientIP,
		RealIP:         realIP,
		OrigIP:         origIP,
		BytesSend:      bytesSend,
		BytesReceived:  bytesRecv,
		Proto:          r.Proto,
		Status:         int64(status),
		ContentLength:  r.ContentLength,
		AuthProto:      aproto,
		Cipher:         cipher,
		CmsAuthCert:    cmsAuthCert,
		CmsAuth:        cauth,
		Referer:        referer,
		UserAgent:      r.Header.Get("User-Agent"),
		XForwardedHost: r.Header.Get("X-Forwarded-Host"),
		RemoteAddr:     r.RemoteAddr,
		ResponseStatus: respHeader.Get("Response-Status"),
		ResponseTime:   rTime,
		RequestTime:    time.Since(start).Seconds(),
		Timestamp:      time.Now().Unix() * 1000, // use milliseconds for MONIT
	}
	if Config.PrintMonitRecord {
		data, err := monitRecord(rec)
		if err == nil {
			fmt.Println(string(data))
		} else {
			log.Println("unable to produce record for MONIT, error", err)
		}
	} else {
		logChannel <- rec
	}
}

// helper function to extract service API from the record URI
func getAPI(uri string) string {
	// /httpgo?test=bla
	arr := strings.Split(uri, "/")
	last := arr[len(arr)-1]
	arr = strings.Split(last, "?")
	return arr[0]
}

// helper function to extract service system from the record URI
func getSystem(uri string) string {
	// /httpgo?test=bla
	arr := strings.Split(uri, "/")
	system := "base"
	if len(arr) > 0 {
		arr = strings.Split(arr[1], "?")
		system = arr[0]
	}
	if system == "" {
		system = "base"
	}
	return system
}

// helper function to prepare record for MONIT
func monitRecord(rec LogRecord) ([]byte, error) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Println("Unable to get hostname", err)
	}
	ltype := Config.LogsEndpoint.Type
	if ltype == "" {
		ltype = "auth"
	}
	producer := Config.LogsEndpoint.Producer
	if producer == "" {
		producer = "cmsweb"
	}
	r := HTTPRecord{
		Producer:  producer,
		Type:      ltype,
		Timestamp: time.Now().Unix() * 1000, // usr milliseconds for MONIT
		Host:      hostname,
		Data:      rec,
	}
	data, err := json.Marshal(r)
	return data, err
}

// logChannelLoop process log records send to channel
func logChannelLoop(logChannel chan LogRecord) {
	log.Println("start logChannelLoop with", logChannel)
	buf := &bytes.Buffer{}
	for {
		select {
		case rec := <-logChannel:
			if Config.LogsEndpoint.URI != "" {
				data, err := monitRecord(rec)
				if err == nil {
					if Config.Verbose > 1 {
						log.Println("send", string(data))
					}
					_, err = buf.Write(data)
					if err == nil {
						send(buf)
					} else {
						log.Println("unable to read data into buffer", err)
					}
					buf.Reset()
				} else {
					log.Printf("unable to marshal record %+v, error %v\n", rec, err)
				}
			}
			if Config.StompConfig.URI != "" {
				data, err := json.Marshal(rec)
				if err == nil {
					stompMgr.Send(data)
				} else {
					log.Printf("unable to marshal record %+v, error %v\n", rec, err)
				}
			}
		default:
			time.Sleep(time.Duration(10) * time.Millisecond) // wait for response
		}
	}
}

// helper function to send our logs to http logs end-point
func send(body *bytes.Buffer) {
	rurl := Config.LogsEndpoint.URI
	ctype := "application/json"
	resp, err := http.Post(rurl, ctype, body)
	if err != nil {
		log.Printf("unable to send data to %s, error %v\n", rurl, err)
	}
	if Config.Verbose == 1 {
		log.Println(rurl, resp.Proto, resp.Status)
	}
}
