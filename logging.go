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
	authMsg := fmt.Sprintf("[auth: %v %v \"%v\" %v]", aproto, cipher, r.Header.Get("Cms-Auth-Cert"), cauth)
	respHeader := w.Header()
	dataMsg := fmt.Sprintf("[data: %v in %v out]", r.ContentLength, respHeader.Get("Content-Length"))
	referer := r.Referer()
	if referer == "" {
		referer = "-"
	}
	addr := fmt.Sprintf("[client: %v] [backend: %v]", r.Header.Get("X-Forwarded-Host"), r.RemoteAddr)
	refMsg := fmt.Sprintf("[ref: \"%s\" \"%v\"]", referer, r.Header.Get("User-Agent"))
	respMsg := fmt.Sprintf("[req: %v resp: %v]", time.Since(start), respHeader.Get("Response-Time"))
	log.Printf("%s %s %s %s %d %s %s %s %s\n", addr, r.Method, r.RequestURI, r.Proto, status, dataMsg, authMsg, refMsg, respMsg)
	rTime, _ := strconv.ParseFloat(respHeader.Get("Response-Time-Seconds"), 10)
	rec := LogRecord{
		Method:         r.Method,
		URI:            r.RequestURI,
		API:            "",    // TODO
		BytesSend:      12345, // TODO
		BytesReceived:  12345, // TODO
		Proto:          r.Proto,
		Status:         int64(status),
		ContentLength:  r.ContentLength,
		AuthProto:      aproto,
		Cipher:         cipher,
		CmsAuthCert:    r.Header.Get("Cms-Auth-Cert"),
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
			fmt.Printf(string(data))
		} else {
			log.Println("unable to produce record for MONIT, error", err)
		}
	} else {
		logChannel <- rec
	}
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
