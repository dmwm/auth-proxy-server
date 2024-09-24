package logging

// logging module provides various logging methods
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	zap "go.uber.org/zap"
	zapcore "go.uber.org/zap/zapcore"
)

// ZapLogger defines zap logger structure
var ZapLogger string

// CMSMonitType controls CMS Monit log record type
var CMSMonitType string

// CMSMonitProducer controls CMS Monit producer name
var CMSMonitProducer string

// CollectorURL
var CollectorURL string

// CollectorSize
var CollectorSize int

// CollectorLogin
var CollectorLogin string

// CollectorPassword
var CollectorPassword string

// CollectorVerbose
var CollectorVerbose int

// LogCollector pointer
var LogCollector *Collector

// HTTPRecord provides http record we send to logs endpoint
type HTTPRecord struct {
	Producer  string    `json:"producer"`  // name of the producer
	Type      string    `json:"type"`      // type of metric
	Timestamp int64     `json:"timestamp"` // UTC milliseconds
	Host      string    `json:"host"`      // used to add extra information about the node submitting your data
	Data      LogRecord `json:"data"`      // log record data
}

// LogRecord represents HTTP log record
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
	AuthCert       string  `json:"auth_cert"`        // auth certificate, user DN
	LoginName      string  `json:"login_name"`       // login name, user DN
	Auth           string  `json:"auth"`             // auth method
	Cipher         string  `json:"cipher"`           // TLS cipher name
	Referer        string  `json:"referer"`          // http referer
	UserAgent      string  `json:"user_agent"`       // http user-agent field
	UserAgentName  string  `json:"user_agent_name"`  // http user-agent name w/o version
	XForwardedHost string  `json:"x_forwarded_host"` // http.Request X-Forwarded-Host
	XForwardedFor  string  `json:"x_forwarded_for"`  // http.Request X-Forwarded-For
	RemoteAddr     string  `json:"remote_addr"`      // http.Request remote address
	ResponseStatus string  `json:"response_status"`  // http.Response status
	ResponseTime   float64 `json:"response_time"`    // http response time
	RequestTime    float64 `json:"request_time"`     // http request time
	Timestamp      int64   `json:"timestamp"`        // record timestamp
	RecTimestamp   int64   `json:"rec_timestamp"`    // timestamp for backward compatibility with apache
	RecDate        string  `json:"rec_date"`         // timestamp for backward compatibility with apache

	// additional fields required by monitoring
	CmswebEnv     string `json:"cmsweb_env"`     // cmsweb environment
	CmswebCluster string `json:"cmsweb_cluster"` // cmsweb cluster
	ClientVersion string `json:"client_version"` // client version
	ProxyServer   string `json:"proxy_server"`   // proxy server
}

// UTC flag represents UTC time zone for log messages
var UTC bool

// helper function to produce UTC time prefixed output
func utcMsg(data []byte) string {
	var msg string
	if UTC {
		msg = fmt.Sprintf("[" + time.Now().UTC().String() + "] " + string(data))
	} else {
		msg = fmt.Sprintf("[" + time.Now().Format(time.RFC3339Nano) + "] " + string(data))
		//     msg = fmt.Sprintf("[" + time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " UTC] " + string(data))
	}
	return msg
}

// custom rotate logger
type RotateLogWriter struct {
	RotateLogs *rotatelogs.RotateLogs
}

func (w RotateLogWriter) Write(data []byte) (int, error) {
	return w.RotateLogs.Write([]byte(utcMsg(data)))
}

// custom logger
type LogWriter struct {
}

func (writer LogWriter) Write(data []byte) (int, error) {
	return fmt.Print(utcMsg(data))
}

// HTTP response data and logging response writer
type (
	// struct for holding response details
	responseData struct {
		status int   // represent status of HTTP response code
		size   int64 // represent size of HTTP response
	}

	// our http.ResponseWriter implementation
	loggingResponseWriter struct {
		http.ResponseWriter // compose original http.ResponseWriter
		responseData        *responseData
	}
)

// Write implements Write API for logging response writer
func (r *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := r.ResponseWriter.Write(b) // write response using original http.ResponseWriter
	r.responseData.size += int64(size)     // capture size
	return size, err
}

// Write implements WriteHeader API for logging response writer
func (r *loggingResponseWriter) WriteHeader(statusCode int) {
	r.ResponseWriter.WriteHeader(statusCode) // write status code using original http.ResponseWriter
	r.responseData.status = statusCode       // capture status code
}

// LoggingMiddleware provides logging middleware for HTTP requests
// https://arunvelsriram.dev/simple-golang-http-logging-middleware
func LoggingMiddleware(h http.Handler) http.Handler {
	loggingFn := func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		tstamp := int64(start.UnixNano() / 1000000) // use milliseconds for MONIT

		// initialize response data struct
		responseData := &responseData{
			status: http.StatusOK, // by default we should return http status OK
			size:   0,
		}
		lrw := loggingResponseWriter{
			ResponseWriter: w, // compose original http.ResponseWriter
			responseData:   responseData,
		}
		h.ServeHTTP(&lrw, r) // inject our implementation of http.ResponseWriter
		cauth := r.Header.Get("Cms-Authn-Method")
		if cauth == "" {
			cauth = "no-auth-method"
		}
		LogRequest(w, r, start, cauth, &responseData.status, tstamp, responseData.size)

	}
	return http.HandlerFunc(loggingFn)
}

// parseHumanReadableTime parses a human-readable time string into seconds represented as a float64
func parseHumanReadableTime(timeStr string) (float64, error) {
	// Define a regular expression to match time components (e.g., 7h, 5m, 3s, etc.)
	re := regexp.MustCompile(`(\d+\.?\d*)([a-zA-Z]+)`)
	matches := re.FindAllStringSubmatch(timeStr, -1)
	if matches == nil {
		return 0, errors.New("invalid time format")
	}

	totalSeconds := float64(0)
	for _, match := range matches {
		value, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid number: %v", match[1])
		}
		unit := strings.ToLower(match[2])
		switch unit {
		case "ns":
			totalSeconds += value / 1000000000
		case "us", "µs":
			totalSeconds += value / 1000000
		case "ms":
			totalSeconds += value / 1000
		case "s":
			totalSeconds += value
		case "m":
			totalSeconds += value * 60
		case "h":
			totalSeconds += value * 3600
		case "d":
			totalSeconds += value * 86400
		default:
			return 0, fmt.Errorf("invalid time unit: %v", unit)
		}
	}

	return totalSeconds, nil
}

// helper function to log every single user request, here we pass pointer to status code
// as it may change through the handler while we use defer logRequest
func LogRequest(w http.ResponseWriter, r *http.Request, start time.Time, cauth string, status *int, tstamp int64, bytesOut int64) {
	// configure zap logger, see https://www.golinuxcloud.com/golang-zap-logger/
	config := zap.NewProductionConfig()
	config.EncoderConfig = zapcore.EncoderConfig{
		MessageKey: "msg", // We just need the message itself
	}
	if ZapLogger != "" {
		config.Encoding = ZapLogger
	}
	// use unstructured zap logger
	logger, e := config.Build()
	if e != nil {
		log.Fatal(e)
	}
	defer logger.Sync()      // flushes buffer, if any
	zapLog := logger.Sugar() // get sugar logger (JSON one)

	// initialize log collector
	if CollectorURL != "" && CollectorLogin != "" && CollectorPassword != "" && LogCollector == nil {
		maxSize := CollectorSize
		if maxSize == 0 {
			maxSize = 1000
		}
		LogCollector = NewCollector(maxSize, CollectorURL, CollectorLogin, CollectorPassword, nil)
	}

	// our apache configuration
	// CustomLog "||@APACHE2_ROOT@/bin/rotatelogs -f @LOGDIR@/access_log_%Y%m%d.txt 86400" \
	//   "%t %v [client: %a] [backend: %h] \"%r\" %>s [data: %I in %O out %b body %D us ] [auth: %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%{SSL_CLIENT_S_DN}x\" \"%{cms-auth}C\" ] [ref: \"%{Referer}i\" \"%{User-Agent}i\" ]"
	//     status := http.StatusOK
	var aproto, cipher string
	var err error
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
			aproto = fmt.Sprintf("TLS-%+v", r.TLS.Version)
		}
		cipher = tls.CipherSuiteName(r.TLS.CipherSuite)
	} else {
		aproto = fmt.Sprintf("no-TLS")
		cipher = "cipher-none"
	}
	if cauth == "" {
		cauth = fmt.Sprintf("%v", r.Header.Get("Cms-Authn-Method"))
	}
	if cauth == "" {
		cauth = "no-auth-method"
	}
	authCert := r.Header.Get("Cms-Auth-Cert")
	if authCert == "" {
		authCert = "no-auth-cert"
	}
	loginName := r.Header.Get("Cms-Authn-Login")
	if loginName == "" {
		loginName = "no-auth-login"
	}
	authMsg := fmt.Sprintf("[auth: %v %v \"%v\" %v %v]", aproto, cipher, authCert, loginName, cauth)
	respHeader := w.Header()
	//     dataMsg := fmt.Sprintf("[data: %v in %v out]", r.ContentLength, respHeader.Get("Content-Length"))
	dataMsg := fmt.Sprintf("[data: %v in %v out]", r.ContentLength, bytesOut)
	if customWriter, ok := w.(*CustomResponseWriter); ok {
		dataMsg = fmt.Sprintf("[data: %v in %v out]", r.ContentLength, customWriter.BytesWritten)
	}
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
	addr := fmt.Sprintf("[host: %v] [remoteAddr: %v] [X-Forwarded-For: %v] [X-Forwarded-Host: %v]", r.Host, r.RemoteAddr, xff, r.Header.Get("X-Forwarded-Host"))
	//     addr := fmt.Sprintf("[X-Forwarded-For: %v] [X-Forwarded-Host: %v] [remoteAddr: %v]", xff, r.Header.Get("X-Forwarded-Host"), r.RemoteAddr)
	ref, err := url.QueryUnescape(referer)
	if err != nil {
		ref = referer
	}
	refMsg := fmt.Sprintf("[ref: \"%v\" \"%v\"]", ref, r.Header.Get("User-Agent"))
	respTime := "0"
	if respHeader.Get("Response-Time") != "" {
		if seconds, err := parseHumanReadableTime(respHeader.Get("Response-Time")); err == nil {
			respTime = fmt.Sprintf("%f", seconds)
		}
	}
	respMsg := fmt.Sprintf("[req: %v (s) proxy-resp: %v (s)]", time.Since(start).Seconds(), respTime)
	uri, err := url.QueryUnescape(r.URL.RequestURI())
	if err != nil {
		uri = r.RequestURI
	}
	statusCode := *status
	if len(w.Header()["Response-Status-Code"]) > 0 {
		// if status code was set by reverse proxy
		scode := w.Header()["Response-Status-Code"][0]
		if c, err := strconv.Atoi(scode); err == nil {
			statusCode = c
		}
	}
	if ZapLogger != "" {
		tstamp := time.Now().Format("[2006-01-02T15:04:05.000000-07:00]")
		zapLog.Infof("%s %s %d %s %s %s %s %s %s %s\n", tstamp, r.Proto, statusCode, r.Method, uri, dataMsg, addr, authMsg, refMsg, respMsg)
	} else {
		log.Printf("%s %d %s %s %s %s %s %s %s\n", r.Proto, statusCode, r.Method, uri, dataMsg, addr, authMsg, refMsg, respMsg)
	}
	if CMSMonitType == "" || CMSMonitProducer == "" {
		return
	}
	rTime, _ := strconv.ParseFloat(respHeader.Get("Response-Time-Seconds"), 10)
	var bytesSend, bytesRecv int64
	bytesSend = r.ContentLength
	bytesRecv, _ = strconv.ParseInt(respHeader.Get("Content-Length"), 10, 64)
	rec := LogRecord{
		Method:         r.Method,
		URI:            uri,
		API:            getAPI(r.RequestURI),
		System:         getSystem(r.RequestURI),
		BytesSend:      bytesSend,
		BytesReceived:  bytesRecv,
		Proto:          r.Proto,
		Status:         int64(*status),
		ContentLength:  r.ContentLength,
		AuthCert:       authCert,
		LoginName:      loginName,
		Auth:           cauth,
		AuthProto:      aproto,
		Cipher:         cipher,
		Referer:        referer,
		UserAgent:      r.Header.Get("User-Agent"),
		UserAgentName:  userAgentName(r.Header.Get("User-Agent")),
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
		CmswebEnv:      os.Getenv("CMSWEB_ENV"),
		CmswebCluster:  os.Getenv("CMSWEB_CLUSTER"),
		ClientVersion:  userAgentName(r.Header.Get("User-Agent")),
		ProxyServer:    os.Getenv("APS_SERVER"),
	}
	// print monit record
	hostname, err := os.Hostname()
	if err != nil {
		log.Println("Unable to get hostname", err)
	}
	hr := HTTPRecord{
		Producer:  CMSMonitProducer,
		Type:      CMSMonitType,
		Timestamp: rec.Timestamp,
		Host:      hostname,
		Data:      rec,
	}
	if LogCollector != nil {
		err = LogCollector.CollectAndSend(hr)
		if err == nil {
			if CollectorVerbose > 0 {
				log.Println("collector successfully send", CollectorSize, "records to MONIT")
			}
		} else {
			log.Println("ERROR: unable to send collector log records, error:", err)
		}
	} else {
		data, err := json.Marshal(hr)
		if err == nil {
			fmt.Println(string(data))
		} else {
			log.Println("ERROR: unable to produce record for MONIT, error", err)
		}
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
		if len(arr) > 1 {
			arr = strings.Split(arr[1], "?")
		}
		system = arr[0]
	}
	if system == "" {
		system = "base"
	}
	return system
}

// integer pattern
var intPattern = regexp.MustCompile(`\d+`)

// helper function to extract user agent name w/o version
func userAgentName(agent string) string {
	var parts []string
	for _, a := range strings.Split(agent, "/") {
		if matched := intPattern.MatchString(a); !matched {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, "/")
}

// CustomResponseWriter wraps http.ResponseWriter to capture the number of bytes written
type CustomResponseWriter struct {
	http.ResponseWriter
	BytesWritten int
}

// Write captures the number of bytes written and calls the underlying Write method
func (w *CustomResponseWriter) Write(data []byte) (int, error) {
	bytesWritten, err := w.ResponseWriter.Write(data)
	w.BytesWritten += bytesWritten
	return bytesWritten, err
}
