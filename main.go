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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

// version of the code
var version string

type transport struct {
	http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	resp, err = t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	b = bytes.Replace(b, []byte("server"), []byte("schmerver"), -1)
	body := io.NopCloser(bytes.NewReader(b))
	resp.Body = body
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	return resp, nil
}

// Serve a reverse proxy for a given url
func reverseProxy(targetURL string, w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// parse the url
	url, _ := url.Parse(targetURL)

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// set custom transport to capture size of response body
	//     proxy.Transport = &transport{http.DefaultTransport}
	if Config.Verbose > 2 {
		log.Printf("HTTP headers: %+v\n", r.Header)
	}

	// handle double slashes in request path
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)

	// Update the headers to allow for SSL redirection
	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	reqHost := r.Header.Get("Host")
	if reqHost == "" {
		name, err := os.Hostname()
		if err == nil {
			reqHost = name
		}
	}
	if Config.XForwardedHost != "" {
		r.Header.Set("X-Forwarded-Host", Config.XForwardedHost)
	} else {
		r.Header.Set("X-Forwarded-Host", reqHost)
	}
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Host = url.Host
	if Config.Verbose > 0 {
		log.Printf("proxy request: %+v\n", r)
	}

	// use custom modify response function to setup response headers
	proxy.ModifyResponse = func(resp *http.Response) error {
		if Config.Verbose > 0 {
			log.Println("proxy ModifyResponse")
		}
		if Config.XContentTypeOptions != "" {
			resp.Header.Set("X-Content-Type-Options", Config.XContentTypeOptions)
		}
		resp.Header.Set("Response-Status", resp.Status)
		resp.Header.Set("Response-Status-Code", fmt.Sprintf("%d", resp.StatusCode))
		resp.Header.Set("Response-Proto", resp.Proto)
		resp.Header.Set("Response-Time", time.Since(start).String())
		resp.Header.Set("Response-Time-Seconds", fmt.Sprintf("%v", time.Since(start).Seconds()))
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, err error) {
		if Config.Verbose > 0 {
			log.Printf("proxy ErrorHandler error was: %+v", err)
		}
		header := rw.Header()
		header.Set("Response-Status", fmt.Sprintf("%d", http.StatusBadGateway))
		header.Set("Response-Status-Code", fmt.Sprintf("%d", http.StatusBadGateway))
		header.Set("Response-Time", time.Since(start).String())
		header.Set("Response-Time-Seconds", fmt.Sprintf("%v", time.Since(start).Seconds()))
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
	}

	// ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(w, r)
}

// helper function to get random service url
func srvURL(surl string) string {
	// if we are given comma separated service urls we'll use random one
	if strings.Contains(surl, ",") {
		arr := strings.Split(surl, ",")
		/* #nosec */
		idx := rand.Intn(len(arr))         /* #nosec */
		return strings.Trim(arr[idx], " ") // remove empty spaces around the string
	}
	return surl
}

// helper function to redirect HTTP requests based on configuration ingress rules
func redirect(w http.ResponseWriter, r *http.Request) {
	// get redirect rule map and rules (in reverse order)
	// here the reverse order will provide /path/rse /path/aaa followed by /path, etc.
	// such that we can match the /path as last reserve
	rmap, rules := RedirectRules(Config.Ingress)
	for _, key := range rules {
		rec := rmap[key]
		// check that request URL path had ingress path with slash
		if PathMatched(r.URL.Path, rec.Path, rec.Strict) {
			if Config.Verbose > 0 {
				log.Printf("ingress request path %s, record path %s, service url %s, old path %s, new path %s\n", r.URL.Path, rec.Path, rec.ServiceURL, rec.OldPath, rec.NewPath)
			}
			url := srvURL(rec.ServiceURL)
			if rec.OldPath != "" {
				// replace old path to new one, e.g. /couchdb/_all_dbs => /_all_dbs
				r.URL.Path = strings.Replace(r.URL.Path, rec.OldPath, rec.NewPath, 1)
				// if r.URL.Path ended with "/", remove it to avoid
				// cases /path/index.html/ after old->new path substitution
				// but for couchdb/_utils we need final slash
				//                 if !strings.Contains(r.URL.Path, "couchdb") {
				//                     r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
				//                 }
				// replace empty path with root path
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
				if Config.Verbose > 0 {
					log.Printf("service url %s, new request path %s\n", url, r.URL.Path)
				}
			}
			reverseProxy(url, w, r)
			return
		}
	}
	// if no redirection was done, then we'll use either TargetURL
	// or return Hello reply
	if Config.TargetURL != "" {
		reverseProxy(Config.TargetURL, w, r)
	} else {
		if Config.DocumentRoot != "" {
			fname := fmt.Sprintf("%s%s", Config.DocumentRoot, r.URL.Path)
			if strings.HasSuffix(fname, "css") {
				w.Header().Set("Content-Type", "text/css")
			} else if strings.HasSuffix(fname, "js") {
				w.Header().Set("Content-Type", "application/javascript")
			}
			if r.URL.Path == "/" {
				fname = fmt.Sprintf("%s/index.html", Config.DocumentRoot)
			}
			if _, err := os.Stat(fname); err == nil {
				body, err := os.ReadFile(filepath.Clean(fname))
				if err == nil {
					data := []byte(body)
					w.Write(data)
					return
				}
			}
		}
		// use static page content if provided in configuration
		if Config.StaticPage != "" {
			tmpl := template.Must(template.ParseFiles(Config.StaticPage))
			tmpl.Execute(w, "")
			return
		}

		// prohibit access to main page
		w.WriteHeader(http.StatusNotFound)
		return
	}
	return
}

// setting handler function, i.e. it can be used to change server settings
func settingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(info()))
		return
	}
	defer r.Body.Close()
	var s = ServerSettings{}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("unable to read incoming request body %s error %v", string(data), err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(data, &s)
	if err != nil {
		log.Printf("unable to unmarshal incoming request, error %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	Config.Verbose = s.Verbose
	log.Println("Update verbose level of config", Config)
	w.WriteHeader(http.StatusOK)
	return
}

// metrics handler function to provide metrics about the server
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(promMetrics()))
	return
}

// helper function to return version string of the server
func info() string {
	goVersion := runtime.Version()
	tstamp := time.Now().Format("2006-02-01")
	return fmt.Sprintf("auth-proxy-server git=%s go=%s date=%s", version, goVersion, tstamp)
}

func main() {
	var config string
	flag.StringVar(&config, "config", "", "configuration file")
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
		logName := Config.LogFile + "_%Y%m%d"
		hostname, err := os.Hostname()
		if err == nil {
			logName = fmt.Sprintf("%s_%s", Config.LogFile, hostname) + "_%Y%m%d"
		} else {
			log.Println("unable to get hostname", err)
		}
		rl, err := rotatelogs.New(logName)
		if err == nil {
			rotlogs := logging.RotateLogWriter{RotateLogs: rl}
			log.SetOutput(rotlogs)
		}
	}
	// initialize logging module
	logging.CMSMonitType = Config.MonitType
	logging.CMSMonitProducer = Config.MonitProducer

	if Config.Verbose > 0 {
		log.Printf("%+v\n", Config)
	}

	// read RootCAs once
	_rootCAs = RootCAs()

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
