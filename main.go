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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dmwm/cmsauth"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	_ "github.com/thomasdarimont/go-kc-example/session_memory"
)

// CMSAuth structure to create CMS Auth headers
var CMSAuth cmsauth.CMSAuth

// Serve a reverse proxy for a given url
func reverseProxy(targetUrl string, w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// parse the url
	url, _ := url.Parse(targetUrl)

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

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
	r.Host = url.Host
	if Config.Verbose > 0 {
		log.Printf("### proxy request: %+v\n", r)
	}

	// use custom modify response function to setup response headers
	proxy.ModifyResponse = func(resp *http.Response) error {
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

	// ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(w, r)
}

// helper function to redirect HTTP requests based on configuration ingress rules
func redirect(w http.ResponseWriter, r *http.Request) {
	// if Configuration provides Ingress rules we'll use them
	// to redirect user request
	for _, rec := range Config.Ingress {
		if strings.Contains(r.URL.Path, rec.Path) {
			if Config.Verbose > 0 {
				log.Printf("ingress request path %s, record path %s, service url %s, old path %s, new path %s\n", r.URL.Path, rec.Path, rec.ServiceUrl, rec.OldPath, rec.NewPath)
			}
			url := rec.ServiceUrl
			if rec.OldPath != "" {
				// replace old path to new one, e.g. /couchdb/_all_dbs => /_all_dbs
				r.URL.Path = strings.Replace(r.URL.Path, rec.OldPath, rec.NewPath, 1)
				// if r.URL.Path ended with "/", remove it to avoid
				// cases /path/index.html/ after old->new path substitution
				r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
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
	if Config.TargetUrl != "" {
		reverseProxy(Config.TargetUrl, w, r)
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
				body, err := ioutil.ReadFile(fname)
				if err == nil {
					data := []byte(body)
					w.Write(data)
					return
				}
			}
		}
		msg := fmt.Sprintf("Hello %s", r.URL.Path)
		data := []byte(msg)
		w.Write(data)
		return
	}
	return
}

// setting handler function, i.e. it can be used to change server settings
func settingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var s = ServerSettings{}
	err := json.NewDecoder(r.Body).Decode(&s)
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

func main() {
	var config string
	flag.StringVar(&config, "config", "", "configuration file")
	var useX509 bool
	flag.BoolVar(&useX509, "useX509", false, "use X509 auth server")
	flag.Parse()
	err := parseConfig(config)
	// log time, filename, and line number
	log.SetFlags(0)
	if Config.Verbose > 0 {
		log.SetFlags(log.Lshortfile)
	}
	log.SetOutput(new(logWriter))

	if Config.Verbose > 0 {
		log.Printf("%+v\n", Config)
	}

	if Config.LogFile != "" {
		rl, err := rotatelogs.New(Config.LogFile + "-%Y%m%d")
		if err == nil {
			rotlogs := rotateLogWriter{RotateLogs: rl}
			log.SetOutput(rotlogs)
		}
	}

	if err == nil {
		CMSAuth.Init(Config.Hmac)
		go updateCricRecords()
		_, e1 := os.Stat(Config.ServerCrt)
		_, e2 := os.Stat(Config.ServerKey)
		var crt, key string
		if e1 == nil && e2 == nil {
			crt = Config.ServerCrt
			key = Config.ServerKey
		}
		if useX509 {
			x509ProxyServer(crt, key)
			return
		}
		oauthProxyServer(crt, key)
	}
}
