package main

// data module holds all data representations used in our package
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"fmt"

	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

// Ingress part of server configuration
type Ingress struct {
	Path       string `json:"path"`        // url path to the service
	ServiceUrl string `json:"service_url"` // service url
	OldPath    string `json:"old_path"`    // path from url to be replaced with new_path
	NewPath    string `json:"new_path"`    // path from url to replace old_path
}

// Configuration stores server configuration parameters
type Configuration struct {
	Port                int         `json:"port"`                   // server port number
	RootCAs             string      `json:"rootCAs"`                // server Root CAs path
	Base                string      `json:"base"`                   // base URL
	StaticPage          string      `json:"static_page"`            // static file to use
	LogFile             string      `json:"log_file"`               // server log file
	ClientID            string      `json:"client_id"`              // OICD client id
	ClientSecret        string      `json:"client_secret"`          // OICD client secret
	TargetUrl           string      `json:"target_url"`             // proxy target url (where requests will go)
	XForwardedHost      string      `json:"X-Forwarded-Host"`       // X-Forwarded-Host field of HTTP request
	XContentTypeOptions string      `json:"X-Content-Type-Options"` // X-Content-Type-Options option
	DocumentRoot        string      `json:"document_root"`          // root directory for the server
	OAuthUrl            string      `json:"oauth_url"`              // CERN SSO OAuth2 realm url
	AuthTokenUrl        string      `json:"auth_token_url"`         // CERN SSO OAuth2 OICD Token url
	CMSHeaders          bool        `json:"cms_headers"`            // set CMS headers
	RedirectUrl         string      `json:"redirect_url"`           // redirect auth url for proxy server
	Verbose             int         `json:"verbose"`                // verbose output
	Ingress             []Ingress   `json:"ingress"`                // incress section
	ServerCrt           string      `json:"server_cert"`            // server certificate
	ServerKey           string      `json:"server_key"`             // server certificate
	Hmac                string      `json:"hmac"`                   // cmsweb hmac file
	CricUrl             string      `json:"cric_url"`               // CRIC URL
	CricFile            string      `json:"cric_file"`              // name of the CRIC file
	UpdateCricInterval  int64       `json:"update_cric"`            // interval (in sec) to update cric records
	UTC                 bool        `json:utc`                      // report logger time in UTC
	StompConfig         StompConfig `json:"stomp_config"`           // Stomp Configuration
}

// Configuration stores server configuration parameters
type StompConfig struct {
	URI         string `json:"uri"`              // StompAMQ URI
	Login       string `json:"login"`            // StompAQM login name
	Password    string `json:"password"`         // StompAQM password
	SendTimeout int    `json:"stompSendTimeout"` // heartbeat send timeout
	RecvTimeout int    `json:"stompRecvTimeout"` // heartbeat recv timeout
	Iterations  int    `json:"iterations"`       // Stomp iterations
	Endpoint    string `json:"endpoint"`         // StompAMQ endpoint
	ContentType string `json:"contentType"`      // content type of stomp message\w
	Verbose     int    `json:"verbose"`          // verbose output
}

// StompRecord represents data we can send to StompAMQ endpoint
type StompRecord struct {
	Method         string  // http.Request HTTP method
	Uri            string  // http.RequestURI
	Proto          string  // http.Request protocol
	Status         int64   // http.Request status code
	ContentLength  int64   // http.Request content-length
	AuthProto      string  // authentication protocol
	Cipher         string  // TLS cipher name
	CmsAuthCert    string  // cms auth certificate, user DN
	CmsAuth        string  // cms auth method
	Referer        string  // http referer
	UserAgent      string  // http user-agent field
	XForwardedHost string  // http.Request X-Forwarded-Host
	RemoteAddr     string  // http.Request remote address
	ResponseStatus string  // http.Response status
	ResponseTime   float64 // http response time
	RequestTime    float64 // http request time
}

// ServerSettings controls server parameters
type ServerSettings struct {
	Verbose int `json:"verbose"` // verbosity output
}

// TokenAttributes contains structure of access token attributes
type TokenAttributes struct {
	UserName     string `json:"username"`      // user name
	Active       bool   `json:"active"`        // is token active or not
	SessionState string `json:"session_state"` // session state fields
	ClientID     string `json:"clientId"`      // client id
	Email        string `json:"email"`         // client email address
	Scope        string `json:"scope"`         // scope of the token
	Expiration   int64  `json:"exp"`           // token expiration
	ClientHost   string `json:"clientHost"`    // client host
}

// TokenInfo contains information about all tokens
type TokenInfo struct {
	AccessToken   string `json:"access_token"`       // access token
	AccessExpire  int64  `json:"expires_in"`         // access token expiration
	RefreshToken  string `json:"refresh_token"`      // refresh token
	RefreshExpire int64  `json:"refresh_expires_in"` // refresh token expireation
	IdToken       string `json:"id_token"`           // id token
}

// String convert TokenInfo into html snippet
func (t *TokenInfo) String() string {
	var s string
	s = fmt.Sprintf("%s\nAccessToken:\n%s", s, t.AccessToken)
	s = fmt.Sprintf("%s\nAccessExpire: %d", s, t.AccessExpire)
	s = fmt.Sprintf("%s\nRefreshToken:\n%s", s, t.RefreshToken)
	s = fmt.Sprintf("%s\nRefreshExpire: %d", s, t.RefreshExpire)
	return s
}

// Memory structure keeps track of server memory
type Memory struct {
	Total       uint64  `json:"total"`
	Free        uint64  `json:"free"`
	Used        uint64  `json:"used"`
	UsedPercent float64 `json:"usedPercent"`
}

// Mem structure keeps track of virtual/swap memory of the server
type Mem struct {
	Virtual Memory `json:"virtual"` // virtual memory metrics from gopsutils
	Swap    Memory `json:"swap"`    // swap memory metrics from gopsutils
}

// Metrics provide various metrics about our server
type Metrics struct {
	CPU               []float64               `json:"cpu"`               // cpu metrics from gopsutils
	Connections       []net.ConnectionStat    `json:"conenctions"`       // connections metrics from gopsutils
	Load              load.AvgStat            `json:"load"`              // load metrics from gopsutils
	Memory            Mem                     `json:"memory"`            // memory metrics from gopsutils
	OpenFiles         []process.OpenFilesStat `json:"openFiles"`         // open files metrics from gopsutils
	GoRoutines        uint64                  `json:"goroutines"`        // total number of go routines at run-time
	Uptime            float64                 `json:"uptime"`            // uptime of the server
	GetX509Requests   uint64                  `json:"x509GetRequests"`   // total number of get x509 requests
	PostX509Requests  uint64                  `json:"x509PostRequests"`  // total number of post X509 requests
	GetOAuthRequests  uint64                  `json:"oAuthGetRequests"`  // total number of get requests form OAuth server
	PostOAuthRequests uint64                  `json:"oAuthPostRequests"` // total number of post requests from OAuth server
	GetRequests       uint64                  `json:"getRequests"`       // total number of get requests across all services
	PostRequests      uint64                  `json:"postRequests"`      // total number of post requests across all services
	RPS               float64                 `json:"rps"`               // throughput req/sec
	RPSPhysical       float64                 `json:"rpsPhysical"`       // throughput req/sec using physical cpu
	RPSLogical        float64                 `json:"rpsLogical"`        // throughput req/sec using logical cpu
}
