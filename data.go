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
	ServiceURL string `json:"service_url"` // service url
	OldPath    string `json:"old_path"`    // path from url to be replaced with new_path
	NewPath    string `json:"new_path"`    // path from url to replace old_path
}

// Configuration stores server configuration parameters
type Configuration struct {
	Port                int          `json:"port"`                   // server port number
	RootCAs             string       `json:"rootCAs"`                // server Root CAs path
	Base                string       `json:"base"`                   // base URL
	StaticPage          string       `json:"static_page"`            // static file to use
	LogFile             string       `json:"log_file"`               // server log file
	ClientID            string       `json:"client_id"`              // OICD client id
	ClientSecret        string       `json:"client_secret"`          // OICD client secret
	TargetURL           string       `json:"target_url"`             // proxy target url (where requests will go)
	XForwardedHost      string       `json:"X-Forwarded-Host"`       // X-Forwarded-Host field of HTTP request
	XContentTypeOptions string       `json:"X-Content-Type-Options"` // X-Content-Type-Options option
	DocumentRoot        string       `json:"document_root"`          // root directory for the server
	OAuthURL            string       `json:"oauth_url"`              // CERN SSO OAuth2 realm url
	AuthTokenURL        string       `json:"auth_token_url"`         // CERN SSO OAuth2 OICD Token url
	CMSHeaders          bool         `json:"cms_headers"`            // set CMS headers
	RedirectURL         string       `json:"redirect_url"`           // redirect auth url for proxy server
	Verbose             int          `json:"verbose"`                // verbose output
	Ingress             []Ingress    `json:"ingress"`                // incress section
	ServerCrt           string       `json:"server_cert"`            // server certificate
	ServerKey           string       `json:"server_key"`             // server certificate
	Hmac                string       `json:"hmac"`                   // cmsweb hmac file
	CricURL             string       `json:"cric_url"`               // CRIC URL
	CricFile            string       `json:"cric_file"`              // name of the CRIC file
	UpdateCricInterval  int64        `json:"update_cric"`            // interval (in sec) to update cric records
	UTC                 bool         `json:"utc"`                    // report logger time in UTC
	ReadTimeout         int          `json:"read_timeout"`           // server read timeout in sec
	WriteTimeout        int          `json:"write_timeout"`          // server write timeout in sec
	StompConfig         StompConfig  `json:"stomp_config"`           // Stomp Configuration (optional)
	LogsEndpoint        LogsEndpoint `json:"logs_endpoint"`          // logs endpoint configuration (optional)
	WellKnown           string       `json:"well_known"`             // location of well-known area
}

// LogsEndpoint keeps information about HTTP logs end-point
type LogsEndpoint struct {
	URI      string `json:"uri"`      // logs http end-point to use
	Producer string `json:"producer"` // name of producer to use in logs
	Type     string `json:"type"`     // type name for logs
	Prefix   string `json:"prefix"`   // type prefix for logs
}

// StompConfig stores server configuration parameters
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

// HTTPRecord provides http record we send to logs endpoint
type HTTPRecord struct {
	Producer   string    `json:"producer"`    // name of the producer
	Type       string    `json:"type"`        // type of metric
	TypePrefix string    `json:"type_prefix"` // used to categorise your metrics, possible values are raw|agg|enr
	Timestamp  int64     `json:"timestamp"`   // UTC seconds
	Host       string    `json:"host"`        // used to add extra information about the node submitting your data
	Data       LogRecord `json:"data"`        // log record data
}

// LogRecord represents data we can send to StompAMQ or HTTP endpoint
type LogRecord struct {
	Method         string  `json:"method"`           // http.Request HTTP method
	URI            string  `json:"uri"`              // http.RequestURI
	Proto          string  `json:"proto"`            // http.Request protocol
	Status         int64   `json:"status"`           // http.Request status code
	ContentLength  int64   `json:"content_length"`   // http.Request content-length
	AuthProto      string  `json:"auth_proto"`       // authentication protocol
	Cipher         string  `json:"cipher"`           // TLS cipher name
	CmsAuthCert    string  `json:"cms_auth_cert"`    // cms auth certificate, user DN
	CmsAuth        string  `json:"cms_auth"`         // cms auth method
	Referer        string  `json:"referer"`          // http referer
	UserAgent      string  `json:"user_agent"`       // http user-agent field
	XForwardedHost string  `json:"x_forwarded_host"` // http.Request X-Forwarded-Host
	RemoteAddr     string  `json:"remote_addr"`      // http.Request remote address
	ResponseStatus string  `json:"response_status"`  // http.Response status
	ResponseTime   float64 `json:"response_time"`    // http response time
	RequestTime    float64 `json:"request_time"`     // http request time
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
	IDToken       string `json:"id_token"`           // id token
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
