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
	Port                int             `json:"port"`                   // server port number
	MetricsPort         int             `json:"metrics_port"`           // server metrics port number
	RootCAs             string          `json:"rootCAs"`                // server Root CAs path
	Base                string          `json:"base"`                   // base URL
	StaticPage          string          `json:"static_page"`            // static file to use
	LogFile             string          `json:"log_file"`               // server log file
	ClientID            string          `json:"client_id"`              // OICD client id
	ClientSecret        string          `json:"client_secret"`          // OICD client secret
	TargetURL           string          `json:"target_url"`             // proxy target url (where requests will go)
	XForwardedHost      string          `json:"X-Forwarded-Host"`       // X-Forwarded-Host field of HTTP request
	XContentTypeOptions string          `json:"X-Content-Type-Options"` // X-Content-Type-Options option
	DocumentRoot        string          `json:"document_root"`          // root directory for the server
	OAuthURL            string          `json:"oauth_url"`              // CERN SSO OAuth2 realm url
	AuthTokenURL        string          `json:"auth_token_url"`         // CERN SSO OAuth2 OICD Token url
	CMSHeaders          bool            `json:"cms_headers"`            // set CMS headers
	RedirectURL         string          `json:"redirect_url"`           // redirect auth url for proxy server
	Verbose             int             `json:"verbose"`                // verbose output
	Ingress             []Ingress       `json:"ingress"`                // incress section
	ServerCrt           string          `json:"server_cert"`            // server certificate
	ServerKey           string          `json:"server_key"`             // server certificate
	Hmac                string          `json:"hmac"`                   // cmsweb hmac file
	CricURL             string          `json:"cric_url"`               // CRIC URL
	CricFile            string          `json:"cric_file"`              // name of the CRIC file
	UpdateCricInterval  int64           `json:"update_cric"`            // interval (in sec) to update cric records
	UTC                 bool            `json:"utc"`                    // report logger time in UTC
	ReadTimeout         int             `json:"read_timeout"`           // server read timeout in sec
	WriteTimeout        int             `json:"write_timeout"`          // server write timeout in sec
	PrintMonitRecord    bool            `json:"print_monit_record"`     // print monit record on stdout
	Scitokens           ScitokensConfig `json:"scitokens"`              // scitokens configuration
	WellKnown           string          `json:"well_known"`             // location of well-known area
}

// HTTPRecord provides http record we send to logs endpoint
type HTTPRecord struct {
	Producer  string    `json:"producer"`  // name of the producer
	Type      string    `json:"type"`      // type of metric
	Timestamp int64     `json:"timestamp"` // UTC milliseconds
	Host      string    `json:"host"`      // used to add extra information about the node submitting your data
	Data      LogRecord `json:"data"`      // log record data
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

// ScitokensConfig represents configuration of scitokens service
type ScitokensConfig struct {
	FileGlog    string `json:"file_glob"`    // file glob
	Lifetime    int    `json:"lifetime"`     // lifetime of token
	IssuerKey   string `json:"issuer_key"`   // issuer key
	Issuer      string `json:"issuer"`       // issuer hostname
	Rules       []Rule `json:"rules"`        // rules
	DNMapping   string `json:"dn_mapping"`   // dn mapping
	Verbose     bool   `json:"verbose"`      // verbosity mode
	Secret      string `json:"secret"`       // secret
	PrivateKey  string `json:"rsa_key"`      // RSA private key to use
	PrivateJWKS string `json:"private_jwks"` // private jwks file name
	PublicJWKS  string `json:"public_jwks"`  // public jwks file name
}

// Rule reperesents scitoken rule
type Rule struct {
	Match  string   `json:"match"`
	Scopes []string `json:"scopes"`
}

// TokenResponse rerpresents structure of returned scitoken
type TokenResponse struct {
	AccessToken string `json:"access_token"` // access token string
	TokenType   string `json:"token_type"`   // token type string
	Expires     int64  `json:"expires_in"`   // token expiration
}

// ErrorRecord represents our error
type ErrorRecord struct {
	Error string `json:"error"`      // error string
	Code  int    `json:"error_code"` // error code
}
