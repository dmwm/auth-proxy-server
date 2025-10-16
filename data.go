package main

// data module holds all data representations used in our package
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"encoding/json"
	"log"
	"time"
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
	Strict     bool   `json:"strict"`      // apply string matching
}

// Configuration stores server configuration parameters
type Configuration struct {
	Port                int       `json:"port"`                   // server port number
	AuthTroublePort     int       `json:"auth_trouble_port"`      // port for /auth/trouble end-point
	MetricsPort         int       `json:"metrics_port"`           // server metrics port number
	RootCAs             []string  `json:"rootCAs"`                // server Root CAs paths
	Base                string    `json:"base"`                   // base URL
	StaticPage          string    `json:"static_page"`            // static file to use
	LogFile             string    `json:"log_file"`               // server log file
	ClientID            string    `json:"client_id"`              // OICD client id
	ClientSecret        string    `json:"client_secret"`          // OICD client secret
	IAMURL              string    `json:"iam_url"`                // IAM URL
	IAMClientID         string    `json:"iam_client_id"`          // IAM client id
	IAMClientSecret     string    `json:"iam_client_secret"`      // IAM client secret
	IAMBatchSize        int       `json:"iam_batch_size"`         // batch size for IAM requests
	IAMRenewInterval    int       `json:"iam_renew_interval"`     // interval to renew IAM records
	TargetURL           string    `json:"target_url"`             // proxy target url (where requests will go)
	XForwardedHost      string    `json:"X-Forwarded-Host"`       // X-Forwarded-Host field of HTTP request
	XContentTypeOptions string    `json:"X-Content-Type-Options"` // X-Content-Type-Options option
	DocumentRoot        string    `json:"document_root"`          // root directory for the server
	OAuthURL            string    `json:"oauth_url"`              // CERN SSO OAuth2 realm url
	AuthTokenURL        string    `json:"auth_token_url"`         // CERN SSO OAuth2 OICD Token url
	CMSHeaders          bool      `json:"cms_headers"`            // set CMS headers
	RedirectURL         string    `json:"redirect_url"`           // redirect auth url for proxy server
	Verbose             int       `json:"verbose"`                // verbose output
	Ingress             []Ingress `json:"ingress"`                // incress section
	IngressFiles        []string  `json:"ingress_files"`          // use ingress files for ingress rules
	ServerCrt           string    `json:"server_cert"`            // server certificate
	ServerKey           string    `json:"server_key"`             // server certificate
	Hmac                string    `json:"hmac"`                   // cmsweb hmac file
	CricURL             string    `json:"cric_url"`               // CRIC URL
	CricFile            string    `json:"cric_file"`              // name of the CRIC file
	CricVerbose         int       `json:"cric_verbose"`           // verbose output for cric
	UpdateCricInterval  int64     `json:"update_cric"`            // interval (in sec) to update cric records
	UTC                 bool      `json:"utc"`                    // report logger time in UTC
	ReadTimeout         int       `json:"read_timeout"`           // server read timeout in sec
	WriteTimeout        int       `json:"write_timeout"`          // server write timeout in sec

	Scitokens            ScitokensConfig `json:"scitokens"`            // scitokens configuration
	WellKnown            string          `json:"well_known"`           // location of well-known area
	Providers            []string        `json:"providers`             // list of JWKS providers
	MinTLSVersion        string          `json:"minTLSVersion"`        // minimum TLS version
	MaxTLSVersion        string          `json:"maxTLSVersion"`        // maximum TLS version
	CipherSuites         string          `json:"cipher_suites"`        // use custom CipherSuites
	InsecureSkipVerify   bool            `json:"insecureSkipVerify"`   // tls configuration option
	DebugTLSHandshake    bool            `json:"debugTLSHandshake"`    // enable TLS handshake debug info on stdout
	X509MiddlewareServer bool            `json:"x509MiddlewareServer"` // use X509 proxy middleware server

	Corps               bool `json:"coprs"`               // enable corps CORPS (Cross-Origin Resource Sharing)
	KeepAlive           bool `json:"keepAlive"`           // keep alive for http proxy transport
	KeepAliveTimeout    int  `json:"keepAliveTimeout"`    // keep alive timeout
	IdleConnTimeout     int  `json:"idleConnTimeout"`     // idle connection timeout
	TLSHandshakeTimeout int  `json:"tlsHandshakeTimeout"` // tls handshake timeout
	MaxIdleConns        int  `json:"maxIdleConnections"`  // number of max idle connections
	MaxIdleConnsPerHost int  `json:"maxIdleConnsPerHost"` // number of max idle connections

	LetsEncrypt bool     `json:"lets_encrypt"` // start LetsEncrypt HTTPs server
	DomainNames []string `json:"domain_names"` // list of domain names to use for LetsEncrypt

	ZapLogger string `json:"zap_logger"` // define zap logger usage

	// debug server info
	DebugAllowedIPs []string `json:"debug_allowed_ips"` // list of allowed IPs to view debug/profile info

    //configuration for crls.go
    CRLDirs       []string      `json:"crl_dirs"`       // directories containing CRL files
    CRLGlobs      []string      `json:"crl_globs"`      // filename patterns (optional, defaults provided)
    CRLInterval   time.Duration `json:"crl_interval"`   // refresh interval, e.g. "6h"
    CRLQuarantine bool          `json:"crl_quarantine"` // true = quarantine bad CRLs, false = skip them
    CRLPort       int           `json:"crl_port"`       // separate HTTP port for /refresh-crls

	// Monit pieces
	MonitType         string `json:"monit_type"`         // monit record type
	MonitProducer     string `json:"monit_producer"`     // monit record producer
	CollectorURL      string `json:"collector_url"`      // collector url end-point
	CollectorLogin    string `json:"collector_login"`    // collector login name
	CollectorPassword string `json:"collector_password"` // collector password
	CollectorSize     int    `json:"collector_size"`     // collector pool size (in terms of record)
	CollectorVerbose  int    `json:"collector_verbose"`  // collector verbosity level

	// CouchDB headers, see
	// https://docs.couchdb.org/en/3.1.2/api/server/authn.html#proxy-authentication
	XAuthCouchDBUserName string `json:"X-Auth-CouchDB-UserName"` // X-Auth-CouchDB-UserName field of HTTP request
	XAuthCouchDBRoles    string `json:"X-Auth-CouchDB-Roles"`    // X-Auth-CouchDB-Roles field of HTTP request
	XAuthCouchDBToken    string `json:"X-Auth-CouchDB-Token"`    // X-Auth-CouchDB-Token field of HTTP request

}

// String representation of Configuration object
func (c Configuration) String() string {
	data, err := json.MarshalIndent(c, "", "  ")
	if err == nil {
		return string(data)
	} else {
		log.Println("unable to marshal Configuration object", err)
	}
	return ""
}

// ServerSettings controls server parameters
type ServerSettings struct {
	Verbose int `json:"verbose"` // verbosity output
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
	CPU                 []float64               `json:"cpu"`                 // cpu metrics from gopsutils
	Connections         []net.ConnectionStat    `json:"conenctions"`         // connections metrics from gopsutils
	DataIn              float64                 `json:"data_in"`             // data into APS (in bytes)
	DataOut             float64                 `json:"data_out"`            // data out of APS (in bytes)
	Load                load.AvgStat            `json:"load"`                // load metrics from gopsutils
	Memory              Mem                     `json:"memory"`              // memory metrics from gopsutils
	OpenFiles           []process.OpenFilesStat `json:"openFiles"`           // open files metrics from gopsutils
	GoRoutines          uint64                  `json:"goroutines"`          // total number of go routines at run-time
	Uptime              float64                 `json:"uptime"`              // uptime of the server
	GetX509Requests     uint64                  `json:"x509GetRequests"`     // total number of get x509 requests
	PostX509Requests    uint64                  `json:"x509PostRequests"`    // total number of post X509 requests
	PutX509Requests     uint64                  `json:"x509PutRequests"`     // total number of put X509 requests
	DeleteX509Requests  uint64                  `json:"x509DeleteRequests"`  // total number of delete X509 requests
	HeadX509Requests    uint64                  `json:"x509HeadRequests"`    // total number of head X509 requests
	GetOAuthRequests    uint64                  `json:"oAuthGetRequests"`    // total number of get requests form OAuth server
	PostOAuthRequests   uint64                  `json:"oAuthPostRequests"`   // total number of post requests from OAuth server
	PutOAuthRequests    uint64                  `json:"oAuthPutRequests"`    // total number of put requests from OAuth server
	DeleteOAuthRequests uint64                  `json:"oAuthDeleteRequests"` // total number of delete requests from OAuth server
	HeadOAuthRequests   uint64                  `json:"oAuthHeadRequests"`   // total number of head requests from OAuth server
	GetRequests         uint64                  `json:"getRequests"`         // total number of get requests across all services
	PostRequests        uint64                  `json:"postRequests"`        // total number of post requests across all services
	PutRequests         uint64                  `json:"putRequests"`         // total number of put requests across all services
	DeleteRequests      uint64                  `json:"deleteRequests"`      // total number of delete requests across all services
	HeadRequests        uint64                  `json:"headRequests"`        // total number of head requests across all services
	RPS                 float64                 `json:"rps"`                 // throughput req/sec
	RPSPhysical         float64                 `json:"rpsPhysical"`         // throughput req/sec using physical cpu
	RPSLogical          float64                 `json:"rpsLogical"`          // throughput req/sec using logical cpu
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
	Version     string `json:"version"`      // version string, e.g. scitokens:2.0
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
