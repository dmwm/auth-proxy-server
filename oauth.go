package main

// oath module provides CERN SSO OAuth2 OICD implementation of reverse proxy
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

/*
This is a Go-based implementation of CMS reverse proxy server
with CERN SSO OAuth2 OICD authentication schema. An initial user
request is redirected oauth_url defined in configuration. Then it is
authenticated and this codebase provides CMS X509 headers based on
CMS CRIC meta-data. An additional hmac is set via cmsauth package.
The server can be initialize either as HTTP or HTTPs and provides the
following end-points
- /token returns information about tokens
- /renew renew user tokens
- /callback handles the callback authentication requests
- / performs reverse proxy redirects to backends defined in ingress part of configuration

To access the server clients need to obtain an original token from web interface,
and then they may use it for CLI access, e.g.
curl -v -H "Authorization: Bearer $token" https://xxx.cern.ch/<path>
If token needs to be renewed, clients should use /renew end-point

CERN SSO OAuth2 OICD
   https://gitlab.cern.ch/authzsvc/docs/keycloak-sso-examples
*/

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/thomasdarimont/go-kc-example/session"
	_ "github.com/thomasdarimont/go-kc-example/session_memory"
	"golang.org/x/oauth2"
)

// TotalOAuthGetRequests counts total number of GET requests received by the server
var TotalOAuthGetRequests uint64

// TotalOAuthPostRequests counts total number of POST requests received by the server
var TotalOAuthPostRequests uint64

// AuthTokenURL holds url for token authentication
var AuthTokenURL string

// OAuth2Config holds OAuth2 configuration
var OAuth2Config oauth2.Config

// Verifier is ID token verifier
var Verifier *oidc.IDTokenVerifier

// Context for our requests
var Context context.Context

// globalSession manager for our HTTP requests
var globalSessions *session.Manager

// initialize global session manager
func init() {
	globalSessions, _ = session.NewManager("memory", "gosessionid", 3600)
	go globalSessions.GC()
}

// helper function to verify/validate given token
func introspectToken(token string) (TokenAttributes, error) {
	verifyURL := fmt.Sprintf("%s/introspect", AuthTokenURL)
	form := url.Values{}
	form.Add("token", token)
	form.Add("client_id", Config.ClientID)
	form.Add("client_secret", Config.ClientSecret)
	r, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		msg := fmt.Sprintf("unable to POST request to %s, %v", verifyURL, err)
		return TokenAttributes{}, errors.New(msg)
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("User-Agent", "go-client")
	client := http.Client{}
	if Config.Verbose > 1 {
		dump, err := httputil.DumpRequestOut(r, true)
		log.Println("request", string(dump), err)
	}
	resp, err := client.Do(r)
	if Config.Verbose > 1 {
		dump, err := httputil.DumpResponse(resp, true)
		log.Println("response", string(dump), err)
	}
	if err != nil {
		msg := fmt.Sprintf("validate error: %+v", err)
		return TokenAttributes{}, errors.New(msg)
	}
	defer resp.Body.Close()
	var tokenAttributes TokenAttributes
	err = json.NewDecoder(resp.Body).Decode(&tokenAttributes)
	if err != nil {
		msg := fmt.Sprintf("unable to decode response body: %+v", err)
		return TokenAttributes{}, errors.New(msg)
	}
	return tokenAttributes, nil

}

// helper function to renew access token of the client
func renewToken(token string, r *http.Request) (TokenInfo, error) {
	if token == "" {
		msg := fmt.Sprintf("empty authorization token")
		return TokenInfo{}, errors.New(msg)
	}
	form := url.Values{}
	form.Add("refresh_token", token)
	form.Add("grant_type", "refresh_token")
	form.Add("client_id", Config.ClientID)
	form.Add("client_secret", Config.ClientSecret)
	r, err := http.NewRequest("POST", AuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		msg := fmt.Sprintf("unable to POST request to %s, %v", AuthTokenURL, err)
		return TokenInfo{}, errors.New(msg)
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("User-Agent", "go-client")
	client := http.Client{}
	if Config.Verbose > 1 {
		dump, err := httputil.DumpRequestOut(r, true)
		log.Println("request", string(dump), err)
	}
	resp, err := client.Do(r)
	if Config.Verbose > 1 {
		dump, err := httputil.DumpResponse(resp, true)
		log.Println("response", string(dump), err)
	}
	if err != nil {
		msg := fmt.Sprintf("validate error: %+v", err)
		return TokenInfo{}, errors.New(msg)
	}
	defer resp.Body.Close()
	var tokenInfo TokenInfo
	err = json.NewDecoder(resp.Body).Decode(&tokenInfo)
	if err != nil {
		msg := fmt.Sprintf("unable to decode response body: %+v", err)
		return TokenInfo{}, errors.New(msg)
	}
	return tokenInfo, nil
}

// helper function to check access token of the client
// it is done via introspect auth end-point
func checkAccessToken(r *http.Request) bool {
	// extract token from a request
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		return false
	}
	// token is last part of Authorization header
	arr := strings.Split(tokenStr, " ")
	token := arr[len(arr)-1]
	// verify token
	attrs, err := introspectToken(token)
	if err != nil {
		msg := fmt.Sprintf("unable to verify token: %+v", err)
		log.Println(msg)
		return false
	}
	if !attrs.Active || attrs.Expiration-time.Now().Unix() < 0 {
		msg := fmt.Sprintf("token is invalid: %+v", attrs)
		log.Println(msg)
		return false
	}
	if Config.Verbose > 2 {
		if err := printJSON(attrs, "token attributes"); err != nil {
			msg := fmt.Sprintf("Failed to output token attributes: %v", err)
			log.Println(msg)
		}
	}
	r.Header.Set("scope", attrs.Scope)
	r.Header.Set("client-host", attrs.ClientHost)
	r.Header.Set("client-id", attrs.ClientID)
	return true
}

// callback handler function performs authentication callback and obtain
// user tokens
func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	sess := globalSessions.SessionStart(w, r)
	if Config.Verbose > 0 {
		msg := fmt.Sprintf("call from '/callback', r.URL %s, sess.path %v", r.URL, sess.Get("path"))
		printHTTPRequest(r, msg)
	}
	state := sess.Get("somestate")
	if state == nil {
		http.Error(w, fmt.Sprintf("state did not match, %v", state), http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != state.(string) {
		http.Error(w, fmt.Sprintf("r.URL state did not match, %v", state), http.StatusBadRequest)
		return
	}

	//exchanging the code for a token
	oauth2Token, err := OAuth2Config.Exchange(Context, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if Config.Verbose > 2 {
		log.Println("oauth2Token", oauth2Token)
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	refreshToken, ok := oauth2Token.Extra("refresh_token").(string)
	refreshExpire, ok := oauth2Token.Extra("refresh_expires_in").(float64)
	accessExpire, ok := oauth2Token.Extra("expires_in").(float64)
	if Config.Verbose > 2 {
		log.Println("rawIDToken", rawIDToken)
	}
	idToken, err := Verifier.Verify(Context, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	//preparing the data to be presented on the page
	//it includes the tokens and the user info
	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	err = idToken.Claims(&resp.IDTokenClaims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//storing the token and the info of the user in session memory
	sess.Set("rawIDToken", rawIDToken)
	sess.Set("refreshToken", refreshToken)
	sess.Set("refreshExpire", int64(refreshExpire))
	sess.Set("accessExpire", int64(accessExpire))
	sess.Set("userinfo", resp.IDTokenClaims)
	urlPath := sess.Get("path").(string)
	if Config.Verbose > 0 {
		log.Println("session data", string(data))
		log.Println("redirect to", urlPath)
	}
	http.Redirect(w, r, urlPath, http.StatusFound)
	return
}

// oauth request handler performs reverse proxy action on incoming user request
// the proxy redirection is based on Config.Ingress dictionary, see Configuration
// struct. The only exceptions are /token and /renew end-points which used internally
// to display or renew user tokens, respectively
func oauthRequestHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// increment GET/POST counters
	if r.Method == "GET" {
		atomic.AddUint64(&TotalOAuthGetRequests, 1)
	}
	if r.Method == "POST" {
		atomic.AddUint64(&TotalOAuthPostRequests, 1)
	}
	defer getRPS(start)

	status := http.StatusOK
	userData := make(map[string]interface{})
	defer logRequest(w, r, start, "CERN-SSO-OAuth2-OICD", status)
	sess := globalSessions.SessionStart(w, r)
	if Config.Verbose > 0 {
		msg := fmt.Sprintf("call from '/', r.URL %s, sess.Path %v", r.URL, sess.Get("path"))
		printHTTPRequest(r, msg)
	}
	oauthState := uuid.New().String()
	sess.Set("somestate", oauthState)
	if sess.Get("path") == nil || sess.Get("path") == "" {
		sess.Set("path", r.URL.Path)
	}
	// checking the userinfo in the session or if client provides valid access token.
	// if either is present we'll allow user request
	userInfo := sess.Get("userinfo")
	hasToken := checkAccessToken(r)
	accept := r.Header["Accept"][0]
	if userInfo != nil || hasToken {
		// decode userInfo
		switch t := userInfo.(type) {
		case *json.RawMessage:
			err := json.Unmarshal(*t, &userData)
			if err != nil {
				msg := fmt.Sprintf("unable to decode user data, %v", err)
				status = http.StatusInternalServerError
				http.Error(w, msg, status)
				return
			}
		}
		// set CMS headers
		if Config.CMSHeaders {
			if Config.Verbose > 2 {
				if err := printJSON(userData, "user data"); err != nil {
					log.Println("unable to print user data")
				}
			}
			if Config.Verbose > 3 {
				CMSAuth.SetCMSHeaders(r, userData, CricRecords, true)
			} else {
				CMSAuth.SetCMSHeaders(r, userData, CricRecords, false)
			}
			if Config.Verbose > 0 {
				printHTTPRequest(r, "cms headers")
			}
		}
		// return token back to the user
		if r.URL.Path == fmt.Sprintf("%s/token", Config.Base) {
			var token, rtoken string
			t := sess.Get("rawIDToken")
			rt := sess.Get("refreshToken")
			if t == nil { // cli request
				if v, ok := r.Header["Authorization"]; ok {
					if len(v) == 1 {
						token = strings.Replace(v[0], "Bearer ", "", 1)
					}
				}
			} else {
				token = t.(string)
			}
			if rt == nil { // cli request
				if v, ok := r.Header["Refresh-Token"]; ok {
					if len(v) == 1 {
						rtoken = v[0]
					}
				}
			} else {
				rtoken = rt.(string)
			}
			var texp, rtexp int64
			if sess.Get("accessExpire") != nil {
				texp = sess.Get("accessExpire").(int64)
			}
			if sess.Get("refreshExpire") != nil {
				rtexp = sess.Get("refreshExpire").(int64)
			}
			tokenInfo := TokenInfo{AccessToken: token, RefreshToken: rtoken, AccessExpire: texp, RefreshExpire: rtexp, IDToken: token}
			if !strings.Contains(strings.ToLower(accept), "json") {
				w.Write([]byte(tokenInfo.String()))
				return
			}
			data, err := json.Marshal(tokenInfo)
			if err != nil {
				msg := fmt.Sprintf("unable to marshal token info, %v", err)
				status = http.StatusInternalServerError
				http.Error(w, msg, status)
				return
			}
			w.Write(data)
			return
		}
		// renew existing token
		if r.URL.Path == fmt.Sprintf("%s/renew", Config.Base) {
			var token string
			t := sess.Get("refreshToken")
			if t == nil { // cli request
				if v, ok := r.Header["Authorization"]; ok {
					if len(v) == 1 {
						token = strings.Replace(v[0], "Bearer ", "", 1)
					}
				}
			} else {
				token = t.(string)
			}
			tokenInfo, err := renewToken(token, r)
			if err != nil {
				msg := fmt.Sprintf("unable to refresh access token, %v", err)
				status = http.StatusInternalServerError
				http.Error(w, msg, status)
				return
			}
			if Config.Verbose > 2 {
				printJSON(tokenInfo, "new token info")
			}
			if !strings.Contains(strings.ToLower(accept), "json") {
				w.Write([]byte(tokenInfo.String()))
				return
			}
			data, err := json.Marshal(tokenInfo)
			if err != nil {
				msg := fmt.Sprintf("unable to marshal token info, %v", err)
				status = http.StatusInternalServerError
				http.Error(w, msg, status)
				return
			}
			w.Write(data)
			return
		}
		redirect(w, r)
		return
	}
	// there is no proper authentication yet, redirect users to auth callback
	aurl := OAuth2Config.AuthCodeURL(oauthState)
	if Config.Verbose > 0 {
		log.Println("auth redirect to", aurl)
	}
	status = http.StatusFound
	http.Redirect(w, r, aurl, status)
	return
}

// oauth server provides reverse proxy functionality with
// CERN SSO OAuth2 OICD authentication method
// It performs authentication of clients via internal callback function
// and redirects their requests to targetUrl of reverse proxy.
// If targetUrl is empty string it will redirect all request to
// simple hello page.
func oauthProxyServer(serverCrt, serverKey string) {

	// redirectURL defines where incoming requests will be redirected for authentication
	redirectURL := fmt.Sprintf("http://localhost:%d/callback", Config.Port)
	if serverCrt != "" {
		redirectURL = fmt.Sprintf("https://localhost:%d/callback", Config.Port)
	}
	if Config.RedirectURL != "" {
		redirectURL = Config.RedirectURL
	}

	// authTokenUrl defines where token can be obtained
	AuthTokenURL = fmt.Sprintf("%s/protocol/openid-connect/token", Config.OAuthURL)
	if Config.AuthTokenURL != "" {
		AuthTokenURL = Config.AuthTokenURL
	}

	// Provider is a struct in oidc package that represents
	// an OpenID Connect server's configuration.
	Context = context.Background()
	provider, err := oidc.NewProvider(Context, Config.OAuthURL)
	if err != nil {
		log.Fatal(err)
	}

	// configure an OpenID Connect aware OAuth2 client
	OAuth2Config = oauth2.Config{
		ClientID:     Config.ClientID,
		ClientSecret: Config.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// define token ID verifier
	oidcConfig := &oidc.Config{ClientID: Config.ClientID}
	Verifier = provider.Verifier(oidcConfig)

	// the server settings handler
	http.HandleFunc(fmt.Sprintf("%s/server", Config.Base), settingsHandler)

	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", Config.Base), metricsHandler)

	// the callback authentication handler
	http.HandleFunc(fmt.Sprintf("%s/callback", Config.Base), oauthCallbackHandler)

	// the request handler
	http.HandleFunc("/", oauthRequestHandler)

	// start HTTP or HTTPs server based on provided configuration
	addr := fmt.Sprintf(":%d", Config.Port)
	if serverCrt != "" && serverKey != "" {
		// start HTTPs server
		rootCAs := x509.NewCertPool()
		files, err := ioutil.ReadDir(Config.RootCAs)
		if err != nil {
			log.Printf("Unable to list files root CAs area Config.RootCA='%s', error: %v\n", Config.RootCAs, err)
			return
		}
		for _, finfo := range files {
			fname := fmt.Sprintf("%s/%s", Config.RootCAs, finfo.Name())
			caCert, err := ioutil.ReadFile(fname)
			if err != nil {
				if Config.Verbose > 1 {
					log.Printf("Unable to read %s\n", fname)
				}
			}
			if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
				if Config.Verbose > 1 {
					log.Printf("invalid PEM format while importing trust-chain: %q", fname)
				}
			}
			log.Println("Load CA file", fname)
		}
		cert, err := tls.LoadX509KeyPair(serverCrt, serverKey)
		if err != nil {
			log.Fatalf("server loadkeys: %s", err)

		}

		tlsConfig := &tls.Config{
			RootCAs:      rootCAs,
			Certificates: []tls.Certificate{cert},
		}
		server := &http.Server{
			Addr:           addr,
			TLSConfig:      tlsConfig,
			ReadTimeout:    300 * time.Second,
			WriteTimeout:   300 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		log.Printf("Starting HTTPs server on %s", addr)
		log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
	} else {
		// Start HTTP server
		log.Printf("Starting HTTP server on %s", addr)
		log.Fatal(http.ListenAndServe(addr, nil))
	}
}
