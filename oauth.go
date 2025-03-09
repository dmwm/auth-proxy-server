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
- /token/renew renew user tokens
- /token returns information about tokens
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// original APS code used v2 of oidc
	//     oidc "github.com/coreos/go-oidc"
	// new oidc is v3
	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/dmwm/auth-proxy-server/auth"
	"github.com/dmwm/auth-proxy-server/cric"
	"github.com/dmwm/auth-proxy-server/logging"
	"github.com/google/uuid"
	"github.com/thomasdarimont/go-kc-example/session"
	_ "github.com/thomasdarimont/go-kc-example/session_memory"
	"golang.org/x/oauth2"
)

// TotalOAuthGetRequests counts total number of GET requests received by the server
var TotalOAuthGetRequests uint64

// TotalOAuthPostRequests counts total number of POST requests received by the server
var TotalOAuthPostRequests uint64

// TotalOAuthPutRequests counts total number of PUT requests received by the server
var TotalOAuthPutRequests uint64

// TotalOAuthDeleteRequests counts total number of DELETE requests received by the server
var TotalOAuthDeleteRequests uint64

// TotalOAuthHeadRequests counts total number of HEAD requests received by the server
var TotalOAuthHeadRequests uint64

// TotalOAuthRequests counts total number of all requests received by the server
var TotalOAuthRequests uint64

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

// sessLock keeps lock for sess updates
var sessLock sync.RWMutex

// iamUsers keeps track of IAM users' records
var iamUsers IAMUserMap

// initialize global session manager
func init() {
	globalSessions, _ = session.NewManager("memory", "gosessionid", 3600)
	go globalSessions.GC()
}

// helper function to get IAM info
func getIAMInfo() {
	// get IAM users
	if Config.IAMClientID != "" && Config.IAMClientSecret != "" {
		IAMRenewInterval = time.Duration(3600) * time.Second
		if Config.IAMRenewInterval > 0 {
			IAMRenewInterval = time.Duration(Config.IAMRenewInterval) * time.Second
		}
		log.Println("obtain IAM data for", Config.IAMClientID, "renew in", IAMRenewInterval)
		iam := IAMUserManager{
			ClientID:     Config.IAMClientID,
			ClientSecret: Config.IAMClientSecret,
			BatchSize:    Config.IAMBatchSize,
			URL:          Config.IAMURL,
			Verbose:      Config.Verbose,
		}
		var err error
		tstamp := time.Now()
		iamUsers, err = iam.GetUsers()
		if err != nil {
			log.Fatalf("unable to get IAM users, error %v", err)
		}
		log.Printf("Loaded IAM %d users in %s", len(iamUsers), time.Since(tstamp))
	}
}

// helper function to verify/validate given token
func introspectToken(token string) (auth.TokenAttributes, error) {
	verifyURL := fmt.Sprintf("%s/introspect", AuthTokenURL)
	form := url.Values{}
	form.Add("token", token)
	form.Add("client_id", Config.ClientID)
	form.Add("client_secret", Config.ClientSecret)
	r, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		msg := fmt.Sprintf("unable to POST request to %s, %v", verifyURL, err)
		return auth.TokenAttributes{}, errors.New(msg)
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
		return auth.TokenAttributes{}, errors.New(msg)
	}
	defer resp.Body.Close()
	var tokenAttributes auth.TokenAttributes
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("unable to read response body %s error %v", string(data), err)
		return auth.TokenAttributes{}, errors.New(msg)
	}
	err = json.Unmarshal(data, &tokenAttributes)
	if err != nil {
		msg := fmt.Sprintf("unable to decode response body, error %v", err)
		return auth.TokenAttributes{}, errors.New(msg)
	}
	return tokenAttributes, nil

}

// helper function to renew access token of the client
func renewToken(token string, r *http.Request) (auth.TokenInfo, error) {
	if token == "" {
		msg := fmt.Sprintf("empty authorization token")
		return auth.TokenInfo{}, errors.New(msg)
	}
	form := url.Values{}
	form.Add("refresh_token", token)
	form.Add("grant_type", "refresh_token")
	form.Add("client_id", Config.ClientID)
	form.Add("client_secret", Config.ClientSecret)
	r, err := http.NewRequest("POST", AuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		msg := fmt.Sprintf("unable to POST request to %s, %v", AuthTokenURL, err)
		return auth.TokenInfo{}, errors.New(msg)
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
		return auth.TokenInfo{}, errors.New(msg)
	}
	defer resp.Body.Close()
	var tokenInfo auth.TokenInfo
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("unable to read response body %s error %v", string(data), err)
		return auth.TokenInfo{}, errors.New(msg)
	}
	err = json.Unmarshal(data, &tokenInfo)
	if err != nil {
		msg := fmt.Sprintf("unable to decode response body, error %v", err)
		return auth.TokenInfo{}, errors.New(msg)
	}
	return tokenInfo, nil
}

// helper function to get token from http request
func getToken(r *http.Request) string {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		return tokenStr
	}
	arr := strings.Split(tokenStr, " ")
	token := arr[len(arr)-1]
	return token
}

// helper function to check access token of the client
// it is done via introspect auth end-point
func checkAccessToken(r *http.Request) (auth.TokenAttributes, error) {
	// extract token from a request
	token := getToken(r)
	if token == "" {
		return auth.TokenAttributes{}, errors.New("no token present in HTTP request")
	}

	attrs, err := checkIAMToken(token, Config.Verbose)
	if err == nil {
		log.Printf("found IAM token attributes %+v", attrs)
		if user, ok := iamUsers[attrs.Subject]; ok {
			r.Header.Set("scope", attrs.Scope)
			r.Header.Set("client-host", attrs.ClientHost)
			r.Header.Set("client-id", attrs.ClientID)
			if Config.Verbose > 0 {
				log.Printf("match checkIAMToken, user info %+v", user)
			}
			r.Header.Set("Cms-Authn-Login", user.UserName)
			var certs []string
			for _, c := range user.IndigoUser.Certificates {
				certs = append(certs, c.String())
			}
			r.Header.Set("Cms-Auth-Cert", fmt.Sprintf("%v", certs))
			iamEmail := user.Emails[0]
			attrs.Email = iamEmail.Value
			attrs.UserName = user.UserName
			return attrs, nil
		}
	} else {
		log.Println("fail to match AIM token, error", err)
	}

	// first, we inspect our token
	attrs, err = auth.InspectTokenProviders(token, Config.Providers, Config.Verbose)
	if err == nil {
		if attrs.ClientHost == "" {
			attrs.ClientHost = r.Referer()
		}
		r.Header.Set("scope", attrs.Scope)
		r.Header.Set("client-host", attrs.ClientHost)
		r.Header.Set("client-id", attrs.ClientID)
		if Config.Verbose > 0 {
			log.Println("match InspectTokenProviders")
		}
		return attrs, nil
	}

	log.Println("unable to inspect token: ", err)
	// if inspection fails, we'll try to send introspect request to auth provider
	// to verify token
	attrs, err = introspectToken(token)
	if err != nil {
		msg := fmt.Sprintf("unable to verify token: %+v", err)
		log.Println(msg)
		return attrs, err
	}
	if !attrs.Active || attrs.Expiration-time.Now().Unix() < 0 {
		msg := fmt.Sprintf("token is invalid: %+v", attrs)
		log.Println(msg)
		return attrs, errors.New("invalid token")
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
	return attrs, nil
}

// callback handler function performs authentication callback and obtain
// user tokens
func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	sess := globalSessions.SessionStart(w, r)
	if Config.Verbose > 0 {
		msg := fmt.Sprintf("call from '/callback', r.URL %s, sess.path %v", r.URL, sess.Get("path"))
		printHTTPRequest(r, msg)
	}
	sessLock.Lock()
	state := sess.Get("somestate")
	sessLock.Unlock()
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
	sessLock.Lock()
	sess.Set("rawIDToken", rawIDToken)
	sess.Set("refreshToken", refreshToken)
	sess.Set("refreshExpire", int64(refreshExpire))
	sess.Set("accessExpire", int64(accessExpire))
	sess.Set("userinfo", resp.IDTokenClaims)
	urlPath := sess.Get("path").(string)
	accessToken := resp.OAuth2Token.AccessToken
	sess.Set("accessToken", accessToken)
	if accessToken != "" {
		sess.Set("accessToken", accessToken)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}
	sessLock.Unlock()
	if Config.Verbose > 0 {
		log.Printf("response data %+v", resp)
		log.Println("session data", string(data))
		log.Println("redirect to", urlPath)
		printHTTPRequest(r, "new http request headers after CERN SSO")
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
	} else if r.Method == "POST" {
		atomic.AddUint64(&TotalOAuthPostRequests, 1)
	} else if r.Method == "PUT" {
		atomic.AddUint64(&TotalOAuthPostRequests, 1)
	} else if r.Method == "DELETE" {
		atomic.AddUint64(&TotalOAuthDeleteRequests, 1)
	} else if r.Method == "HEAD" {
		atomic.AddUint64(&TotalOAuthHeadRequests, 1)
	}
	atomic.AddUint64(&TotalOAuthRequests, 1)
	defer getRPS(start)

	status := http.StatusOK
	userData := make(map[string]interface{})
	mapMutex := sync.RWMutex{}
	tstamp := int64(start.UnixNano() / 1000000) // use milliseconds for MONIT
	sess := globalSessions.SessionStart(w, r)
	oauthState := uuid.New().String()

	// check userinfo in the session or if client provides valid access token.
	sessLock.Lock()
	sess.Set("somestate", oauthState)
	if sess.Get("path") == nil || sess.Get("path") == "" {
		sess.Set("path", r.URL.Path)
	}
	if sess.Get("accessToken") != nil && sess.Get("accessToken") != "" && r.Header.Get("Authorization") == "" {
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sess.Get("accessToken")))
	}
	userInfo := sess.Get("userinfo")
	sessLock.Unlock()

	if Config.Verbose > 0 {
		sessLock.Lock()
		msg := fmt.Sprintf("oauthRequestHandler, r.URL %s, sess.Path %v", r.URL, sess.Get("path"))
		printHTTPRequest(r, msg)
		sessLock.Unlock()
	}

	// Use the custom response writer to capture number of bytes written back by BE
	crw := &logging.CustomResponseWriter{ResponseWriter: w}
	// collect how much bytes we consume and write out with every HTTP request
	defer func() {
		DataIn += float64(r.ContentLength) / float64(TotalOAuthRequests)
		DataOut += float64(crw.BytesWritten) / float64(TotalOAuthRequests)
	}()

	attrs, err := checkAccessToken(r)
	// add LogRequest after we set cms headers in HTTP request
	defer logging.LogRequest(crw, r, start, "CERN-SSO-OAuth2-OICD", &status, tstamp, 0)
	if err != nil {
		// there is no proper authentication yet, redirect users to auth callback
		aurl := OAuth2Config.AuthCodeURL(oauthState)
		if Config.Verbose > 0 {
			log.Printf("token attributes %+v, error %v", attrs, err)
			log.Println("auth redirect to", aurl)
		}
		status = http.StatusFound
		http.Redirect(crw, r, aurl, status)
		return
	} else {
		if Config.Verbose > 0 {
			log.Printf("match checkAccessToken, attributes: %+v", attrs)
		}
	}

	// if user wants to renew token
	if r.URL.Path == fmt.Sprintf("%s/token/renew", Config.Base) {
		var token string
		sessLock.Lock()
		t := sess.Get("refreshToken")
		sessLock.Unlock()
		if t == nil { // cli request
			token = getToken(r)
		} else {
			token = t.(string)
		}
		tokenInfo, err := renewToken(token, r)
		if err != nil {
			msg := fmt.Sprintf("unable to refresh access token, %v", err)
			status = http.StatusInternalServerError
			http.Error(crw, msg, status)
			return
		}
		if Config.Verbose > 2 {
			printJSON(tokenInfo, "new token info")
		}
		if !strings.Contains(strings.ToLower(r.Header.Get("Accept")), "json") {
			crw.Write([]byte(tokenInfo.String()))
			return
		}
		data, err := json.Marshal(tokenInfo)
		if err != nil {
			msg := fmt.Sprintf("unable to marshal token info, %v", err)
			status = http.StatusInternalServerError
			http.Error(crw, msg, status)
			return
		}
		crw.Write(data)
		return
	}
	// if user wants to see token
	if r.URL.Path == fmt.Sprintf("%s/token", Config.Base) {
		var token, rtoken string
		sessLock.Lock()
		t := sess.Get("accessToken")
		rt := sess.Get("refreshToken")
		sessLock.Unlock()
		if t == nil { // cli request
			token = getToken(r)
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
		sessLock.Lock()
		if sess.Get("accessExpire") != nil {
			texp = sess.Get("accessExpire").(int64)
		}
		if sess.Get("refreshExpire") != nil {
			rtexp = sess.Get("refreshExpire").(int64)
		}
		sessLock.Unlock()
		tokenInfo := auth.TokenInfo{AccessToken: token, RefreshToken: rtoken, AccessExpire: texp, RefreshExpire: rtexp, IDToken: token}
		if !strings.Contains(strings.ToLower(r.Header.Get("Accept")), "json") {
			crw.Write([]byte(tokenInfo.String()))
			return
		}
		data, err := json.Marshal(tokenInfo)
		if err != nil {
			msg := fmt.Sprintf("unable to marshal token info, %v", err)
			status = http.StatusInternalServerError
			http.Error(w, msg, status)
			return
		}
		crw.Write(data)
		return
	}

	// fill out user data
	if userInfo != nil {
		// request through CERN SSO web interface which fills out user info
		// which we use to initialize user data
		switch t := userInfo.(type) {
		case *json.RawMessage:
			err := json.Unmarshal(*t, &userData)
			if err != nil {
				msg := fmt.Sprintf("unable to decode user data, %v", err)
				status = http.StatusInternalServerError
				http.Error(crw, msg, status)
				return
			}
		}
	} else {
		// in case of existing token CERN SSO or IAM we use token attributes as user data
		mapMutex.Lock()
		userData["email"] = attrs.Email
		userData["name"] = attrs.UserName
		userData["exp"] = attrs.Expiration
		mapMutex.Unlock()
	}
	// set id in user data based on token ClientID. The id will be used by SetCMSHeadersXXX calls
	mapMutex.Lock()
	userData["id"] = attrs.ClientID
	mapMutex.Unlock()

	// set CMS headers
	if Config.CMSHeaders {
		if Config.Verbose > 2 {
			if err := printJSON(userData, "user data"); err != nil {
				log.Println("unable to print user data")
			}
		}
		level := false
		if Config.Verbose > 3 {
			level = true
		}
		CMSAuth.SetCMSHeadersByKey(r, userData, cric.CricRecords, "id", "oauth", level)
		if Config.Verbose > 0 {
			printHTTPRequest(r, "cms headers")
		}

		// check if cms credentials are in place
		cmsLoginName := r.Header.Get("Cms-Authn-Login")
		cmsAuthCert := r.Header.Get("Cms-Auth-Cert")
		if cmsAuthCert == "" || cmsLoginName == "" {
			log.Printf("request headers %+v\n", r.Header)
			msg := fmt.Sprintf("not authorized access")
			status = http.StatusUnauthorized
			http.Error(crw, msg, status)
			return
		}
	}

	// for /auth path we simply return status ok
	if r.URL.Path == fmt.Sprintf("%s/auth", Config.Base) {
		crw.WriteHeader(http.StatusOK)
		return
	}

	// redirect HTTP requests
	redirect(crw, r)
}

// oauth server provides reverse proxy functionality with
// CERN SSO OAuth2 OICD authentication method
// It performs authentication of clients via internal callback function
// and redirects their requests to targetUrl of reverse proxy.
// If targetUrl is empty string it will redirect all request to
// simple hello page.
func oauthProxyServer() {

	// redirectURL defines where incoming requests will be redirected for authentication
	redirectURL := fmt.Sprintf("http://localhost:%d/callback", Config.Port)
	if Config.ServerCrt != "" {
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

	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", Config.Base), metricsHandler)
	// rules handler
	http.HandleFunc(fmt.Sprintf("%s/rules", Config.Base), rulesHandler)

	// start http server to serve metrics only
	if Config.MetricsPort > 0 {
		log.Println("Start oauth server metrics on port", Config.MetricsPort)
		go http.ListenAndServe(fmt.Sprintf(":%d", Config.MetricsPort), nil)
	}

	// the server settings handler
	http.HandleFunc(fmt.Sprintf("%s/server", Config.Base), settingsHandler)

	// the callback authentication handler
	http.HandleFunc(fmt.Sprintf("%s/callback", Config.Base), oauthCallbackHandler)

	// Only expose debug endpoints (pprof, expvar) if the client IP is allowed
	http.HandleFunc("/debug/", debugHandler)

	// the request handler
	http.HandleFunc("/", oauthRequestHandler)

	// start HTTPs server
	if Config.LetsEncrypt {
		server := LetsEncryptServer(Config.DomainNames...)
		log.Println("Start OAuth HTTPs server with LetsEncrypt", Config.DomainNames)
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		// check if provided crt/key files exists
		serverCrt := checkFile(Config.ServerCrt)
		serverKey := checkFile(Config.ServerKey)

		server, err := getServer(serverCrt, serverKey, false)
		if err != nil {
			log.Fatalf("unable to start oauth server, error %v\n", err)
		}
		log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
	}
}
