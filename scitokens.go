package main

// scitokens module provides CMS scitokens server implementation based on CRIC records
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//
// List of supplemental materials
// Scitokens docs:
// https://scitokens.org/
// https://demo.scitokens.org/
// https://github.com/scitokens/x509-scitokens-issuer/blob/master/tools/cms-scitoken-init.go
// https://github.com/scitokens/scitokens
//
// JWT docs:
// https://gist.github.com/josemarjobs/23acc123b3cce1b251a5d5bafdca1140
// https://www.thepolyglotdeveloper.com/2017/03/authenticate-a-golang-api-with-json-web-tokens/
// https://github.com/dgrijalva/jwt-go
// https://godoc.org/github.com/dgrijalva/jwt-go#example-NewWithClaims--CustomClaimsType

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	// jwt "github.com/cristalhq/jwt/v3"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// server private/public keys to be used for signing
var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

// PublicJWKS represents public structure of jwks keys
type PublicJWKS struct {
	Keys []PublicJWKSKey
}

// PublicJWKSKey represents public jwks key
type PublicJWKSKey struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	Use string `json:"use"`
}

// server variable to hold public jwks key
var publicJWKSkey PublicJWKSKey

// helper function to handle http server errors
func handleError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	log.Println(Stack())
	rec := ErrorRecord{Error: msg}
	log.Printf("error %+v\n", rec)
	data, err := json.Marshal(rec)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("unable to marshal data, error=%v", err)))
		return
	}
	w.WriteHeader(code)
	w.Write(data)
}

// helper function to generate UUID
func genUUID() string {
	uuidWithHyphen := uuid.New()
	return uuidWithHyphen.String()
}

// helper function to get user scopes
// should in a form of "write:/store/user/<username> read:/store"
func getScopes(r *http.Request, userData map[string]interface{}) []string {
	var scopes []string
	var username string
	if u, ok := userData["cern_upn"]; ok {
		username = u.(string)
	}
	var userDN string
	if u, ok := userData["dn"]; ok {
		userDN = u.(string)
	}

	// loop over scitokens rules and construct user's scopes
	for _, rule := range Config.Scitokens.Rules {
		var rulesScopes []string
		if strings.HasPrefix(rule.Match, "fqan:/cms") {
			rulesScopes = rule.Scopes
		} else if strings.HasPrefix(rule.Match, "dn:") {
			userRuleDN := strings.Replace(rule.Match, "dn:", "", -1)
			if userRuleDN == userDN {
				rulesScopes = rule.Scopes
			}
		}
		for _, s := range rulesScopes {
			s = strings.Replace(strings.Trim(s, " "), "{username}", username, -1)
			if !InList(s, scopes) {
				scopes = append(scopes, s)
			}
		}
	}
	if len(scopes) == 0 {
		scopes = append(scopes, "read:/protected")
	}
	return scopes
}

// helper function to get issuer
func getIssuer(r *http.Request) (string, string) {
	issuer := Config.Scitokens.Issuer
	if issuer == "" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatal(err)
		}
		kid := ""
		return hostname, kid
	}
	// read kid from issuer_public.jwks file
	kid := ""
	rec, err := readPublicJWKS(Config.Scitokens.PublicJWKS)
	if err == nil {
		kid = rec.Kid
	}
	return issuer, kid
}

// read public JWKS data
func readPublicJWKS(fname string) (PublicJWKSKey, error) {
	var p PublicJWKSKey
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Printf("unable to read, file: %s, error: %v\n", fname, err)
		return p, err
	}
	var rec PublicJWKS
	err = json.Unmarshal(data, &rec)
	if err != nil {
		log.Printf("unable to parse, file: %s, error: %v\n", fname, err)
		return p, err
	}
	return rec.Keys[0], nil
}

// scitokensHandler handle requests for x509 clients
func scitokensHandler(w http.ResponseWriter, r *http.Request) {
	// record all events
	start := time.Now()
	status := http.StatusOK
	tstamp := int64(start.UnixNano() / 1000000) // use milliseconds for MONIT
	defer logRequest(w, r, start, "scitokens", &status, tstamp)

	err := r.ParseForm()
	if err != nil {
		log.Printf("could not parse http form, error %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		msg := fmt.Sprintf("Incorrect grant_type '%s'", grantType)
		handleError(w, r, msg, http.StatusForbidden)
		return
	}
	// fetch user data from our request
	userData := getUserData(r)

	// get token attribute values: issuer, jti, sub, scopes
	issuer, kid := getIssuer(r)
	jti := genUUID()
	scopes := getScopes(r, userData)
	if len(scopes) == 0 {
		msg := "No applicable scopes for this user"
		handleError(w, r, msg, http.StatusForbidden)
		return
	}
	var sub string
	if v, ok := userData["cern_upn"]; ok {
		sub = v.(string)
	} else {
		msg := fmt.Sprintf("No CMS credentials found in TLS authentication")
		handleError(w, r, msg, http.StatusForbidden)
		return
	}

	// generate new token and return it back to user
	expires := time.Now().Add(time.Minute * time.Duration(Config.Scitokens.Lifetime)).Unix()
	token, err := getSciToken(issuer, kid, jti, sub, strings.Join(scopes, " "))
	if err != nil {
		w.Write([]byte(fmt.Sprintf("unable to get token, error=%v", err)))
		return
	}
	resp := TokenResponse{AccessToken: token, TokenType: "bearer", Expires: expires}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("unable to marshal token response, error=%v", err)))
		return
	}
}

// ScitokensClaims represent structure of scitokens claims
type ScitokensClaims struct {
	Scope   string `json:"scope"` // user's scopes
	Version string `json:"ver"`   // version string
	jwt.StandardClaims
}

// helper function to generate RSA key
// Generate RSA key as following
// PKC8 key
// openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt > /tmp/issuer.pem
// scitokens key
// scitokens-admin-create-key --create-keys --pem-private --pem-public > /tmp/issuer.pem
func getRSAKey(fname string) (*rsa.PrivateKey, error) {
	if fname != "" {
		file, err := os.Open(fname)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		pemString, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}
		// https://stackoverflow.com/questions/44230634/how-to-read-an-rsa-key-from-file
		// read block of bytes related to the key but we are not interested in reminder of the input
		block, _ := pem.Decode([]byte(pemString))
		if err != nil {
			log.Fatal(err)
		}
		// use RSA normal encoded key
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			return key, err
		}
		log.Println("unable to ParsePKCS1PrivateKey", fname, err)
		// try out RSA PKCS#8 encoded key
		parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			key = parseResult.(*rsa.PrivateKey)
			return key, err
		}
		log.Fatal("unable to ParsePKCS8PrivateKey", fname, err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	return key, err
}

// helper function to get scitoken
func getSciToken(issuer, kid, jti, sub, scopes string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	expires := time.Now().Add(time.Minute * time.Duration(Config.Scitokens.Lifetime)).Unix()
	now := time.Now().Unix()
	iat := now
	version := "scitoken:2.0"
	if Config.Scitokens.Version != "" {
		version = Config.Scitokens.Version
	}
	// for definitions see
	// https://godoc.org/github.com/dgrijalva/jwt-go#StandardClaims
	// https://tools.ietf.org/html/rfc7519#section-4.1
	claims := ScitokensClaims{
		scopes, version,
		jwt.StandardClaims{
			ExpiresAt: expires, // exp
			Issuer:    issuer,  // iss
			IssuedAt:  iat,     // iat
			Id:        jti,     // jti
			Subject:   sub,     // sub
			NotBefore: now,     // nbf
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if _, ok := token.Header["kid"]; !ok {
		if kid == "" {
			token.Header["kid"] = "key-rs256"
		} else {
			token.Header["kid"] = kid
		}
	}
	tokenString, err := token.SignedString(privateKey)
	return tokenString, err
}

// helper function to validate token
func validateToken(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return publicKey, nil
}

// validateJWT validate given JWT
func validateJWT(w http.ResponseWriter, r *http.Request) (jwt.Claims, error) {
	var jwtClaims jwt.Claims

	// get token from HTTP header
	bearToken := r.Header.Get("Authorization")

	// normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	var tokenString string
	if len(strArr) == 2 {
		tokenString = strArr[1]
	} else {
		return jwtClaims, errors.New("invalid token header")
	}

	// validate JWT token
	parser := new(jwt.Parser)
	token, err := parser.ParseWithClaims(tokenString, &ScitokensClaims{}, validateToken)
	if err != nil {
		return jwtClaims, fmt.Errorf("unable to parse JWT token, error: %v", err)
	}
	tokenClaims, ok := token.Claims.(jwt.Claims)

	if !ok && !token.Valid {
		return jwtClaims, errors.New("invalid token")
	}
	return tokenClaims, nil
}

// validateHandler validate given JWT
func validateHandler(w http.ResponseWriter, r *http.Request) {
	jwtClaims, err := validateJWT(w, r)
	if err != nil {
		handleError(w, r, fmt.Sprintf("%v", err), http.StatusUnauthorized)
		return
	}
	if err := json.NewEncoder(w).Encode(jwtClaims); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("unable to marshal jwt claims, error=%v", err)))
		return
	}
}

// helper function to start scitokens server
func scitokensServer() {
	// check if provided crt/key files exists
	serverCrt := checkFile(Config.ServerCrt)
	serverKey := checkFile(Config.ServerKey)

	// initialize server private/public RSA keys to be used for signing
	fname := Config.Scitokens.PrivateKey
	key, err := getRSAKey(fname)
	if err != nil {
		log.Fatal(err)
	}
	privateKey = key
	publicKey = &privateKey.PublicKey

	// read jwks record
	publicJWKSkey, err = readPublicJWKS(Config.Scitokens.PublicJWKS)

	// the server settings handler
	base := Config.Base
	http.HandleFunc(fmt.Sprintf("%s/server", base), settingsHandler)
	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", base), metricsHandler)
	// static content
	http.Handle(fmt.Sprintf("%s/.well-known/", base), http.StripPrefix(base+"/.well-known/", http.FileServer(http.Dir(Config.WellKnown))))

	// the HTTP handlers
	http.HandleFunc(fmt.Sprintf("%s/token", base), scitokensHandler)
	http.HandleFunc(fmt.Sprintf("%s/validate", base), validateHandler)
	if base == "" {
		base = "/"
	}
	http.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		_, err := validateJWT(w, r)
		if err != nil {
			handleError(w, r, fmt.Sprintf("%v", err), http.StatusForbidden)
			return
		}
		redirect(w, r)
	})

	// start HTTPS server
	server, err := getServer(serverCrt, serverKey, true)
	if err != nil {
		log.Fatalf("unable to start scitokens server, error %v\n", err)
	}
	log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
}
