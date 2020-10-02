package main

// https://gist.github.com/josemarjobs/23acc123b3cce1b251a5d5bafdca1140
// https://www.thepolyglotdeveloper.com/2017/03/authenticate-a-golang-api-with-json-web-tokens/
// https://github.com/dgrijalva/jwt-go
// https://godoc.org/github.com/dgrijalva/jwt-go#example-NewWithClaims--CustomClaimsType
// https://demo.scitokens.org/
// https://scitokens.org/
// https://github.com/scitokens/x509-scitokens-issuer/blob/master/tools/cms-scitoken-init.go
// https://github.com/scitokens/scitokens

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// SciTokensSconfig represents configuration of scitokens service
type ScitokensConfig struct {
	FileGlog  string `json:"CONFIG_FILE_GLOB"`
	Lifetime  int    `json:"LIFETIME"`
	IssuerKey string `json:"ISSUER_KEY"`
	Rules     string `json:"RULES"`
	DNMapping string `json:"DN_MAPPING"`
	CMS       bool   `json:"CMS"`
	Verbose   bool   `json:"VERBOSE"`
	Enabled   bool   `json:"ENABLED"`
	Secret    string `json:"SECRET"`
}

var scitokensConfig ScitokensConfig

// TokenResponse rerpresents structure of returned scitoken
type TokenResponse struct {
	AccessToken string `json:"access_token"` // access token string
	TokenType   string `json:"token_type"`   // token type string
	Expires     int64  `json:"expires_in"`   // token expiration
	Scopes      string `json:"scopes"`       // specific scopes
	Sub         string `json:"sub"`          // either user name or DN
}

// helper function to handle http server errors
func handleError(w http.ResponseWriter, r *http.Request, rec map[string]string) {
	log.Printf("error %+v\n", rec)
	data, err := json.Marshal(rec)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("unable to marshal data, error=%v", err)))
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Write(data)
}

// helper function to generate scopes and user fields
func generateScopesUser(entries []string) ([]string, string) {
	var scopes []string
	var user string
	return scopes, user
}

// scitokensHandler handle requests for x509 clients
func scitokensHandler(w http.ResponseWriter, r *http.Request) {
	errRecord := make(map[string]string)
	err := r.ParseForm()
	if err != nil {
		log.Printf("could not parse http form, error %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		errRecord["error"] = fmt.Sprintf("Incorrect grant_type %s", grantType)
		handleError(w, r, errRecord)
		return
	}
	// get scopes
	var scopes []string
	for _, s := range strings.Split(r.FormValue("scopes"), " ") {
		scopes = append(scopes, strings.Trim(s, " "))
	}
	// defaults
	creds := make(map[string]string)
	// TODO: fill out creds with dn, username, fqan obtained from x509 call

	dn := ""
	//     pattern := "GRST_CRED_AURI_"
	//     if scitokensConfig.CMS {
	//         pattern = "HTTP_CMS_AUTH"
	//     }
	// entries should be read from server environment, e.g. in apache we have
	// HTTP_CMS_AUTH, CMS_LOGIN, CMS_DN headers
	var entries []string
	if dn == "" {
		errRecord["error"] = fmt.Sprintf("No client certificate or proxy used for TLS authentication")
		handleError(w, r, errRecord)
		return
	}
	scopes, user := generateScopesUser(entries)
	if scitokensConfig.Verbose {
		log.Printf("creds %+v", creds)
		log.Printf("entries %+v", entries)
		log.Printf("scopes %+v", scopes)
		log.Printf("user %+v", user)
	}
	// Compare the generated scopes against the requested scopes (if given)
	// If we don't give the user everything they want, then we
	// TODO: parse scopes

	if len(scopes) == 0 {
		errRecord["error"] = "No applicable scopes for this user"
		handleError(w, r, errRecord)
		return
	}
	// generate new token and return it back to user
	sub := dn
	if user != "" {
		sub = user
	}
	expires := time.Now().Add(time.Minute * time.Duration(scitokensConfig.Lifetime)).Unix()
	var issuer, kid string
	token, err := getSciToken(issuer, kid, sub)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("unable to get token, error=%v", err)))
		return
	}
	resp := TokenResponse{AccessToken: token, TokenType: "bearer", Expires: expires, Scopes: strings.Join(scopes, " ")}
	data, err := json.Marshal(resp)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("unable to marshal data, error=%v", err)))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ScitokensClaims represent structure of scitokens claims
type ScitokensClaims struct {
	Foo string `json:"foo"` // TODO: replace with scitokens claim attributes
	jwt.StandardClaims
}

// helper function to get scitoken
func getSciToken(issuer, kid, sub string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	expires := time.Now().Add(time.Minute * time.Duration(scitokensConfig.Lifetime)).Unix()
	claims := ScitokensClaims{
		"bar",
		jwt.StandardClaims{
			ExpiresAt: expires,
			Issuer:    issuer,
			Id:        kid,
			Subject:   sub,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//     token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	//         "iss":    "admin",
	//         "iat":    "",
	//         "jti":    "",
	//         "nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	//         "exp":    time.Now().Add(time.Minute * 20).Unix(),
	//         "issuer": key,
	//         "id":     kid,
	//     })

	secret := []byte(scitokensConfig.Secret)
	tokenString, err := token.SignedString(secret)
	return tokenString, err
}

// helper function to start scitokens server
func scitokensServer() {
	// check if provided crt/key files exists
	serverCrt := checkFile(Config.ServerCrt)
	serverKey := checkFile(Config.ServerKey)

	// the server settings handler
	http.HandleFunc(fmt.Sprintf("%s/server", Config.Base), settingsHandler)
	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", Config.Base), metricsHandler)

	// the request handler
	http.HandleFunc("/token", scitokensHandler)

	// start HTTPS server
	server, err := getServer(serverCrt, serverKey, true)
	if err != nil {
		log.Fatalf("unable to start scitokens server, error %v\n", err)
	}
	log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
}
