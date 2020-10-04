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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

// SciTokensSconfig represents configuration of scitokens service
type ScitokensConfig struct {
	FileGlog   string `json:"file_glob"`  // file glob
	Lifetime   int    `json:"lifetime"`   // lifetime of token
	IssuerKey  string `json:"issuer_key"` // issuer key
	Issuer     string `json:"issuer"`     // issuer hostname
	Rules      string `json:"rules"`      // rules file
	DNMapping  string `json:"dn_mapping"` // dn mapping
	CMS        bool   `json:"cms"`        // use cms
	Verbose    bool   `json:"verbose"`    // verbosity mode
	Enabled    bool   `json:"enabled"`    // enable
	Secret     string `json:"secret"`     // secret
	PrivateKey string `json:"rsa_key"`    // RSA private key to use
}

var scitokensConfig ScitokensConfig

// TokenResponse rerpresents structure of returned scitoken
type TokenResponse struct {
	AccessToken string `json:"access_token"` // access token string
	TokenType   string `json:"token_type"`   // token type string
	Expires     int64  `json:"expires_in"`   // token expiration
}

// helper function to handle http server errors
func handleError(w http.ResponseWriter, r *http.Request, rec map[string]string) {
	log.Println(Stack())
	log.Printf("error %+v\n", rec)
	data, err := json.Marshal(rec)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("unable to marshal data, error=%v", err)))
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	w.Write(data)
}

// helper function to generate UUID
func genUUID() string {
	uuidWithHyphen := uuid.New()
	return uuidWithHyphen.String()
}

// helper function to get user scopes
// should in a form of "write:/store/user/username read:/store"
func getScopes(r *http.Request, userData map[string]interface{}) []string {
	var scopes []string
	//     for _, s := range strings.Split(r.FormValue("scopes"), " ") {
	//         scopes = append(scopes, strings.Trim(s, " "))
	//     }
	scopes = append(scopes, "read:/protected")
	// Compare the generated scopes against the requested scopes (if given)
	// If we don't give the user everything they want, then we
	// TODO: parse roles and creat scopes
	//     if roles, ok := userData["roles"]; ok {
	//         rmap := roles.(map[string][]string)
	//         for k, _ := range rmap {
	//             scopes = append(scopes, k)
	//         }
	//     } else {
	//         errRecord["error"] = "No applicable roles found"
	//         handleError(w, r, errRecord)
	//         return
	//     }
	return scopes
}

// helper function to get issuer
func getIssuer(r *http.Request) string {
	// get hostname from http Request if not provided use hostname
	// or get issuer from userData
	// issuer should be hostname of our server
	//     var issuer string
	//     if v, ok := userData["issuer"]; ok {
	//         issuer = v.(string)
	//     }
	issuer := scitokensConfig.Issuer
	if issuer == "" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatal(err)
		}
		return hostname
	}
	return issuer
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
	// getch user data from our request
	userData := getUserData(r)
	if Config.Verbose > 0 {
		log.Printf("user data %+v\n", userData)
	}

	// get token attribute values: issuer, jti, sub, scopes
	issuer := getIssuer(r)
	jti := genUUID()
	scopes := getScopes(r, userData)
	if len(scopes) == 0 {
		errRecord["error"] = "No applicable scopes for this user"
		handleError(w, r, errRecord)
		return
	}
	var sub string
	if v, ok := userData["cern_upn"]; ok {
		sub = v.(string)
	} else {
		errRecord["error"] = fmt.Sprintf("No CMS credentials found in TLS authentication")
		handleError(w, r, errRecord)
		return
	}

	// generate new token and return it back to user
	expires := time.Now().Add(time.Minute * time.Duration(scitokensConfig.Lifetime)).Unix()
	token, err := getSciToken(issuer, jti, sub, strings.Join(scopes, " "))
	if err != nil {
		w.Write([]byte(fmt.Sprintf("unable to get token, error=%v", err)))
		return
	}
	resp := TokenResponse{AccessToken: token, TokenType: "bearer", Expires: expires}
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
	Scope   string `json:"scope"` // user's scopes
	Version string `json:"ver"`   // version string
	jwt.StandardClaims
}

// helper function to generate RSA key
// Generate RSA key as following
// openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt
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
		block, _ := pem.Decode([]byte(pemString))
		// use RSA normal encoded key
		//         key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		// use RSA PKCS#8 encoded key
		parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		key := parseResult.(*rsa.PrivateKey)
		return key, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	return key, err
}

/*
// helper function to get scitoken, it is based on
// github.com/cristalhq/jwt/v3
func getSciToken(issuer, jti, sub, scopes string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	expires := jwt.NewNumericDate(time.Now().Add(time.Minute * time.Duration(scitokensConfig.Lifetime)))
	now := jwt.NewNumericDate(time.Now())
	iat := jwt.NewNumericDate(time.Now())
	// for definitions see
	// https://godoc.org/github.com/dgrijalva/jwt-go#StandardClaims
	// https://tools.ietf.org/html/rfc7519#section-4.1
	claims := ScitokensClaims{
		scopes,
		jwt.StandardClaims{
			ExpiresAt: expires, // exp
			Issuer:    issuer,  // iss
			IssuedAt:  iat,     // iat
			ID:        jti,     // jti
			Subject:   sub,     // sub
			NotBefore: now,     // nbf
		},
	}
	//     fname := "/some/path/id_rsa"
	fname := ""
	key, err := getRSAKey(fname)
	signer, err := jwt.NewSignerRS(jwt.RS256, key)
	if err != nil {
		log.Fatal(err)
	}
	builder := jwt.NewBuilder(signer)
	token, err := builder.Build(claims)
	tokenString := token.String()
	return tokenString, err
}
*/

// helper function to get scitoken
func getSciToken(issuer, jti, sub, scopes string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	expires := time.Now().Add(time.Minute * time.Duration(scitokensConfig.Lifetime)).Unix()
	now := time.Now().Unix()
	iat := now
	version := "scitoken:2.0"
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
	fname := scitokensConfig.PrivateKey
	key, err := getRSAKey(fname)
	if err != nil {
		log.Fatal(err)
	}

	//     token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//     secret := []byte(scitokensConfig.Secret)
	//     tokenString, err := token.SignedString(secret)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if _, ok := token.Header["kid"]; !ok {
		token.Header["kid"] = "key-rs256"
	}
	tokenString, err := token.SignedString(key)
	return tokenString, err
}

// helper function to start scitokens server
func scitokensServer() {
	// check if provided crt/key files exists
	serverCrt := checkFile(Config.ServerCrt)
	serverKey := checkFile(Config.ServerKey)

	// the server settings handler
	base := Config.Base
	http.HandleFunc(fmt.Sprintf("%s/server", base), settingsHandler)
	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", base), metricsHandler)
	// static content
	http.Handle(fmt.Sprintf("%s/.well-known/", base), http.StripPrefix(base+"/.well-known/", http.FileServer(http.Dir(Config.WellKnown))))

	// the request handler
	http.HandleFunc(fmt.Sprintf("%s/token", base), scitokensHandler)

	// start HTTPS server
	server, err := getServer(serverCrt, serverKey, true)
	if err != nil {
		log.Fatalf("unable to start scitokens server, error %v\n", err)
	}
	log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
}
