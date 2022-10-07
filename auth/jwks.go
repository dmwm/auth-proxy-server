package auth

// https://github.com/pascaldekloe/jwt
// https://github.com/dgrijalva/jwt-go
// https://github.com/golang-jwt/jwt
// https://github.com/MicahParks/keyfunc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/pascaldekloe/jwt"
	//     jwtgo "github.com/dgrijalva/jwt-go"
	//     "github.com/MicahParks/keyfunc"
)

// JWKSKeys struct represent structure of JWKS Keys
type Keys struct {
	Kid     string   `json:"kid"`
	Kty     string   `json:"kty"`
	Alg     string   `json:"alg"`
	Use     string   `json:"use"`
	N       string   `json:"n"`
	E       string   `json:"e"`
	X5c     []string `json:"x5c"`
	X5y     string   `json:"x5y"`
	Xt5S256 string   `json:"x5t#S256"`
}

// Certs represents structure of JWKS uri
type Certs struct {
	Keys []Keys
}

// OpenIDConfiguration holds configuration for OpenID Provider
type OpenIDConfiguration struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	ClaimsSupported       []string `json:"claims_supported"`
	ScopeSupported        []string `json:"scopes_supported"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
}

type publicKey struct {
	key *rsa.PublicKey // RSA public key
	kid string         // Key Id
}

// Provider holds all information about given provider
type Provider struct {
	URL           string              // provider url
	Configuration OpenIDConfiguration // provider OpenID configuration
	PublicKeys    []publicKey         // Public keys of the provider
	JWKSBody      []byte              // jwks body content of the provider
}

// String provides string representation of provider
func (p *Provider) String() string {
	data, err := json.MarshalIndent(p, "", "    ")
	if err != nil {
		return fmt.Sprintf("Provider, error=%v", err)
	}
	return string(data)
}

// Init function initialize provider configuration
func (p *Provider) Init(purl string, verbose int) error {
	resp, err := http.Get(fmt.Sprintf("%s/.well-known/openid-configuration", purl))
	if err != nil {
		log.Println("unable to contact ", purl, " error ", err)
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("unable to read body of HTTP response ", err)
		return err
	}
	var conf OpenIDConfiguration
	err = json.Unmarshal(body, &conf)
	if err != nil {
		log.Println("unable to unmarshal body of HTTP response ", err)
		return err
	}
	p.URL = purl
	p.Configuration = conf
	if verbose > 0 {
		log.Println("provider configuration", conf)
	}

	// obtain public key for our OpenID provider, for that we send
	// HTTP request to jwks_uri, fetch cert information and decode its public key
	resp2, err := http.Get(p.Configuration.JWKSUri)
	if err != nil {
		log.Println("unable to contact ", p.Configuration.JWKSUri, " error ", err)
		return err
	}
	defer resp2.Body.Close()
	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		log.Println("unable to read body of HTTP response ", err)
		return err
	}
	var certs Certs
	err = json.Unmarshal(body2, &certs)
	if err != nil {
		log.Println("unable to unmarshal body of HTTP response ", err)
		return err
	}
	p.JWKSBody = body2
	for _, key := range certs.Keys {
		exp := key.E   // exponent
		mod := key.N   // modulus
		kty := key.Kty // kty attribute
		if strings.ToLower(kty) != "rsa" {
			msg := fmt.Sprintf("not RSA kty key: %s", kty)
			log.Println(msg)
			return errors.New(msg)
		}
		pub, err := getPublicKey(exp, mod)
		if err != nil {
			log.Println("unable to get public key ", err)
			return err
		}
		p.PublicKeys = append(p.PublicKeys, publicKey{pub, key.Kid})
	}
	if verbose > 0 {
		log.Println("\n", p.String())
	}
	return nil
}

/*
// helper function to check given access token and return its claims
// it is based on github.com/dgrijalva/jwt-go and github.com/MicahParks/keyfunc go packages
func tokenClaims(provider Provider, accessToken string) (map[string]interface{}, error) {
	out := make(map[string]interface{})
	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.New(provider.JWKSBody)
	if err != nil {
		return out, err
	}
	// Parse the JWT.
	token, err := jwtgo.Parse(accessToken, jwks.KeyFunc)
	if err != nil {
		return out, err
	}

	// Check if the token is valid.
	if !token.Valid {
		msg := "The token is not valid"
		return out, errors.New(msg)
	}
	if claims, ok := token.Claims.(jwtgo.MapClaims); ok {
		for k, v := range claims {
			out[k] = v
		}
	}
	return out, nil
}
*/

// helper function to get RSA public key from given exponent and modulus
// it is based on implementation of
// https://github.com/MicahParks/keyfunc/blob/master/rsa.go
func getPublicKey(exp, mod string) (*rsa.PublicKey, error) {
	// Decode the exponent from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	var exponent []byte
	var err error
	if exponent, err = base64.RawURLEncoding.DecodeString(exp); err != nil {
		return nil, err
	}

	// Decode the modulus from Base64.
	var modulus []byte
	if modulus, err = base64.RawURLEncoding.DecodeString(mod); err != nil {
		return nil, err
	}

	// Create the RSA public key.
	publicKey := &rsa.PublicKey{}

	// Turn the exponent into an integer.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	publicKey.E = int(big.NewInt(0).SetBytes(exponent).Uint64())

	// Turn the modulus into a *big.Int.
	publicKey.N = big.NewInt(0).SetBytes(modulus)

	return publicKey, nil
}

// helper function to check access token and return claims map based on
// github.com/pascaldekloe/jwt go package
func tokenClaims(provider Provider, token string) (map[string]interface{}, error) {
	out := make(map[string]interface{})
	// First parse without checking signature, to get the Kid
	claims, err := jwt.ParseWithoutCheck([]byte(token))
	log.Println("ParseWithoutCheck returns %v", err)
	if err != nil {
		return out, err
	}
	var pub *rsa.PublicKey
	for _, pubkey := range provider.PublicKeys {
		if claims.KeyID == pubkey.kid {
			pub = pubkey.key
			break
		}
	}
	if pub == nil {
		return out, fmt.Errorf("key id %s not found", claims.KeyID)
	}
	// verify a JWT
	claims, err = jwt.RSACheck([]byte(token), pub)
	if err != nil {
		return out, err
	}
	if !claims.Valid(time.Now()) {
		msg := "The token is not valid"
		return out, errors.New(msg)
	}
	for k, v := range claims.Set {
		out[k] = v
	}
	t := claims.Registered.Expires.Time()
	out["exp"] = t.Unix()
	out["sub"] = claims.Subject
	out["iss"] = claims.Issuer
	out["aud"] = claims.Audiences
	return out, nil
}
