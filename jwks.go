package main

// https://github.com/pascaldekloe/jwt
// https://github.com/dgrijalva/jwt-go
// https://github.com/MicahParks/keyfunc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/pascaldekloe/jwt"

	jwtgo "github.com/dgrijalva/jwt-go"

	"github.com/MicahParks/keyfunc"
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

// JWKSBody holds content of JWKS body
var JWKSBody []byte

// PublicKey holds RSA public key
var PublicKey *rsa.PublicKey

// helper funciont to get JWKS body content
func getJWKS(rurl string) ([]byte, error) {
	var out []byte
	resp, err := http.Get(rurl)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}
	return body, err
}

// helper function to check given access token and return its claims
// it is based on github.com/dgrijalva/jwt-go and github.com/MicahParks/keyfunc go packages
func tokenClaims(accessToken string) (map[string]interface{}, error) {
	out := make(map[string]interface{})
	rurl := fmt.Sprintf("%s/protocol/openid-connect/certs", Config.OAuthURL)
	if JWKSBody == nil {
		body, err := getJWKS(rurl)
		if err != nil {
			return out, err
		}
		JWKSBody = body
	}
	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.New(JWKSBody)
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
func tokenClaims2(token string) (map[string]interface{}, error) {
	out := make(map[string]interface{})
	rurl := fmt.Sprintf("%s/protocol/openid-connect/certs", Config.OAuthURL)
	if PublicKey == nil {
		if JWKSBody == nil {
			body, err := getJWKS(rurl)
			if err != nil {
				return out, err
			}
			JWKSBody = body
		}
		var certs Certs
		err := json.Unmarshal(JWKSBody, &certs)
		if err != nil {
			return out, err
		}
		pub, err := getPublicKey(certs.Keys[0].E, certs.Keys[0].N)
		if err != nil {
			return out, err
		}
		PublicKey = pub
	}
	// verify a JWT
	claims, err := jwt.RSACheck([]byte(token), PublicKey)
	if err != nil {
		return out, err
	}
	if !claims.Valid(time.Now()) {
		msg := "The token is not valid"
		return out, errors.New(msg)
	}
	return claims.Set, nil
}
