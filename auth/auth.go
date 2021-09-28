package auth

import (
	"errors"
	"fmt"
	"log"
	"strings"
)

// OAuthProviders contains maps of all participated providers
var OAuthProviders map[string]Provider

// TokenAttributes contains structure of access token attributes
type TokenAttributes struct {
	Subject      string `json:"sub"`           // token subject
	Audiences    string `json:"aud"`           // token audience
	Issuer       string `json:"iss"`           // token issuer
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

// Init initializes map of OAuth providers
func Init(providers []string, verbose int) {
	OAuthProviders = make(map[string]Provider)
	for _, purl := range providers {
		if verbose > 0 {
			log.Println("initialize provider ", purl)
		}
		p := Provider{}
		err := p.Init(purl, verbose)
		if err != nil {
			log.Fatalf("fail to initialize %s error %v", p.URL, err)
		}
		OAuthProviders[purl] = p
	}
}

// InspectTokenProviders inspects token against all participated providers and return
// TokenAttributes
func InspectTokenProviders(token string, providers []string, verbose int) (TokenAttributes, error) {
	for _, purl := range providers {
		if p, ok := OAuthProviders[purl]; ok {
			attrs, err := InspectToken(p, token, verbose)
			if err == nil {
				if verbose > 0 {
					log.Println("token is validated with provider ", purl)
				}
				return attrs, nil
			} else {
				log.Println("provider", p.URL, " token error ", err)
			}
		}
	}
	msg := fmt.Sprintf("Token is not valid with participated providers: %v", providers)
	return TokenAttributes{}, errors.New(msg)
}

// InspectToken extracts token attributes
func InspectToken(provider Provider, token string, verbose int) (TokenAttributes, error) {
	var attrs TokenAttributes
	claims, err := tokenClaims(provider, token)
	if err != nil {
		return attrs, err
	}
	if verbose > 1 {
		log.Println("token claims", claims)
	}
	for k, v := range claims {
		if k == "email" {
			attrs.Email = fmt.Sprintf("%v", v)
		}
		if k == "cern_upn" || k == "preferred_username" {
			attrs.UserName = fmt.Sprintf("%v", v)
		}
		if k == "client_id" {
			attrs.ClientID = fmt.Sprintf("%v", v)
		}
		if k == "cern_person_id" {
			attrs.ClientID = fmt.Sprintf("%v", v)
		}
		if k == "session_state" {
			attrs.SessionState = fmt.Sprintf("%v", v)
		}
		if k == "exp" {
			switch val := v.(type) {
			case float64:
				attrs.Expiration = int64(val)
			case int64:
				attrs.Expiration = val
			}
		}
		if k == "scope" {
			attrs.Scope = fmt.Sprintf("%v", v)
		}
		if k == "sub" {
			attrs.Subject = fmt.Sprintf("%v", v)
		}
		if k == "iss" {
			attrs.Issuer = fmt.Sprintf("%v", v)
		}
		if k == "aud" {
			attrs.Audiences = fmt.Sprintf("%v", v)
		}
		if k == "cern_roles" {
			s := fmt.Sprintf("%v", v)
			s = strings.Replace(s, "[", "", -1)
			s = strings.Replace(s, "]", "", -1)
			attrs.Scope = s
		}
	}
	attrs.Active = true
	if verbose > 1 {
		log.Printf("token attributes %+v\n", attrs)
	}
	return attrs, err
}

/*
// Example of usage:
func main() {
	var token string
	flag.StringVar(&token, "token", "", "token")
	var purl string
	flag.StringVar(&purl, "purl", "", "provider url")
	flag.Parse()
	verbose := 2
	provider := Provider{}
	err := provider.Init(purl, verbose)
	if err != nil {
		log.Fatalf("fail to initialize %s error %v", provider.URL, err)
	}
	attrs, err := InspectToken(provider, token, verbose)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("attributes %+v", attrs)
}
*/
