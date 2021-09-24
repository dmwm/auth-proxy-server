package main

// iam module provides IAM implementation
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// IAMRenewInterval represent renewal interval for IAMUsers
var IAMRenewInterval time.Duration

// IAMEmail represents email structure
type IAMEmail struct {
	Type    string
	Value   string
	Primary bool
}

// IAMGroup represents group structure
type IAMGroup struct {
	Display string
	Value   string
	Ref     string `json:"$ref"`
}

// IAMLabel represents label structure
type IAMLabel struct {
	Prefix string
	Name   string
	Value  string
}

// IAMCertificate represents certificate structure
type IAMCertificate struct {
	Primary             bool
	SubjectDN           string `json:"subjectDn"`
	IssuerDN            string `json:"issuerDn"`
	Display             string
	Created             string
	LastModified        string `json:"lastModified"`
	HasProxyCertificate bool   `json:"hasProxyCertificate"`
}

// IAMIndigoUser represents indigo user structure
type IAMIndigoUser struct {
	Labels       []IAMLabel
	Certificates []IAMCertificate
}

// IAMMeta represents meta structure
type IAMMeta struct {
	Created      string
	LastModified string `json:"lastModified"`
	Location     string
	ResourceType string `json:"resourceType"`
}

// IAMUser represents IAM user information used by auth proxy server
type IAMUser struct {
	ID          string            `json:"id"`
	Meta        IAMMeta           `json:"meta"`
	Schemas     []string          `json:"schemas"`
	UserName    string            `json:"userName"`
	Name        map[string]string `json:"name"`
	DisplayName string            `json:"displayName"`
	Active      bool
	Emails      []IAMEmail
	Groups      []IAMGroup
	IndigoUser  IAMIndigoUser `json:"urn:indigo-dc:scim:schemas:IndigoUser"`
}

// IAMUserManager holds IAMUser info in its cache
type IAMUserManager struct {
	URL          string    // IAM URL, e.g. https://cms-auth.web.cern.ch
	ClientID     string    // IAM client id
	ClientSecret string    // IAM client secret
	Users        []IAMUser // IAM user list
	Expire       time.Time // expiration time stamp
	Verbose      int       // verbose level
}

// GetUsers returns list of IAM users info
func (m *IAMUserManager) GetUsers() ([]IAMUser, error) {
	var lock = sync.Mutex{}
	lock.Lock()
	defer lock.Unlock()
	// we'll use existing certs if our window is not expired
	if m.Users == nil || time.Since(m.Expire) > IAMRenewInterval {
		token, err := IAMToken(m.URL, m.ClientID, m.ClientSecret, m.Verbose)
		if err != nil {
			log.Println("unable to obtain IAM token", err)
			return m.Users, err
		}
		if m.Verbose > 0 {
			log.Println("IAM token", token)
		}
		users, err := IAMUsers(m.URL, token, m.Verbose)
		if err != nil {
			log.Println("unable to get IAM users info", err)
		}
		m.Users = users
		m.Expire = time.Now()

	}
	return m.Users, nil
}

// IAMTokenResponse
type IAMTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// IAMToken returns access token from IAM provider for given client ID/Secret fields
func IAMToken(rurl, cid, secret string, verbose int) (string, error) {
	// place the following call to IAM provider URL
	// curl -k -u "${CLIENT_ID}:${CLIENT_SECRET}" -dgrant_type=client_credentials https://cms-auth.web.cern.ch/token
	rurl = fmt.Sprintf("%s/token", rurl)
	if verbose > 0 {
		log.Println("iam query", rurl)
	}
	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	//     form.Add("client_id", cid)
	//     form.Add("client_secret", secret)
	req, err := http.NewRequest("POST", rurl, strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("Unable to make GET request to %s, error: %s", rurl, err)
		return "", err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cid, secret)
	if verbose > 1 {
		dump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			log.Println("request: ", string(dump))
		}
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Unable to get response from %s, error: %s", rurl, err)
		return "", err
	}
	if verbose > 1 {
		dump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			log.Println("response:", string(dump))
		}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("unable to read response body", err)
		return "", err
	}
	var rec IAMTokenResponse
	err = json.Unmarshal(data, &rec)
	if err != nil {
		log.Println("unable to unmarshall reponse body", err)
		return "", err
	}
	if verbose > 1 {
		log.Println("response", rec)
	}
	return rec.AccessToken, nil
}

// IAMResponse represents IAM scim users response
type IAMScimResponse struct {
	TotalResults int `json:"totalResults"`
	ItemsPerPage int `json:"itemsPerPage`
	StartIndex   int `json:"startIndex"`
	Resources    []IAMUser
}

// IAMUsers return list of IAM users for given token
func IAMUsers(rurl, token string, verbose int) ([]IAMUser, error) {
	var users []IAMUser

	rurl = fmt.Sprintf("%s/scim/Users", rurl)

	if verbose > 0 {
		log.Println(rurl)
	}
	req, err := http.NewRequest("GET", rurl, nil)
	if err != nil {
		log.Fatalf("Unable to make GET request to %s, error: %s", rurl, err)
	}
	//     req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	if verbose > 1 {
		dump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			log.Println("request: ", string(dump))
		}
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Unable to get response from %s, error: %s", rurl, err)
	}
	if verbose > 1 {
		dump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			log.Println("response:", string(dump))
		}
	}
	var rec IAMScimResponse
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("unable to read response body", err)
		return users, err
	}
	err = json.Unmarshal(data, &rec)
	if err != nil {
		log.Println("unable to unmarshal IAM response", err)
		return users, nil
	}
	users = rec.Resources

	return users, nil
}
