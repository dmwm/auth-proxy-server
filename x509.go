package main

// x509 module provides x509 implementation of reverse proxy with
// CMS headers based on CRIC service
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dmwm/cmsauth"
	_ "github.com/thomasdarimont/go-kc-example/session_memory"
)

// TotalX509GetRequests counts total number of GET requests received by the server
var TotalX509GetRequests uint64

// TotalX509PostRequests counts total number of POST requests received by the server
var TotalX509PostRequests uint64

// helper function to extract CN from given subject
func findCN(subject string) (string, error) {
	parts := strings.Split(subject, " ")
	for i, s := range parts {
		if strings.HasPrefix(s, "CN=") && len(parts) > i {
			cn := s
			for _, ss := range parts[i+1:] {
				if strings.Contains(ss, "=") {
					break
				}
				cn = fmt.Sprintf("%s %s", cn, ss)
			}
			return cn, nil
		}
	}
	return "", errors.New("no user CN is found in subject: " + subject)
}

// helper function to find user info in cric records for given cert subject
func findUser(subjects []string) (cmsauth.CricEntry, error) {
	for _, r := range CricRecords {
		// loop over subjects is tiny, we may have only few subjects in certificates
		for _, s := range subjects {
			if cn, e := findCN(s); e == nil {
				// loop over record DNs is tiny, we only have one or two DNs per user
				for _, dn := range r.DNs {
					if strings.HasSuffix(dn, cn) {
						return r, nil
					}
				}
			}
		}
	}
	msg := fmt.Sprintf("user not found: %v\n", subjects)
	return cmsauth.CricEntry{}, errors.New(msg)
}

// x509RequestHandler handle requests for x509 clients
func x509RequestHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	// increment GET/POST counters
	if r.Method == "GET" {
		atomic.AddUint64(&TotalX509GetRequests, 1)
	}
	if r.Method == "POST" {
		atomic.AddUint64(&TotalX509PostRequests, 1)
	}
	defer getRPS(start)

	status := http.StatusOK
	userData := make(map[string]interface{})
	defer logRequest(w, r, start, "x509", status)
	// get client CAs
	validUser := false
	if r.TLS != nil {
		certs := r.TLS.PeerCertificates
		for _, asn1Data := range certs {
			cert, err := x509.ParseCertificate(asn1Data.Raw)
			if err != nil {
				log.Println("x509RequestHandler tls: failed to parse certificate from server: " + err.Error())
			}
			if len(cert.UnhandledCriticalExtensions) > 0 {
				continue
			}
			start := time.Now()
			rec, err := findUser(strings.Split(cert.Subject.String(), ","))
			if Config.Verbose > 0 {
				log.Println("find user", rec, err, time.Since(start))
			}
			if err == nil {
				userData["issuer"] = cert.Issuer.String()
				userData["Subject"] = cert.Subject.String()
				userData["name"] = rec.Name
				userData["cern_upn"] = rec.Login
				userData["cern_person_id"] = rec.ID
				userData["auth_time"] = time.Now().Unix()
				userData["exp"] = cert.NotAfter.Unix()
				userData["email"] = cert.EmailAddresses
				validUser = true
			} else {
				log.Println(err)
				continue
				//                 log.Println("unauthorized access", err)
				//                 status = http.StatusUnauthorized
				//                 w.WriteHeader(status)
				//                 return
			}
		}
		if !validUser {
			log.Println("unauthorized access, user not found in CRIC DB")
			status = http.StatusUnauthorized
			w.WriteHeader(status)
			return
		}
		// set CMS headers based on provided user certificate
		if Config.Verbose > 3 {
			CMSAuth.SetCMSHeaders(r, userData, CricRecords, true)
		} else {
			CMSAuth.SetCMSHeaders(r, userData, CricRecords, false)
		}
	}
	// check CMS headers
	authStatus := CMSAuth.CheckAuthnAuthz(r.Header)
	if Config.Verbose > 0 {
		log.Println("x509RequestHandler", r.Header, authStatus)
	}
	if authStatus {
		redirect(w, r)
		return
	}
	status = http.StatusUnauthorized
	w.WriteHeader(status)
}

// helper function to start x509 proxy server
func x509ProxyServer() {
	// check if provided crt/key files exists
	serverCrt := checkFile(Config.ServerCrt)
	serverKey := checkFile(Config.ServerKey)

	// the server settings handler
	http.HandleFunc(fmt.Sprintf("%s/server", Config.Base), settingsHandler)
	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", Config.Base), metricsHandler)

	// the request handler
	http.HandleFunc("/", x509RequestHandler)

	// start HTTPS server
	server, err := getServer(serverCrt, serverKey, true)
	if err != nil {
		log.Fatalf("unable to start x509 server, error %v\n", err)
	}
	log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
}
