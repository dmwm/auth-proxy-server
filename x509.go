package main

// x509 module provides x509 implementation of reverse proxy with
// CMS headers based on CRIC service
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
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
func x509ProxyServer(serverCrt, serverKey string) {

	// the server settings handler
	http.HandleFunc(fmt.Sprintf("%s/server", Config.Base), settingsHandler)
	// metrics handler
	http.HandleFunc(fmt.Sprintf("%s/metrics", Config.Base), metricsHandler)

	// the request handler
	http.HandleFunc("/", x509RequestHandler)

	// start HTTP or HTTPs server based on provided configuration
	rootCAs := x509.NewCertPool()
	files, err := ioutil.ReadDir(Config.RootCAs)
	if err != nil {
		log.Printf("Unable to list files in '%s', error: %v\n", Config.RootCAs, err)
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

	tlsConfig := &tls.Config{
		// Set InsecureSkipVerify to skip the default validation we are
		// replacing. This will not disable VerifyPeerCertificate.
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequestClientCert,
		RootCAs:            rootCAs,
	}
	// see concrete example here:
	// https://golang.org/pkg/crypto/tls/#example_Config_verifyPeerCertificate
	// https://www.example-code.com/golang/cert.asp
	// https://golang.org/pkg/crypto/x509/pkix/#Extension
	tlsConfig.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
		if Config.Verbose > 1 {
			log.Println("call custom tlsConfig.VerifyPeerCertificate")
		}
		certs := make([]*x509.Certificate, len(certificates))
		for i, asn1Data := range certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			if Config.Verbose > 1 {
				log.Println("Issuer", cert.Issuer)
				log.Println("Subject", cert.Subject)
				log.Println("emails", cert.EmailAddresses)
			}
			// check validity of user certificate
			tstamp := time.Now().Unix()
			if cert.NotBefore.Unix() > tstamp || cert.NotAfter.Unix() < tstamp {
				msg := fmt.Sprintf("Expired user certificate, valid from %v to %v\n", cert.NotBefore, cert.NotAfter)
				return errors.New(msg)
			}
			// dump cert UnhandledCriticalExtensions
			for _, ext := range cert.UnhandledCriticalExtensions {
				if Config.Verbose > 1 {
					log.Printf("Cetificate extension: %+v\n", ext)
				}
				continue
			}
			if len(cert.UnhandledCriticalExtensions) == 0 && cert != nil {
				certs[i] = cert
			}
		}
		if Config.Verbose > 1 {
			log.Println("### number of certs", len(certs))
			for _, cert := range certs {
				log.Println("### cert", cert)
			}
		}
		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if certs[0] != nil {
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			return err
		}
		for _, cert := range certs {
			if cert == nil {
				continue
			}
			_, err := cert.Verify(opts)
			if err != nil {
				return err
			}
		}
		return nil
	}
	addr := fmt.Sprintf(":%d", Config.Port)
	if serverCrt != "" && serverKey != "" {
		//start HTTPS server which require user certificates
		server := &http.Server{
			Addr:           addr,
			TLSConfig:      tlsConfig,
			ReadTimeout:    300 * time.Second,
			WriteTimeout:   300 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		log.Printf("Starting x509 HTTPs server on %s", addr)
		log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
	} else {
		// Start server without user certificates
		log.Printf("Starting x509 HTTP server on %s", addr)
		log.Fatal(http.ListenAndServe(addr, nil))
	}
}
