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
	"time"

	"github.com/dmwm/cmsauth"
	_ "github.com/thomasdarimont/go-kc-example/session_memory"
)

// helper function to find user info in cric records for given cert subject
func findUser(subjects []string) (cmsauth.CricEntry, error) {
	for _, r := range CricRecords {
		for _, s := range subjects {
			if strings.HasSuffix(r.DN, s) {
				return r, nil
			}
		}
	}
	msg := fmt.Sprintf("user not found: %v\n", subjects)
	return cmsauth.CricEntry{}, errors.New(msg)
}

// x509RequestHandler handle requests for x509 clients
func x509RequestHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := http.StatusOK
	userData := make(map[string]interface{})
	defer logRequest(w, r, start, "x509", status)
	// get client CAs
	if r.TLS != nil {
		certs := r.TLS.PeerCertificates
		for _, asn1Data := range certs {
			cert, err := x509.ParseCertificate(asn1Data.Raw)
			if err != nil {
				log.Println("x509RequestHandler tls: failed to parse certificate from server: " + err.Error())
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
			} else {
				log.Println("unauthorized access", err)
				status = http.StatusUnauthorized
				w.WriteHeader(status)
				return
			}
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

	// the request handler
	http.HandleFunc("/", x509RequestHandler)

	// start HTTP or HTTPs server based on provided configuration
	rootCAs := x509.NewCertPool()
	for _, fname := range Config.RootCAs {
		caCert, err := ioutil.ReadFile(fname)
		if err != nil {
			log.Fatalf("Unable to read RootCA, %s\n", fname)
		}
		log.Println("Load", fname)
		if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
			log.Fatalf("invalid PEM format while importing trust-chain: %q", fname)
		}
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
			certs[i] = cert
		}
		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := certs[0].Verify(opts)
		return err
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
