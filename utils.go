package main

// utils module
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// helper function to check if given file name exists
func checkFile(fname string) string {
	_, err := os.Stat(fname)
	if err == nil {
		return fname
	}
	log.Fatalf("unable to read %s, error %v\n", fname, err)
	return ""
}

// helper function to print JSON data
func printJSON(j interface{}, msg string) error {
	if msg != "" {
		log.Println(msg)
	}
	var out []byte
	var err error
	out, err = json.MarshalIndent(j, "", "    ")
	if err == nil {
		fmt.Println(string(out))
	}
	return err
}

// helper function to print HTTP request information
func printHTTPRequest(r *http.Request, msg string) {
	log.Printf("HTTP request: %s\n", msg)
	fmt.Println("TLS:", r.TLS)
	fmt.Println("Header:", r.Header)

	// print out all request headers
	fmt.Printf("%s %s %s \n", r.Method, r.URL, r.Proto)
	for k, v := range r.Header {
		fmt.Printf("Header field %q, Value %q\n", k, v)
	}
	fmt.Printf("Host = %q\n", r.Host)
	fmt.Printf("RemoteAddr= %q\n", r.RemoteAddr)
	fmt.Printf("\n\nFinding value of \"Accept\" %q\n", r.Header["Accept"])
}

// helper function to construct http server with TLS
func getServer(serverCrt, serverKey string, customVerify bool) (*http.Server, error) {
	// start HTTP or HTTPs server based on provided configuration
	rootCAs := x509.NewCertPool()
	files, err := ioutil.ReadDir(Config.RootCAs)
	if err != nil {
		log.Printf("Unable to list files in '%s', error: %v\n", Config.RootCAs, err)
		return nil, err
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

	var tlsConfig *tls.Config
	// if we do not require custom verification we'll load server crt/key and present to client
	if customVerify == false {
		cert, err := tls.LoadX509KeyPair(serverCrt, serverKey)
		if err != nil {
			log.Fatalf("server loadkeys: %s", err)

		}
		tlsConfig = &tls.Config{
			RootCAs:      rootCAs,
			Certificates: []tls.Certificate{cert},
		}
	} else { // otherwise we'll perform custom verification of client's certificates
		tlsConfig = &tls.Config{
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
	}
	addr := fmt.Sprintf(":%d", Config.Port)
	server := &http.Server{
		Addr:           addr,
		TLSConfig:      tlsConfig,
		ReadTimeout:    time.Duration(Config.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(Config.WriteTimeout) * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Printf("Starting HTTPs server on %s", addr)
	return server, nil
}
