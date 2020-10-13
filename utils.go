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
	"runtime"
	"strings"
	"time"

	"github.com/dmwm/cmsauth"
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
					if cert != nil {
						log.Printf("issuer %v subject %v valid from %v till %v\n", cert.Issuer, cert.Subject, cert.NotBefore, cert.NotAfter)
					}
				}
			}
			opts := x509.VerifyOptions{
				Roots:         rootCAs,
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if len(certs) > 0 && certs[0] != nil {
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

// Stack retuns string representation of the stack function calls
func Stack() string {
	trace := make([]byte, 2048)
	count := runtime.Stack(trace, false)
	return fmt.Sprintf("\nStack of %d bytes: %s\n", count, trace)
}

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
func findUserOld(subjects []string) (cmsauth.CricEntry, error) {
	for _, s := range subjects {
		// loop over subjects is tiny, we may have only few subjects in certificates
		for _, r := range CricRecords {
			cn, e := findCN(s)
			if Config.Verbose > 2 {
				log.Println("subject", s, "findCN", cn)
				log.Println("DNs", r.DNs)
			}
			if e == nil {
				// loop over record DNs is tiny, we only have one or two DNs per user
				for _, dn := range r.DNs {
					if strings.HasSuffix(dn, cn) {
						if Config.Verbose > 2 {
							log.Println("match DN", dn, "with CN", cn)
						}
						return r, nil
					}
				}
			}
		}
	}
	msg := fmt.Sprintf("user not found: %v\n", subjects)
	return cmsauth.CricEntry{}, errors.New(msg)
}

// helper function to find user info in cric records for given cert subject
func findUser(subjects []string) (cmsauth.CricEntry, error) {
	for _, s := range subjects {
		if r, ok := cmsRecords[s]; ok {
			return r, nil
		}
	}
	msg := fmt.Sprintf("user not found: %v\n", subjects)
	return cmsauth.CricEntry{}, errors.New(msg)
}

// helper function to get user data from TLS request
func getUserData(r *http.Request) map[string]interface{} {
	userData := make(map[string]interface{})
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
		var subjects []string
		for _, s := range strings.Split(cert.Subject.String(), ",") {
			if strings.Contains(s, "ROOT") && strings.Contains(s, "CERN") || strings.Contains(s, "Grid") {
				continue
			}
			if Config.Verbose > 2 {
				log.Println("cert subject", s)
			}
			subjects = append(subjects, s)
		}
		rec, err := findUser(subjects)
		if Config.Verbose > 0 {
			log.Printf("found user %+v error=%v elapsed time %v\n", rec, err, time.Since(start))
		}
		if err == nil {
			userData["issuer"] = strings.Split(cert.Issuer.String(), ",")[0]
			userData["Subject"] = strings.Split(cert.Subject.String(), ",")[0]
			userData["name"] = rec.Name
			userData["cern_upn"] = rec.Login
			userData["cern_person_id"] = rec.ID
			userData["auth_time"] = time.Now().Unix()
			userData["exp"] = cert.NotAfter.Unix()
			userData["email"] = cert.EmailAddresses
			userData["roles"] = rec.Roles
			userData["dn"] = rec.DN
			break
		} else {
			log.Println(err)
			continue
		}
	}
	return userData
}

// InList helper function to check item in a list
func InList(a string, list []string) bool {
	check := 0
	for _, b := range list {
		if b == a {
			check++
		}
	}
	if check != 0 {
		return true
	}
	return false
}
