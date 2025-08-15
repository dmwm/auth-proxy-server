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
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dmwm/auth-proxy-server/cric"
	"golang.org/x/crypto/acme/autocert"
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
		log.Println(string(out))
	}
	return err
}

// helper function to print HTTP request information
func printHTTPRequest(r *http.Request, msg string) {
	log.Printf("HTTP request: %s\n", msg)
	log.Println("TLS:", r.TLS)
	log.Println("Header:", r.Header)

	// print out all request headers
	log.Printf("%s %s %s \n", r.Method, r.URL, r.Proto)
	for k, v := range r.Header {
		log.Printf("Header field %q, Value %q\n", k, v)
	}
	log.Printf("Host = %q\n", r.Host)
	log.Printf("RemoteAddr= %q\n", r.RemoteAddr)
	log.Printf("\n\nFinding value of \"Accept\" %q\n", r.Header["Accept"])
}

// RootCAs returns cert pool of our root CAs
func RootCAs() *x509.CertPool {
	if Config.Verbose > 2 {
		log.Println("Load RootCAs from", Config.RootCAs)
	}
	rootCAs := x509.NewCertPool()
	for _, rootCAdir := range Config.RootCAs {
		files, err := ioutil.ReadDir(rootCAdir)
		if err != nil {
			log.Printf("Unable to list files in '%s', error: %v\n", rootCAdir, err)
			return rootCAs
		}
		for _, finfo := range files {
			fname := fmt.Sprintf("%s/%s", rootCAdir, finfo.Name())
			caCert, err := os.ReadFile(filepath.Clean(fname))
			if err != nil {
				if Config.Verbose > 2 {
					log.Printf("Unable to read %s\n", fname)
				}
			}
			if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
				if Config.Verbose > 2 {
					log.Printf("invalid PEM format while importing trust-chain: %q", fname)
				}
			}
			if Config.Verbose > 2 {
				log.Println("Load CA file", fname)
			}
		}
	}
	return rootCAs
}

// global rootCAs
var _rootCAs *x509.CertPool

// VerifyPeerCertificate function provides custom verification of client's
// certificate, see details
// https://golang.org/pkg/crypto/tls/#example_Config_verifyPeerCertificate
// https://www.example-code.com/golang/cert.asp
// https://golang.org/pkg/crypto/x509/pkix/#Extension
func VerifyPeerCertificate(certificates [][]byte, _ [][]*x509.Certificate) error {
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
		Roots:         _rootCAs,
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

// helper function to construct http server with TLS
// very informative blog about TLS setup:
// https://youngkin.github.io/post/gohttpsclientserver/
func getServer(serverCrt, serverKey string, customVerify bool) (*http.Server, error) {
	// start HTTP or HTTPs server based on provided configuration

	var tlsConfig *tls.Config
	// see go doc tls.VersionTLS13 for different versions
	var minVer, maxVer int
	if Config.MinTLSVersion == "tls10" {
		minVer = tls.VersionTLS10
	} else if Config.MinTLSVersion == "tls11" {
		minVer = tls.VersionTLS11
	} else if Config.MinTLSVersion == "tls12" {
		minVer = tls.VersionTLS12
	} else if Config.MinTLSVersion == "tls13" {
		minVer = tls.VersionTLS13
	} else {
		minVer = tls.VersionTLS12
	}
	if Config.MaxTLSVersion == "tls10" {
		maxVer = tls.VersionTLS10
	} else if Config.MaxTLSVersion == "tls11" {
		maxVer = tls.VersionTLS11
	} else if Config.MaxTLSVersion == "tls12" {
		maxVer = tls.VersionTLS12
	} else if Config.MaxTLSVersion == "tls13" {
		maxVer = tls.VersionTLS13
	} else {
		maxVer = tls.VersionTLS13
	}
	cert, err := tls.LoadX509KeyPair(serverCrt, serverKey)
	if err != nil {
		log.Fatalf("server loadkeys: %s", err)

	}

	// if we do not require custom verification we'll load server crt/key and present to client
	if customVerify == false { // oauth server
		tlsConfig = &tls.Config{
			RootCAs:      _rootCAs,
			Certificates: []tls.Certificate{cert},
		}
	} else { // otherwise (x509 server) we'll perform custom verification of client's certificates
		tlsConfig = &tls.Config{
			// Set InsecureSkipVerify to skip the default validation we are
			// replacing. This will not disable VerifyPeerCertificate.
			InsecureSkipVerify: Config.InsecureSkipVerify,
			// we must use tls.RequestClientCert for CMS proxy, otherwise client
			// cert will not be present during TLS handshake
			// then it will only work for user's cert but not for proxies
			ClientAuth:   tls.RequestClientCert,
			ClientCAs:    _rootCAs, // this comes from /etc/grid-security/certificate
			RootCAs:      _rootCAs,
			Certificates: []tls.Certificate{cert},
			// to use TLS handshake phase for client certificate validation use
			// VerifyPeerCertificate: VerifyPeerCertificate,
			// but if we want to move this validation to middleware layer (after TLS handshake but before end-point)
			// we do not need this assignment. Insetad, use certMiddleware and HTTP server mux
		}
	}
	// enable debugging of TLS handshake
	if Config.DebugTLSHandshake {
		tlsConfig.KeyLogWriter = os.Stdout
	}
	// set min/max TLS version only if they are provided in configuration
	if Config.MinTLSVersion != "" {
		log.Println("use minTLSVersion", minVer)
		tlsConfig.MinVersion = uint16(minVer)
	}
	if Config.MaxTLSVersion != "" {
		log.Println("use maxTLSVersion", maxVer)
		tlsConfig.MaxVersion = uint16(maxVer)
	}
	if Config.CipherSuites == "frontend" {
		tlsConfig.CipherSuites = []uint16{
			// TLS 1.0 - 1.2 cipher suites.
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

			// TLS 1.3 cipher suites.
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,

			// fallback
			tls.TLS_FALLBACK_SCSV,
		}
	}
	// setup HTTPs server
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

// LetsEncryptServer provides HTTPs server with Let's encrypt for
// given domain names (hosts)
func LetsEncryptServer(hosts ...string) *http.Server {
	// setup LetsEncrypt cert manager
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Cache:      autocert.DirCache("certs"),
	}

	tlsConfig := &tls.Config{
		// Set InsecureSkipVerify to skip the default validation we are
		// replacing. This will not disable VerifyPeerCertificate.
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequestClientCert,
		RootCAs:            _rootCAs,
		GetCertificate:     certManager.GetCertificate,
	}
	tlsConfig.VerifyPeerCertificate = VerifyPeerCertificate

	// start HTTP server with our rootCAs and LetsEncrypt certificates
	server := &http.Server{
		Addr:      ":https",
		TLSConfig: tlsConfig,
		//         TLSConfig: &tls.Config{
		//             GetCertificate:     certManager.GetCertificate,
		//         },
	}
	// start cert Manager goroutine
	go http.ListenAndServe(":http", certManager.HTTPHandler(nil))
	log.Println("Starting LetsEncrypt HTTPs server")
	return server
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

// helper function to convert attr ANS.1 to human readable form
// https://cs.opensource.google/go/go/+/master:src/crypto/x509/pkix/pkix.go;l=26
// crypto/x509/pkix/pkix.go
// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772812(v=ws.10)?redirectedfrom=MSDN
// https://stackoverflow.com/questions/6465454/table-of-oids-for-certificates-subject
func attrDN(attr string) string {
	switch attr {
	case "2.5.4.3": // CN (Common Name)
		return "CN"
	case "2.5.4.11": // OU (Organizational Unit)
		return "OU"
	case "0.9.2342.19200300.100.1.25": // DC (Domain Component)
		return "DC"
	case "2.5.4.6":
		return "C"
	case "2.5.4.10":
		return "O"
	case "2.5.4.5":
		return "SERIALNUMBER"
	case "2.5.4.7":
		return "L"
	case "2.5.4.8":
		return "ST"
	case "2.5.4.17":
		return "POSTALCODE"
	case "2.5.4.12":
		return "T" // Title
	case "2.5.4.42":
		return "GN" // GivenName
	case "2.5.4.43":
		return "I" // Initials
	case "2.5.4.4":
		return "SN" // SurName
	case "1.2.840.113549.1.9.1":
		return "EMail" // EMail
	}
	return attr

}

func getDNParts(cert *x509.Certificate) string {
	dnParts := []string{}
	parts := []string{}

	// loop over names
	for _, obj := range cert.Subject.Names {
		aType := attrDN(obj.Type.String())
		aValue := obj.Value
		part := fmt.Sprintf("%s=%s", aType, aValue)
		parts = append(parts, part)
	}
	for _, obj := range cert.Subject.ExtraNames {
		aType := attrDN(obj.Type.String())
		aValue := obj.Value
		part := fmt.Sprintf("%s=%s", aType, aValue)
		parts = append(parts, part)
	}
	// Extract all RDNs from the Subject field
	rdnSequence := cert.Subject.ToRDNSequence()
	for _, rdnSet := range rdnSequence {
		for _, rdn := range rdnSet {
			aType := attrDN(rdn.Type.String())
			aValue := rdn.Value.(string)
			part := fmt.Sprintf("%s=%s", aType, aValue)
			parts = append(parts, part)
		}
	}
	sort.Strings(parts)
	for _, value := range parts {
		if !contains(dnParts, value) {
			dnParts = append(dnParts, value)
		}
	}
	dn := "/" + strings.Join(dnParts, "/")
	dn = strings.Replace(dn, "//", "/", -1)
	return dn
}

// contains checks if a slice contains a specific value
func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// helper function to get user data from TLS request
func getUserData(r *http.Request) map[string]interface{} {
	userData := make(map[string]interface{})
	mapMutex := sync.RWMutex{}
	if r.TLS == nil {
		if Config.Verbose > 2 {
			log.Printf("HTTP request does not support TLS, %+v", r)
		}
		return userData
	}
	certs := r.TLS.PeerCertificates
	if Config.Verbose > 2 {
		log.Printf("found %d peer certificates in HTTP request", len(certs))
		log.Printf("HTTP request %+v", r)
		log.Printf("HTTP request TLS %+v", r.TLS)
	}
	for _, asn1Data := range certs {
		cert, err := x509.ParseCertificate(asn1Data.Raw)
		if err != nil {
			log.Println("x509RequestHandler tls: failed to parse certificate from server: " + err.Error())
			continue
		}
		if len(cert.UnhandledCriticalExtensions) > 0 {
			if Config.Verbose > 2 {
				log.Println("cert.UnhandledCriticalExtensions equal to", len(cert.UnhandledCriticalExtensions))
			}
			continue
		}
		dnParts := getDNParts(cert)
		start := time.Now()
		rec, err := cric.FindUser(dnParts)
		if Config.Verbose > 1 {
			log.Printf("found user %+v error=%v elapsed time %v\n", rec, err, time.Since(start))
		}
		if err == nil {
			mapMutex.Lock()
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
			userData["dns"] = rec.DNs
			if len(rec.DNs) > 1 {
				if dn := matchDN(cert.Subject.CommonName, rec.DNs); dn != "" {
					userData["dn"] = dn
				}
			}
			mapMutex.Unlock()
			break
		} else {
			log.Println(err)
			continue
		}
	}
	return userData
}

// helper function to match user DN from list of all user DNs. The logic is based on exact
// match of CommonName field
func matchDN(cnField string, dns []string) string {
	cn := fmt.Sprintf("CN=%s", cnField)
	for _, dn := range dns {
		for _, r := range strings.Split(dn, "/") {
			if cn == r {
				return dn
			}
		}
	}
	return ""
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

// PathMatched check if given path are matched with rurl
func PathMatched(rurl, path string, strict bool) bool {
	if v, err := url.QueryUnescape(rurl); err == nil {
		rurl = v
	}
	if Config.Verbose > 2 {
		log.Printf("PathMatched rurl=%s path=%s strict=%v", rurl, path, strict)
	}
	matched := false
	if strings.HasSuffix(path, "/") {
		if !strings.HasSuffix(rurl, "/") {
			rurl += "/"
		}
	}
	var prefixMatch bool
	if strings.Contains(path, ".") || strings.Contains(path, "*") || strings.Contains(path, "^") || strings.Contains(path, "$") {
		prefixMatch, _ = regexp.MatchString(path, rurl)
	} else {
		prefixMatch = strings.HasPrefix(rurl, path)
	}
	if strict {
		if prefixMatch {
			rest := strings.Replace(rurl, path, "", -1)
			if len(rest) > 0 && string(rest[0]) == "/" {
				rest = strings.Replace(rest, "/", "", 1)
			}
			// the rest of the path is just parameters and not sub-path of URI
			if !strings.Contains(rest, "/") {
				matched = true
			}
		}
	} else {
		if prefixMatch {
			matched = true
		} else if rurl == path {
			matched = true
		}
	}
	if Config.Verbose > 1 {
		log.Printf("PathMatched rurl=%s path=%s strict=%v matched %v", rurl, path, strict, matched)
	}
	return matched
}

// RedirectRules provides redirect rules map by reading Config.Ingress items
func RedirectRules(ingressRules []Ingress) (map[string]Ingress, []string) {
	rmap := make(map[string]Ingress)
	mapMutex := sync.RWMutex{}
	var rules []string
	for _, rec := range ingressRules {
		rules = append(rules, rec.Path)
		mapMutex.Lock()
		rmap[rec.Path] = rec
		mapMutex.Unlock()
	}
	// we should not sort rules, otherwise we break order of the rules which is important, e.g.
	// /wmstats should point to /wmstats/index.html, while /wmstats/.* should go further
	// therefore we can put ^/wmstats$ before ^/wmstats/.* in redirect rules
	return rmap, rules
}

// RedirectRulesFromFiles provides redirect rules map by reading Config.IngressFiles
func RedirectRulesFromFiles(ingressFiles []string) (map[string]Ingress, []string) {
	rmap := make(map[string]Ingress)
	mapMutex := sync.RWMutex{}
	var rules []string
	for _, fname := range ingressFiles {
		file, err := os.Open(fname)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		bytes, err := io.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}
		var ingressRules []Ingress
		err = json.Unmarshal(bytes, &ingressRules)
		if err != nil {
			log.Fatal(err)
		}
		for _, rec := range ingressRules {
			rules = append(rules, rec.Path)
			mapMutex.Lock()
			rmap[rec.Path] = rec
			mapMutex.Unlock()
		}
	}
	// we should not sort rules, otherwise we break order of the rules which is important, e.g.
	// /wmstats should point to /wmstats/index.html, while /wmstats/.* should go further
	// therefore we can put ^/wmstats$ before ^/wmstats/.* in redirect rules
	return rmap, rules
}

// LogName return proper log name based on Config.LogName and either
// hostname or pod name (used in k8s environment).
func LogName() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Println("unable to get hostname", err)
	}
	if os.Getenv("MY_POD_NAME") != "" {
		hostname = os.Getenv("MY_POD_NAME")
	}
	logName := Config.LogFile + "_%Y%m%d"
	if hostname != "" {
		logName = fmt.Sprintf("%s_%s", Config.LogFile, hostname) + "_%Y%m%d"
	}
	return logName
}

// SetReferrer set  HTTP Referrer/Referer HTTP headers
func SetReferrer(r *http.Request) {
	ref := r.Header.Get("X-Forwarded-Host")
	if !strings.HasPrefix(ref, "http") {
		ref = fmt.Sprintf("https://%s", ref)
	}
	r.Header.Set("Referer", ref)
	r.Header.Set("Referrer", ref)
}

// Checks if the remote IP is in the allowed range
func isAllowedIP(r *http.Request) bool {
	// Extract the remote IP from the request (format could be IP:port)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Printf("Error parsing RemoteAddr: %v\n", err)
		return false
	}

	// check if IP is allowed to view debug info
	return InList(ip, Config.DebugAllowedIPs)
}

// Middleware to restrict pprof and expvar to allowed IPs
func debugHandler(w http.ResponseWriter, r *http.Request) {
	if !isAllowedIP(r) {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// Serve the original debug endpoint if the IP is allowed
	http.DefaultServeMux.ServeHTTP(w, r)
}
