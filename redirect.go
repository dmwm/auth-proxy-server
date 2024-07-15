package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// common set of ingress rule maps
var _ingressMap map[string]Ingress

// common set of ingress rules
var _ingressRules []string

type transport struct {
	http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	resp, err = t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	b = bytes.Replace(b, []byte("server"), []byte("schmerver"), -1)
	body := io.NopCloser(bytes.NewReader(b))
	resp.Body = body
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	return resp, nil
}

// Serve a reverse proxy for a given url
func reverseProxy(targetURL string, w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// parse the url
	url, _ := url.Parse(targetURL)

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// make additional http transport if we requested to have keep alive
	if Config.KeepAlive {
		proxy.Transport = &http.Transport{
			MaxIdleConns:        Config.MaxIdleConns,
			MaxIdleConnsPerHost: Config.MaxIdleConnsPerHost,
			IdleConnTimeout:     time.Duration(Config.IdleConnTimeout) * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   time.Duration(Config.KeepAliveTimeout) * time.Second,
				KeepAlive: time.Duration(Config.KeepAliveTimeout) * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: time.Duration(Config.TLSHandshakeTimeout) * time.Second,
		}
	}

	// set custom transport to capture size of response body
	//     proxy.Transport = &transport{http.DefaultTransport}
	if Config.Verbose > 2 {
		log.Printf("HTTP headers: %+v\n", r.Header)
	}

	// handle double slashes in request path
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)

	// Update the headers to allow for SSL redirection
	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	r.URL.User = url.User
	if Config.Verbose > 1 {
		log.Printf("redirect to url.Scheme=%s url.User=%s url.Host=%s url.Path=%s", r.URL.Scheme, r.URL.User, r.URL.Host, r.URL.Path)
	}
	if url.User != nil {
		// set basic authorization for provided user credentials
		hash := base64.StdEncoding.EncodeToString([]byte(url.User.String()))
		r.Header.Set("Authorization", fmt.Sprintf("Basic %s", hash))
	}
	reqHost := r.Header.Get("Host")
	if reqHost == "" {
		name, err := os.Hostname()
		if err == nil {
			reqHost = name
		}
	}

	// CouchDB headers
	if Config.XAuthCouchDBUserName != "" {
		r.Header.Set("X-Auth-CouchDB-UserName", Config.XAuthCouchDBUserName)
	}
	if Config.XAuthCouchDBRoles != "" {
		r.Header.Set("X-Auth-CouchDB-Roles", Config.XAuthCouchDBRoles)
	}
	if Config.XAuthCouchDBToken != "" {
		r.Header.Set("X-Auth-CouchDB-Token", Config.XAuthCouchDBToken)
	}

	// XForward headers
	if Config.XForwardedHost != "" {
		r.Header.Set("X-Forwarded-Host", Config.XForwardedHost)
	} else {
		r.Header.Set("X-Forwarded-Host", reqHost)
	}
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Host = url.Host
	if Config.Verbose > 1 {
		log.Printf("proxy request: %+v\n", r)
	}
	// Set Referrer header
	SetReferrer(r)

	// use custom modify response function to setup response headers
	proxy.ModifyResponse = func(resp *http.Response) error {
		if Config.Verbose > 1 {
			log.Printf("proxy ModifyResponse: %+v", resp)
		}
		if Config.XContentTypeOptions != "" {
			resp.Header.Set("X-Content-Type-Options", Config.XContentTypeOptions)
		}
		resp.Header.Set("Response-Status", resp.Status)
		resp.Header.Set("Response-Status-Code", fmt.Sprintf("%d", resp.StatusCode))
		resp.Header.Set("Response-Proto", resp.Proto)
		resp.Header.Set("Response-Time", time.Since(start).String())
		resp.Header.Set("Response-Time-Seconds", fmt.Sprintf("%v", time.Since(start).Seconds()))

		// Set the status code from the backend response
		//         w.WriteHeader(resp.StatusCode)

		// Copy headers from the backend response
		//         for k, v := range resp.Header {
		//             w.Header()[k] = v
		//         }

		// Check the Content-Type header and set it correctly if necessary
		//         if resp.Header.Get("Content-Type") == "" || strings.Contains(r.URL.Path, "wmstats") {
		/*
			if strings.Contains(r.URL.Path, "wmstats") {
				ext := filepath.Ext(resp.Request.URL.Path)
				mimeType := mime.TypeByExtension(ext)
				log.Println("### path=", resp.Request.URL.Path, ext, mimeType)
				if mimeType != "" {
					resp.Header.Set("Content-Type", mimeType)
				}
			}
		*/

		// create gzip reader if response is in gzip data-format
		/*
			body := resp.Body
			defer resp.Body.Close()
			if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
				if Config.Verbose > 1 {
					log.Println("### use gzip.NewReader to read from back-end response")
				}
				reader, err := gzip.NewReader(resp.Body)
				if err != nil {
					return err
				}
				body = GzipReader{reader, resp.Body}
			} else {
				if Config.Verbose > 1 {
					log.Println("### use plain resp.Body to read from back-end response")
				}
			}
			// we need to copy the data sent from BE server back to the client
			data, err := io.ReadAll(body)
			if err != nil {
				return err
			}
			buf := bytes.NewBuffer(data)
			resp.Body = io.NopCloser(buf)
		*/

		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, err error) {
		if Config.Verbose > 0 {
			log.Printf("proxy ErrorHandler error was: %+v", err)
		}
		header := rw.Header()
		header.Set("Response-Status", fmt.Sprintf("%d", http.StatusBadGateway))
		header.Set("Response-Status-Code", fmt.Sprintf("%d", http.StatusBadGateway))
		header.Set("Response-Time", time.Since(start).String())
		header.Set("Response-Time-Seconds", fmt.Sprintf("%v", time.Since(start).Seconds()))
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
	}

	// ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(w, r)
}

// GzipReader struct to handle GZip'ed content of HTTP requests
type GzipReader struct {
	*gzip.Reader
	io.Closer
}

// Close function closes gzip reader
func (gz GzipReader) Close() error {
	return gz.Closer.Close()
}

// helper function to get random service url
func srvURL(surl string) string {
	// if we are given comma separated service urls we'll use random one
	if strings.Contains(surl, ",") {
		arr := strings.Split(surl, ",")
		/* #nosec */
		idx := rand.Intn(len(arr))         /* #nosec */
		return strings.Trim(arr[idx], " ") // remove empty spaces around the string
	}
	return surl
}

// helper function to print APS redirect rules from given config
func printRules() {
	var rmap map[string]Ingress
	var rules []string
	if len(Config.IngressFiles) > 0 {
		rmap, rules = RedirectRulesFromFiles(Config.IngressFiles)
	} else {
		rmap, rules = RedirectRules(Config.Ingress)
	}
	sort.Strings(rules)
	var maxLen int
	for _, r := range rules {
		if len(r) > maxLen {
			maxLen = len(r)
		}
	}
	for _, r := range rules {
		if rule, ok := rmap[r]; ok {
			fmt.Println(redirectRule(rule, maxLen))
		}
	}
}

// helper function to read ingress rules
func readIngressRules() (map[string]Ingress, []string) {
	var rmap map[string]Ingress
	var rules []string
	if len(Config.IngressFiles) > 0 {
		rmap, rules = RedirectRulesFromFiles(Config.IngressFiles)
	} else {
		rmap, rules = RedirectRules(Config.Ingress)
	}
	if Config.Verbose > 0 {
		sort.Strings(rules)
		var maxLen int
		for _, r := range rules {
			if len(r) > maxLen {
				maxLen = len(r)
			}
		}
		log.Println("ingress paths", rules)
		for _, item := range rmap {
			log.Println(redirectRule(item, maxLen))
		}
	}
	return rmap, rules
}

// helper function to print human readable redirect rule
func redirectRule(r Ingress, maxLen int) string {
	for i := len(r.Path); i < maxLen; i++ {
		r.Path += " "
	}
	out := fmt.Sprintf("%s => %s/%s", r.Path, r.ServiceURL, r.NewPath)
	if strings.HasPrefix(r.NewPath, "/") {
		out = fmt.Sprintf("%s => %s%s", r.Path, r.ServiceURL, r.NewPath)
	}
	if r.Strict {
		out += " (strict)"
	}
	return out
}

// helper function to redirect HTTP requests based on configuration ingress rules
func redirect(w http.ResponseWriter, r *http.Request) {
	for _, key := range _ingressRules {
		rec := _ingressMap[key]
		if (r.URL.Path == "/" && rec.Path == "/") || r.URL.Path == "/index.html" {
			staticContent(w, r)
			return
		}
		// check that request URL path had ingress path with slash
		if PathMatched(r.URL.Path, rec.Path, rec.Strict) {
			if Config.Verbose > 0 {
				log.Printf("HTTP r.URL.Path=%s redirected to %s%s\n", r.URL.Path, rec.ServiceURL, rec.NewPath)
			}
			if rec.ServiceURL == "" {
				// if service url is not set we need to look-up static content from this server
				staticContent(w, r)
				return
			}
			url := srvURL(rec.ServiceURL)
			if rec.OldPath != "" {
				// replace old path to new one, e.g. /couchdb/_all_dbs => /_all_dbs
				r.URL.Path = strings.Replace(r.URL.Path, rec.OldPath, rec.NewPath, 1)
				// if r.URL.Path ended with "/", remove it to avoid
				// cases /path/index.html/ after old->new path substitution
				// but for couchdb/_utils we need final slash
				//                 if !strings.Contains(r.URL.Path, "couchdb") {
				//                     r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
				//                 }
				// replace empty path with root path
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
				if Config.Verbose > 1 {
					log.Printf("service url %s, new request path %s\n", url, r.URL.Path)
				}
			}
			reverseProxy(url, w, r)
			return
		}
	}
	// if no redirection was done, then we'll use either TargetURL
	// or return Hello reply
	if Config.TargetURL != "" {
		reverseProxy(Config.TargetURL, w, r)
	} else {
		staticContent(w, r)
		return
	}
	return
}

func staticContent(w http.ResponseWriter, r *http.Request) {
	if Config.Verbose > 0 {
		log.Printf("staticContent, path=%s\n", r.URL.Path)
	}
	if Config.DocumentRoot != "" {
		fname := fmt.Sprintf("%s%s", Config.DocumentRoot, r.URL.Path)
		if r.URL.Path == "/" || r.URL.Path == "" {
			fname = fmt.Sprintf("%s/index.html", Config.DocumentRoot)
		}
		if strings.HasSuffix(fname, "css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(fname, "js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		if _, err := os.Stat(fname); err == nil {
			body, err := os.ReadFile(filepath.Clean(fname))
			if err == nil {
				data := []byte(body)
				w.Write(data)
				return
			}
		}
	}
	// use static page content if provided in configuration
	if Config.StaticPage != "" {
		tmpl := template.Must(template.ParseFiles(Config.StaticPage))
		tmpl.Execute(w, "")
		return
	}
	w.WriteHeader(http.StatusNotFound)
	msg := fmt.Sprintf("requested path '%s' not found", r.URL.Path)
	w.Write([]byte(msg))
}

// setting handler function, i.e. it can be used to change server settings
func settingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(info()))
		return
	}
	defer r.Body.Close()
	var s = ServerSettings{}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("unable to read incoming request body %s error %v", string(data), err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(data, &s)
	if err != nil {
		log.Printf("unable to unmarshal incoming request, error %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	Config.Verbose = s.Verbose
	log.Println("Update verbose level of config", Config)
	w.WriteHeader(http.StatusOK)
	return
}

// metrics handler function to provide metrics about the server
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(promMetrics()))
	return
}
