package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime"
	"strings"
	"time"
)

// git version of our code
var version string

// helper function to show version info
func info() string {
	goVersion := runtime.Version()
	tstamp := time.Now()
	return fmt.Sprintf("git=%s go=%s date=%s", version, goVersion, tstamp)
}

// helper function to read token
func ReadToken(r string) string {
	if _, err := os.Stat(r); err == nil {
		b, e := ioutil.ReadFile(r)
		if e != nil {
			log.Fatalf("Unable to read data from file: %s, error: %s", r, e)
		}
		return strings.Replace(string(b), "\n", "", -1)
	}
	return r
}

// TokenRecord represents token record
type TokenRecord struct {
	AccessToken        string `json:"access_token"`
	AccessTokenExpire  int64  `json:"expires_in"`
	RefreshToken       string `json:"refresh_token"`
	RefreshTokenExpire int64  `json:"refresh_expires_in"`
	IdToken            string `json:"id_token"`
}

// renew token
func renew(uri, token string, verbose int) TokenRecord {
	t := ReadToken(token)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t))
	req.Header.Set("Accept", "application/json")
	if verbose > 0 {
		dump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			log.Println("request: ", string(dump))
		}
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if verbose > 1 {
		dump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			log.Println("[DEBUG] response:", string(dump))
		}
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var rec TokenRecord
	err = json.Unmarshal(data, &rec)
	if err != nil {
		log.Fatal(err)
	}
	return rec
}

// main function
func main() {
	var version bool
	flag.BoolVar(&version, "version", false, "Show version")
	var verbose int
	flag.IntVar(&verbose, "verbose", 0, "verbosity level")
	var token string
	flag.StringVar(&token, "token", "", "token string or file")
	var out string
	flag.StringVar(&out, "out", "", "output file to store refreshed token")
	var uri string
	flag.StringVar(&uri, "url", "", "token URL")
	var interval int
	flag.IntVar(&interval, "interval", 0, "run as daemon with given interval")
	flag.Parse()
	if version {
		fmt.Println(info())
		os.Exit(0)
	}
	rurl := fmt.Sprintf("%s/token", uri)
	rec := renew(rurl, token, verbose)
	if out != "" {
		err := ioutil.WriteFile(out, []byte(rec.AccessToken), 0777)
		if err != nil {
			log.Fatalf("Unable to write, file: %s, error: %v\n", out, err)
		}
	}
	// run as daemon if requested
	if interval > 0 {
		for {
			d := time.Duration(interval) * time.Second
			time.Sleep(d)
			rurl := fmt.Sprintf("%s/token/renew", uri)
			// get refresh token from previous record
			rtoken := rec.RefreshToken
			if verbose > 0 {
				log.Printf("Renew token at %s", rurl)
			}
			// renew token using our refresh token
			rec = renew(rurl, rtoken, verbose)
			if out != "" {
				err := ioutil.WriteFile(out, []byte(rec.AccessToken), 0777)
				if err != nil {
					log.Fatalf("Unable to write, file: %s, error: %v\n", out, err)
				}
			}
		}
	}
}
