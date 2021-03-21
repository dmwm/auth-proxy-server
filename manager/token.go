package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/vkuznet/TokenManager"
)

// git version of our code
var version string

// helper function to show version info
func info() string {
	goVersion := runtime.Version()
	tstamp := time.Now()
	return fmt.Sprintf("git=%s go=%s date=%s", version, goVersion, tstamp)
}

// helper function to print our token record
func printRecord(rec TokenManager.TokenRecord, verbose int) {
	if verbose > 0 {
		data, err := json.MarshalIndent(rec, "", "    ")
		if err == nil {
			log.Printf("New token record:\n%s", string(data))
		} else {
			log.Println("Unable to marshal record", err)
		}
	}
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
	var rootCAs string
	flag.StringVar(&rootCAs, "rootCAs", "", "location of root CAs")
	var interval int
	flag.IntVar(&interval, "interval", 0, "run as daemon with given interval")
	flag.Parse()
	if version {
		fmt.Println(info())
		os.Exit(0)
	}
	if rootCAs == "" {
		dir, err := TokenManager.LoadCAs(verbose)
		if err != nil {
			log.Fatalf("unable to load CERN CAs: %v", err)
		}
		rootCAs = dir
	}
	if verbose > 0 {
		fmt.Println("Read CERN CAs from", rootCAs)
	}
	rurl := fmt.Sprintf("%s/token/renew", uri)
	rec := TokenManager.Renew(rurl, token, rootCAs, verbose)
	if out != "" {
		err := ioutil.WriteFile(out, []byte(rec.AccessToken), 0777)
		if err != nil {
			log.Fatalf("Unable to write, file: %s, error: %v\n", out, err)
		}
	}
	printRecord(rec, verbose)
	// run as daemon if requested
	if interval > 0 {
		for {
			d := time.Duration(interval) * time.Second
			time.Sleep(d)
			// get refresh token from previous record
			rtoken := rec.RefreshToken
			// renew token using our refresh token
			rec = TokenManager.Renew(rurl, rtoken, rootCAs, verbose)
			if out != "" {
				err := ioutil.WriteFile(out, []byte(rec.AccessToken), 0777)
				if err != nil {
					log.Fatalf("Unable to write, file: %s, error: %v\n", out, err)
				}
			}
			printRecord(rec, verbose)
		}
	}
}
