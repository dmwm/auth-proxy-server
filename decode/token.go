package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/dmwm/auth-proxy-server/auth"
)

// ReadToken reads either given token file or string and return the token
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

// Example of usage:
func main() {
	var token string
	flag.StringVar(&token, "token", "", "token or file containing the token")
	var purl string
	providers := []string{
		"https://auth.cern.ch/auth/realms/cern",
		"https://cms-auth.web.cern.ch",
		"https://wlcg.cloud.cnaf.infn.it",
	}
	msg := fmt.Sprintf("provider url, supported providers:")
	for _, p := range providers {
		msg = fmt.Sprintf("%s\n\t%s", msg, p)
	}
	msg += "\n"
	flag.StringVar(&purl, "provider", "https://cms-auth.web.cern.ch", msg)
	var verbose int
	flag.IntVar(&verbose, "verbose", 0, "verbose level")
	flag.Parse()
	provider := auth.Provider{}
	err := provider.Init(purl, verbose)
	if err != nil {
		log.Fatalf("fail to initialize %s error %v", provider.URL, err)
	}
	token = ReadToken(token)
	attrs, err := auth.InspectToken(provider, token, verbose)
	if err != nil {
		log.Fatal(err)
	}
	s, e := PrettyStruct(attrs)
	if e == nil {
		fmt.Println(s)
	} else {
		log.Fatal(err)
	}
}

func PrettyStruct(data interface{}) (string, error) {
	val, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return "", err
	}
	return string(val), nil
}
