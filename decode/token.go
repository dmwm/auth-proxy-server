package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/vkuznet/auth-proxy-server/auth"
)

// Example of usage:
func main() {
	var token string
	flag.StringVar(&token, "token", "", "token")
	var purl string
	flag.StringVar(&purl, "provider", "https://cms-auth.web.cern.ch", "provider url")
	var verbose int
	flag.IntVar(&verbose, "verbose", 0, "verbose level")
	flag.Parse()
	provider := auth.Provider{}
	err := provider.Init(purl, verbose)
	if err != nil {
		log.Fatalf("fail to initialize %s error %v", provider.URL, err)
	}
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
