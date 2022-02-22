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
