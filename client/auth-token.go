package main

// https://www.janua.fr/offline-sessions-and-offline-tokens-within-keycloak/
// https://gitlab.cern.ch/authzsvc/docs/keycloak-sso-examples/-/blob/master/OfflineToken-bash/offline_token_demo.sh

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func call(aurl string, formData url.Values, verbose bool) map[string]interface{} {
	resp, err := http.PostForm(aurl, formData)
	if err != nil {
		log.Fatal("Unable to post data", err)
	}
	if verbose {
		dump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			log.Println("response: ", string(dump))
		}
	}
	defer resp.Body.Close()
	var rec map[string]interface{}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("unable to read incoming request body %s error %v", string(data), err)
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		log.Fatalf("Error parsing the response body %s error %v\n", string(data), err)
	}
	return rec
}

func credentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')
	fmt.Print("Enter Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	password := string(bytePassword)
	fmt.Println("")
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func run(clientId, clientSecret, token string, returnJson, verbose bool) {
	aurl := "https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/token"

	// if we were gien existing token we'll request new access one for it
	if token != "" {
		formData := make(url.Values)
		formData.Add("grant_type", "refresh_token")
		formData.Add("refresh_token", token)
		formData.Add("client_id", clientId)
		formData.Add("client_secret", clientSecret)
		data := call(aurl, formData, verbose)
		if returnJson {
			bytes, err := json.Marshal(data)
			if err != nil {
				log.Fatal("Unable to marshal the data", err)
			}
			fmt.Println(string(bytes))
			return
		}
		fmt.Printf("access token: %+v\n", data["access_token"])
		return
	}

	username, password := credentials()
	formData := make(url.Values)
	formData.Add("grant_type", "password")
	formData.Add("scope", "openid info offline_access")
	formData.Add("client_id", clientId)
	formData.Add("client_secret", clientSecret)
	formData.Add("username", username)
	formData.Add("password", password)

	// get offline token
	data := call(aurl, formData, verbose)
	if returnJson {
		bytes, err := json.Marshal(data)
		if err != nil {
			log.Fatal("Unable to marshal the data", err)
		}
		fmt.Println(string(bytes))
		return
	}
	fmt.Printf("access token : %+v\n", data["access_token"])
	fmt.Printf("refresh token: %+v\n", data["refresh_token"])
}

func main() {
	var clientId string
	flag.StringVar(&clientId, "clientId", "", "client ID")
	var clientSecret string
	flag.StringVar(&clientSecret, "clientSecret", "", "client secret")
	var token string
	flag.StringVar(&token, "token", "", "refresh token")
	var returnJson bool
	flag.BoolVar(&returnJson, "json", false, "return json document")
	var verbose bool
	flag.BoolVar(&verbose, "verbose", false, "verbosity output")
	flag.Parse()
	run(clientId, clientSecret, token, returnJson, verbose)
}
