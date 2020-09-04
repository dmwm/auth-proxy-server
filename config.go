package main

// config module
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

// Config variable represents configuration object
var Config Configuration

// helper function to parse server configuration file
func parseConfig(configFile string) error {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Println("Unable to read", err)
		return err
	}
	err = json.Unmarshal(data, &Config)
	if err != nil {
		log.Println("Unable to parse", err)
		return err
	}
	if Config.ClientID == "" {
		log.Fatal("No ClientID found in configuration file")
	}
	if Config.ClientSecret == "" {
		log.Fatal("No ClientSecret found in configuration file")
	}
	// default values
	if Config.Port == 0 {
		Config.Port = 8181
	}
	if Config.OAuthUrl == "" {
		Config.OAuthUrl = "https://auth.cern.ch/auth/realms/cern"
	}
	return nil
}
