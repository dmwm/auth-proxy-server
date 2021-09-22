package main

// config module
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

// Config variable represents configuration object
var Config Configuration

// helper function to parse server configuration file
func parseConfig(configFile string) error {
	data, err := os.ReadFile(filepath.Clean(configFile))
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
		v := os.Getenv("APS_CLIENT_ID")
		if v != "" {
			Config.ClientID = v
		} else {
			log.Fatal("No ClientID found in configuration file")
		}
	}
	if Config.ClientSecret == "" {
		v := os.Getenv("APS_CLIENT_SECRET")
		if v != "" {
			Config.ClientSecret = v
		} else {
			log.Fatal("No ClientSecret found in configuration file")
		}
	}
	// default values
	if Config.Port == 0 {
		Config.Port = 8181
	}
	if Config.OAuthURL == "" {
		Config.OAuthURL = "https://auth.cern.ch/auth/realms/cern"
	}
	if Config.ReadTimeout == 0 {
		Config.ReadTimeout = 300
	}
	if Config.WriteTimeout == 0 {
		Config.WriteTimeout = 300
	}
	return nil
}
