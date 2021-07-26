package main

// auth module to perform oAuth token based authentication
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>

import (
	"log"

	"github.com/vkuznet/auth-proxy-server/auth"
	"github.com/vkuznet/auth-proxy-server/cric"
)

// helper function to validate given token
func validate(token string, providers []string, verbose int) bool {

	// first, we inspect our token
	attrs, err := auth.InspectTokenProviders(token, providers, verbose)
	if verbose > 0 {
		log.Printf("token %s providers %v attributes %+v\n", token, providers, attrs)
	}
	if err != nil {
		log.Println("Unable to extract token providers", err)
		return false
	}

	// check if user cliend ID exists in CRIC records
	if user, ok := cric.CricRecords[attrs.ClientID]; ok {
		if verbose > 0 {
			log.Printf("token is validated, user %+v", user)
		}
		return true
	}
	return false
}
