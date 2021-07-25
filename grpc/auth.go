package main

// auth module to perform oAuth token based authentication
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>

import "log"

// helper function to validate given token
func auth(token string) bool {
	// TODO: perform the token validation
	log.Println("auth token", token)
	return token == "some-secret-token"
}
