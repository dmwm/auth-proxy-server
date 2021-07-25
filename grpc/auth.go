package main

// auth module to perform oAuth token based authentication
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>

import "log"

// helper function to validate given token
func auth(token string) bool {
	// Perform the token validation here. For the sake of this example, the code
	// here forgoes any of the usual OAuth2 token validation and instead checks
	// for a token matching an arbitrary string.
	log.Println("auth token", token)
	return token == "some-secret-token"
	//     if token != "" {
	//         return true
	//     }
	//     return false
}
