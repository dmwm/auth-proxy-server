package main

// http handlers
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>

import (
	"log"
	"net/http"

	"github.com/vkuznet/auth-proxy-server/grpc/cms"
)

// RequestHandler performs reverse proxy action on incoming user request
func RequestHandler(w http.ResponseWriter, r *http.Request) {
	if Config.Verbose > 0 {
		log.Printf("HTTP request: %+v", r)
	}
	token := r.Header.Get("Authorization")
	if !validate(token, Config.Providers, Config.Verbose) {
		msg := "Not authorized"
		status := http.StatusUnauthorized
		http.Error(w, msg, status)
		return
	}

	// proceed with gRPC request
	req := &cms.Request{
		Data: &cms.Data{Id: 1, Token: token},
	}
	resp, err := backendGRPC.GetData(req)

	if err != nil {
		msg := "Unable to make gRPC request"
		status := http.StatusBadRequest
		http.Error(w, msg, status)
	}
	if Config.Verbose > 0 {
		log.Println("gRPC response", resp, err)
	}
	w.Write([]byte(resp.String()))
}
