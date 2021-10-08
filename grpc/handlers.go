package main

// http handlers
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/vkuznet/auth-proxy-server/grpc/cms"
)

// RequestHandler performs reverse proxy action on incoming user request
func RequestHandler(w http.ResponseWriter, r *http.Request) {
	if Config.Verbose > 0 {
		log.Printf("HTTP request: %+v", r)
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer func() {
		cancel()
	}()

	// compose new GRPC service request
	var err error
	if Config.RootCA == "" {
		// non-secure connection
		backendGRPC, err = NewGRPCServiceSimple(Config.GRPCAddress)
	} else {
		// fully secure connection with Token based authentication
		backendGRPC, err = NewGRPCService(
			ctx,
			Config.GRPCAddress,
			Config.RootCA,
			Config.Domain,
			token,
			Config.Verbose,
		)
	}
	if err != nil {
		log.Fatal(err)
	}
	// place GRPC request to backend GRPC server
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
