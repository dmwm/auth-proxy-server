package main

import (
	"net/http"

	"github.com/vkuznet/auth-proxy-server/grpc/cms"
)

func auth(token string) bool {
	if token != "" {
		return true
	}
	return false
}

// RequestHandler performs reverse proxy action on incoming user request
func RequestHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !auth(token) {
		msg := "Not authorized"
		status := http.StatusUnauthorized
		http.Error(w, msg, status)
		return
	}

	// proceed with gRPC request
	req := &cms.Request{
		Data: &cms.Data{Id: 1, Token: token},
	}
	grpcResult, err := backendGrpc.GetData(req)
	//     grpcResult, err := backendGrpc.GetData(r)

	if err != nil {
		msg := "Unable to make gRPC request"
		status := http.StatusBadRequest
		http.Error(w, msg, status)
	}
	w.Write(grpcResult)
}
