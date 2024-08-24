package main

// gRPC server example based on auth-proxy-server/grpc/cms representation
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"context"
	"flag"
	"log"
	"net"
	"strings"

	"github.com/dmwm/auth-proxy-server/grpc/cms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// gRPC server type
type server struct {
}

// GetData implements gRPC server API
func (*server) GetData(ctx context.Context, request *cms.Request) (*cms.Response, error) {
	log.Println("gRPC request", request)
	response := &cms.Response{
		Ids: []int64{1, 2, 3},
	}
	return response, nil
}

func main() {
	var address string
	flag.StringVar(&address, "address", "", "gRPC address, e.g. 0.0.0.0:9999")
	var oauth bool
	flag.BoolVar(&oauth, "oauth", false, "gRPC server with oAuth support")
	var serverKey string
	flag.StringVar(&serverKey, "serverKey", "", "gRPC server key file")
	var serverCrt string
	flag.StringVar(&serverCrt, "serverCrt", "", "gRPC server crt file")
	flag.Parse()

	// set verbose log output
	log.SetFlags(0)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if address == "" {
		log.Fatal("invalid gRPC address")
	}
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Error %v", err)
	}
	log.Printf("gRPC server is listening on %v ...", address)

	var opts []grpc.ServerOption

	if oauth {
		opts = append(opts, grpc.UnaryInterceptor(ensureValidToken))
	}
	if serverKey != "" {
		creds, err := credentials.NewServerTLSFromFile(serverCrt, serverKey)
		if err != nil {
			log.Fatal(err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	s := grpc.NewServer(opts...)

	cms.RegisterDataServiceServer(s, &server{})

	s.Serve(lis)
}

// helper function to validate the authorization.
func valid(authorization []string) bool {
	if len(authorization) < 1 {
		return false
	}
	token := strings.TrimPrefix(authorization[0], "Bearer ")
	log.Println("validate token", token)
	// Perform the token validation here. For the sake of this example, the code
	// here forgoes any of the usual OAuth2 token validation and instead checks
	// for a token matching an arbitrary string.
	//     return token == "some-secret-token"

	if token == "" {
		return false
	}
	return true
}

// ensureValidToken ensures a valid token exists within a request's metadata. If
// the token is missing or invalid, the interceptor blocks execution of the
// handler and returns an error. Otherwise, the interceptor invokes the unary
// handler.
func ensureValidToken(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "missing metadata")
	}
	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	if !valid(md["authorization"]) {
		log.Println("invalid token, context metadata", md)
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}
	// Continue execution of handler after ensuring a valid token.
	return handler(ctx, req)
}
