package main

// grpc module provides gRPC service
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>

import (
	"context"
	"log"
	"time"

	cms "github.com/dmwm/auth-proxy-server/grpc/cms"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

var defaultRequestTimeout = time.Second * 10

// Service defines the interface exposed by this package.
type GRPCService interface {
	GetData(request *cms.Request) (*cms.Response, error)
}

type grpcService struct {
	grpcClient cms.DataServiceClient
}

// NewGRPCServiceSimple creates a new gRPC user service connection using the specified connection string.
func NewGRPCServiceSimple(connString string) (GRPCService, error) {
	conn, err := grpc.Dial(connString, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return &grpcService{grpcClient: cms.NewDataServiceClient(conn)}, nil
}

// fetchToken simulates a token lookup and omits the details of proper token
// acquisition. For examples of how to acquire an OAuth2 token, see:
// https://godoc.org/golang.org/x/oauth2
func fetchToken(token string, verbose int) *oauth2.Token {
	if verbose > 0 {
		log.Println("### client token", token)
	}
	return &oauth2.Token{
		AccessToken: token,
	}
}

// NewGRPCService creates a new gRPC user service connection using the specified connection string.
func NewGRPCService(ctx context.Context, connString, cert, domain, token string, verbose int) (GRPCService, error) {
	var err error
	var conn *grpc.ClientConn
	var opts []grpc.DialOption

	// Set up the credentials for the connection.
	if cert == "" {
		opts = append(opts, grpc.WithInsecure())
	} else {
		// secure (TLS) gRPC connection
		// for details see
		// https://github.com/grpc/grpc-go/blob/master/Documentation/grpc-auth-support.md
		// https://pkg.go.dev/google.golang.org/grpc/credentials
		creds, err := credentials.NewClientTLSFromFile(cert, domain)
		if err != nil {
			return nil, err
		}
		if verbose > 0 {
			log.Println("credentials", creds, err)
		}
		perRPC := oauth.NewOauthAccess(fetchToken(token, verbose))
		opts = []grpc.DialOption{
			grpc.WithPerRPCCredentials(perRPC),
			grpc.WithTransportCredentials(creds),
			grpc.WithBlock(),
		}
	}

	conn, err = grpc.DialContext(ctx, connString, opts...)
	//     conn, err = grpc.Dial(connString, opts...)
	if err != nil {
		return nil, err
	}
	if verbose > 0 {
		log.Println("gRPC connection", conn)
	}
	return &grpcService{grpcClient: cms.NewDataServiceClient(conn)}, nil
}

// GetData implements grpcServer GetData API
func (s *grpcService) GetData(req *cms.Request) (*cms.Response, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancelFunc()
	// pass incoming gRPC request to backend gRPC server
	resp, err := s.grpcClient.GetData(ctx, req)
	return resp, err
}
