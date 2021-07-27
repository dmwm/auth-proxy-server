package main

// gRPC client example based on auth-proxy-server/grpc/cms representation
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/vkuznet/auth-proxy-server/grpc/cms"
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

// fetchToken simulates a token lookup and omits the details of proper token
// acquisition. For examples of how to acquire an OAuth2 token, see:
// https://godoc.org/golang.org/x/oauth2
func fetchToken(token string) *oauth2.Token {
	log.Println("client token", token)
	return &oauth2.Token{
		AccessToken: token,
	}
}

// NewGRPCService creates a new gRPC user service connection using the specified connection string.
func NewGRPCService(connString, cert, token string) (GRPCService, error) {
	var err error
	var conn *grpc.ClientConn
	var opts []grpc.DialOption

	// Set up the credentials for the connection.
	perRPC := oauth.NewOauthAccess(fetchToken(token))
	if cert == "" {
		opts = append(opts, grpc.WithInsecure())
	} else {

		// secure (TLS) gRPC connection
		// for details see
		// https://github.com/grpc/grpc-go/blob/master/Documentation/grpc-auth-support.md
		// https://pkg.go.dev/google.golang.org/grpc/credentials
		creds, err := credentials.NewClientTLSFromFile(cert, "")
		if err != nil {
			return nil, err
		}
		opts = []grpc.DialOption{
			grpc.WithPerRPCCredentials(perRPC),
			grpc.WithTransportCredentials(creds),
		}
		opts = append(opts, grpc.WithBlock())
	}

	conn, err = grpc.Dial(connString, opts...)
	if err != nil {
		return nil, err
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

func main() {
	var address string
	flag.StringVar(&address, "address", "", "gRPC address")
	var token string
	flag.StringVar(&token, "token", "", "gRPC authorization token")
	var rootCA string
	flag.StringVar(&rootCA, "rootCA", "", "root CA rootCAificate file(s) to validate server connections")
	flag.Parse()
	log.SetFlags(log.Lshortfile)

	backendGRPC, err := NewGRPCService(address, rootCA, token)
	if err != nil {
		log.Fatal(err)
	}
	data := &cms.Data{Id: 1, Token: token}
	req := &cms.Request{Data: data}
	resp, err := backendGRPC.GetData(req)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("gRPC response", resp.String())
}
