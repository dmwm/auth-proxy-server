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

	"github.com/vkuznet/auth-proxy-server/grpc/cms"
	"google.golang.org/grpc"
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
	flag.StringVar(&address, "address", "", "gRPC address, e.g. 0.0.0.0.:9999")
	flag.Parse()
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Error %v", err)
	}
	log.Printf("gRPC server is listening on %v ...", address)

	s := grpc.NewServer()
	cms.RegisterDataServiceServer(s, &server{})

	s.Serve(lis)
}
