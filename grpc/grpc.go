package main

// grpc module provides gRPC service
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>

import (
	"context"
	"time"

	cms "github.com/vkuznet/auth-proxy-server/grpc/cms"
	"google.golang.org/grpc"
)

var defaultRequestTimeout = time.Second * 10

// Service defines the interface exposed by this package.
type GRPCService interface {
	GetData(request *cms.Request) (*cms.Response, error)
}

type grpcService struct {
	grpcClient cms.DataServiceClient
}

// NewGRPCService creates a new gRPC user service connection using the specified connection string.
func NewGRPCService(connString string) (GRPCService, error) {
	conn, err := grpc.Dial(connString, grpc.WithInsecure())
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
