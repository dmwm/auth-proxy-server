package main

import (
	"context"
	"log"
	"time"

	cms "github.com/vkuznet/auth-proxy-server/grpc/cms"
	"google.golang.org/grpc"
)

var defaultRequestTimeout = time.Second * 10

// Service defines the interface exposed by this package.
type GrpcService interface {
	//     GetData(input interface{}) ([]byte, error)
	GetData(request *cms.Request) ([]byte, error)
}

type grpcService struct {
	grpcClient cms.DataServiceClient
}

// NewGRPCService creates a new gRPC user service connection using the specified connection string.
func NewGRPCService(connString string) (GrpcService, error) {
	conn, err := grpc.Dial(connString, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return &grpcService{grpcClient: cms.NewDataServiceClient(conn)}, nil
}

// func (s *grpcService) GetData(input interface{}) ([]byte, error) {
func (s *grpcService) GetData(req *cms.Request) ([]byte, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancelFunc()
	// TODO: we should read data from the input
	//     log.Printf("gRPC request: %+v\n", input)
	//     data := cms.Data{Id: 1, Token: "token"}
	//     req := &cms.Request{
	//         Data: &data,
	//     }
	resp, err := s.grpcClient.GetData(ctx, req)
	log.Println("gRPC response", resp, err)
	return []byte(resp.String()), err
}
