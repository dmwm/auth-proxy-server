### gRPC proxy server
This area contains proof of concept for gRPC proxy server. It can be
implemented in two different modes:
- HTTP proxy server to talk to gRPC backend (this implementation)
  - it consumes HTTP requests from clients using token based authentication
  and construct gRPC request to the server. Then it return results from gRPC
  server back to the client
- gRPC proxy server which only talks gRPC protocol between client and backend
gRPC server. For this we need to setup proper gRPC data format which will
include authorization token.

To build the code we need to (adjust) build proper gRPC service which can be
found in cms area:
```
cd cms
protoc -I=$PWD --go_out=plugins=grpc:$PWD $PWD/service.proto
```
Then, build http-gRPC server using this command:
```
go build
```
The client can use HTTP POST request and provide necessary data.

### References:
[1] https://towardsdatascience.com/grpc-in-golang-bb40396eb8b1
[2] https://grpc.io/docs/languages/go/basics/
[3] https://pkg.go.dev/google.golang.org/grpc
[4] https://github.com/vkuznet/mysvc
[5] https://github.com/mwitkow/grpc-proxy
[6] https://github.com/grpc/grpc-go/blob/master/Documentation/grpc-auth-support.md
