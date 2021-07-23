### gRPC proxy server
This area contains proof of concept for gRPC proxy server. It can be
implemented in two different modes:
- HTTP proxy server to talk to gRPC backend (this implementation)
  - it consumes HTTP requests from clients using token based authentication
  and construct gRPC request to the server. Then it return results from gRPC
  server back to the client
```
client (HTTP) -> http+gRPC server (performs auth/authz) -> gRPC backend server
```
In this case, the client can use HTTP POST request and provide necessary data.

- gRPC proxy server which only talks gRPC protocol between gRPC client and gRPC backend
server. For this we need to setup proper gRPC data format which will
include authorization token, see cms/service.proto
```
client (gRPC) -> gRPC server (performs auth/authz) -> gRPC backend server
```
In this case, gRPC client should provide data with token where token will
be part of gRPC data structure.

To build the code we need to build proper gRPC service which can be
found in cms area. The `service.proto` defines data representation used
between gRPC parties. To build this code follow this command:
```
cd cms
protoc -I=$PWD --go_out=plugins=grpc:$PWD $PWD/service.proto
```
Then, build http+gRPC server using this command:
```
cd .. # return from cms area to grpc one
go build
```
To start the service you'll need a proper configuration which is defined in
`server.go` Configruation struct:
```
# Configuration for http+gRPC proxy server
{
    "base": "",
    "http_server": true,
    "server_cert": "/Users/vk/certificates/tls.crt",
    "server_key": "/Users/vk/certificates/tls.key",
    "grpc_address": "0.0.0.0:9999",
    "verbose": 1,
    "port": 8443
}
# Configuration for secure gRPC proxy server
{
    "base": "",
    "http_server": false,
    "server_cert": "/Users/vk/certificates/tls.crt",
    "server_key": "/Users/vk/certificates/tls.key",
    "grpc_address": "0.0.0.0:9999",
    "verbose": 1,
    "port": 8443
}
# Configuration for non-secure gRPC proxy server
{
    "base": "",
    "http_server": false,
    "server_cert": "",
    "server_key": "",
    "grpc_address": "0.0.0.0:9999",
    "verbose": 1,
    "port": 8888
}
```

### References:
- [gRPC example](https://towardsdatascience.com/grpc-in-golang-bb40396eb8b1)
- [gRPC tutorial](https://grpc.io/docs/languages/go/basics/)
- [gRPC google documentation](https://pkg.go.dev/google.golang.org/grpc)
- [gRPC authentication](https://github.com/grpc/grpc-go/blob/master/Documentation/grpc-auth-support.md)
