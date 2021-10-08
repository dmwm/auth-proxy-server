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
server.
```
client (gRPC) -> gRPC server (performs auth/authz) -> gRPC backend server
```
In this case, gRPC client should provide data with token.

In addition, the communication between gRPC proxy server and backend one
can be encrypted or not (so far in this repository it is not the case, but
can be easily added to proxy server via additional grpc options, see example
in backend/client area).

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
    "providers": [... list of OAuth providers ...],
    "cric_url": "CRIC_URL_HERE",
    "cric_file": "/path/cric.json (optional)",
    "update_cric": 36000,
    "verbose": 1,
    "port": 8443
}
# Configuration for secure gRPC proxy server:
{
    ...
    "http_server": false,
    ...
}
# Configuration for non-secure gRPC proxy server:
{
    ...
    "http_server": false,
    "server_cert": "",
    "server_key": "",
    ...
}
```

### Testing procedure
To test http+gRPC proxy server we need to setup 3 pieces:
##### Scenario I: http client
In this case we need http+gRPC proxy server, the gRPC backend server and
HTTP client. You may start the first two seaprately (in different terminals):
```
# create gRPC proxy server config:
cat > grpc-http.json << EOF
{
    "base": "",
    "http_server": true,
    "server_cert": "/path/hostcert.pem",
    "server_key":  "/path/hostkey.pem",
    "grpc_address": "0.0.0.0:9999",
    "providers": [... list of OAuth providers ...],
    "cric_url": "CRIC_URL_HERE",
    "cric_file": "/path/cric.json (optional)",
    "update_cric": 36000,
    "verbose": 1,
    "port": 8443
}
EOF

# compile the code if necessary (make) and start gRPC proxy server
./grpc-proxy-server -config grpc-http.json
...
[2021-07-24 09:37:16.697304 -0400 EDT m=+0.004304882] server.go:82: Starting HTTPs server on :8443
...
```
Then, start gRPC backend server:
```
# cd grpc/backend/server
# compile code
make
# start gRPC server
./grpc-server -address "0.0.0.0:9999"
```
Finally, we can use any HTTP based client to send our request, e.g.
```
curl -k -H "Authorization: bearer dymmy-token" https://localhost:8443/
```


##### Scenario II: gRPC client
In this case we need gRPC proxy server, the gRPC backend server and gRPC
client. You may start the first two separately (in different terminals):
```
# create secure gRPC proxy server config:
cat > grpc-secure.json << EOF
{
    "base": "",
    "http_server": false,
    "server_cert": "/path/hostcert.pem",
    "server_key":  "/path/hostkey.pem",
    "grpc_address": "0.0.0.0:9999",
    "providers": [... list of OAuth providers ...],
    "cric_url": "CRIC_URL_HERE",
    "cric_file": "/path/cric.json (optional)",
    "update_cric": 36000,
    "verbose": 1,
    "port": 8443
}
EOF

# compile the code if necessary (make) and start gRPC proxy server
./grpc-proxy-server -config grpc-secure.json
...
[2021-07-24 15:02:28.748320737 +0200 CEST m=+0.012208058] server.go:121: gRPC server is listening on 0.0.0.0:8443 ...
[2021-07-24 15:02:28.752045754 +0200 CEST m=+0.015933077] server.go:138: start secure gRPC proxy server with backend gRPC 0.0.0.0:9999
...
```
Then, start gRPC backend server:
```
# cd grpc/backend/server
# compile code
make
# start gRPC server
grpc-server -address "0.0.0.0:9999"
```
Finally, we can use `grpc-client` to test our proxy setup
```
# you'll need to replace <hostname> with actual hostname of gRPC proxy server
./grpc-client -address "<hostame>:8443" -token "some-secret-token" -rootCA=/path/rootCA.pem
```

If you want to disable security (development mode), you may start non-secure
gRPC proxy server with the following config:
```
# non-secure gRPC proxy config
cat > grpc-nonsecure.json << EOF
{
    "base": "",
    "grpc_address": "0.0.0.0:9999",
    "verbose": 1,
    "port": 8443
}
EOF

# start non-secure gRPC proxy server
./grpc-proxy-server -config grpc.json
...
[2021-07-24 09:39:05.443806 -0400 EDT m=+0.003433299] server.go:121: gRPC server is listening on 0.0.0.0:8443 ...
[2021-07-24 09:39:05.444003 -0400 EDT m=+0.003630668] server.go:141: start non-secure gRPC proxy server with backend gRPC 0.0.0.0:9999
```
and proceed as usual with gRPC client (in this case your client do not need
rootCA option), e.g.:
```
# you'll need to replace <hostname> with actual hostname of gRPC proxy server
./grpc-client -address "<hostame>:8443" -token "some-secret-token"
```

### End-to-end encryption
Here we describe how to setup gRPC proxy and gRPC client to server end-to-end
encryption. To start we need to either obtain valid certificates or
generate ones:
```
# Generate own self-signed certificates
# https://stackoverflow.com/questions/64814173/how-do-i-use-sans-with-openssl-instead-of-common-name

openssl genrsa -out rootCA.key 2048
openssl req -new -x509 -days 365 -key rootCA.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=Acme Root CA" -out rootCA.crt

openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=*.mydomain.com" -out server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:mydomain.com,DNS:www.mydomain.com") -days 365 -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out server.crt
```

Now, let's take two sceinarious:

#### End-to-end ecnription between gRPC client and gRPC server
First, we run gRPC server on port 9999
```
cd backend/server
make
# adjust path of certificates
./grpc-server -address "0.0.0.0:9999" -oauth \
    -serverCrt /Users/vk/certificates/self/server.crt \
    -serverKey /Users/vk/certificates/self/server.key
```
Then (in another window), we run gRPC client to connect to our server on port 9999
```
# obtain valid token
token=....

# visit client area and run the client
cd backend/client
./grpc-client -address "127.0.0.1:9999" \
    -token=$token \
    -rootCA=/Users/vk/certificates/self/rootCA.crt -domain="mydomain.com"
```

#### End-to-end ecnription between gRPC client and gRPC server via gRPC proxy server
Here we need three pieces, the gRPC server, gRPC proxy and gRPC client:

The gRPC server:
```
cd backend/server
make
# adjust path of certificates
./grpc-server -address "0.0.0.0:9999" -oauth \
    -serverCrt /Users/vk/certificates/self/server.crt \
    -serverKey /Users/vk/certificates/self/server.key
```

Now, we start gRPC proxy server with the following config:
```
{
    "base": "",
    "http_server": false,
    "providers": [...],
    "cric_url": "https://someurl.com
    "cric_file": "/Users/vk/certificates/cric.json",
    "server_cert": "/Users/vk/certificates/self/server.crt",
    "server_key": "/Users/vk/certificates/self/server.key",
    "grpc_address": "0.0.0.0:9999",
    "root_ca": "/Users/vk/certificates/self/rootCA.crt",
    "domain": "mydomain.com",
    "verbose": 1,
    "port": 8443
}
```
The config above defines IAM providers, cric parts, server certificates, root
CA, and grpc server address. The proxy will start on port 8443
```
# compile proxy server
make

# start server
./grpc-proxy-server -config grpc-secure.json
```

Finally, we can now run our client and point it to port of the proxy server
(8443):
```
# obtain valid token
token=....

# visit client area and run the client
cd backend/client
./grpc-client -address "127.0.0.1:8443" \
    -token=$token \
    -rootCA=/Users/vk/certificates/self/rootCA.crt -domain="mydomain.com"
```

We can also start gRPC proxy server in HTTP mode. For that we need to add
only `"http_server": true` to our proxy config file, and then use normal 
HTTP client like curl:
```
curl -k -H "Authorization: Bearer $token" https://localhost:8443/
```

### References:
- [gRPC example](https://towardsdatascience.com/grpc-in-golang-bb40396eb8b1)
- [gRPC tutorial](https://grpc.io/docs/languages/go/basics/)
- [gRPC google documentation](https://pkg.go.dev/google.golang.org/grpc)
- [gRPC authentication](https://github.com/grpc/grpc-go/blob/master/Documentation/grpc-auth-support.md)
- [gRPC oAuth](https://github.com/grpc/grpc-go/tree/master/examples/features/authentication)
