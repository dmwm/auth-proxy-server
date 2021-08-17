The gRCP client follows example from
[grpc-go client](https://github.com/grpc/grpc-go/blob/master/examples/features/authentication/client/main.go).

In order to properly use it with end-to-end TLS encryption several steps will
be required, e.g.
```
# on your server side please provide proper server certiciates

# enable debug printout of gRPC machinery
export GRPC_GO_LOG_VERBOSITY_LEVEL=99
export GRPC_GO_LOG_SEVERITY_LEVEL=info

# if you use self signed certificates
# https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309
# then you'll need to enable the following option
export GODEBUG=x509ignoreCN=0

# obtain valid token
token=....

# place gRPC client call
./grpc-client -address "127.0.0.1:1443" -token=$token -rootCA=/path/rootCA.crt -domain="mydomain.com"
```
