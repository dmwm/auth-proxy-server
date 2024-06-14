### auth-proxy-server

[![Go CI build](https://github.com/vkuznet/auth-proxy-server/actions/workflows/go-ci.yml/badge.svg)](https://github.com/vkuznet/auth-proxy-server/actions/workflows/go-ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/vkuznet/auth-proxy-server)](https://goreportcard.com/report/github.com/vkuznet/auth-proxy-server)

Go implementation of reverse proxy server with OAuth OIDC or x509 authentication.
It provides CMS authentication headers based on CRIC information, and
build-in rotate logs functionality.

For full details please refer to this [document](docs/aps.md).


#### Building and runnign the code

The code can be build as following:
```
# to build
make
# or use go build command
go build -ldflags="-X main.version=`git rev-parse --short HEAD`"
```

To run the service we can choose either between CERN SSO OAuth2 OICD
authentication or x509 one. In both cases, please provide CRIC file and/or URL.
```
# to run with CERN SSO OAuth OICD authentication
auth-proxy-server -config config.json

# to run with x509 authentication
auth-proxy-server -config config.json -useX509
```
