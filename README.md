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

### Code organization
The code is implemented as the following modules:
- [config.go](config.go) provides server configuration methods
- [cric.go](cric/cric.go) provides CMS CRIC service functionality
- [data.go](data.go) holds all data structures used in the package
- [logging.go](logging/logging.go) provides logging functionality
- [iam.go](iam.go) module provides all necessary logic to handle IAM
- [main.go](main.go) the main module
- [metrics.go](metrics.go) Prometheus metrics module
- [oauth.go](oauth.go) provides implementation of oathProxyServer
- [redirect.go](redirect.go) provides logic of reverse proxy
- [server.go](server.go) provides main APS server logic
- [scitokens.go](scitokens.go) module provides support for [SciTokens](https://scitokens.org/)
- [utils.go](utils.go) provides various utils used in a code
- [x509.go](x509.go) provides implementation of x509ProxyServer

Both server implementations (oauthProxyServer and x509ProxyServer) support
/server end-point which can be used to update server settings, e.g.
curl -X POST -H"Content-type: application/json" -d '{"verbose":true}' https://a.b.com/server

This codebase is based on different examples taken from:
- [Reverse proxy server in one line](https://hackernoon.com/writing-a-reverse-proxy-in-just-one-line-with-go-c1edfa78c84b)
- [Reverse proxy server demo](https://github.com/bechurch/reverse-proxy-demo/blob/master/main.go)
- [Reverse proxy server](https://imti.co/golang-reverse-proxy/)
- [Metrics in reverse proxy server](https://itnext.io/capturing-metrics-with-gos-reverse-proxy-5c36cb20cb20)
- [GoLang reverse proxy](https://www.integralist.co.uk/posts/golang-reverse-proxy/)
