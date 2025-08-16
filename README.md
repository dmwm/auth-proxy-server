### auth-proxy-server

[![Go CI build](https://github.com/dmwm/auth-proxy-server/actions/workflows/go-ci.yml/badge.svg)](https://github.com/dmwm/auth-proxy-server/actions/workflows/go-ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/dmwm/auth-proxy-server)](https://goreportcard.com/report/github.com/dmwm/auth-proxy-server)

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
- [middleware.go](middleware.go) middleware functions
- [trouble.go](trouble.go) certification troubleshooting

Both server implementations (oauthProxyServer and x509ProxyServer) support
/server end-point which can be used to update server settings, e.g.
curl -X POST -H"Content-type: application/json" -d '{"verbose":true}' https://a.b.com/server

This codebase is based on different examples taken from:
- [Reverse proxy server in one line](https://hackernoon.com/writing-a-reverse-proxy-in-just-one-line-with-go-c1edfa78c84b)
- [Reverse proxy server demo](https://github.com/bechurch/reverse-proxy-demo/blob/master/main.go)
- [Reverse proxy server](https://imti.co/golang-reverse-proxy/)
- [Metrics in reverse proxy server](https://itnext.io/capturing-metrics-with-gos-reverse-proxy-5c36cb20cb20)
- [GoLang reverse proxy](https://www.integralist.co.uk/posts/golang-reverse-proxy/)

### Examples
Here we will provide few examples how to run APS (auth-proxy-server) in
different modes:
- first mode is X509 server which accepts users certificates. The user
  certificate verification is done via TLS handshake mode (before passing HTTP
  request to particular end-point):
```
# x509 server
auth-proxy-server -port 7743 -useX509 -config config.json
```
- x509 server with mix modes TLS handshake certification verification for all
  end-points and additional middleware certificte verication for dedicated
  end-point). This mode is useful to provide end-users a web UI interface
  to inspect and troubleshoot their certificates

```
# x509 server with additional /auth/trouble on separate port
# please include in your config.json the option
# please include in your config.json the option
# "auth_trouble_port": 4443 // or any port you want
auth-proxy-server -port 7743 -useX509 -config config.json

# in this mode you'll get APS with two ports, one main port for all HTTP
# requests and another (port 4443) where /auth/trouble end-point will be served
```

- x509 server with midleeware certificate verification (during TLS handshake
layer server will accept any user certificate but it will be verified within
middleware layer but before passing request to particular end-point). This
method provides ability to customize HTTP response when user provide wrong
certificate but adds overhead (and loose rejection of clients at TLS handshake
mode) in terms of processing of user ceriticates.

```
# x509 server with additional /auth/trouble on separate port
# please include in your config.json the option
# "x509MiddlewareServer": true,
auth-proxy-server -port 7743 -useX509 -config config.json
```

- OAuth server with token based authentication

```
# oauth server, in this mode your config should have the following settings:
#    "client_id": "xxx",
#    "client_secret": "yyy",
#    "iam_client_id": "abc",
#    "iam_client_secret": "sldkfjlskdfj",
#    "iam_url": "https://cms-auth.web.cern.ch",
#    "oauth_url": "https://auth.cern.ch/auth/realms/cern",
#    "providers": ["https://auth.cern.ch/auth/realms/cern"],
auth-proxy-server -port 7743 -config config.json
```
