### auth-proxy-server

[![Build Status](https://travis-ci.org/vkuznet/auth-proxy-server.svg?branch=master)](https://travis-ci.org/vkuznet/auth-proxy-server)
[![Go Report Card](https://goreportcard.com/badge/github.com/vkuznet/auth-proxy-server)](https://goreportcard.com/report/github.com/vkuznet/auth-proxy-server)

Go implementation of reverse proxy server with with OAuth OIDC or x509 authentication.
It provides CMS authentication headers based on CRIC information, and
build-in rotate logs functionality.

#### Server configuration
The server relies on the followign configuration file:
```
# server configuration file, for more see Config struct in the code
cat > config.json << EOF
{
    "base": "",
    "client_id": "xxx",
    "client_secret": "xxx-yyy-zzz"
    "oauth_url": "https://auth.cern.ch/auth/realms/cern",
    "server_cert": "/etc/secrets/tls.crt",
    "server_key": "/etc/secrets/tls.key",
    "redirect_url": "redirect_url",
    "hmac": "/etc/secrets/hmac",
    "document_root": "/www",
    "cric_url": "cric_url",
    "cric_file": "/etc/secrets/cric.json",
    "update_cric": 3600,
    "ingress": [
        {"path":"/path", "service_url":"http://services.namespace.svc.cluster.local:<port>"}
    ],
    "cms_headers": true,
    "rootCAs": ["/path/certificates/CA.crt", "/path/certificates/CA1.crt"],
    "verbose": false,
    "log_file": "/tmp/access.log",
    "port": 8181
}
EOF
```
The ingress section allows to route incoming requests to specified backend
services and it is based on path matching. The `log_file` controls writing logs
to provided log file, the logs will be rotated on daily basis.
The `cric_url` and `cric_file` controls CRIC usage. If `cric_file` is provided
it will be used to initialize CRIC map which later can be updated by fetching
data through `cric_url`. The `update_cric` controls update interval for
fetching new CRIC map.

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
proxy_auth_server -config config.json

# to run with x509 authentication
proxy_auth_server -config config.json -useX509
```

### Benchmarks
We benchmark code in k8s cluster with 8GB of RAM and 4CPUs node. For comparison
we deployed apache frontend server and used
[hey](https://github.com/vkuznet/hey) tool (with x509 support) to run the
tests. For our results we used [httpgo](docs/httpgo.go) services behind
reverse proxy which only return HTTP requests headers.

Here are the results of our tests using 1000 requests and different set of
concurrent clients (100, 200, 300, 400, 500). Each time we measured average
requests/second throughput as well as count number of successfull and failed
responses. For tests below we disabled keep-alive to simulate load from
distributed clients.

#### throughput measurements
The following plots shows throughput performance of Go-based and apache based
reverse proxy servers. Here we use the following notations: Go-auth-srvN and
Apache-srvN where N refers to number of replicas of given server in k8s
setup, i.e. srv4 means we run 4 replicas of that server in k8s cluster.
![Throughput](https://github.com/vkuznet/auth-proxy-server/raw/master/docs/perf-rps.png)

#### failure rate measurements
![Failure-rate](https://github.com/vkuznet/auth-proxy-server/raw/master/docs/perf-failure.png)

#### Additional remarks
We also want to point out that k8s image sizes are quite different, the
Go-based server has uncompressed size of 12.4MB/5.18MB (for uncompressed/compressed),
while cmsweb frontend image is 1.97GB/707MB, respectively. The average memory
usage of srv4 tests was 20MB for Go-based server, and 1GB or more for apache one.
And, CPU usage was about 900 millicore for Go-based server and 400 millicore for
apache one.

### Test with DBS service
We also performed more realistics tests using frontend (apache or Go-based) and
DBS services with different queries. As before, srvN correspond to number of
fronends used in tests, and keep-alive option was disabled in tests.

In these tests we used DBS datasets queries with different dataset names.

#### throughput measurements
![Throughput](https://github.com/vkuznet/auth-proxy-server/raw/master/docs/perf-rps-dbs.png)

#### failure rate measurements
![Failure-rate](https://github.com/vkuznet/auth-proxy-server/raw/master/docs/perf-failure-dbs.png)
