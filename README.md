### auth-proxy-server
Go implementation of reverse proxy server with with OAuth OIDC or x509 authentication.
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
        {"path":"/path", "service_url":"http://srv.namespace.svc.cluster.local:<port>"}
    ],
    "cms_headers": true,
    "rootCAs": ["/path/certificates/CA.crt", "/path/certificates/CA1.crt"],
    "verbose": false,
    "port": 8181
}
EOF
```

The code can be build as following:
```
# to build
go build proxy_auth_server.go
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
responses.
![Throughput](https://github.com/vkuznet/auth-proxy-server/raw/master/docs/perf-rps.png)
![Failure-rate](https://github.com/vkuznet/auth-proxy-server/raw/master/docs/perf-failure.png)
