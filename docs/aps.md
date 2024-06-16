# Auth-Proxy-Server (APS)
The auth-proxy-server is generic Go-base HTTP frontend which supports the
following features:
- token based authentication
- X509 authentication (usually referred as XPS)
- scitokens (usually referred as SPS)
- gRPC protocol and clients, see [grpc](grpc/README.md) proxy server
(can be useful for ML backends)

### Configuration file
Here is basic example of APS configuration file:
```
{
    "base": "",
    "client_id": "CLIENT_ID",
    "client_secret": "CLIENT_SECRET",
    "iam_client_id": "IAM_CLIENT_ID",
    "iam_client_secret": "IAM_CLIENT_SECRET"
    "iam_url": "IAM_URL",
    "oauth_url": "OAUTH_URL",
    "providers": ["IAM_URL1", "IAM_URL2", ...],
    "static": "/path/auth-proxy-server/static/hello",
    "server_cert": "/path/certificates/tls.crt",
    "server_key": "/path/certificates/tls.key",
    "hmac": "/path/secrets/hmac",
    "document_root": "/path/www",
    "cric_url": "CMS_CRIC_URL",
    "cric_file": "CMS_CRIC_FILE (optional)",
    "cms_headers": true,
    "update_cric": 36000,
    "ingress": [
        {"path":"/httpgo", "service_url":"http://localhost:8888"},
        {"path":"/token", "service_url":"http://localhost:8443"}
    ],
    "rootCAs": "/etc/grid-security/certificates",
    "test_log_channel": true,
    "well_known": "/tmp/scitokens/.well-known",
    "scitokens": {
        "lifetime": 10,
        "issuer_key": "issuer-key",
        "issuer": "ISSUER_URL",
        "rules": [
          {"match": "fqan:/users", "scopes": ["read:/store", "write:/store/user/{username}"]},
          {"match": "fqan:/cms", "scopes": ["read:/store", "write:/store/user/{username}"]}
        ],
        "verbose": true,
        "secret": "some-secret-string",
        "public_jwks": "/tmp/issuer_public.jwks",
        "rsa_key": "/tmp/issuer.pem"
    },
    "monit_type": "cmsweb-auth",
    "monit_producer": "cmsweb-auth",
    "metrics_port": 9091,
    "verbose": 1,
    "port": 8181
}
```
Since CMS relies on CRIC service for DN matching the configuration can either
use CRIC URL directly to fetch users DNs or you may supply `cric_file` file.
The later is useful if you want to avoid CRIC service interruptions during
start-up of APS.

The ingress rule entries are represented as dictionary with the following
structure:
```
    {
      "path": "/couchdb/tier0_wmstats/_design/WMStats/_view/cooledoffRequests",
      "service_url": "http://xxx.cern.ch:5984",
      "old_path": "/couchdb/tier0_wmstats/_design/WMStats/_view/cooledoffRequests",
      "new_path": "/tier0_wmstats/_design/WMStatsErl4/_view/cooledoffRequests"
    },
```
Here we used one of the couchdb rules to explain all dictionary attributes:
- `path` represents API end-point of the service
- `service_url` points to service backend, it may include port if necessary
- `old_path` represents URI path which will be replaced by `new_path`
In this case, we replace `http://frontend.../couchdb/tier0_wmstats/_design/WMStats/_view/cooledoffRequests`
with `http://backend.../tier0_wmstats/_design/WMStatsErl4/_view/cooledoffRequests`.
The `old_path` to `new_path` substitution is useful in cases when frontend
and backend routes are different.

The full list of configuration options can be found in [data.go](../data.go).
The full list of CMS redirect rules can be found
[here](https://gitlab.cern.ch/cmsweb-k8s/services_config/-/tree/preprod/auth-proxy-server?ref_type=heads).
Please use appropriate branch if necessary.

### Deployment
To deploy APS you basically need Go-compiler and your infrastructure.
To compile code use the following:
```
# compile code
make

# run aps, default mode
./auth-proxy-server -config config.json

# run x509 server on dedicated port
./auth-proxy-server -config config.json -useX509 -port 7743
```
You can find CMS kubernetes deployment:
- [docker](https://github.com/dmwm/CMSKubernetes/blob/master/docker/auth-proxy-server/Dockerfile)
- [k8s manifest for daemonset](https://github.com/dmwm/CMSKubernetes/blob/master/kubernetes/cmsweb/daemonset/auth-proxy-server.yaml)

Please note, the static area in CMS is deployed as 
[side car container](https://github.com/dmwm/CMSKubernetes/blob/master/kubernetes/cmsweb/daemonset/auth-proxy-server.yaml#L143)

### Logging
The APS/XPS logging is provided by
[logging module](../logging/logging.go). In particular, this module mimic
apache log format but also enhance it further. For instance, here is a typical
log entry:
```
[2024-06-14 11:36:17.611781625 +0000 UTC m=+4111.311647917] HTTP/1.1 200 PUT /workqueue/_local/29c809a8e0d15785a82faf581c10796a [data: 11342 in 0 out] [remoteAddr: 188.185.123.179:11401] [X-Forwarded-For: 188.185.123.179:11401] [X-Forwarded-Host: cmsweb-xxx.cern.ch] [auth: TLS13 TLS_AES_128_GCM_SHA256 "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=user/CN=000000/CN=Robot:" user x509] [ref: "https://xxx.cern.ch" "CouchDB-Replicator/3.2.2"] [req: 32.514995ms proxy-resp: 32.107549ms]
```
As you can see the timestamp provide proper locale, i.e. UTC, and at the end it
provides request and proxy response times consumed by HTTP request

### Modules
The APS codebase provides additional modules for day-to-day operations. Here we
briefly list all of them:
- [auth-token client](client/README.md) allows fetch token from CERN SSO
- [decode token](decode/README.md) is a simple tool to decode given token and shows its details
  on stdout
- [cric module](cric/README.md) provides list of useful utilities to handle CMS
  CRIC data
- [token manager](manager/README.md) provides token manager, an utility to
  periodically obtain/renew tokens 
- [gRPC proxy server](grpc/README.md) provides fully function gRPC reverse
  proxy server. It supports both HTTP and gRPC clients via the following
  workflows:
```
# HTTP based client
client (HTTP) -> http+gRPC server (performs auth/authz) -> gRPC backend server

# gRPC client
client (gRPC) -> gRPC server (performs auth/authz) -> gRPC backend server
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

### References

- [Certified OpenID connect implementations](https://openid.net/developers/certified/)
- [JWT tokens](https://jwt.io/)
- [WLCG tokens](https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md)
- [SciTokens](https://scitokens.org/)
- [CERN SSO OAuth2 OICD](https://gitlab.cern.ch/authzsvc/docs/keycloak-sso-examples)
- JSON Web Token libraries: [jwt](https://github.com/pascaldekloe/jwt) and [jwt-go](https://github.com/dgrijalva/jwt-go)
