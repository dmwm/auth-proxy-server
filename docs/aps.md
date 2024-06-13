# Auth-Proxy-Server (APS)
The auth-proxy-server is generic Go-base HTTP frontend which supports the
following features:
- it supports token based authentication
- it supports X509 authentication
- it supports scitokens

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
