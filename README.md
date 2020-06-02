### auth-proxy-server
A basic implementation of OAuth OIDC based auth proxy server. To run it use the
following:
```
# to build
go build proxy_auth_server.go

# to run in k8s
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
    "cms_headers": true,
    "update_cric": 3600,
    "ingress": [
        {"path":"/path", "service_url":"http://srv.namespace.svc.cluster.local:<port>"}
    ],
    "verbose": false,
    "port": 8181
}
EOF
proxy_auth_server -config config.json
```
