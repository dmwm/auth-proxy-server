### scitokens Go based server
The `scitokens.go` implements [Scitokens](https://scitokens.org/)
server which issue the scitoken and consumes it for redirecting
to CMS services via logic of reverse proxy function. Here we provide
a typical workflow on server and client side:

#### server side workflow

```
# issue proper server PEM file which contains both private and public RSA keys
scitokens-admin-create-key --create-keys --pem-private --pem-public > /tmp/issuer.pem

# start the server
./auth-proxy-server -config config.json -scitokens
```

#### client side workflow
For clarify we use here `localhost:8443` as our server:port pair which will
be properly assigned at a deployment time to some DNS alias.
```
# initiate client's request to obtain new token
scurl -d grant_type=client_credentials https://localhost:8443/token

# validate client with existing JWT token
scurl -H "Authorization: bearer $token" https://localhost:8443/validate

# access resource (httpgo) using valid JWT token
scurl -H "Authorization: bearer $token" https://localhost:8443/httpgo
```
