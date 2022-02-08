### scitokens Go based server
The `scitokens.go` implements [Scitokens](https://scitokens.org/)
server which issue the scitoken and consumes it for redirecting
to CMS services via logic of reverse proxy function. Here we provide
a typical workflow on server and client side:

#### server side workflow
Obtain `scitokens-admin-create-key`
tool from [Scitokens](https://github.com/scitokens/scitokens) repository
and/or generate RSA256 certificate (see below)

```
# install python venv
python3 -m venv venv
cd venv
source bin/activate

# install required package
pip install scitokens


# issue proper server PEM file which contains both private and public RSA keys
scitokens-admin-create-key --create-keys --pem-private --pem-public > /tmp/issuer.pem

# optionally you may generate jwks files
scitokens-admin-create-key --private-keyfile /tmp/issuer.pem --jwks-private > /tmp/issuer_key.jwks
scitokens-admin-create-key --public-keyfile /tmp/issuer.pem --jwks-public > /tmp/issuer_public.jwks

# start the server
./auth-proxy-server -config config.json -scitokens
```

#### generate RSA keypair
Optionally you may generate RSA keypair via `openssl` command and use them
instead of `scitokens-admin-create-key` tool. Here how you can do it:
```
# generate a 2048 bit RSA Key
openssl genrsa -des3 -out private.pem 2048

# Export the RSA Public Key to a File
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# create single issuer.pem file out of the two
cat private.pem public.pem > /tmp/issuer.pem

# use issuer.pem file in your server configuration
```

#### client side workflow
For clarify we use here `localhost:8443` as our server:port pair which will
be properly assigned at a deployment time to some DNS alias.
```
# initiate client's request to obtain new token
scurl -d grant_type=client_credentials https://localhost:8443/token

# validate client with existing JWT token
scurl -H "Authorization: bearer $token" https://localhost:8443/token/validate

# access resource (httpgo) using valid JWT token
scurl -H "Authorization: bearer $token" https://localhost:8443/httpgo
```
