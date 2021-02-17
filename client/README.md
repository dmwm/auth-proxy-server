The `auth-token` client is a simple tool to acquire a token from CERN SSO
authentication. For that user requires to provide `clientId` and `clientSecret`
parameters which should be known a-priori.

```
# setup environment and obtain dependencies
export GOPATH=/path/to/your/gopath/area
go get golang.org/x/crypto/ssh/terminal

# build client
go build auth-token.go

# run client
./auth-token -clientId <id> -clientSecret <secret>
# provide output in JSON format
./auth-token -clientId <id> -clientSecret <secret> -json
```
