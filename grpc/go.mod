module github.com/vkuznet/auth-proxy-server/grpc

go 1.16

require (
	cloud.google.com/go/compute v1.10.0 // indirect
	github.com/golang/protobuf v1.5.2
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	github.com/lestrrat-go/strftime v1.0.6 // indirect
	github.com/pascaldekloe/jwt v1.12.0 // indirect
	github.com/vkuznet/auth-proxy-server/auth v0.0.0-20221007130226-52e0a5feeaa6
	github.com/vkuznet/auth-proxy-server/cric v0.0.0-20221007130226-52e0a5feeaa6
	github.com/vkuznet/auth-proxy-server/logging v0.0.0-20221007130226-52e0a5feeaa6
	github.com/vkuznet/x509proxy v0.0.0-20210801171832-e47b94db99b6 // indirect
	golang.org/x/net v0.0.0-20221004154528-8021a29435af
	golang.org/x/oauth2 v0.0.0-20221006150949-b44042a4b9c1
	golang.org/x/sys v0.0.0-20221006211917-84dc82d7e875 // indirect
	google.golang.org/genproto v0.0.0-20220930163606-c98284e70a91 // indirect
	google.golang.org/grpc v1.50.0
)
