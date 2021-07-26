module github.com/vkuznet/auth-proxy-server/grpc

go 1.16

require (
	github.com/golang/protobuf v1.5.2
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	github.com/lestrrat-go/strftime v1.0.5 // indirect
	github.com/vkuznet/auth-proxy-server/auth v0.0.0-20210726200103-cffa690dda9b
	github.com/vkuznet/auth-proxy-server/cric v0.0.0-20210726200103-cffa690dda9b
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	google.golang.org/grpc v1.39.0
)
