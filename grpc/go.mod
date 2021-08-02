module github.com/vkuznet/auth-proxy-server/grpc

go 1.16

require (
	github.com/golang/protobuf v1.5.2
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	github.com/lestrrat-go/strftime v1.0.5 // indirect
	github.com/vkuznet/auth-proxy-server/auth v0.0.0-20210801185242-f43234225c85
	github.com/vkuznet/auth-proxy-server/cric v0.0.0-20210801185242-f43234225c85
	github.com/vkuznet/auth-proxy-server/logging v0.0.0-20210801185242-f43234225c85
	github.com/vkuznet/x509proxy v0.0.0-20210801171832-e47b94db99b6 // indirect
	golang.org/x/net v0.0.0-20210726213435-c6fcb2dbf985
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	google.golang.org/genproto v0.0.0-20210729151513-df9385d47c1b // indirect
	google.golang.org/grpc v1.39.0
)
