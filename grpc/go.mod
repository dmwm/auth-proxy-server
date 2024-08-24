module github.com/dmwm/auth-proxy-server/grpc

go 1.23.0

require (
	github.com/dmwm/auth-proxy-server/auth v0.0.0-20240824201455-d491444f799e
	github.com/dmwm/auth-proxy-server/cric v0.0.0-20240824201455-d491444f799e
	github.com/dmwm/auth-proxy-server/logging v0.0.0-20240824201455-d491444f799e
	github.com/golang/protobuf v1.5.4
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	golang.org/x/net v0.28.0
	golang.org/x/oauth2 v0.22.0
	google.golang.org/grpc v1.65.0
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/dmwm/cmsauth v0.0.3 // indirect
	github.com/lestrrat-go/strftime v1.0.6 // indirect
	github.com/pascaldekloe/jwt v1.12.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/vkuznet/x509proxy v0.0.0-20210801171832-e47b94db99b6 // indirect
	golang.org/x/sys v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240528184218-531527333157 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
)
