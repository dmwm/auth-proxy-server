module github.com/dmwm/auth-proxy-server/grpc

go 1.25.0

require (
	github.com/dmwm/auth-proxy-server/auth v0.0.0-20260226182337-f82102e24d5c
	github.com/dmwm/auth-proxy-server/cric v0.0.0-20260226182337-f82102e24d5c
	github.com/dmwm/auth-proxy-server/logging v0.0.0-20260226182337-f82102e24d5c
	github.com/golang/protobuf v1.5.4
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	golang.org/x/net v0.52.0
	golang.org/x/oauth2 v0.36.0
	google.golang.org/grpc v1.79.3
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/dmwm/cmsauth v0.0.4 // indirect
	github.com/lestrrat-go/strftime v1.1.1 // indirect
	github.com/pascaldekloe/jwt v1.12.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/vkuznet/x509proxy v1.0.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260316180232-0b37fe3546d5 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
