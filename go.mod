module github.com/dmwm/auth-proxy-server

go 1.23.0

require (
	github.com/coreos/go-oidc/v3 v3.11.0
	github.com/dmwm/auth-proxy-server/auth v0.0.0-20240904171434-807d5a71f43e
	github.com/dmwm/auth-proxy-server/cric v0.0.0-20240904171434-807d5a71f43e
	github.com/dmwm/auth-proxy-server/logging v0.0.0-20240904171434-807d5a71f43e
	github.com/dmwm/cmsauth v0.0.4
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/google/uuid v1.6.0
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/stretchr/testify v1.9.0
	github.com/thomasdarimont/go-kc-example v0.0.0-20170529223628-e3951d8faa4c
	golang.org/x/crypto v0.26.0
	golang.org/x/oauth2 v0.23.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lestrrat-go/strftime v1.0.6 // indirect
	github.com/pascaldekloe/jwt v1.12.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/tklauser/go-sysconf v0.3.14 // indirect
	github.com/tklauser/numcpus v0.8.0 // indirect
	github.com/vkuznet/TokenManager v0.0.1 // indirect
	github.com/vkuznet/x509proxy v0.0.0-20210801171832-e47b94db99b6 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	golang.org/x/term v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/dmwm/auth-proxy-server/logging => /Users/vk/Work/Languages/Go/gopath/src/github.com/dmwm/auth-proxy-server/logging
