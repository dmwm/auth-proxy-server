VERSION=`git rev-parse --short HEAD`
#flags=-ldflags="-s -w -X main.version=${VERSION}"
OS := $(shell uname)
ifeq ($(OS),Darwin)
flags=-ldflags="-s -w -X main.version=${VERSION}"
else
flags=-ldflags="-s -w -X main.version=${VERSION} -extldflags -static"
endif

all: build build_client build_token

vet:
	go vet .

build:
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o auth-proxy-server ${flags}

build_client:
	CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go

build_token:
	CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go

build_debug:
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o auth-proxy-server ${flags} -gcflags="-m -m"

build_amd64: build_linux

build_darwin:
	go clean; rm -rf pkg auth-proxy-server; GOOS=darwin CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=darwin CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=darwin CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go

build_linux:
	go clean; rm -rf pkg auth-proxy-server; GOOS=linux CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=linux CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=linux CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go

build_power8:
	go clean; rm -rf pkg auth-proxy-server; GOARCH=ppc64le GOOS=linux CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=linux GOARCH=ppc64le CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=linux GOARCH=ppc64le CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go

build_arm64:
	go clean; rm -rf pkg auth-proxy-server; GOARCH=arm64 GOOS=linux CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go

build_windows:
	go clean; rm -rf pkg auth-proxy-server; GOARCH=amd64 GOOS=windows CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go

install:
	go install

clean:
	go clean; rm -rf pkg

test : test1

test1:
	go test -v -bench=.
