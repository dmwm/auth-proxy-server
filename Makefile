GITVERSION=`git rev-parse --short HEAD`
VERSION=`git describe --tags`
#flags=-ldflags="-s -w -X main.gitVersion=${GITVERSION} -X main.version=${VERBOSE}"
OS := $(shell uname)
ifeq ($(OS),Darwin)
flags=-ldflags="-s -w -X main.gitVersion=${GITVERSION} -X main.tagVersion=${VERSION}"
else
flags=-ldflags="-s -w -X main.gitVersion=${GITVERSION} -X main.tagVersion=${VERSION} -extldflags -static"
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

build_decode:
	CGO_ENABLED=0 go build -o decode-token ${flags} decode/token.go

build_debug:
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o auth-proxy-server ${flags} -gcflags="-m -m"

build_amd64: build_linux

build_darwin:
	go clean; rm -rf pkg auth-proxy-server; GOOS=darwin CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=darwin CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=darwin CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go
	GOOS=darwin CGO_ENABLED=0 go build -o decode-token ${flags} decode/token.go

build_linux:
	go clean; rm -rf pkg auth-proxy-server; GOOS=linux CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=linux CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=linux CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go
	GOOS=linux CGO_ENABLED=0 go build -o decode-token ${flags} decode/token.go
	mkdir -p /tmp/auth-proxy-tools/amd64
	cp auth-proxy-server token-manager auth-token decode-token /tmp/auth-proxy-tools/amd64

build_power8:
	go clean; rm -rf pkg auth-proxy-server; GOARCH=ppc64le GOOS=linux CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=linux GOARCH=ppc64le CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=linux GOARCH=ppc64le CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go
	GOOS=linux GOARCH=ppc64le CGO_ENABLED=0 go build -o decode-token ${flags} decode/token.go
	mkdir -p /tmp/auth-proxy-tools/power8
	cp auth-proxy-server token-manager auth-token decode-token /tmp/auth-proxy-tools/power8

build_arm64:
	go clean; rm -rf pkg auth-proxy-server; GOARCH=arm64 GOOS=linux CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o decode-token ${flags} decode/token.go
	mkdir -p /tmp/auth-proxy-tools/arm64
	cp auth-proxy-server token-manager auth-token decode-token /tmp/auth-proxy-tools/arm64

build_windows:
	go clean; rm -rf pkg auth-proxy-server; GOARCH=amd64 GOOS=windows CGO_ENABLED=0 go build -o auth-proxy-server ${flags}
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o auth-token ${flags} client/auth-token.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o token-manager ${flags} manager/token.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o decode-token ${flags} decode/token.go
	mkdir -p /tmp/auth-proxy-tools/windows
	cp auth-proxy-server token-manager auth-token decode-token /tmp/auth-proxy-tools/windows

install:
	go install

clean:
	go clean; rm -rf pkg; rm -rf auth-proxy-tools

test : test1

test1:
	# we filter 401 and unauthorized log messages as we perform test without
	# user credentials in BenchmarkX509RequestHandler
	go test -v -race -bench=. | egrep -v "401 GET|unauthorized access"

tarball:
	cp -r /tmp/auth-proxy-tools .
	tar cfz auth-proxy-tools.tar.gz auth-proxy-tools
	rm -rf /tmp/auth-proxy-tools

changes:
	./gen_release_log.sh

last_changes:
	./extract_last_changes.sh 2>&1 1>& last_changes.txt

release: clean build_amd64 build_arm64 build_windows build_power8 build_darwin tarball changes
