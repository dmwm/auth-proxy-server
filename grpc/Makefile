VERSION=`git rev-parse --short HEAD`
#flags=-ldflags="-s -w -X main.version=${VERSION}"
OS := $(shell uname)
ifeq ($(OS),Darwin)
flags=-ldflags="-s -w -X main.version=${VERSION}"
else
flags=-ldflags="-s -w -X main.version=${VERSION} -extldflags -static"
endif

all: build

vet:
	go vet .

build:
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o grpc-proxy-server ${flags}

build_debug:
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o grpc-proxy-server ${flags} -gcflags="-m -m"

build_amd64: build_linux

build_darwin:
	go clean; rm -rf pkg grpc-proxy-server; GOOS=darwin CGO_ENABLED=0 go build -o grpc-proxy-server ${flags}

build_linux:
	go clean; rm -rf pkg grpc-proxy-server; GOOS=linux CGO_ENABLED=0 go build -o grpc-proxy-server ${flags}

build_power8:
	go clean; rm -rf pkg grpc-proxy-server; GOARCH=ppc64le GOOS=linux CGO_ENABLED=0 go build -o grpc-proxy-server ${flags}

build_arm64:
	go clean; rm -rf pkg grpc-proxy-server; GOARCH=arm64 GOOS=linux CGO_ENABLED=0 go build -o grpc-proxy-server ${flags}

build_windows:
	go clean; rm -rf pkg grpc-proxy-server; GOARCH=amd64 GOOS=windows CGO_ENABLED=0 go build -o grpc-proxy-server ${flags}

install:
	go install

clean:
	go clean; rm -rf pkg

test : test1

test1:
	go test -v -bench=.
