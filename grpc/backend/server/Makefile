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
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o grpc-server ${flags}

build_debug:
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o grpc-server ${flags} -gcflags="-m -m"

build_all: build_osx build_linux build

build_osx:
	go clean; rm -rf pkg grpc-server; GOOS=darwin CGO_ENABLED=0 go build -o grpc-server ${flags}

build_linux:
	go clean; rm -rf pkg grpc-server; GOOS=linux CGO_ENABLED=0 go build -o grpc-server ${flags}

build_power8:
	go clean; rm -rf pkg grpc-server; GOARCH=ppc64le GOOS=linux CGO_ENABLED=0 go build -o grpc-server ${flags}

build_arm64:
	go clean; rm -rf pkg grpc-server; GOARCH=arm64 GOOS=linux CGO_ENABLED=0 go build -o grpc-server ${flags}

build_windows:
	go clean; rm -rf pkg grpc-server; GOARCH=amd64 GOOS=windows CGO_ENABLED=0 go build -o grpc-server ${flags}

install:
	go install

clean:
	go clean; rm -rf pkg

test : test1

test1:
	go test -v -bench=.
