VERSION=`git rev-parse --short HEAD`
OS := $(shell uname)
ifeq ($(OS),Darwin)
flags=-ldflags="-s -w -X main.version=${VERSION}"
else
flags=-ldflags="-s -w -X main.version=${VERSION} -static"
endif

all: vet build

vet:
	go vet .

build:
	go clean; rm -rf pkg; go build -o token ${flags}

build_debug:
	go clean; rm -rf pkg; go build -o token ${flags} -gcflags="-m -m"

build_all: build_osx build_linux build

build_osx:
	go clean; rm -rf pkg token_osx; GOOS=darwin go build -o token ${flags}

build_linux:
	go clean; rm -rf pkg token_linux; GOOS=linux go build -o token ${flags}

build_power8:
	go clean; rm -rf pkg token_power8; GOARCH=ppc64le GOOS=linux go build -o token ${flags}

build_arm64:
	go clean; rm -rf pkg token_arm64; GOARCH=arm64 GOOS=linux go build -o token ${flags}

build_windows:
	go clean; rm -rf pkg token.exe; GOARCH=amd64 GOOS=windows go build -o token ${flags}

install:
	go install

clean:
	go clean; rm -rf pkg

test : test1

test1:
	go test -v -bench=.
