all: build test

vet:
	go vet .

build:
	go build

test:
	go test -v -race -bench=.
