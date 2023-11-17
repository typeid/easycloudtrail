export PATH := $(PWD)/bin:$(PATH)

.DEFAULT_GOAL := all
.PHONY: all
all: build test lint

.PHONY: build
build:
	go build -o bin/easycloudtrail main.go

.PHONY: test
test:
	go test -race -mod=readonly ./...

.PHONY: build_all
build_all:
	echo "Compiling for every OS and Platform"
	GOOS=freebsd GOARCH=386 go build -o bin/easycloudtrail-freebsd-386 main.go
	GOOS=linux GOARCH=386 go build -o bin/easycloudtrail-linux-386 main.go
	GOOS=windows GOARCH=386 go build -o bin/easycloudtrail-windows-386 main.go

.PHONY: lint
lint:
	golangci-lint run

.PHONY: install
install:
	go install