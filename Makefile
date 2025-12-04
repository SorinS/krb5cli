# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOLINT=bin/golangci-lint run
BINARY_NAME=krb5cli
MODULE_NAME=krb5cli
BUILD_DIR=bin

ifeq ($(OS),Windows_NT)
  RMDIR = if exist "$(1)\*" rmdir /S /Q "$(1)"
else
  RMDIR = rm -rf -- "$(1)"
endif

DATE=$(shell date +%Y%m%d_%H%M%S)
COMMIT=$(shell git rev-parse HEAD)
LDFLAGS=-ldflags="-X main.commit=$(COMMIT) -X main.buildDate=$(DATE)"

-include Makefile.local

# Compilation targets
all: darwin-arm64 linux-amd64 linux-arm64
#all: darwin-arm64 linux-amd64

darwin-arm64:
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o=$(BUILD_DIR)/$(BINARY_NAME).darwin-arm64.bin 

darwin-amd64:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME).darwin-amd64.bin

linux-amd64: 
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME).linux-amd64.bin

linux-arm64:
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME).linux-arm64.bin

windows-amd64:
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME).windows-amd64.exe

# Testing and linting targets
test:
	$(GOTEST) -v ./...

.PHONY: test-race
test-race:
	$(GOCMD) test -v --race ./...

lint:
	$(GOLINT) ./...

cover:
	$(GOCMD) test -cover ./...

clean:
	$(GOCLEAN)
	rm -f build/*.bin build/*.exe

