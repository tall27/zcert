# Makefile for zcert CLI tool

.PHONY: all build clean windows linux darwin test

# Variables
BINARY_NAME=zcert
VERSION=1.0.0
BUILD_DIR=./build
SOURCE=./main.go

# Build flags
LDFLAGS=-ldflags "-w -s"

# Default target
all: clean build

# Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) $(SOURCE)

# Build for Windows
windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME).exe $(SOURCE)

# Build for Linux
linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux $(SOURCE)

# Build for macOS
darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin $(SOURCE)

# Build all platforms
build-all: clean
	mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME).exe $(SOURCE)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux $(SOURCE)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin $(SOURCE)
	
# Test
test:
	go test ./...

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe

# Install dependencies
deps:
	go mod download
	go mod tidy