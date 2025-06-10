#!/bin/bash
# Build script for zcert CLI tool

set -e

VERSION="1.0.0"
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"

echo "Building zcert CLI tool..."
echo "Version: $VERSION"
echo "Build Time: $BUILD_TIME"
echo "Git Commit: $GIT_COMMIT"
echo

# Clean previous builds
rm -f zcert zcert.exe

# Build for current platform
echo "Building for current platform..."
go build -ldflags "$LDFLAGS" -o zcert main.go
echo "✓ Built: zcert"

# Build for Windows
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o zcert.exe main.go
echo "✓ Built: zcert.exe"

# Build for macOS
echo "Building for macOS..."
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o zcert-darwin main.go
echo "✓ Built: zcert-darwin"

# Build for Linux ARM64
echo "Building for Linux ARM64..."
GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -o zcert-linux-arm64 main.go
echo "✓ Built: zcert-linux-arm64"

echo
echo "Build completed successfully!"
echo "Windows executable: zcert.exe"
echo "Linux executable: zcert"
echo "macOS executable: zcert-darwin"
echo "Linux ARM64 executable: zcert-linux-arm64"