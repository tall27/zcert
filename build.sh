#!/bin/bash

# Build script for zcert with version information injection

set -e

# Get version information
VERSION="1.2.0"
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(env TZ=America/Chicago date '+%Y%m%d.%H%M%S')
GO_VERSION=$(go version | awk '{print $3}')
PLATFORM="$(go env GOOS)/$(go env GOARCH)"

# Ldflags for version injection
LDFLAGS="-X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GoVersion=${GO_VERSION}"

echo "Building zcert..."
echo "Version: ${VERSION}"
echo "Git Commit: ${GIT_COMMIT}"
echo "Build Time: ${BUILD_TIME}"
echo "Go Version: ${GO_VERSION}"
echo "Platform: ${PLATFORM}"
echo

# Determine binary name based on platform
BINARY_NAME="zcert"
if [[ "$GOOS" == "windows" ]]; then
    BINARY_NAME="zcert.exe"
fi

# Build the binary
go build -ldflags "${LDFLAGS}" -o "${BINARY_NAME}" main.go

# Test the version output
echo
echo "Testing version output:"
./"${BINARY_NAME}" --version

echo "Build completed: ${BINARY_NAME}"
echo "Run './${BINARY_NAME} --version' to see version information"