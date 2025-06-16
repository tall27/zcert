#!/bin/bash

# Cross-platform build script for ZCert CLI
# Builds binaries for macOS (ARM/AMD64), Linux (AMD64/ARM64), and Windows (AMD64/ARM64)

set -e

# Configuration
APP_NAME="zcert"
VERSION=${VERSION:-"1.2.0"}
BUILD_TIME=$(date -u +%Y%m%d.%H%M%S)
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build information
echo "Building $APP_NAME"
echo "Version: $VERSION"
echo "Git Commit: $GIT_COMMIT"
echo "Build Time: $BUILD_TIME"
echo

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf dist/
mkdir -p dist/

# Build targets
declare -a targets=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

# Build function
build_target() {
    local target=$1
    local goos=$(echo $target | cut -d'/' -f1)
    local goarch=$(echo $target | cut -d'/' -f2)
    local suffix=""
    
    if [ "$goos" = "windows" ]; then
        suffix=".exe"
    fi
    
    local output_name="${APP_NAME}-${goos}-${goarch}${suffix}"
    local archive_name="${APP_NAME}-${VERSION}-${goos}-${goarch}"
    
    echo "Building $target..."
    
    # Set environment variables for cross-compilation
    export GOOS=$goos
    export GOARCH=$goarch
    export CGO_ENABLED=0
    
    # Build with version information
    go build -ldflags="-X 'main.Version=$VERSION' -X 'main.GitCommit=$GIT_COMMIT' -X 'main.BuildTime=$BUILD_TIME' -w -s" -o "dist/$output_name" main.go
    
    # Create archive
    cd dist/
    if [ "$goos" = "windows" ]; then
        zip "${archive_name}.zip" "$output_name" ../README.md ../SECURITY.md ../DEPLOYMENT.md
        echo "Created: ${archive_name}.zip"
    else
        tar -czf "${archive_name}.tar.gz" "$output_name" ../README.md ../SECURITY.md ../DEPLOYMENT.md
        echo "Created: ${archive_name}.tar.gz"
    fi
    cd ..
    
    # Reset environment
    unset GOOS GOARCH CGO_ENABLED
}

# Build all targets
echo "Building for all platforms..."
echo

for target in "${targets[@]}"; do
    build_target "$target"
    echo
done

# Summary
echo "Build Summary:"
echo "=============="
ls -la dist/
echo

echo "Build completed successfully!"
echo "Archives are available in the dist/ directory"
echo

# Create checksums
echo "Generating checksums..."
cd dist/
sha256sum * > checksums.txt
echo "Checksums saved to dist/checksums.txt"
cd ..

echo
echo "Installation instructions:"
echo "1. Download the appropriate archive for your platform"
echo "2. Extract: tar -xzf zcert-*.tar.gz (Linux/macOS) or unzip zcert-*.zip (Windows)"
echo "3. Make executable: chmod +x zcert (Linux/macOS)"
echo "4. Run: ./zcert --version"