#!/bin/bash

# Cross-platform build script for zcert
# Builds binaries for Linux, macOS, and Windows

set -e

# Get version information
VERSION="1.0.0"
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S_UTC')
GO_VERSION=$(go version | awk '{print $3}')

# Ldflags for version injection
LDFLAGS="-X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GoVersion=${GO_VERSION}"

# Output directory
BUILD_DIR="dist"
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

echo "Cross-platform build for zcert"
echo "Version: ${VERSION}"
echo "Git Commit: ${GIT_COMMIT}"
echo "Build Time: ${BUILD_TIME}"
echo "Go Version: ${GO_VERSION}"
echo "Output Directory: ${BUILD_DIR}"
echo

# Build matrix: OS/ARCH combinations
declare -a platforms=(
    "linux/amd64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

# Build for each platform
for platform in "${platforms[@]}"; do
    IFS='/' read -r -a platform_split <<< "$platform"
    GOOS="${platform_split[0]}"
    GOARCH="${platform_split[1]}"
    
    output_name="zcert"
    if [ "$GOOS" = "windows" ]; then
        output_name+=".exe"
    fi
    
    output_path="${BUILD_DIR}/${GOOS}-${GOARCH}/${output_name}"
    
    echo "Building for ${GOOS}/${GOARCH}..."
    mkdir -p "${BUILD_DIR}/${GOOS}-${GOARCH}"
    
    env GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "${LDFLAGS}" \
        -o "$output_path" \
        main.go
    
    # Create platform-specific archive
    archive_name="zcert-${VERSION}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        # Create ZIP for Windows
        (cd "${BUILD_DIR}/${GOOS}-${GOARCH}" && zip "../${archive_name}.zip" "$output_name")
    else
        # Create tar.gz for Unix-like systems
        (cd "${BUILD_DIR}/${GOOS}-${GOARCH}" && tar -czf "../${archive_name}.tar.gz" "$output_name")
    fi
    
    echo "✓ Built: $output_path"
done

echo
echo "Cross-platform build completed!"
echo "Artifacts created in ${BUILD_DIR}/ directory:"
ls -la ${BUILD_DIR}/

# Test local binary if it exists
if [ -f "${BUILD_DIR}/$(go env GOOS)-$(go env GOARCH)/zcert" ]; then
    echo
    echo "Testing local binary:"
    "${BUILD_DIR}/$(go env GOOS)-$(go env GOARCH)/zcert" --version
fi