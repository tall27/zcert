#!/bin/bash
# Example script for automated certificate enrollment with zcert

set -e

# Configuration
CN="app.example.com"
SANS="www.example.com,api.example.com"
POLICY="Web Server Policy"
OUTPUT_DIR="./certificates"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting certificate enrollment for ${CN}${NC}"

# Check if zcert is available
if ! command -v zcert &> /dev/null; then
    echo -e "${RED}Error: zcert command not found${NC}"
    echo "Please ensure zcert is built and in your PATH"
    exit 1
fi

# Check environment variables
if [[ -z "$ZCERT_HAWK_ID" || -z "$ZCERT_HAWK_KEY" ]]; then
    echo -e "${RED}Error: HAWK credentials not set${NC}"
    echo "Please set ZCERT_HAWK_ID and ZCERT_HAWK_KEY environment variables"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Enroll certificate
echo -e "${YELLOW}Enrolling certificate...${NC}"
if zcert enroll \
    --cn "$CN" \
    --sans "$SANS" \
    --policy "$POLICY" \
    --file "$OUTPUT_DIR/$CN" \
    --format pem \
    --verbose; then
    
    echo -e "${GREEN}Certificate enrolled successfully!${NC}"
    
    # Show certificate details
    echo -e "${YELLOW}Certificate details:${NC}"
    zcert search --cn "$CN" --format table
    
    # List generated files
    echo -e "${YELLOW}Generated files:${NC}"
    ls -la "$OUTPUT_DIR"/*
    
else
    echo -e "${RED}Certificate enrollment failed${NC}"
    exit 1
fi

echo -e "${GREEN}Certificate enrollment completed successfully${NC}"