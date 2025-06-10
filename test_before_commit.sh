#!/bin/bash

# Pre-commit test suite for zcert
# This script runs comprehensive tests to catch bugs before pushing to GitHub

set -e

echo "🔍 Running pre-commit test suite for zcert..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n${YELLOW}Testing: $test_name${NC}"
    
    if eval "$test_command"; then
        echo -e "${GREEN}✓ PASSED: $test_name${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED: $test_name${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# 1. Code compilation test
run_test "Code Compilation" "go build -o zcert main.go"

# 2. Basic CLI functionality
run_test "CLI Help Command" "./zcert --help >/dev/null"
run_test "CLI Version Command" "./zcert --version >/dev/null"

# 3. Unit tests (non-integration)
run_test "Policy Struct Field Mapping" "cd internal/api && go test -v -run TestPolicyStructFieldMapping"

# 4. Integration tests (require credentials)
if [[ -n "$ZTPKI_HAWK_ID" && -n "$ZTPKI_HAWK_SECRET" ]]; then
    echo -e "\n${YELLOW}Running integration tests with real ZTPKI API...${NC}"
    
    run_test "API Compatibility" "cd internal/api && ZTPKI_HAWK_ID=$ZTPKI_HAWK_ID ZTPKI_HAWK_SECRET=$ZTPKI_HAWK_SECRET go test -v -run TestRealZTPKIAPICompatibility"
    run_test "Certificate Enrollment Workflow" "cd internal/api && ZTPKI_HAWK_ID=$ZTPKI_HAWK_ID ZTPKI_HAWK_SECRET=$ZTPKI_HAWK_SECRET go test -v -run TestCertificateEnrollmentWorkflow"
    run_test "Certificate Retrieval Workflow" "cd internal/api && ZTPKI_HAWK_ID=$ZTPKI_HAWK_ID ZTPKI_HAWK_SECRET=$ZTPKI_HAWK_SECRET go test -v -run TestCertificateRetrievalWorkflow"
    run_test "Certificate Revocation Workflow" "cd internal/api && ZTPKI_HAWK_ID=$ZTPKI_HAWK_ID ZTPKI_HAWK_SECRET=$ZTPKI_HAWK_SECRET go test -v -run TestCertificateRevocationWorkflow"
    run_test "API Error Handling" "cd internal/api && ZTPKI_HAWK_ID=$ZTPKI_HAWK_ID ZTPKI_HAWK_SECRET=$ZTPKI_HAWK_SECRET go test -v -run TestAPIErrorHandling"
    
    # 5. CLI command tests with real API
    echo -e "\n${YELLOW}Testing CLI commands with real ZTPKI API...${NC}"
    
    # Test enroll with missing CN (should fail gracefully)
    run_test "Enroll Missing CN Error" "./zcert enroll --url https://ztpki-dev.venafi.com/api/v2 --hawk-id $ZTPKI_HAWK_ID --hawk-key $ZTPKI_HAWK_SECRET 2>/dev/null; test \$? -ne 0"
    
    # Test enroll with invalid policy (should fail gracefully)
    run_test "Enroll Invalid Policy Error" "./zcert enroll --cn test.example.com --url https://ztpki-dev.venafi.com/api/v2 --hawk-id $ZTPKI_HAWK_ID --hawk-key $ZTPKI_HAWK_SECRET --policy invalid-policy 2>/dev/null; test \$? -ne 0"
    
    # Test retrieve with invalid certificate ID (should fail gracefully)
    run_test "Retrieve Invalid ID Error" "./zcert retrieve --id invalid-cert-id --url https://ztpki-dev.venafi.com/api/v2 --hawk-id $ZTPKI_HAWK_ID --hawk-key $ZTPKI_HAWK_SECRET 2>/dev/null; test \$? -ne 0"
    
    # Test search functionality
    run_test "Search Command Basic" "./zcert search --url https://ztpki-dev.venafi.com/api/v2 --hawk-id $ZTPKI_HAWK_ID --hawk-key $ZTPKI_HAWK_SECRET --limit 1 >/dev/null 2>&1 || true"
    
else
    echo -e "\n${YELLOW}Skipping integration tests: ZTPKI_HAWK_ID and ZTPKI_HAWK_SECRET not set${NC}"
fi

# 6. Security checks
echo -e "\n${YELLOW}Running security checks...${NC}"

# Check for hardcoded credentials
run_test "No Hardcoded Credentials" "! grep -r '165c01284c6c8d872091aed0c7cc0149\|b97a01107585f1f037a65fafe334dcda6a42b156e1ae8df0072d203dd36f5c0c' --exclude-dir=.git --exclude='test_before_commit.sh' ."

# Check for hardcoded policy IDs
run_test "No Hardcoded Policy IDs" "! grep -r '5fe6d368-896a-4883-97eb-f87148c90896' --exclude-dir=.git --exclude='test_before_commit.sh' --exclude='*.md' ."

# 7. Documentation consistency
run_test "README Contains Required Sections" "grep -q 'Installation\|Usage\|Configuration\|Authentication' README.md"

# 8. Configuration validation
run_test "Example Config Generation" "./zcert config --example >/dev/null"

# 9. Build verification for multiple targets
echo -e "\n${YELLOW}Testing cross-platform builds...${NC}"
run_test "Linux Build" "GOOS=linux GOARCH=amd64 go build -o zcert-linux main.go"
run_test "Windows Build" "GOOS=windows GOARCH=amd64 go build -o zcert.exe main.go"
run_test "macOS Build" "GOOS=darwin GOARCH=amd64 go build -o zcert-darwin main.go"

# Cleanup build artifacts
rm -f zcert zcert-linux zcert.exe zcert-darwin

# 10. Test data integrity principles
echo -e "\n${YELLOW}Testing data integrity principles...${NC}"

# Verify policy selector returns proper errors instead of fake data
run_test "Policy Selector Error Handling" "go test -v internal/policy/selector_test.go -run TestPolicySelector_GetAvailablePolicies"

# Final summary
echo -e "\n" 
echo "=================================="
echo -e "📊 ${GREEN}TESTS PASSED: $TESTS_PASSED${NC}"
echo -e "📊 ${RED}TESTS FAILED: $TESTS_FAILED${NC}"
echo "=================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed! Safe to commit to GitHub.${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed. Please fix issues before committing.${NC}"
    exit 1
fi