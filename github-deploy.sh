#!/bin/bash

# GitHub Deployment Script for ZCERT v1.1.0
# This script initializes a new GitHub repository and prepares for release

set -e

REPO_NAME="zcert"
VERSION="v1.1.0"
GITHUB_ORG="${GITHUB_ORG:-your-org}"  # Override with: export GITHUB_ORG="your-github-org"

echo "=== ZCERT v1.1.0 GitHub Deployment Script ==="
echo ""

# Check prerequisites
if ! command -v git &> /dev/null; then
    echo "❌ Error: git is not installed"
    exit 1
fi

if ! command -v gh &> /dev/null; then
    echo "⚠️  Warning: GitHub CLI (gh) not found. Manual repository creation required."
    echo "   Install: https://cli.github.com/"
fi

# Initialize git repository if not already done
if [ ! -d ".git" ]; then
    echo "📦 Initializing git repository..."
    git init
    git branch -M main
else
    echo "✅ Git repository already initialized"
fi

# Create .gitignore if it doesn't exist
if [ ! -f ".gitignore" ]; then
    echo "📝 Creating .gitignore..."
    cat > .gitignore << 'EOF'
# Binaries
zcert
zcert.exe
dist/
*.tar.gz
*.zip

# Go build artifacts
*.o
*.a
*.so

# Test files
*.test
coverage.out
test-output/

# Configuration files with secrets
*.key
*.pem
*-real.cnf
*-prod.cnf

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db

# Temporary files
tmp/
temp/
*.tmp
*.bak
EOF
fi

# Verify essential files exist
echo "🔍 Verifying project files..."
REQUIRED_FILES=("main.go" "go.mod" "README.md" "LICENSE" "RELEASE_NOTES_v1.1.0.md")
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing required file: $file"
        exit 1
    fi
    echo "  ✅ $file"
done

# Build and test before deployment
echo ""
echo "🔨 Building and testing project..."
go mod tidy
go test ./... || {
    echo "❌ Tests failed. Fix issues before deployment."
    exit 1
}
go build -o zcert main.go || {
    echo "❌ Build failed. Fix compilation errors before deployment."
    exit 1
}
echo "✅ Build and tests successful"

# Create cross-platform builds
echo ""
echo "🏗️  Creating cross-platform builds..."
if [ -x "./build-cross-platform.sh" ]; then
    ./build-cross-platform.sh $VERSION
    echo "✅ Cross-platform builds created"
else
    echo "⚠️  build-cross-platform.sh not executable or missing"
fi

# Add all files to git
echo ""
echo "📋 Staging files for commit..."
git add .
git add -f LICENSE README.md RELEASE_NOTES_v1.1.0.md

# Create initial commit
if [ -z "$(git log --oneline 2>/dev/null)" ]; then
    echo "💾 Creating initial commit..."
    git commit -m "feat: Initial release of ZCERT v1.1.0

- Zero Touch PKI certificate management CLI
- Support for 2048, 3072, and 4096-bit RSA keys
- HAWK authentication with CyberArk ZTPKI
- Cross-platform support (Linux, macOS, Windows)
- Comprehensive certificate lifecycle management
- Enhanced security with 3072-bit default key size"
else
    echo "💾 Creating v1.1.0 release commit..."
    git commit -m "release: ZCERT v1.1.0

- Enhanced RSA key size support (2048, 3072, 4096-bit)
- Improved configuration validation
- Added comprehensive test coverage
- Fixed profile selection priority
- Updated default key size to 3072-bit for enhanced security"
fi

# Tag the release
echo "🏷️  Creating release tag..."
git tag -a $VERSION -m "ZCERT $VERSION

Enhanced security release with flexible RSA key size support.

Key Features:
- Support for 2048, 3072, and 4096-bit RSA keys
- Enhanced configuration validation
- Comprehensive test coverage
- Cross-platform binaries
- Improved security defaults"

echo ""
echo "✅ Repository prepared for GitHub deployment"
echo ""
echo "📋 Next Steps:"
echo ""

if command -v gh &> /dev/null; then
    echo "🚀 Automatic GitHub Repository Creation:"
    echo "   gh repo create $GITHUB_ORG/$REPO_NAME --public --source=. --remote=origin --push"
    echo ""
    echo "🏷️  Create GitHub Release:"
    echo "   gh release create $VERSION dist/* --title \"ZCERT $VERSION\" --notes-file RELEASE_NOTES_v1.1.0.md"
    echo ""
    read -p "Do you want to create the GitHub repository now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🚀 Creating GitHub repository..."
        gh repo create $GITHUB_ORG/$REPO_NAME --public --source=. --remote=origin --push
        
        echo "🏷️  Creating GitHub release..."
        gh release create $VERSION dist/* --title "ZCERT $VERSION" --notes-file RELEASE_NOTES_v1.1.0.md
        
        echo ""
        echo "🎉 GitHub repository and release created successfully!"
        echo "🔗 Repository: https://github.com/$GITHUB_ORG/$REPO_NAME"
        echo "🔗 Release: https://github.com/$GITHUB_ORG/$REPO_NAME/releases/tag/$VERSION"
    fi
else
    echo "📋 Manual GitHub Repository Creation:"
    echo ""
    echo "1. Create new repository at: https://github.com/new"
    echo "   - Repository name: $REPO_NAME"
    echo "   - Description: Zero Touch PKI Certificate Management CLI"
    echo "   - Public repository"
    echo "   - Don't initialize with README (we have our own)"
    echo ""
    echo "2. Add remote and push:"
    echo "   git remote add origin git@github.com:$GITHUB_ORG/$REPO_NAME.git"
    echo "   git push -u origin main"
    echo "   git push origin $VERSION"
    echo ""
    echo "3. Create release at: https://github.com/$GITHUB_ORG/$REPO_NAME/releases/new"
    echo "   - Tag: $VERSION"
    echo "   - Title: ZCERT $VERSION"
    echo "   - Upload files from dist/ directory"
    echo "   - Copy release notes from RELEASE_NOTES_v1.1.0.md"
fi

echo ""
echo "📦 Release Artifacts Ready:"
ls -la dist/ 2>/dev/null || echo "   (Run ./build-cross-platform.sh to create release binaries)"

echo ""
echo "🔒 Security Notes:"
echo "   - Verify all sensitive data is excluded from repository"
echo "   - Review .gitignore before public release" 
echo "   - Update placeholder URLs in README.md"
echo "   - Configure branch protection rules after repository creation"

echo ""
echo "✅ ZCERT v1.1.0 deployment preparation complete!"