# Setting Up Your zcert GitHub Repository

## Step 1: Create GitHub Repository

1. Go to GitHub.com and sign in
2. Click "+" → "New repository"
3. Name: `zcert`
4. Description: `Go-based CLI certificate management tool for Venafi Zero Touch PKI`
5. Public repository (recommended)
6. Don't initialize with README/gitignore/license
7. Click "Create repository"

## Step 2: Prepare Local Directory

Create a new directory for your project:

```bash
mkdir zcert
cd zcert
```

## Step 3: Copy Project Files

Copy all the following files to your zcert directory:

### Core Files
- `main.go` - Entry point
- `go.mod` - Go module definition
- `go.sum` - Dependencies
- `README.md` - Documentation
- `LICENSE` - MIT license
- `.gitignore` - Git ignore rules
- `Makefile` - Build automation
- `build.sh` - Build script

### Directories to Create and Copy
- `cmd/` - All command files (root.go, enroll.go, etc.)
- `internal/` - All internal packages (api/, auth/, cert/, config/, utils/)
- `examples/` - Configuration and script examples
- `.github/workflows/` - GitHub Actions for automated builds

## Step 4: Initialize and Push

```bash
git init
git add .
git commit -m "Initial release of zcert CLI tool

- Complete certificate lifecycle management for Venafi ZTPKI
- HAWK authentication implementation  
- Interactive and scripted workflows
- Multiple output formats (PEM, PKCS#12, JKS, DER)
- Certificate enrollment, retrieval, revocation, and search
- Comprehensive documentation and examples"

git remote add origin https://github.com/yourusername/zcert.git
git branch -M main
git push -u origin main
```

## Step 5: Verify Setup

After pushing:
1. Check repository appears correctly on GitHub
2. Verify GitHub Actions workflow starts building
3. Download Windows executable from Actions artifacts

## Project Structure

```
zcert/
├── main.go
├── go.mod
├── go.sum
├── README.md
├── LICENSE
├── .gitignore
├── Makefile
├── build.sh
├── cmd/
│   ├── root.go
│   ├── enroll.go
│   ├── retrieve.go
│   ├── revoke.go
│   ├── search.go
│   └── renew.go
├── internal/
│   ├── api/
│   ├── auth/
│   ├── cert/
│   ├── config/
│   └── utils/
├── examples/
│   ├── config.yaml
│   └── enroll-script.sh
└── .github/
    └── workflows/
        └── build.yml
```

The automated workflow will build executables for Windows, Linux, and macOS.