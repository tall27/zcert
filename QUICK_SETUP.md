# Quick Setup for Your GitHub Repository

You created: https://github.com/tall27/zcert

## Method 1: Upload Files Directly on GitHub (Easiest)

1. **Go to your repository**: https://github.com/tall27/zcert
2. **Click "uploading an existing file"** link on the main page
3. **Drag and drop ALL these files** from this workspace:

### Core Files (drag these to GitHub):
- `main.go`
- `go.mod` 
- `go.sum`
- `README.md`
- `LICENSE`
- `.gitignore`
- `Makefile`
- `build.sh`

### Folders to create and upload:
**Create folder `cmd`** and upload:
- `cmd/root.go`
- `cmd/enroll.go`
- `cmd/retrieve.go`
- `cmd/revoke.go`
- `cmd/search.go`
- `cmd/renew.go`

**Create folder `internal`** with subfolders and upload:
- `internal/api/client.go`
- `internal/api/types.go`
- `internal/auth/hawk.go`
- `internal/cert/generator.go`
- `internal/cert/output.go`
- `internal/config/config.go`
- `internal/utils/prompt.go`

**Create folder `examples`** and upload:
- `examples/config.yaml`
- `examples/enroll-script.sh`

**Create folder `.github/workflows`** and upload:
- `.github/workflows/build.yml`

## Method 2: Use Git Commands on Your Computer

1. **Install Git** on your computer if not already installed
2. **Open terminal/command prompt**
3. **Run these commands**:

```bash
# Create project folder
mkdir zcert
cd zcert

# Initialize git
git init

# Download and copy all the files from this workspace to your zcert folder

# Add files and commit
git add .
git commit -m "Initial release of zcert CLI tool"

# Connect to your GitHub repository
git remote add origin https://github.com/tall27/zcert.git

# Push to GitHub
git branch -M main
git push -u origin main
```

## After Upload

Once files are uploaded, GitHub Actions will automatically:
1. Build Windows executable (zcert.exe)
2. Build Linux and macOS versions
3. Make them available for download in the "Actions" tab

You'll find your Windows executable in the Actions tab after the build completes (about 2-3 minutes).