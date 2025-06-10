# How to Get zcert Windows Executable

There are several ways to get the Windows executable for testing on your laptop:

## Option 1: Build from Source on Windows (Recommended)

1. **Install Go on Windows**:
   - Download from https://golang.org/dl/
   - Install Go 1.19 or later

2. **Download the source code**:
   - Clone the GitHub repository (once created)
   - Or download as ZIP from GitHub

3. **Build the executable**:
   ```cmd
   cd zcert
   go mod tidy
   go build -o zcert.exe main.go
   ```

## Option 2: GitHub Actions Automated Builds

Once you push to GitHub, the automated workflow will build Windows executables:

1. Push code to GitHub
2. Go to "Actions" tab in your repository
3. Wait for build to complete
4. Download the Windows artifact from the build

## Option 3: Manual Cross-Compilation

If you have a Linux or macOS machine with Go installed:

```bash
# Clone the repository
git clone https://github.com/yourusername/zcert.git
cd zcert

# Install dependencies
go mod tidy

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o zcert.exe main.go

# Transfer zcert.exe to your Windows laptop
```

## Option 4: Release Downloads

After creating your first release on GitHub:

1. Go to the "Releases" section of your repository
2. Download the Windows executable from the latest release
3. The automated build will create `zcert-windows-amd64.exe`

## Testing the Executable

Once you have `zcert.exe` on your Windows laptop:

1. **Open Command Prompt or PowerShell**
2. **Navigate to the directory containing zcert.exe**
3. **Test basic functionality**:
   ```cmd
   zcert.exe --help
   zcert.exe --version
   zcert.exe enroll --help
   ```

4. **Set up test credentials** (optional):
   ```cmd
   set ZCERT_HAWK_ID=165c01284c6c8d872091aed0c7cc0149
   set ZCERT_HAWK_KEY=b431afc1ed6a6b7db5f760671840efa14224be60a11e0c164a6d0d021a45748c
   ```

5. **Test API connectivity**:
   ```cmd
   zcert.exe search --limit 1 --verbose
   ```

## Quick Start Commands

```cmd
# Show help
zcert.exe --help

# List available commands
zcert.exe

# Test enrollment (interactive)
zcert.exe enroll --cn test.example.com --verbose

# Search certificates
zcert.exe search --format table

# Show configuration options
zcert.exe enroll --help
```

The executable is self-contained and doesn't require additional dependencies on Windows.