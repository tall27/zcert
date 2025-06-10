# Contributing to zcert

Thank you for your interest in contributing to zcert! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your feature or bug fix
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

## Development Setup

### Prerequisites

- Go 1.19 or later
- Git
- Access to a Venafi Zero Touch PKI instance for testing

### Building the Project

```bash
# Clone your fork
git clone https://github.com/yourusername/zcert.git
cd zcert

# Install dependencies
go mod tidy

# Build the project
go build -o zcert main.go

# Run tests
go test ./...
```

## Code Style

- Follow standard Go formatting (use `go fmt`)
- Write meaningful commit messages
- Include tests for new functionality
- Update documentation for any user-facing changes
- Follow Go naming conventions

## Testing

Before submitting a pull request:

1. Run all tests: `go test ./...`
2. Test the CLI manually with various scenarios
3. Verify that help text is accurate and helpful
4. Test error conditions and edge cases

### Test Credentials

Use the provided test credentials for development:
```bash
export ZCERT_HAWK_ID="165c01284c6c8d872091aed0c7cc0149"
export ZCERT_HAWK_KEY="b431afc1ed6a6b7db5f760671840efa14224be60a11e0c164a6d0d021a45748c"
```

## Pull Request Process

1. Ensure your code follows the project's coding standards
2. Update the README.md if you've added new features
3. Add or update tests as appropriate
4. Ensure all tests pass
5. Write a clear pull request description explaining your changes

## Reporting Issues

When reporting issues, please include:

- Operating system and version
- Go version
- zcert version
- Complete error messages
- Steps to reproduce the issue
- Expected vs actual behavior

## Feature Requests

Feature requests are welcome! Please:

- Check if the feature already exists or is planned
- Provide a clear description of the feature
- Explain the use case and benefits
- Consider whether it fits the project's scope

## Code Organization

The project is organized as follows:

```
zcert/
├── main.go                 # Entry point
├── cmd/                    # CLI commands
│   ├── root.go            # Root command and global flags
│   ├── enroll.go          # Certificate enrollment
│   ├── retrieve.go        # Certificate retrieval
│   ├── revoke.go          # Certificate revocation
│   ├── search.go          # Certificate search
│   └── renew.go           # Certificate renewal (future)
├── internal/              # Internal packages
│   ├── api/               # ZTPKI API client
│   ├── auth/              # HAWK authentication
│   ├── cert/              # Certificate operations
│   ├── config/            # Configuration management
│   └── utils/             # Utility functions
├── go.mod                 # Go module definition
├── go.sum                 # Go module checksums
├── README.md              # Project documentation
├── LICENSE                # MIT license
└── .gitignore            # Git ignore rules
```

## Areas for Contribution

Some areas where contributions are particularly welcome:

1. **Testing**: Unit tests, integration tests, edge case testing
2. **Documentation**: Improve README, add examples, fix typos
3. **Error Handling**: Better error messages, recovery scenarios
4. **Output Formats**: Additional certificate output formats
5. **Performance**: Optimize API calls, improve response times
6. **Security**: Security reviews, vulnerability fixes
7. **Usability**: Improved CLI interface, better help text

## Communication

- Use GitHub issues for bug reports and feature requests
- Be respectful and constructive in all interactions
- Follow the code of conduct

## License

By contributing to zcert, you agree that your contributions will be licensed under the MIT License.