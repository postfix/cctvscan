# CRUSH.md - cctvscan Development Guide

## Build & Test Commands
- `go build ./...` - Build all packages
- `go test ./...` - Run all tests
- `go test -v ./internal/targets/` - Run specific package tests
- `go test -v ./internal/fingerprint/ -run TestDetect` - Run single test
- `go test -v ./internal/util/` - Test utility functions
- `go mod tidy` - Clean up dependencies

## Code Style Guidelines
- **Imports**: Use full module path (`github.com/postfix/cctvscan/internal/...`)
- **Formatting**: Standard Go formatting with `gofmt`
- **Error Handling**: Return errors, don't panic; use context for timeouts
- **Naming**: camelCase for variables, PascalCase for exports
- **Types**: Use strong typing; avoid interface{} where possible
- **Testing**: Table-driven tests preferred; use testdata fixtures
- **Concurrency**: Use context for cancellation, sync primitives carefully
- **Networking**: Timeouts on all network operations (350ms default)
- **Security**: No hardcoded credentials; validate all inputs
- **DRY**: Use shared utilities in `internal/util/` package

## Project Structure
- `cmd/cctvscan/` - Main application
- `internal/` - Internal packages (not for external use)
- `internal/util/` - Shared utility functions
- Each internal package has single responsibility
- Test files use `_test.go` suffix alongside implementation

## Dependencies
- Go 1.22+ standard library
- Uses `github.com/projectdiscovery/naabu/v2` for port scanning
- No external binary dependencies required

## Recent Improvements
- Fixed all compilation errors
- Added shared utility package to eliminate code duplication
- Enhanced error handling in network operations
- Improved test coverage with comprehensive unit tests
- Added proper GoDoc documentation to all packages