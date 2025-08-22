# rigid-go

[![Go Reference](https://pkg.go.dev/badge/github.com/bahadrix/rigid-go.svg)](https://pkg.go.dev/github.com/bahadrix/rigid-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/bahadrix/rigid-go)](https://goreportcard.com/report/github.com/bahadrix/rigid-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/bahadrix/rigid-go/workflows/CI/badge.svg)](https://github.com/bahadrix/rigid-go/actions)

Cryptographically secured ULIDs with built-in integrity verification - Go port of the Python [rigid](https://github.com/bahadrix/rigid) library.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Creating a Rigid Instance](#creating-a-rigid-instance)
  - [Generating IDs](#generating-ids)
  - [Verification](#verification)
  - [Utility Methods](#utility-methods)
  - [Error Types](#error-types)
- [ID Format](#id-format)
- [Security Considerations](#security-considerations)
- [Examples](#examples)
  - [Basic Usage](#basic-usage)
  - [Advanced Usage](#advanced-usage)
- [Benchmarks](#benchmarks)
- [Compatibility](#compatibility)
- [Testing](#testing)
- [Migration from v0.x](#migration-from-v0x)
- [Contributing](#contributing)
  - [Development Setup](#development-setup)
  - [Issues and Support](#issues-and-support)
- [License](#license)
- [Changelog](#changelog)

## Overview

Rigid is a Go library that generates cryptographically secure, unique identifiers based on ULIDs (Universally Unique Lexicographically Sortable Identifiers) with HMAC-based integrity verification. It provides tamper detection, metadata binding, and ensures that IDs cannot be forged without the secret key.

## Features

- **Cryptographically Secure**: Uses HMAC-SHA256 for integrity verification
- **Time-Ordered**: Based on ULIDs, naturally sorted by creation time
- **Tamper-Proof**: Any modification to an ID will be detected during verification
- **Metadata Support**: Optional metadata can be cryptographically bound to IDs  
- **Configurable Signatures**: Adjustable signature length (4-32 bytes)
- **Thread-Safe**: Safe for concurrent use across multiple goroutines
- **Compatible**: Multi-instance compatible when using the same secret key

## Installation

```bash
go get github.com/bahadrix/rigid-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "github.com/bahadrix/rigid-go"
)

func main() {
    // Your secret key - keep this secure!
    secretKey := []byte("your-secret-key-here")
    
    // Create a new Rigid instance
    r, err := rigid.NewRigid(secretKey)
    if err != nil {
        log.Fatal(err)
    }
    
    // Generate a new Rigid ULID
    rigidID, err := r.Generate()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Generated ID: %s\n", rigidID)
    
    // Generate with metadata
    rigidWithMetadata, err := r.Generate("user:alice:role:admin")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("With metadata: %s\n", rigidWithMetadata)
    
    // Verify the ID
    result, err := r.Verify(rigidWithMetadata)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Valid: %t, ULID: %s, Metadata: %s\n", 
        result.Valid, result.ULID, result.Metadata)
}
```

## API Reference

### Creating a Rigid Instance

```go
// Create with default signature length (8 bytes)
r, err := rigid.NewRigid(secretKey)

// Create with custom signature length (4-32 bytes)
r, err := rigid.NewRigid(secretKey, 16)
```

### Generating IDs

```go
// Generate without metadata
rigidID, err := r.Generate()

// Generate with metadata
rigidID, err := r.Generate("metadata-string")
```

### Verification

```go
// Verify returns a VerifyResult struct
result, err := r.Verify(rigidID)

// VerifyResult contains:
// - Valid (bool): whether the ID is valid
// - ULID (string): the extracted ULID
// - Metadata (string): the extracted metadata (if any)
```

### Utility Methods

```go
// Extract the ULID object
ulidObj, err := r.ExtractULID(rigidID)

// Extract the timestamp
timestamp, err := r.ExtractTimestamp(rigidID)
```

### Error Types

- `ErrInvalidFormat`: Invalid Rigid ID format
- `ErrInvalidULID`: Invalid ULID component
- `ErrIntegrityFailure`: ID failed integrity verification
- `ErrEmptySecretKey`: Empty or nil secret key
- `ErrInvalidSigLength`: Invalid signature length

## ID Format

A Rigid ID has the format: `ULID-SIGNATURE` or `ULID-SIGNATURE-METADATA`

- **ULID**: 26-character standard ULID (timestamp + randomness)
- **SIGNATURE**: Base32-encoded HMAC signature (configurable length)
- **METADATA**: Optional metadata string (can contain hyphens)

Example: `01ARZ3NDEKTSV4RRFFQ69G5FAV-MFRGG2BA-user:alice:role:admin`

## Security Considerations

1. **Key Management**: Keep your secret key secure and rotate it periodically
2. **Key Sharing**: Use the same key across all systems that need to verify IDs
3. **Signature Length**: Longer signatures provide more security but increase ID length
4. **Constant-Time Verification**: Uses `crypto/subtle` for timing-attack resistance

## Examples

### Basic Usage
```go
secretKey := []byte("your-secret-key")
r, _ := rigid.NewRigid(secretKey)

// Simple generation
id, _ := r.Generate()
fmt.Println(id) // 01ARZ3NDEKTSV4RRFFQ69G5FAV-MFRGG2BA

// With metadata
id, _ = r.Generate("session:12345")
fmt.Println(id) // 01ARZ3NDEKTSV4RRFFQ69G5FAV-MFRGG2BA-session:12345
```

### Advanced Usage
See `examples/advanced/main.go` for comprehensive examples including:
- User management systems
- Session management
- Multi-instance compatibility
- Different signature lengths
- Tamper detection

## Benchmarks

Run benchmarks with:

```bash
go test -bench=. -benchmem
```

Performance on Apple M1 Pro (darwin/arm64):
- **Generation**: 1,885,310 ops/sec (631.3 ns/op, 624 B/op, 10 allocs/op)
- **Verification**: 2,172,638 ops/sec (555.4 ns/op, 592 B/op, 9 allocs/op)
- **Generation with metadata**: 1,750,885 ops/sec (689.7 ns/op, 712 B/op, 12 allocs/op)

## Compatibility

This Go implementation is compatible with the Python [rigid](https://github.com/bahadrix/rigid) library when using the same:
- Secret key
- Signature length
- HMAC algorithm (SHA-256)

## Testing

Run the full test suite:

```bash
go test -v                # Run all tests
go test -race -v          # Test for race conditions
go test -cover            # Generate coverage report
```

## Migration from v0.x

The new API is completely different from v0.x versions. Key changes:

- Use `NewRigid()` instead of `New()`
- Use `Generate()` method instead of direct function
- Use `Verify()` method that returns a `VerifyResult` struct
- IDs are now string-based with ULID format instead of binary
- Metadata support is now built-in
- Configurable signature lengths

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new functionality
4. Ensure all tests pass (`go test -v`)
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/bahadrix/rigid-go.git
cd rigid-go
go mod download
go test -v
```

### Issues and Support

- 🐛 [Report bugs](https://github.com/bahadrix/rigid-go/issues/new?template=bug_report.md)
- 💡 [Request features](https://github.com/bahadrix/rigid-go/issues/new?template=feature_request.md)
- 💬 [Start discussions](https://github.com/bahadrix/rigid-go/discussions)

## License

MIT License - see LICENSE file for details.

## Changelog

### v1.0.2
- **Documentation**: Add comprehensive Go package documentation for pkg.go.dev
- **Documentation**: Document all public types, functions, constants, and variables
- **Documentation**: Include usage examples and security feature descriptions

### v1.0.1
- **Documentation**: Update README with actual benchmark results from Apple M1 Pro
- **Documentation**: Add comprehensive Table of Contents with navigation links
- **Code Quality**: Fix concurrent generation race conditions and improve thread safety
- **Code Quality**: Fix various linting errors (gofmt, errcheck, fmt redundancy)
- **CI/CD**: Improve CI workflow and update golangci-lint configuration
- **Code Quality**: Code formatting improvements across examples and tests
- **Bug Fix**: Fix Go version compatibility issues

### v1.0.0
- Complete rewrite to match Python rigid library API
- ULID-based implementation using github.com/oklog/ulid/v2
- Configurable signature lengths (4-32 bytes)
- Metadata support with cryptographic binding
- Constant-time signature verification
- Thread-safe concurrent generation
- Comprehensive test suite and examples