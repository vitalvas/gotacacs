# Technology Stack

## Language

- **Primary Language**: Go (Golang)
- **Minimum Go Version**: 1.21+

## Dependencies

### Core Dependencies

- Standard library only for core protocol implementation
- `crypto/md5` - Body obfuscation (legacy)
- `crypto/tls` - TLS transport
- `encoding/binary` - Packet encoding/decoding

### Testing

- `github.com/stretchr/testify` - Testing assertions and mocks

### Example Binaries

- Standard library only (`flag`, `log`)

## Protocol

- **Specification**: RFC8907 - The Terminal Access Controller Access-Control System Plus (TACACS+) Protocol
- **Transport**: TCP (default port 49) with optional TLS
- **Security**: Body obfuscation (MD5-based) and TLS encryption

## Architecture

- **Pattern**: SDK library with pluggable interfaces
- **Structure**: Follows golang-standards/project-layout
- **API Style**: Callback-based with options pattern

## Project Structure

```
gotacacs/
├── cmd/
│   ├── tacacs-client/     # Example client binary
│   └── tacacs-server/     # Example server binary
├── docs/
│   └── technology.md      # This file
├── header.go              # Fixed header implementation
├── packet.go              # Packet interface and common types
├── packet_authen.go       # Authentication packets
├── packet_author.go       # Authorization packets
├── packet_acct.go         # Accounting packets
├── obfuscation.go         # Body obfuscation
├── client.go              # Client SDK
├── server.go              # Server SDK
├── transport.go           # Transport abstraction
├── session.go             # Session management
├── options.go             # Configuration options
├── errors.go              # Error definitions
├── go.mod
├── go.sum
└── roadmap.md
```
