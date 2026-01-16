# gotacacs

A Go implementation of the TACACS+ protocol as defined in [RFC8907](https://datatracker.ietf.org/doc/html/rfc8907).

This package provides both client and server SDK interfaces for Authentication, Authorization, and Accounting (AAA) services.

## Features

- Full TACACS+ protocol implementation (RFC8907)
- Client SDK with simple high-level API
- Server SDK with pluggable handler interfaces
- TCP and TLS transport support
- Body obfuscation (MD5-based pseudo-pad)
- Single-connect mode for connection reuse
- Per-client secret provider with custom user data

## Installation

```bash
go get github.com/vitalvas/gotacacs
```

## Quick Start

### Client

```go
client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithSecret("sharedsecret"),
)

// Authentication
reply, err := client.Authenticate(ctx, "username", "password")
if reply.IsPass() {
    fmt.Println("Authentication successful")
}

// Authorization
resp, err := client.Authorize(ctx, "username", []string{"service=shell", "cmd=show"})
if resp.IsPass() {
    fmt.Println("Authorization granted")
}

// Accounting
acctReply, err := client.Accounting(ctx, gotacacs.AcctFlagStart, "username", []string{"task_id=123"})
if acctReply.IsSuccess() {
    fmt.Println("Accounting recorded")
}
```

### Server

```go
ln, err := gotacacs.ListenTCP(":49")
if err != nil {
    log.Fatal(err)
}

server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithServerSecret("sharedsecret"),
    gotacacs.WithHandler(&myHandler{}),
)

if err := server.Serve(); err != nil {
    log.Fatal(err)
}
```

Implement the handler interface:

```go
type myHandler struct{}

func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    if string(req.Start.User) == "admin" && string(req.Start.Data) == "secret" {
        return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
    }
    return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
}

func (h *myHandler) HandleAuthenContinue(_ context.Context, _ *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
    return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
}

func (h *myHandler) HandleAuthorRequest(_ context.Context, _ *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
    return &gotacacs.AuthorResponse{
        Status: gotacacs.AuthorStatusPassAdd,
        Args:   [][]byte{[]byte("priv-lvl=15")},
    }
}

func (h *myHandler) HandleAcctRequest(_ context.Context, _ *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
    return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
}
```

### Per-Client Secret Provider

```go
secretProvider := gotacacs.SecretProviderFunc(func(ctx context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
    return gotacacs.SecretResponse{
        Secret: []byte("sharedsecret"),
        UserData: map[string]string{
            "client_ip": req.RemoteAddr.String(),
            "local_ip":  req.LocalAddr.String(),
        },
    }
})

server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithSecretProvider(secretProvider),
    gotacacs.WithHandler(&myHandler{}),
)
```

## Documentation

- [Client Documentation](docs/client.md) - Client options, authentication, authorization, accounting, TLS, error handling
- [Server Documentation](docs/server.md) - Server options, handlers, secret providers, session management, TLS

## Examples

The package includes example binaries in `cmd/`:

```bash
# Run the server
go run ./cmd/tacacs-server

# Run the client
go run ./cmd/tacacs-client
```

## Protocol Reference

- [RFC8907: The Terminal Access Controller Access-Control System Plus (TACACS+) Protocol](https://datatracker.ietf.org/doc/html/rfc8907)

## License

See LICENSE file.
