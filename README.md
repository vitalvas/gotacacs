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
- Per-client secret provider support

## Installation

```bash
go get github.com/vitalvas/gotacacs
```

## Usage

### Client

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/vitalvas/gotacacs"
)

func main() {
    client := gotacacs.NewClient("tacacs.example.com:49",
        gotacacs.WithSecret("sharedsecret"),
        gotacacs.WithTimeout(30*time.Second),
    )

    ctx := context.Background()

    // Authentication
    reply, err := client.Authenticate(ctx, "username", "password")
    if err != nil {
        log.Fatal(err)
    }
    if reply.IsPass() {
        fmt.Println("Authentication successful")
    }

    // Authorization
    resp, err := client.Authorize(ctx, "username", []string{"service=shell", "cmd=show"})
    if err != nil {
        log.Fatal(err)
    }
    if resp.IsPass() {
        fmt.Println("Authorization granted")
        for _, arg := range resp.GetArgs() {
            fmt.Printf("  %s\n", arg)
        }
    }

    // Accounting
    acctReply, err := client.AccountingStart(ctx, "username", []string{"task_id=123"})
    if err != nil {
        log.Fatal(err)
    }
    if acctReply.IsSuccess() {
        fmt.Println("Accounting recorded")
    }
}
```

### Server

```go
package main

import (
    "context"
    "log"

    "github.com/vitalvas/gotacacs"
)

type handler struct {
    users map[string]string
}

func (h *handler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    user := string(req.Start.User)
    password := string(req.Start.Data)

    if expectedPass, ok := h.users[user]; ok && expectedPass == password {
        return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
    }
    return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
}

func (h *handler) HandleAuthenContinue(_ context.Context, _ *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
    return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
}

func (h *handler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
    return &gotacacs.AuthorResponse{
        Status: gotacacs.AuthorStatusPassAdd,
        Args:   [][]byte{[]byte("priv-lvl=15")},
    }
}

func (h *handler) HandleAcctRequest(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
    return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
}

func main() {
    ln, err := gotacacs.ListenTCP(":49")
    if err != nil {
        log.Fatal(err)
    }

    server := gotacacs.NewServer(
        gotacacs.WithServerListener(ln),
        gotacacs.WithServerSecret("sharedsecret"),
        gotacacs.WithHandler(&handler{
            users: map[string]string{
                "admin": "admin123",
                "user":  "user123",
            },
        }),
    )

    log.Println("Starting TACACS+ server on :49")
    if err := server.Serve(); err != nil {
        log.Fatal(err)
    }
}
```

### TLS Support

```go
// Client with TLS
tlsConfig := &tls.Config{
    RootCAs: certPool,
}
client := gotacacs.NewClient("tacacs.example.com:49",
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithTLSConfig(tlsConfig),
)

// Server with TLS
tlsConfig, err := gotacacs.NewTLSConfig("cert.pem", "key.pem")
if err != nil {
    log.Fatal(err)
}
ln, err := gotacacs.ListenTLS(":49", tlsConfig)
```

### Single-Connect Mode

```go
client := gotacacs.NewClient("tacacs.example.com:49",
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithSingleConnect(true),
)
defer client.Close()

// Multiple requests reuse the same connection
for i := 0; i < 10; i++ {
    reply, err := client.Authenticate(ctx, "user", "pass")
    // ...
}
```

## Example Binaries

The package includes example client and server binaries in `cmd/`:

### tacacs-client

```bash
go run ./cmd/tacacs-client -server localhost:49 -secret sharedsecret -user admin -pass admin123 -mode authenticate
```

### tacacs-server

```bash
go run ./cmd/tacacs-server -listen :49 -secret sharedsecret -users admin:admin123,user:user123 -verbose
```

## Protocol Reference

- [RFC8907: The Terminal Access Controller Access-Control System Plus (TACACS+) Protocol](https://datatracker.ietf.org/doc/html/rfc8907)

## License

See LICENSE file.
