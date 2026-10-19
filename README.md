# gotacacs

A Go implementation of the TACACS+ protocol as defined in [RFC 8907](https://datatracker.ietf.org/doc/html/rfc8907), with TLS 1.3 transport support per [RFC 9887](https://datatracker.ietf.org/doc/html/rfc9887).

Provides both client and server SDK interfaces for Authentication, Authorization, and Accounting (AAA) services.

## Features

- TACACS+ authentication, authorization, and accounting packet types (RFC 8907)
- TLS 1.3 transport support (RFC 9887)
- Client SDK with high-level API (PAP and ASCII interactive authentication)
- Server SDK with pluggable handler interfaces
- TCP and TLS transport support
- Body obfuscation (MD5-based pseudo-pad)
- Single-connect mode for connection reuse
- Per-client secret provider with custom user data
- Argument helpers for TACACS+ `key=value` attributes
- Graceful server shutdown

## Requirements

- Go 1.27 or later

## Installation

```bash
go get go.vitalvas.com/gotacacs
```

## Quick Start

### Client

```go
client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithSecret("sharedsecret"),
)
defer client.Close()

// Authentication (PAP)
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
}

// Accounting
acctReply, err := client.Accounting(ctx, gotacacs.AcctFlagStart, "username", []string{
    "task_id=123",
    "service=shell",
    "cmd=",
})
if err != nil {
    log.Fatal(err)
}
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

Implement the `Handler` interface. This example supports PAP login:

```go
type myHandler struct{}

func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    if req.Start.Action != gotacacs.AuthenActionLogin ||
        req.Start.AuthenType != gotacacs.AuthenTypePAP ||
        req.Start.Service != gotacacs.AuthenServiceLogin {
        return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
    }
    if string(req.Start.User) == "admin" && string(req.Start.Data) == "secret" {
        return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
    }
    return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
}

func (h *myHandler) HandleAuthenContinue(_ context.Context, _ *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
    return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusError, ServerMsg: []byte("CONTINUE not supported")}
}

func (h *myHandler) HandleAuthorRequest(_ context.Context, _ *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
    return &gotacacs.AuthorResponse{
        Status:  gotacacs.AuthorStatusPassAdd,
        RawArgs: gotacacs.ArgsFromMap(map[string]string{"priv-lvl": "15"}),
    }
}

func (h *myHandler) HandleAcctRequest(_ context.Context, _ *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
    return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
}
```

### Per-Client Secret Provider

```go
secretProvider := gotacacs.SecretProviderFunc(func(_ context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
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

### TLS 1.3 (RFC 9887)

Configure certificates and trusted CA pools on both peers for mutual authentication:

```go
// clientCert and serverCert are loaded with tls.LoadX509KeyPair.
// serverCAs and clientCAs contain the trusted CA certificates for each peer.
client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:300"),
    gotacacs.WithTLSConfig(&tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      serverCAs,
        ServerName:   "tacacs.example.com",
    }),
)
defer client.Close()

// Server with TLS
ln, err := gotacacs.ListenTLS(":300", &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    clientCAs,
    ClientAuth:   tls.RequireAndVerifyClientCert,
})
if err != nil {
    log.Fatal(err)
}
```

When using TLS, the `FlagUnencrypted` header flag is set automatically and body obfuscation is disabled, as specified by RFC 9887.

RFC 9887 also requires certificate revocation and peer identity checks. Configure these through `tls.Config`, including `VerifyConnection`; see the [client](docs/client.md#tls-configuration-rfc-9887) and [server](docs/server.md#tls-configuration-rfc-9887) guides. TCP shared-secret obfuscation does not provide TLS encryption or integrity protection.

## Examples

The package includes example binaries in `examples/`:

```bash
# TCP mode
go run ./examples/tacacs-server -addr :49 -secret sharedsecret
go run ./examples/tacacs-client -addr localhost:49 -secret sharedsecret

# Basic TLS transport demonstration (server certificate must be trusted)
go run ./examples/tacacs-server-tls -addr :300 -cert server.crt -key server.key
go run ./examples/tacacs-client-tls -addr localhost:300
```

The TLS example binaries do not configure mutual authentication or certificate revocation checks. Use the SDK configuration above and the linked guides for RFC 9887 deployments.

## Documentation

- [Client Documentation](docs/client.md)
- [Server Documentation](docs/server.md)

## Protocol Reference

- [RFC 8907 - TACACS+ Protocol](https://datatracker.ietf.org/doc/html/rfc8907)
- [RFC 9887 - TACACS+ TLS 1.3](https://datatracker.ietf.org/doc/html/rfc9887)
