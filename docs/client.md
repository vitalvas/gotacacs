# TACACS+ Client

The gotacacs client provides a high-level API for communicating with TACACS+ servers, supporting Authentication, Authorization, and Accounting (AAA) operations.

## Creating a Client

Create a client using `NewClient` with functional options:

```go
import (
    "time"
    "github.com/vitalvas/gotacacs"
)

client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithTimeout(30*time.Second),
)
```

## Client Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithAddress(addr string)` | Server address in `host:port` format | Required |
| `WithSecret(secret string)` | Shared secret for packet obfuscation | None (unencrypted) |
| `WithSecretBytes(secret []byte)` | Shared secret as byte slice | None |
| `WithTimeout(duration time.Duration)` | Connection and operation timeout | 30 seconds |
| `WithTLSConfig(config *tls.Config)` | TLS configuration for secure connections | None (plain TCP) |
| `WithDialer(dialer Dialer)` | Custom dialer implementation | TCPDialer |
| `WithSingleConnect(enabled bool)` | Enable connection reuse | false |
| `WithMaxBodyLength(length uint32)` | Maximum allowed response body length | 65535 |

## Authentication

### PAP Authentication

Password Authentication Protocol (PAP) sends credentials in a single request:

```go
ctx := context.Background()

reply, err := client.Authenticate(ctx, "username", "password")
if err != nil {
    log.Fatal(err)
}

if reply.IsPass() {
    fmt.Println("Authentication successful")
    fmt.Printf("Server message: %s\n", string(reply.ServerMsg))
} else if reply.IsFail() {
    fmt.Println("Authentication failed")
    fmt.Printf("Server message: %s\n", string(reply.ServerMsg))
} else if reply.IsError() {
    fmt.Println("Server error occurred")
}
```

### Authentication with Extended Context

Use `AuthenticateWithContext` for additional context information:

```go
authCtx := &gotacacs.AuthenticateContext{
    Username:   "admin",
    Password:   "secret123",
    Port:       "tty0",
    RemoteAddr: "192.168.1.100",
}

reply, err := client.AuthenticateWithContext(ctx, authCtx)
if err != nil {
    log.Fatal(err)
}
```

### ASCII Authentication (Interactive)

ASCII authentication supports multi-step interactive prompts:

```go
promptHandler := func(prompt string, noEcho bool) (string, error) {
    if noEcho {
        // Password prompt - don't echo input
        return readPassword(prompt)
    }
    // Regular prompt
    return readLine(prompt)
}

reply, err := client.AuthenticateASCII(ctx, "username", promptHandler)
if err != nil {
    log.Fatal(err)
}
```

### AuthenReply Methods

| Method | Description |
|--------|-------------|
| `IsPass()` | Returns true if authentication succeeded |
| `IsFail()` | Returns true if authentication failed |
| `IsError()` | Returns true if server returned an error |
| `NeedsInput()` | Returns true if server needs more input (GETDATA/GETUSER/GETPASS) |
| `NoEcho()` | Returns true if input should not be echoed (password entry) |

## Authorization

Request authorization for specific services or commands:

```go
resp, err := client.Authorize(ctx, "username", []string{
    "service=shell",
    "cmd=show",
    "cmd-arg=running-config",
})
if err != nil {
    log.Fatal(err)
}

if resp.IsPass() {
    fmt.Println("Authorization granted")

    // Get server-provided arguments
    for _, arg := range resp.GetArgs() {
        fmt.Printf("  %s\n", arg)
    }
} else if resp.IsFail() {
    fmt.Println("Authorization denied")
    fmt.Printf("Reason: %s\n", string(resp.ServerMsg))
}
```

### Common Authorization Arguments

| Argument | Description |
|----------|-------------|
| `service=shell` | Shell/exec service |
| `service=ppp` | PPP service |
| `cmd=<command>` | Command being executed |
| `cmd-arg=<arg>` | Command argument |
| `protocol=ip` | Protocol type |
| `priv-lvl=<0-15>` | Privilege level |

### AuthorResponse Methods

| Method | Description |
|--------|-------------|
| `IsPass()` | Returns true if authorized (PASS_ADD or PASS_REPL) |
| `IsFail()` | Returns true if authorization denied |
| `IsError()` | Returns true if server returned an error |
| `GetArgs()` | Returns server-provided arguments as string slice |

## Accounting

Send accounting records for session tracking:

```go
// Session start
startReply, err := client.Accounting(ctx, gotacacs.AcctFlagStart, "username", []string{
    "task_id=12345",
    "service=shell",
    "start_time=1234567890",
})
if err != nil {
    log.Fatal(err)
}

// Watchdog (periodic update)
watchdogReply, err := client.Accounting(ctx, gotacacs.AcctFlagWatchdog, "username", []string{
    "task_id=12345",
    "bytes_in=1024",
    "bytes_out=2048",
})

// Session stop
stopReply, err := client.Accounting(ctx, gotacacs.AcctFlagStop, "username", []string{
    "task_id=12345",
    "elapsed_time=3600",
    "stop_time=1234571490",
})
```

### Accounting Flags

| Flag | Description |
|------|-------------|
| `AcctFlagStart` | Session start record |
| `AcctFlagStop` | Session stop record |
| `AcctFlagWatchdog` | Periodic update record |

### Common Accounting Arguments

| Argument | Description |
|----------|-------------|
| `task_id=<id>` | Unique session identifier |
| `start_time=<epoch>` | Session start time |
| `stop_time=<epoch>` | Session stop time |
| `elapsed_time=<seconds>` | Session duration |
| `bytes_in=<count>` | Bytes received |
| `bytes_out=<count>` | Bytes sent |
| `service=<name>` | Service type |
| `cmd=<command>` | Command executed |

### AcctReply Methods

| Method | Description |
|--------|-------------|
| `IsSuccess()` | Returns true if accounting record accepted |
| `IsError()` | Returns true if server returned an error |

## TLS Configuration

### Basic TLS

```go
tlsConfig := &tls.Config{
    RootCAs: certPool,  // CA certificate pool
}

client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithTLSConfig(tlsConfig),
)
```

### TLS with Client Certificate

```go
cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      certPool,
}

client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithTLSConfig(tlsConfig),
)
```

### Skip Certificate Verification (Testing Only)

```go
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,  // NOT for production
}
```

## Single-Connect Mode

Single-connect mode reuses connections for multiple requests, reducing latency:

```go
client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithSingleConnect(true),
)
defer client.Close()  // Important: close when done

// All requests reuse the same connection
for i := 0; i < 100; i++ {
    reply, err := client.Authenticate(ctx, "user", "pass")
    if err != nil {
        // Connection may have been closed by server
        // Client will reconnect automatically on next request
        log.Printf("Request %d failed: %v", i, err)
        continue
    }
    // Process reply...
}
```

## Connection Management

### Manual Connection

```go
// Explicitly connect
err := client.Connect(ctx)
if err != nil {
    log.Fatal(err)
}

// Check connection status
if client.IsConnected() {
    fmt.Println("Connected to server")
}

// Get addresses
fmt.Printf("Local: %s\n", client.LocalAddr())
fmt.Printf("Remote: %s\n", client.RemoteAddr())
fmt.Printf("Server: %s\n", client.Address())
```

### Closing Connections

```go
// Close the connection
err := client.Close()
if err != nil {
    log.Printf("Close error: %v", err)
}
```

## Custom Dialer

Implement the `Dialer` interface for custom connection handling:

```go
type Dialer interface {
    Dial(ctx context.Context, network, address string) (Conn, error)
}
```

Example with custom timeout per operation:

```go
type customDialer struct {
    timeout time.Duration
}

func (d *customDialer) Dial(ctx context.Context, network, address string) (gotacacs.Conn, error) {
    dialer := &net.Dialer{
        Timeout: d.timeout,
    }
    conn, err := dialer.DialContext(ctx, network, address)
    if err != nil {
        return nil, err
    }
    return conn, nil
}

client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithDialer(&customDialer{timeout: 5 * time.Second}),
)
```

## Error Handling

### Common Errors

| Error | Description |
|-------|-------------|
| `ErrConnectionClosed` | Server closed the connection |
| `ErrInvalidPacket` | Malformed packet received |
| `ErrInvalidSequence` | Sequence number mismatch |
| `ErrSessionNotFound` | Session ID mismatch |
| `ErrBodyTooLarge` | Response body exceeds maximum length |
| `ErrAuthenFollow` | Server requests authentication elsewhere |
| `ErrAuthenRestart` | Server requests authentication restart |

### Error Handling Example

```go
reply, err := client.Authenticate(ctx, "user", "pass")
if err != nil {
    switch {
    case errors.Is(err, gotacacs.ErrConnectionClosed):
        log.Println("Connection was closed, retrying...")
        // Retry logic
    case errors.Is(err, gotacacs.ErrAuthenFollow):
        log.Printf("Follow to: %s", reply.ServerMsg)
    case errors.Is(err, gotacacs.ErrAuthenRestart):
        log.Println("Restart authentication")
    default:
        log.Fatalf("Authentication error: %v", err)
    }
    return
}
```

## Best Practices

1. **Use Timeouts**: Always set appropriate timeouts to prevent hanging connections.

2. **Close Connections**: When using single-connect mode, always defer `client.Close()`.

3. **Handle Errors**: Check and handle all error returns appropriately.

4. **Use TLS in Production**: Always use TLS for production deployments.

5. **Validate Responses**: Check `IsPass()`, `IsFail()`, `IsError()` before processing responses.

6. **Limit Body Size**: Set `WithMaxBodyLength` to prevent memory exhaustion from malicious servers.

```go
client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithTimeout(30*time.Second),
    gotacacs.WithTLSConfig(tlsConfig),
    gotacacs.WithMaxBodyLength(65535),
)
defer client.Close()
```
