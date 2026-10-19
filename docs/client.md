# TACACS+ Client

The gotacacs client provides a high-level API for communicating with TACACS+ servers, supporting Authentication, Authorization, and Accounting (AAA) operations.

## Creating a Client

Create a client using `NewClient` with functional options:

```go
import (
    "time"
    "go.vitalvas.com/gotacacs"
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
| `WithTimeout(duration time.Duration)` | Built-in dialer timeout and timeout for each network read/write; zero disables this timeout | 30 seconds |
| `WithTLSConfig(config *tls.Config)` | TLS configuration with a minimum version of TLS 1.3 | None (plain TCP) |
| `WithDialer(dialer Dialer)` | Custom dialer implementation | TCPDialer |
| `WithSingleConnect(enabled bool)` | Enable connection reuse | false |
| `WithMaxBodyLength(length uint32)` | Maximum allowed response body length | 256 KiB |

## Authentication

### PAP Authentication

Password Authentication Protocol (PAP) sends credentials in a single START request using TACACS+ version `0xc1`. Use `AuthenticateASCII` when the server needs interactive prompts.

```go
ctx := context.Background()

reply, err := client.Authenticate(ctx, "username", "password")
if errors.Is(err, gotacacs.ErrAuthenticationFailed) {
    fmt.Println("Authentication failed")
    fmt.Printf("Server message: %s\n", string(reply.ServerMsg))
    return
}
if err != nil {
    log.Fatal(err)
}

if reply.IsPass() {
    fmt.Println("Authentication successful")
    fmt.Printf("Server message: %s\n", string(reply.ServerMsg))
} else if reply.IsError() {
    fmt.Println("Server error occurred")
}
```

A FAIL status returns the reply together with `ErrAuthenticationFailed`, so the server message stays available while `errors.Is` branching works.

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

Set `Action: gotacacs.AuthenActionChPass` to request a password change instead of a login; the zero value is `AuthenActionLogin`. Set `Session` to use a specific session ID on the wire instead of a fresh random one.

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

ASCII authentication uses version `0xc0`. The client allows up to 20 prompt responses and still accepts a final reply after the twentieth response. A further prompt returns `ErrMaxPrompts`.

If input is requested, a nil `promptHandler` returns `ErrInvalidPacket`. An answer exceeding the CONTINUE field limit of 65,535 bytes returns an error and closes the connection. If the callback returns an error, the client attempts to send ABORT, closes the connection, and returns that error. Implement `readPassword` and `readLine` in your application; the callback runs synchronously and must handle cancellation of its own input operation.

### CHAP Authentication

CHAP ([RFC 8907 Section 5.4.2.3](https://www.rfc-editor.org/rfc/rfc8907.html#section-5.4.2.3)) is a single START / single REPLY exchange. The caller supplies the PPP id and challenge; the client computes the MD5 response from the shared secret and sends it in the START data field:

```go
challenge := make([]byte, 16) // SHOULD be >= 8 octets and unpredictable
if _, err := rand.Read(challenge); err != nil {
    log.Fatal(err)
}

reply, err := client.AuthenticateCHAP(ctx, "username", id, []byte("shared-secret"), challenge)
if errors.Is(err, gotacacs.ErrAuthenticationFailed) {
    log.Println("CHAP rejected")
    return
}
if err != nil {
    log.Fatal(err)
}
```

CHAP uses version `0xc1`. A FAIL status returns the reply with `ErrAuthenticationFailed`. The lower-level helpers `CHAPResponse`, `BuildCHAPData`, `ParseCHAPData`, and `NewCHAPStart` are exported for callers assembling the exchange manually; MS-CHAP and MS-CHAPv2 are not implemented.

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
if errors.Is(err, gotacacs.ErrAuthorizationDenied) {
    fmt.Println("Authorization denied")
    fmt.Printf("Reason: %s\n", string(resp.ServerMsg))
    return
}
if err != nil {
    log.Fatal(err)
}

if resp.IsPass() {
	fmt.Println("Authorization granted")

	// Get server-provided arguments by key
	values := resp.ArgValues()
	fmt.Printf("Privilege level: %s\n", values.Get("priv-lvl"))
}
```

A FAIL status returns the response together with `ErrAuthorizationDenied`.

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
| `Args()` | Returns server-provided arguments as string slice |
| `ArgValues()` | Returns server-provided `key=value` arguments parsed by key |

## Accounting

Send accounting records for session tracking:

```go
// Session start
startReply, err := client.Accounting(ctx, gotacacs.AcctFlagStart, "username", []string{
    "task_id=12345",
    "start_time=1234567890",
    "service=shell",
    "cmd=",
})
if err != nil {
    log.Fatal(err)
}

// Watchdog (periodic update)
watchdogReply, err := client.Accounting(ctx, gotacacs.AcctFlagWatchdog|gotacacs.AcctFlagStart, "username", []string{
    "task_id=12345",
    "bytes_in=1024",
    "bytes_out=2048",
    "service=shell",
    "cmd=",
})
if err != nil {
    log.Fatal(err)
}

// Session stop
stopReply, err := client.Accounting(ctx, gotacacs.AcctFlagStop, "username", []string{
    "task_id=12345",
    "elapsed_time=3600",
    "stop_time=1234571490",
    "service=shell",
    "cmd=",
})
if err != nil {
    log.Fatal(err)
}
```

Keep accounting attributes before service/authorization attributes. Shell records include both `service=shell` and `cmd=` (or the command name). Use a distinct `task_id` for each active task and the same value for its matching records, as specified in [RFC 8907 Section 8](https://datatracker.ietf.org/doc/html/rfc8907#section-8).

### Accounting Flags

| Flag | Description |
|------|-------------|
| `AcctFlagStart` | Session start record |
| `AcctFlagStop` | Session stop record |
| `AcctFlagWatchdog` | Keepalive without updated arguments |
| `AcctFlagWatchdog \| AcctFlagStart` | Periodic update with additional or changed arguments |

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

## TLS Configuration (RFC 9887)

When using TLS, the shared secret is not needed as TLS provides encryption.
The default TLS port for TACACS+ is 300. `WithTLSConfig` clones the configuration and sets `MinVersion` to TLS 1.3; a nonzero `MaxVersion` below TLS 1.3 is raised to TLS 1.3. `TLSDialer` also enforces a minimum of TLS 1.3 and rejects incompatible version limits.

### Mutual Certificate Authentication

[RFC 9887 Section 3](https://www.rfc-editor.org/rfc/rfc9887.html#section-3) requires mutual authentication. Load a client certificate and configure trust for the server:

```go
cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      certPool, // Trusted server CAs.
    ServerName:   "tacacs.example.com",
}

client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:300"),
    gotacacs.WithTLSConfig(tlsConfig),
)
defer client.Close()
```

`ServerName` controls server identity verification and SNI independently of the address used for dialing. The server must require and verify the client certificate; see the [server TLS configuration](server.md#tls-configuration-rfc-9887).

RFC 9887 also requires certificate revocation checking. Go's [default certificate verifier](https://pkg.go.dev/crypto/x509#Certificate.Verify) does not check revocation. Supply application verification through `tls.Config.VerifyConnection`, retaining normal chain and hostname verification. This callback also runs on resumed connections. Setting `InsecureSkipVerify` disables normal server certificate and hostname checks.

## Single-Connect Mode

Single-connect mode reuses connections when the server accepts it in the first reply. The result applies for the lifetime of that connection; later single-connect flags do not renegotiate the mode ([RFC 8907 Section 4.3](https://datatracker.ietf.org/doc/html/rfc8907#section-4.3)).

```go
client := gotacacs.NewClient(
    gotacacs.WithAddress("tacacs.example.com:49"),
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithSingleConnect(true),
)
defer client.Close()  // Important: close when done

// Reuse the connection when the server accepted single-connect mode.
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

If the server declines single-connect, the client closes the connection after the session. A server may also close an idle connection after accepting single-connect. The operation that detects a broken connection returns an error; the next operation reconnects. Failed operations are not automatically replayed.

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

`IsConnected` reports whether the client holds a connection; it does not probe whether the peer is still reachable.

### Context Cancellation and Deadlines

Each network read and write uses the earlier of the context deadline and the configured timeout. A later operation without a deadline clears the earlier operation's deadline. Context cancellation interrupts in-flight network I/O and closes the connection, including when the context has no deadline and `WithTimeout(0)` is used.

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
    Dial(ctx context.Context, network, address string) (net.Conn, error)
}
```

Example with a custom connection timeout:

```go
type customDialer struct {
    timeout time.Duration
}

func (d *customDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
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
    gotacacs.WithSecret("sharedsecret"),
    gotacacs.WithDialer(&customDialer{timeout: 5 * time.Second}),
)
```

`WithTimeout` updates built-in `TCPDialer` and `TLSDialer` timeouts regardless of option order. Other dialers manage their own connection timeout; client read/write timeouts still apply. When combining `WithTLSConfig` and `WithDialer`, put `WithDialer` last and return a TLS connection. A plaintext result is rejected in TLS mode.

## Error Handling

### Common Errors

| Error | Description |
|-------|-------------|
| `ErrAuthenticationFailed` | Authentication returned FAIL; the reply is returned alongside the error |
| `ErrAuthorizationDenied` | Authorization returned FAIL; the response is returned alongside the error |
| `ErrAccountingFailed` | Accounting returned ERROR; the reply is returned alongside the error |
| `ErrTimeout` | A network read, write, or dial timed out; wraps the underlying net error |
| `ErrConnectionClosed` | Server closed the connection |
| `ErrInvalidPacket` | Invalid packet or input, including a required prompt callback missing or a plaintext dialer result in TLS mode |
| `ErrInvalidSequence` | Sequence number mismatch |
| `ErrSessionNotFound` | Session ID mismatch |
| `ErrBodyTooLarge` | Response body exceeds maximum length |
| `ErrAuthenFollow` | Authentication returned FOLLOW; the reply is returned alongside the error |
| `ErrAuthenRestart` | Server requests authentication restart |
| `ErrMaxPrompts` | ASCII authentication requested more than 20 prompt responses |

FOLLOW remains a distinct `Status` value. Authentication methods return it with `ErrAuthenFollow`; `Authorize` and `Accounting` return it with a nil error. The client does not redirect automatically. Check `IsPass()` or `IsSuccess()` to determine success.

### Error Handling Example

```go
reply, err := client.Authenticate(ctx, "user", "pass")
if err != nil {
    switch {
    case errors.Is(err, gotacacs.ErrAuthenticationFailed):
        log.Printf("Credentials rejected: %s", reply.ServerMsg)
    case errors.Is(err, gotacacs.ErrTimeout):
        log.Println("Server did not respond in time")
    case errors.Is(err, gotacacs.ErrConnectionClosed):
        log.Println("Connection was closed, retrying...")
        // Retry logic
    case errors.Is(err, gotacacs.ErrAuthenFollow):
        log.Println("Server returned FOLLOW")
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
    gotacacs.WithAddress("tacacs.example.com:300"),
    gotacacs.WithTimeout(30*time.Second),
    gotacacs.WithTLSConfig(tlsConfig),
    gotacacs.WithMaxBodyLength(gotacacs.DefaultMaxBodyLength),
)
defer client.Close()
```
