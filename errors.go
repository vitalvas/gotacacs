package gotacacs

import "errors"

// Protocol errors for TACACS+ operations.
var (
	// ErrInvalidHeader indicates the packet header is malformed or invalid.
	ErrInvalidHeader = errors.New("invalid header")

	// ErrInvalidPacket indicates the packet body is malformed or invalid.
	ErrInvalidPacket = errors.New("invalid packet")

	// ErrInvalidVersion indicates an unsupported protocol version.
	ErrInvalidVersion = errors.New("invalid version")

	// ErrInvalidType indicates an unsupported packet type.
	ErrInvalidType = errors.New("invalid packet type")

	// ErrInvalidSequence indicates a sequence number violation.
	ErrInvalidSequence = errors.New("invalid sequence number")

	// ErrSessionNotFound indicates the session ID is unknown.
	ErrSessionNotFound = errors.New("session not found")

	// ErrConnectionClosed indicates the connection was terminated.
	ErrConnectionClosed = errors.New("connection closed")

	// ErrTimeout indicates a network operation timed out.
	// Client operations wrap it around the underlying net error.
	ErrTimeout = errors.New("operation timeout")

	// ErrAuthenticationFailed indicates the server returned a FAIL
	// authentication status. The reply is returned alongside this error.
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrAuthorizationDenied indicates the server returned a FAIL
	// authorization status. The response is returned alongside this error.
	ErrAuthorizationDenied = errors.New("authorization denied")

	// ErrAccountingFailed indicates the server returned an ERROR
	// accounting status. The reply is returned alongside this error.
	ErrAccountingFailed = errors.New("accounting failed")

	// ErrBufferTooShort indicates the buffer is too short for the operation.
	ErrBufferTooShort = errors.New("buffer too short")

	// ErrBodyTooLarge indicates the packet body exceeds maximum size.
	ErrBodyTooLarge = errors.New("body too large")

	// ErrAuthenFollow indicates the server returned the authentication FOLLOW status.
	// Authentication methods return the reply along with this error.
	ErrAuthenFollow = errors.New("authentication follow requested")

	// ErrAuthenRestart indicates the server requested authentication restart.
	// The client should restart authentication from the beginning.
	ErrAuthenRestart = errors.New("authentication restart requested")

	// ErrSequenceOverflow indicates the sequence number would overflow.
	// This happens after 255 packets in a session.
	ErrSequenceOverflow = errors.New("sequence number overflow")

	// ErrMaxPrompts indicates that an ASCII authentication exchange exceeded
	// the maximum number of interactive prompt round-trips.
	ErrMaxPrompts = errors.New("maximum prompt count exceeded")

	// ErrBadSecret indicates the shared secret may be incorrect.
	// This error is returned when packet parsing fails in a way that
	// suggests the body was deobfuscated with the wrong secret,
	// resulting in garbage length fields.
	ErrBadSecret = errors.New("bad secret")

	// ErrTooManySessions indicates a connection exceeded the maximum
	// number of concurrent sessions and was terminated.
	ErrTooManySessions = errors.New("too many sessions")

	// ErrNoSecret indicates a non-TLS connection had no shared secret
	// configured. RFC 8907 Section 10.5.2 requires a shared secret on every
	// non-TLS connection; the server rejects such connections unless
	// WithServerAllowInsecure is set.
	ErrNoSecret = errors.New("no shared secret for non-TLS connection")

	// ErrInvalidUsername indicates a username is not valid per the RFC 8907
	// Section 3.7 / RFC 8265 UsernameCasePreserved rules enforced by
	// ValidateUsername.
	ErrInvalidUsername = errors.New("invalid username")

	// ErrInvalidText indicates a text field contains non-printable or
	// non-US-ASCII bytes, violating RFC 8907 Section 3.7.
	ErrInvalidText = errors.New("invalid text field")
)
