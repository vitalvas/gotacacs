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

	// ErrTimeout indicates an operation timed out.
	ErrTimeout = errors.New("operation timeout")

	// ErrAuthenticationFailed indicates authentication failed.
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrAuthorizationDenied indicates authorization was denied.
	ErrAuthorizationDenied = errors.New("authorization denied")

	// ErrAccountingFailed indicates accounting operation failed.
	ErrAccountingFailed = errors.New("accounting failed")

	// ErrBufferTooShort indicates the buffer is too short for the operation.
	ErrBufferTooShort = errors.New("buffer too short")

	// ErrBodyTooLarge indicates the packet body exceeds maximum size.
	ErrBodyTooLarge = errors.New("body too large")

	// ErrAuthenFollow indicates the server requested authentication follow.
	// The client should connect to an alternate server specified in ServerMsg.
	ErrAuthenFollow = errors.New("authentication follow requested")

	// ErrAuthenRestart indicates the server requested authentication restart.
	// The client should restart authentication from the beginning.
	ErrAuthenRestart = errors.New("authentication restart requested")

	// ErrSequenceOverflow indicates the sequence number would overflow.
	// This happens after 255 packets in a session.
	ErrSequenceOverflow = errors.New("sequence number overflow")
)
