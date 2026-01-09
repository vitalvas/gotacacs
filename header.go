package gotacacs

import (
	"encoding/binary"
	"fmt"
)

// Header represents a TACACS+ packet header as defined in RFC8907 Section 4.1.
// The header is 12 bytes and contains the following fields:
//   - Version (1 byte): major version (high nibble) and minor version (low nibble)
//   - Type (1 byte): packet type (authentication, authorization, or accounting)
//   - SeqNo (1 byte): sequence number for the session
//   - Flags (1 byte): various flags (unencrypted, single-connect)
//   - SessionID (4 bytes): session identifier
//   - Length (4 bytes): length of the packet body
type Header struct {
	Version   uint8
	Type      uint8
	SeqNo     uint8
	Flags     uint8
	SessionID uint32
	Length    uint32
}

// NewHeader creates a new Header with the specified packet type and session ID.
// It sets the default version and initializes sequence number to 1.
func NewHeader(packetType uint8, sessionID uint32) *Header {
	return &Header{
		Version:   MajorVersion<<4 | MinorVersionDefault,
		Type:      packetType,
		SeqNo:     1,
		Flags:     0,
		SessionID: sessionID,
		Length:    0,
	}
}

// MarshalBinary encodes the header to binary format (big-endian).
func (h *Header) MarshalBinary() ([]byte, error) {
	buf := make([]byte, HeaderLength)
	buf[0] = h.Version
	buf[1] = h.Type
	buf[2] = h.SeqNo
	buf[3] = h.Flags
	binary.BigEndian.PutUint32(buf[4:8], h.SessionID)
	binary.BigEndian.PutUint32(buf[8:12], h.Length)
	return buf, nil
}

// UnmarshalBinary decodes the header from binary format.
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderLength {
		return fmt.Errorf("%w: need %d bytes, got %d", ErrBufferTooShort, HeaderLength, len(data))
	}

	h.Version = data[0]
	h.Type = data[1]
	h.SeqNo = data[2]
	h.Flags = data[3]
	h.SessionID = binary.BigEndian.Uint32(data[4:8])
	h.Length = binary.BigEndian.Uint32(data[8:12])

	return nil
}

// Validate checks if the header contains valid values according to RFC8907.
func (h *Header) Validate() error {
	// Check major version
	majorVersion := h.Version >> 4
	if majorVersion != MajorVersion {
		return fmt.Errorf("%w: major version %d, expected %d", ErrInvalidVersion, majorVersion, MajorVersion)
	}

	// Check minor version
	minorVersion := h.Version & 0x0F
	if minorVersion != MinorVersionDefault && minorVersion != MinorVersionOne {
		return fmt.Errorf("%w: minor version %d", ErrInvalidVersion, minorVersion)
	}

	// Check packet type
	if h.Type != PacketTypeAuthen && h.Type != PacketTypeAuthor && h.Type != PacketTypeAcct {
		return fmt.Errorf("%w: %d", ErrInvalidType, h.Type)
	}

	// Check sequence number (must not be 0)
	if h.SeqNo == 0 {
		return fmt.Errorf("%w: sequence number cannot be 0", ErrInvalidSequence)
	}

	return nil
}

// MajorVersionNumber returns the major version from the version byte.
func (h *Header) MajorVersionNumber() uint8 {
	return h.Version >> 4
}

// MinorVersionNumber returns the minor version from the version byte.
func (h *Header) MinorVersionNumber() uint8 {
	return h.Version & 0x0F
}

// IsUnencrypted returns true if the unencrypted flag is set.
func (h *Header) IsUnencrypted() bool {
	return h.Flags&FlagUnencrypted != 0
}

// IsSingleConnect returns true if the single-connect flag is set.
func (h *Header) IsSingleConnect() bool {
	return h.Flags&FlagSingleConnect != 0
}

// SetUnencrypted sets or clears the unencrypted flag.
func (h *Header) SetUnencrypted(unencrypted bool) {
	if unencrypted {
		h.Flags |= FlagUnencrypted
	} else {
		h.Flags &^= FlagUnencrypted
	}
}

// SetSingleConnect sets or clears the single-connect flag.
func (h *Header) SetSingleConnect(singleConnect bool) {
	if singleConnect {
		h.Flags |= FlagSingleConnect
	} else {
		h.Flags &^= FlagSingleConnect
	}
}
