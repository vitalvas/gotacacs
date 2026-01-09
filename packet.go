package gotacacs

import (
	"encoding"
	"fmt"
)

// Packet is the interface that all TACACS+ packet types implement.
type Packet interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// ParseAuthenPacket parses an authentication packet body based on the sequence number.
// Odd sequence numbers indicate client packets (START, CONTINUE).
// Even sequence numbers indicate server packets (REPLY).
func ParseAuthenPacket(seqNo uint8, data []byte) (Packet, error) {
	if seqNo == 0 {
		return nil, fmt.Errorf("%w: sequence number cannot be 0", ErrInvalidSequence)
	}

	if seqNo == 1 {
		// First packet is always START
		p := &AuthenStart{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	if seqNo%2 == 0 {
		// Even sequence numbers are server replies
		p := &AuthenReply{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	// Odd sequence numbers > 1 are client continues
	p := &AuthenContinue{}
	if err := p.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseAuthorPacket parses an authorization packet body based on the sequence number.
// Sequence number 1 indicates a REQUEST.
// Sequence number 2 indicates a RESPONSE.
func ParseAuthorPacket(seqNo uint8, data []byte) (Packet, error) {
	if seqNo == 0 {
		return nil, fmt.Errorf("%w: sequence number cannot be 0", ErrInvalidSequence)
	}

	if seqNo == 1 {
		// Request from client
		p := &AuthorRequest{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	if seqNo == 2 {
		// Response from server
		p := &AuthorResponse{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	return nil, fmt.Errorf("%w: authorization only supports sequence 1 (request) or 2 (response)", ErrInvalidSequence)
}

// ParseAcctPacket parses an accounting packet body based on the sequence number.
// Sequence number 1 indicates a REQUEST.
// Sequence number 2 indicates a REPLY.
func ParseAcctPacket(seqNo uint8, data []byte) (Packet, error) {
	if seqNo == 0 {
		return nil, fmt.Errorf("%w: sequence number cannot be 0", ErrInvalidSequence)
	}

	if seqNo == 1 {
		// Request from client
		p := &AcctRequest{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	if seqNo == 2 {
		// Reply from server
		p := &AcctReply{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	return nil, fmt.Errorf("%w: accounting only supports sequence 1 (request) or 2 (reply)", ErrInvalidSequence)
}

// ParsePacket parses a packet body based on the header information.
// It determines the packet type from the header and delegates to the appropriate parser.
func ParsePacket(header *Header, data []byte) (Packet, error) {
	if header == nil {
		return nil, fmt.Errorf("%w: header is nil", ErrInvalidHeader)
	}

	switch header.Type {
	case PacketTypeAuthen:
		return ParseAuthenPacket(header.SeqNo, data)
	case PacketTypeAuthor:
		return ParseAuthorPacket(header.SeqNo, data)
	case PacketTypeAcct:
		return ParseAcctPacket(header.SeqNo, data)
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidType, header.Type)
	}
}

// PacketType returns the packet type constant for a given packet.
func PacketType(p Packet) uint8 {
	switch p.(type) {
	case *AuthenStart, *AuthenReply, *AuthenContinue:
		return PacketTypeAuthen
	case *AuthorRequest, *AuthorResponse:
		return PacketTypeAuthor
	case *AcctRequest, *AcctReply:
		return PacketTypeAcct
	default:
		return 0
	}
}

// IsClientPacket returns true if the packet is sent by the client.
func IsClientPacket(p Packet) bool {
	switch p.(type) {
	case *AuthenStart, *AuthenContinue:
		return true
	case *AuthorRequest:
		return true
	case *AcctRequest:
		return true
	default:
		return false
	}
}

// IsServerPacket returns true if the packet is sent by the server.
func IsServerPacket(p Packet) bool {
	switch p.(type) {
	case *AuthenReply:
		return true
	case *AuthorResponse:
		return true
	case *AcctReply:
		return true
	default:
		return false
	}
}
