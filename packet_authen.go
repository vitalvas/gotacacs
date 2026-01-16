package gotacacs

import (
	"encoding/binary"
	"fmt"
)

// AuthenStart represents a TACACS+ authentication START packet as defined in RFC8907 Section 5.1.
// This packet is sent by the client to initiate an authentication session.
type AuthenStart struct {
	Action     uint8  // Authentication action (LOGIN, CHPASS, SENDAUTH)
	PrivLevel  uint8  // Privilege level
	AuthenType uint8  // Authentication type (ASCII, PAP, CHAP, etc.)
	Service    uint8  // Authentication service (LOGIN, ENABLE, etc.)
	User       []byte // Username (optional)
	Port       []byte // Port identifier (optional)
	RemoteAddr []byte // Remote address (optional)
	Data       []byte // Authentication data (optional)
}

// NewAuthenStart creates a new AuthenStart packet with the specified parameters.
func NewAuthenStart(action, authenType, service uint8, user string) *AuthenStart {
	return &AuthenStart{
		Action:     action,
		PrivLevel:  1, // Default privilege level
		AuthenType: authenType,
		Service:    service,
		User:       []byte(user),
	}
}

// MarshalBinary encodes the AuthenStart packet to binary format.
func (p *AuthenStart) MarshalBinary() ([]byte, error) {
	userLen := len(p.User)
	portLen := len(p.Port)
	remAddrLen := len(p.RemoteAddr)
	dataLen := len(p.Data)

	if userLen > 255 || portLen > 255 || remAddrLen > 255 || dataLen > 255 {
		return nil, fmt.Errorf("%w: field length exceeds 255 bytes", ErrInvalidPacket)
	}

	// Fixed header (8 bytes) + variable fields
	size := 8 + userLen + portLen + remAddrLen + dataLen
	buf := make([]byte, size)

	buf[0] = p.Action
	buf[1] = p.PrivLevel
	buf[2] = p.AuthenType
	buf[3] = p.Service
	buf[4] = uint8(userLen)
	buf[5] = uint8(portLen)
	buf[6] = uint8(remAddrLen)
	buf[7] = uint8(dataLen)

	offset := 8
	copy(buf[offset:], p.User)
	offset += userLen
	copy(buf[offset:], p.Port)
	offset += portLen
	copy(buf[offset:], p.RemoteAddr)
	offset += remAddrLen
	copy(buf[offset:], p.Data)

	return buf, nil
}

// UnmarshalBinary decodes the AuthenStart packet from binary format.
func (p *AuthenStart) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: need at least 8 bytes, got %d", ErrBufferTooShort, len(data))
	}

	p.Action = data[0]
	p.PrivLevel = data[1]
	p.AuthenType = data[2]
	p.Service = data[3]

	userLen := int(data[4])
	portLen := int(data[5])
	remAddrLen := int(data[6])
	dataLen := int(data[7])

	expectedLen := 8 + userLen + portLen + remAddrLen + dataLen
	if len(data) < expectedLen {
		if isBadSecretError(len(data), expectedLen) {
			return fmt.Errorf("%w: calculated length %d far exceeds actual %d", ErrBadSecret, expectedLen, len(data))
		}
		return fmt.Errorf("%w: need %d bytes, got %d", ErrBufferTooShort, expectedLen, len(data))
	}

	offset := 8
	if userLen > 0 {
		p.User = make([]byte, userLen)
		copy(p.User, data[offset:offset+userLen])
	} else {
		p.User = nil
	}
	offset += userLen

	if portLen > 0 {
		p.Port = make([]byte, portLen)
		copy(p.Port, data[offset:offset+portLen])
	} else {
		p.Port = nil
	}
	offset += portLen

	if remAddrLen > 0 {
		p.RemoteAddr = make([]byte, remAddrLen)
		copy(p.RemoteAddr, data[offset:offset+remAddrLen])
	} else {
		p.RemoteAddr = nil
	}
	offset += remAddrLen

	if dataLen > 0 {
		p.Data = make([]byte, dataLen)
		copy(p.Data, data[offset:offset+dataLen])
	} else {
		p.Data = nil
	}

	return nil
}

// AuthenReply represents a TACACS+ authentication REPLY packet as defined in RFC8907 Section 5.2.
// This packet is sent by the server in response to START or CONTINUE packets.
type AuthenReply struct {
	Status    uint8  // Authentication status (PASS, FAIL, GETDATA, etc.)
	Flags     uint8  // Reply flags (NOECHO)
	ServerMsg []byte // Server message to display (optional)
	Data      []byte // Authentication data (optional)
}

// NewAuthenReply creates a new AuthenReply packet with the specified status.
func NewAuthenReply(status uint8) *AuthenReply {
	return &AuthenReply{
		Status: status,
	}
}

// MarshalBinary encodes the AuthenReply packet to binary format.
func (p *AuthenReply) MarshalBinary() ([]byte, error) {
	serverMsgLen := len(p.ServerMsg)
	dataLen := len(p.Data)

	if serverMsgLen > 65535 || dataLen > 65535 {
		return nil, fmt.Errorf("%w: field length exceeds 65535 bytes", ErrInvalidPacket)
	}

	// Fixed header (6 bytes) + variable fields
	size := 6 + serverMsgLen + dataLen
	buf := make([]byte, size)

	buf[0] = p.Status
	buf[1] = p.Flags
	binary.BigEndian.PutUint16(buf[2:4], uint16(serverMsgLen))
	binary.BigEndian.PutUint16(buf[4:6], uint16(dataLen))

	offset := 6
	copy(buf[offset:], p.ServerMsg)
	offset += serverMsgLen
	copy(buf[offset:], p.Data)

	return buf, nil
}

// UnmarshalBinary decodes the AuthenReply packet from binary format.
func (p *AuthenReply) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("%w: need at least 6 bytes, got %d", ErrBufferTooShort, len(data))
	}

	p.Status = data[0]
	p.Flags = data[1]
	serverMsgLen := int(binary.BigEndian.Uint16(data[2:4]))
	dataLen := int(binary.BigEndian.Uint16(data[4:6]))

	expectedLen := 6 + serverMsgLen + dataLen
	if len(data) < expectedLen {
		if isBadSecretError(len(data), expectedLen) {
			return fmt.Errorf("%w: calculated length %d far exceeds actual %d", ErrBadSecret, expectedLen, len(data))
		}
		return fmt.Errorf("%w: need %d bytes, got %d", ErrBufferTooShort, expectedLen, len(data))
	}

	offset := 6
	if serverMsgLen > 0 {
		p.ServerMsg = make([]byte, serverMsgLen)
		copy(p.ServerMsg, data[offset:offset+serverMsgLen])
	} else {
		p.ServerMsg = nil
	}
	offset += serverMsgLen

	if dataLen > 0 {
		p.Data = make([]byte, dataLen)
		copy(p.Data, data[offset:offset+dataLen])
	} else {
		p.Data = nil
	}

	return nil
}

// IsPass returns true if the status indicates authentication passed.
func (p *AuthenReply) IsPass() bool {
	return p.Status == AuthenStatusPass
}

// IsFail returns true if the status indicates authentication failed.
func (p *AuthenReply) IsFail() bool {
	return p.Status == AuthenStatusFail
}

// IsError returns true if the status indicates an error occurred.
func (p *AuthenReply) IsError() bool {
	return p.Status == AuthenStatusError
}

// NeedsInput returns true if the server is requesting more input.
func (p *AuthenReply) NeedsInput() bool {
	return p.Status == AuthenStatusGetData ||
		p.Status == AuthenStatusGetUser ||
		p.Status == AuthenStatusGetPass
}

// NoEcho returns true if the NOECHO flag is set.
func (p *AuthenReply) NoEcho() bool {
	return p.Flags&AuthenReplyFlagNoEcho != 0
}

// AuthenContinue represents a TACACS+ authentication CONTINUE packet as defined in RFC8907 Section 5.3.
// This packet is sent by the client in response to a REPLY requesting more data.
type AuthenContinue struct {
	Flags   uint8  // Continue flags (ABORT)
	UserMsg []byte // User message/response (optional)
	Data    []byte // Authentication data (optional)
}

// NewAuthenContinue creates a new AuthenContinue packet with the specified user message.
func NewAuthenContinue(userMsg string) *AuthenContinue {
	return &AuthenContinue{
		UserMsg: []byte(userMsg),
	}
}

// MarshalBinary encodes the AuthenContinue packet to binary format.
func (p *AuthenContinue) MarshalBinary() ([]byte, error) {
	userMsgLen := len(p.UserMsg)
	dataLen := len(p.Data)

	if userMsgLen > 65535 || dataLen > 65535 {
		return nil, fmt.Errorf("%w: field length exceeds 65535 bytes", ErrInvalidPacket)
	}

	// Fixed header (5 bytes) + variable fields
	size := 5 + userMsgLen + dataLen
	buf := make([]byte, size)

	binary.BigEndian.PutUint16(buf[0:2], uint16(userMsgLen))
	binary.BigEndian.PutUint16(buf[2:4], uint16(dataLen))
	buf[4] = p.Flags

	offset := 5
	copy(buf[offset:], p.UserMsg)
	offset += userMsgLen
	copy(buf[offset:], p.Data)

	return buf, nil
}

// UnmarshalBinary decodes the AuthenContinue packet from binary format.
func (p *AuthenContinue) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return fmt.Errorf("%w: need at least 5 bytes, got %d", ErrBufferTooShort, len(data))
	}

	userMsgLen := int(binary.BigEndian.Uint16(data[0:2]))
	dataLen := int(binary.BigEndian.Uint16(data[2:4]))
	p.Flags = data[4]

	expectedLen := 5 + userMsgLen + dataLen
	if len(data) < expectedLen {
		if isBadSecretError(len(data), expectedLen) {
			return fmt.Errorf("%w: calculated length %d far exceeds actual %d", ErrBadSecret, expectedLen, len(data))
		}
		return fmt.Errorf("%w: need %d bytes, got %d", ErrBufferTooShort, expectedLen, len(data))
	}

	offset := 5
	if userMsgLen > 0 {
		p.UserMsg = make([]byte, userMsgLen)
		copy(p.UserMsg, data[offset:offset+userMsgLen])
	} else {
		p.UserMsg = nil
	}
	offset += userMsgLen

	if dataLen > 0 {
		p.Data = make([]byte, dataLen)
		copy(p.Data, data[offset:offset+dataLen])
	} else {
		p.Data = nil
	}

	return nil
}

// IsAbort returns true if the ABORT flag is set.
func (p *AuthenContinue) IsAbort() bool {
	return p.Flags&AuthenContinueFlagAbort != 0
}

// SetAbort sets or clears the ABORT flag.
func (p *AuthenContinue) SetAbort(abort bool) {
	if abort {
		p.Flags |= AuthenContinueFlagAbort
	} else {
		p.Flags &^= AuthenContinueFlagAbort
	}
}
