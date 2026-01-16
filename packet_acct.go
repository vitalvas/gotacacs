package gotacacs

import (
	"fmt"
)

// AcctRequest represents a TACACS+ accounting REQUEST packet as defined in RFC8907 Section 7.1.
// This packet is sent by the client to send accounting records to the server.
type AcctRequest struct {
	Flags        uint8    // Accounting flags (START, STOP, WATCHDOG)
	AuthenMethod uint8    // Authentication method used
	PrivLevel    uint8    // Privilege level
	AuthenType   uint8    // Authentication type
	Service      uint8    // Authentication service
	User         []byte   // Username
	Port         []byte   // Port identifier
	RemoteAddr   []byte   // Remote address
	Args         [][]byte // Accounting arguments
}

// NewAcctRequest creates a new AcctRequest packet with the specified parameters.
func NewAcctRequest(flags, authenMethod, authenType, service uint8, user string) *AcctRequest {
	return &AcctRequest{
		Flags:        flags,
		AuthenMethod: authenMethod,
		PrivLevel:    1, // Default privilege level
		AuthenType:   authenType,
		Service:      service,
		User:         []byte(user),
	}
}

// AddArg adds an argument to the accounting request.
func (p *AcctRequest) AddArg(arg string) {
	p.Args = append(p.Args, []byte(arg))
}

// GetArgs returns the arguments as strings.
func (p *AcctRequest) GetArgs() []string {
	result := make([]string, len(p.Args))
	for i, arg := range p.Args {
		result[i] = string(arg)
	}
	return result
}

// IsStart returns true if the START flag is set.
func (p *AcctRequest) IsStart() bool {
	return p.Flags&AcctFlagStart != 0
}

// IsStop returns true if the STOP flag is set.
func (p *AcctRequest) IsStop() bool {
	return p.Flags&AcctFlagStop != 0
}

// IsWatchdog returns true if the WATCHDOG flag is set.
func (p *AcctRequest) IsWatchdog() bool {
	return p.Flags&AcctFlagWatchdog != 0
}

// MarshalBinary encodes the AcctRequest packet to binary format.
func (p *AcctRequest) MarshalBinary() ([]byte, error) {
	userLen := len(p.User)
	portLen := len(p.Port)
	remAddrLen := len(p.RemoteAddr)
	argCount := len(p.Args)

	if userLen > 255 || portLen > 255 || remAddrLen > 255 {
		return nil, fmt.Errorf("%w: field length exceeds 255 bytes", ErrInvalidPacket)
	}
	if argCount > 255 {
		return nil, fmt.Errorf("%w: argument count exceeds 255", ErrInvalidPacket)
	}

	// Calculate total args length and validate individual arg lengths
	totalArgsLen := 0
	for _, arg := range p.Args {
		if len(arg) > 255 {
			return nil, fmt.Errorf("%w: argument length exceeds 255 bytes", ErrInvalidPacket)
		}
		totalArgsLen += len(arg)
	}

	// Fixed header (9 bytes) + arg lengths (arg_count bytes) + variable fields
	size := 9 + argCount + userLen + portLen + remAddrLen + totalArgsLen
	buf := make([]byte, size)

	buf[0] = p.Flags
	buf[1] = p.AuthenMethod
	buf[2] = p.PrivLevel
	buf[3] = p.AuthenType
	buf[4] = p.Service
	buf[5] = uint8(userLen)
	buf[6] = uint8(portLen)
	buf[7] = uint8(remAddrLen)
	buf[8] = uint8(argCount)

	offset := 9

	// Write argument lengths
	for _, arg := range p.Args {
		buf[offset] = uint8(len(arg))
		offset++
	}

	// Write variable fields
	copy(buf[offset:], p.User)
	offset += userLen
	copy(buf[offset:], p.Port)
	offset += portLen
	copy(buf[offset:], p.RemoteAddr)
	offset += remAddrLen

	// Write arguments
	for _, arg := range p.Args {
		copy(buf[offset:], arg)
		offset += len(arg)
	}

	return buf, nil
}

// UnmarshalBinary decodes the AcctRequest packet from binary format.
func (p *AcctRequest) UnmarshalBinary(data []byte) error {
	if len(data) < 9 {
		return fmt.Errorf("%w: need at least 9 bytes, got %d", ErrBufferTooShort, len(data))
	}

	p.Flags = data[0]
	p.AuthenMethod = data[1]
	p.PrivLevel = data[2]
	p.AuthenType = data[3]
	p.Service = data[4]

	userLen := int(data[5])
	portLen := int(data[6])
	remAddrLen := int(data[7])
	argCount := int(data[8])

	// Calculate minimum length needed
	minLen := 9 + argCount + userLen + portLen + remAddrLen
	if len(data) < minLen {
		if isBadSecretError(len(data), minLen) {
			return fmt.Errorf("%w: calculated length %d far exceeds actual %d", ErrBadSecret, minLen, len(data))
		}
		return fmt.Errorf("%w: need at least %d bytes for header and lengths, got %d", ErrBufferTooShort, minLen, len(data))
	}

	offset := 9

	// Read argument lengths
	argLens := make([]int, argCount)
	totalArgsLen := 0
	for i := range argCount {
		argLens[i] = int(data[offset])
		totalArgsLen += argLens[i]
		offset++
	}

	// Verify we have enough data for all fields
	expectedLen := offset + userLen + portLen + remAddrLen + totalArgsLen
	if len(data) < expectedLen {
		if isBadSecretError(len(data), expectedLen) {
			return fmt.Errorf("%w: calculated length %d far exceeds actual %d", ErrBadSecret, expectedLen, len(data))
		}
		return fmt.Errorf("%w: need %d bytes, got %d", ErrBufferTooShort, expectedLen, len(data))
	}

	// Read variable fields
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

	// Read arguments
	if argCount > 0 {
		p.Args = make([][]byte, argCount)
		for i, argLen := range argLens {
			if argLen > 0 {
				p.Args[i] = make([]byte, argLen)
				copy(p.Args[i], data[offset:offset+argLen])
			}
			offset += argLen
		}
	} else {
		p.Args = nil
	}

	return nil
}

// AcctReply represents a TACACS+ accounting REPLY packet as defined in RFC8907 Section 7.2.
// This packet is sent by the server in response to an accounting request.
type AcctReply struct {
	Status    uint8  // Accounting status
	ServerMsg []byte // Server message (optional)
	Data      []byte // Additional data (optional)
}

// NewAcctReply creates a new AcctReply packet with the specified status.
func NewAcctReply(status uint8) *AcctReply {
	return &AcctReply{
		Status: status,
	}
}

// MarshalBinary encodes the AcctReply packet to binary format.
func (p *AcctReply) MarshalBinary() ([]byte, error) {
	serverMsgLen := len(p.ServerMsg)
	dataLen := len(p.Data)

	if serverMsgLen > 65535 || dataLen > 65535 {
		return nil, fmt.Errorf("%w: field length exceeds 65535 bytes", ErrInvalidPacket)
	}

	// Fixed header (5 bytes) + variable fields
	size := 5 + serverMsgLen + dataLen
	buf := make([]byte, size)

	buf[0] = uint8(serverMsgLen >> 8)
	buf[1] = uint8(serverMsgLen)
	buf[2] = uint8(dataLen >> 8)
	buf[3] = uint8(dataLen)
	buf[4] = p.Status

	offset := 5
	copy(buf[offset:], p.ServerMsg)
	offset += serverMsgLen
	copy(buf[offset:], p.Data)

	return buf, nil
}

// UnmarshalBinary decodes the AcctReply packet from binary format.
func (p *AcctReply) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return fmt.Errorf("%w: need at least 5 bytes, got %d", ErrBufferTooShort, len(data))
	}

	serverMsgLen := int(data[0])<<8 | int(data[1])
	dataLen := int(data[2])<<8 | int(data[3])
	p.Status = data[4]

	expectedLen := 5 + serverMsgLen + dataLen
	if len(data) < expectedLen {
		if isBadSecretError(len(data), expectedLen) {
			return fmt.Errorf("%w: calculated length %d far exceeds actual %d", ErrBadSecret, expectedLen, len(data))
		}
		return fmt.Errorf("%w: need %d bytes, got %d", ErrBufferTooShort, expectedLen, len(data))
	}

	offset := 5
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

// IsSuccess returns true if the status indicates success.
func (p *AcctReply) IsSuccess() bool {
	return p.Status == AcctStatusSuccess
}

// IsError returns true if the status indicates an error.
func (p *AcctReply) IsError() bool {
	return p.Status == AcctStatusError
}
