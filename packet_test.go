package gotacacs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketInterfaceCompliance(t *testing.T) {
	// Verify all packet types implement the Packet interface
	packets := []Packet{
		&AuthenStart{},
		&AuthenReply{},
		&AuthenContinue{},
		&AuthorRequest{},
		&AuthorResponse{},
		&AcctRequest{},
		&AcctReply{},
	}

	for _, p := range packets {
		t.Run("implements Packet interface", func(t *testing.T) {
			// Test MarshalBinary
			data, err := p.MarshalBinary()
			require.NoError(t, err)
			require.NotNil(t, data)

			// Test UnmarshalBinary roundtrip
			newPacket := createPacketOfSameType(p)
			err = newPacket.UnmarshalBinary(data)
			require.NoError(t, err)
		})
	}
}

func createPacketOfSameType(p Packet) Packet {
	switch p.(type) {
	case *AuthenStart:
		return &AuthenStart{}
	case *AuthenReply:
		return &AuthenReply{}
	case *AuthenContinue:
		return &AuthenContinue{}
	case *AuthorRequest:
		return &AuthorRequest{}
	case *AuthorResponse:
		return &AuthorResponse{}
	case *AcctRequest:
		return &AcctRequest{}
	case *AcctReply:
		return &AcctReply{}
	default:
		return nil
	}
}

func TestParseAuthenPacket(t *testing.T) {
	t.Run("parse START (seq=1)", func(t *testing.T) {
		original := &AuthenStart{
			Action:     AuthenActionLogin,
			PrivLevel:  1,
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAuthenPacket(1, data)
		require.NoError(t, err)

		start, ok := p.(*AuthenStart)
		require.True(t, ok, "expected *AuthenStart")
		assert.Equal(t, original.User, start.User)
	})

	t.Run("parse REPLY (seq=2)", func(t *testing.T) {
		original := &AuthenReply{
			Status:    AuthenStatusPass,
			ServerMsg: []byte("Welcome"),
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAuthenPacket(2, data)
		require.NoError(t, err)

		reply, ok := p.(*AuthenReply)
		require.True(t, ok, "expected *AuthenReply")
		assert.Equal(t, original.Status, reply.Status)
	})

	t.Run("parse CONTINUE (seq=3)", func(t *testing.T) {
		original := &AuthenContinue{
			UserMsg: []byte("password123"),
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAuthenPacket(3, data)
		require.NoError(t, err)

		cont, ok := p.(*AuthenContinue)
		require.True(t, ok, "expected *AuthenContinue")
		assert.Equal(t, original.UserMsg, cont.UserMsg)
	})

	t.Run("parse REPLY (seq=4)", func(t *testing.T) {
		original := &AuthenReply{
			Status: AuthenStatusGetPass,
			Flags:  AuthenReplyFlagNoEcho,
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAuthenPacket(4, data)
		require.NoError(t, err)

		_, ok := p.(*AuthenReply)
		require.True(t, ok, "expected *AuthenReply for even seq")
	})

	t.Run("parse CONTINUE (seq=5)", func(t *testing.T) {
		original := &AuthenContinue{
			UserMsg: []byte("response"),
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAuthenPacket(5, data)
		require.NoError(t, err)

		_, ok := p.(*AuthenContinue)
		require.True(t, ok, "expected *AuthenContinue for odd seq > 1")
	})

	t.Run("invalid sequence 0", func(t *testing.T) {
		_, err := ParseAuthenPacket(0, []byte{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSequence))
	})

	t.Run("invalid data for START", func(t *testing.T) {
		_, err := ParseAuthenPacket(1, []byte{0x01})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("invalid data for REPLY", func(t *testing.T) {
		_, err := ParseAuthenPacket(2, []byte{0x01})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("invalid data for CONTINUE", func(t *testing.T) {
		_, err := ParseAuthenPacket(3, []byte{0x01})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})
}

func TestParseAuthorPacket(t *testing.T) {
	t.Run("parse REQUEST (seq=1)", func(t *testing.T) {
		original := &AuthorRequest{
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
			User:         []byte("testuser"),
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAuthorPacket(1, data)
		require.NoError(t, err)

		req, ok := p.(*AuthorRequest)
		require.True(t, ok, "expected *AuthorRequest")
		assert.Equal(t, original.User, req.User)
	})

	t.Run("parse RESPONSE (seq=2)", func(t *testing.T) {
		original := &AuthorResponse{
			Status:    AuthorStatusPassAdd,
			ServerMsg: []byte("Authorized"),
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAuthorPacket(2, data)
		require.NoError(t, err)

		resp, ok := p.(*AuthorResponse)
		require.True(t, ok, "expected *AuthorResponse")
		assert.Equal(t, original.Status, resp.Status)
	})

	t.Run("invalid sequence 0", func(t *testing.T) {
		_, err := ParseAuthorPacket(0, []byte{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSequence))
	})

	t.Run("invalid sequence 3", func(t *testing.T) {
		_, err := ParseAuthorPacket(3, []byte{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSequence))
	})

	t.Run("invalid data for REQUEST", func(t *testing.T) {
		_, err := ParseAuthorPacket(1, []byte{0x01})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("invalid data for RESPONSE", func(t *testing.T) {
		_, err := ParseAuthorPacket(2, []byte{0x01})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})
}

func TestParseAcctPacket(t *testing.T) {
	t.Run("parse REQUEST (seq=1)", func(t *testing.T) {
		original := &AcctRequest{
			Flags:        AcctFlagStart,
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
			User:         []byte("testuser"),
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAcctPacket(1, data)
		require.NoError(t, err)

		req, ok := p.(*AcctRequest)
		require.True(t, ok, "expected *AcctRequest")
		assert.Equal(t, original.Flags, req.Flags)
	})

	t.Run("parse REPLY (seq=2)", func(t *testing.T) {
		original := &AcctReply{
			Status:    AcctStatusSuccess,
			ServerMsg: []byte("Recorded"),
		}
		data, err := original.MarshalBinary()
		require.NoError(t, err)

		p, err := ParseAcctPacket(2, data)
		require.NoError(t, err)

		reply, ok := p.(*AcctReply)
		require.True(t, ok, "expected *AcctReply")
		assert.Equal(t, original.Status, reply.Status)
	})

	t.Run("invalid sequence 0", func(t *testing.T) {
		_, err := ParseAcctPacket(0, []byte{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSequence))
	})

	t.Run("invalid sequence 3", func(t *testing.T) {
		_, err := ParseAcctPacket(3, []byte{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSequence))
	})

	t.Run("invalid data for REQUEST", func(t *testing.T) {
		_, err := ParseAcctPacket(1, []byte{0x01})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("invalid data for REPLY", func(t *testing.T) {
		_, err := ParseAcctPacket(2, []byte{0x01})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})
}

func TestParsePacket(t *testing.T) {
	t.Run("parse authentication packet", func(t *testing.T) {
		header := &Header{Type: PacketTypeAuthen, SeqNo: 1}
		original := &AuthenStart{
			Action:     AuthenActionLogin,
			PrivLevel:  1,
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
		}
		data, _ := original.MarshalBinary()

		p, err := ParsePacket(header, data)
		require.NoError(t, err)
		_, ok := p.(*AuthenStart)
		assert.True(t, ok)
	})

	t.Run("parse authorization packet", func(t *testing.T) {
		header := &Header{Type: PacketTypeAuthor, SeqNo: 1}
		original := &AuthorRequest{
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
		}
		data, _ := original.MarshalBinary()

		p, err := ParsePacket(header, data)
		require.NoError(t, err)
		_, ok := p.(*AuthorRequest)
		assert.True(t, ok)
	})

	t.Run("parse accounting packet", func(t *testing.T) {
		header := &Header{Type: PacketTypeAcct, SeqNo: 1}
		original := &AcctRequest{
			Flags:        AcctFlagStart,
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
		}
		data, _ := original.MarshalBinary()

		p, err := ParsePacket(header, data)
		require.NoError(t, err)
		_, ok := p.(*AcctRequest)
		assert.True(t, ok)
	})

	t.Run("nil header", func(t *testing.T) {
		_, err := ParsePacket(nil, []byte{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidHeader))
	})

	t.Run("invalid packet type", func(t *testing.T) {
		header := &Header{Type: 0xFF, SeqNo: 1}
		_, err := ParsePacket(header, []byte{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidType))
	})
}

func TestPacketType(t *testing.T) {
	tests := []struct {
		packet   Packet
		expected uint8
	}{
		{&AuthenStart{}, PacketTypeAuthen},
		{&AuthenReply{}, PacketTypeAuthen},
		{&AuthenContinue{}, PacketTypeAuthen},
		{&AuthorRequest{}, PacketTypeAuthor},
		{&AuthorResponse{}, PacketTypeAuthor},
		{&AcctRequest{}, PacketTypeAcct},
		{&AcctReply{}, PacketTypeAcct},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.expected, PacketType(tt.packet))
		})
	}

	t.Run("unknown packet type returns 0", func(t *testing.T) {
		// Use a mock type that implements Packet but isn't one of our types
		assert.Equal(t, uint8(0), PacketType(nil))
	})
}

func TestIsClientPacket(t *testing.T) {
	clientPackets := []Packet{
		&AuthenStart{},
		&AuthenContinue{},
		&AuthorRequest{},
		&AcctRequest{},
	}

	serverPackets := []Packet{
		&AuthenReply{},
		&AuthorResponse{},
		&AcctReply{},
	}

	for _, p := range clientPackets {
		t.Run("client packet", func(t *testing.T) {
			assert.True(t, IsClientPacket(p))
			assert.False(t, IsServerPacket(p))
		})
	}

	for _, p := range serverPackets {
		t.Run("server packet", func(t *testing.T) {
			assert.False(t, IsClientPacket(p))
			assert.True(t, IsServerPacket(p))
		})
	}

	t.Run("nil returns false", func(t *testing.T) {
		assert.False(t, IsClientPacket(nil))
		assert.False(t, IsServerPacket(nil))
	})
}

func BenchmarkParseAuthenPacket(b *testing.B) {
	scenarios := []struct {
		name  string
		seqNo uint8
		data  []byte
	}{
		{
			name:  "start",
			seqNo: 1,
			data: func() []byte {
				p := &AuthenStart{Action: AuthenActionLogin, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin, User: []byte("user")}
				d, _ := p.MarshalBinary()
				return d
			}(),
		},
		{
			name:  "reply",
			seqNo: 2,
			data: func() []byte {
				p := &AuthenReply{Status: AuthenStatusPass}
				d, _ := p.MarshalBinary()
				return d
			}(),
		},
		{
			name:  "continue",
			seqNo: 3,
			data: func() []byte {
				p := &AuthenContinue{UserMsg: []byte("password")}
				d, _ := p.MarshalBinary()
				return d
			}(),
		},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = ParseAuthenPacket(sc.seqNo, sc.data)
			}
		})
	}
}

func BenchmarkParseAuthorPacket(b *testing.B) {
	b.Run("request", func(b *testing.B) {
		p := &AuthorRequest{AuthenMethod: AuthenTypePAP, PrivLevel: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin, User: []byte("user")}
		data, _ := p.MarshalBinary()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParseAuthorPacket(1, data)
		}
	})

	b.Run("response", func(b *testing.B) {
		p := &AuthorResponse{Status: AuthorStatusPassAdd}
		data, _ := p.MarshalBinary()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParseAuthorPacket(2, data)
		}
	})
}

func BenchmarkParseAcctPacket(b *testing.B) {
	b.Run("request", func(b *testing.B) {
		p := &AcctRequest{Flags: AcctFlagStart, AuthenMethod: AuthenTypePAP, PrivLevel: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin, User: []byte("user")}
		data, _ := p.MarshalBinary()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParseAcctPacket(1, data)
		}
	})

	b.Run("reply", func(b *testing.B) {
		p := &AcctReply{Status: AcctStatusSuccess}
		data, _ := p.MarshalBinary()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParseAcctPacket(2, data)
		}
	})
}

func BenchmarkFullPacketFlow(b *testing.B) {
	header := &Header{
		Version:   0xc0,
		Type:      PacketTypeAuthen,
		SeqNo:     1,
		SessionID: 0x12345678,
	}
	secret := []byte("sharedsecret123")
	pkt := &AuthenStart{
		Action:     AuthenActionLogin,
		PrivLevel:  15,
		AuthenType: AuthenTypePAP,
		Service:    AuthenServiceLogin,
		User:       []byte("administrator"),
		Port:       []byte("console"),
		RemoteAddr: []byte("192.168.1.100"),
		Data:       []byte("secretpassword"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := pkt.MarshalBinary()
		obfuscated := Obfuscate(header, secret, data)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		result := &AuthenStart{}
		_ = result.UnmarshalBinary(deobfuscated)
	}
}

func FuzzParseAuthenPacket(f *testing.F) {
	start := &AuthenStart{Action: AuthenActionLogin, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin, User: []byte("user")}
	if data, _ := start.MarshalBinary(); data != nil {
		f.Add(uint8(1), data)
	}

	reply := &AuthenReply{Status: AuthenStatusPass}
	if data, _ := reply.MarshalBinary(); data != nil {
		f.Add(uint8(2), data)
	}

	cont := &AuthenContinue{UserMsg: []byte("password")}
	if data, _ := cont.MarshalBinary(); data != nil {
		f.Add(uint8(3), data)
	}

	f.Fuzz(func(t *testing.T, seqNo uint8, data []byte) {
		p, err := ParseAuthenPacket(seqNo, data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful parse: %v", err)
		}

		if marshaled == nil {
			t.Fatal("marshal returned nil")
		}
	})
}

func FuzzParseAuthorPacket(f *testing.F) {
	req := &AuthorRequest{AuthenMethod: AuthenTypePAP, PrivLevel: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin, User: []byte("user")}
	if data, _ := req.MarshalBinary(); data != nil {
		f.Add(uint8(1), data)
	}

	resp := &AuthorResponse{Status: AuthorStatusPassAdd}
	if data, _ := resp.MarshalBinary(); data != nil {
		f.Add(uint8(2), data)
	}

	f.Fuzz(func(t *testing.T, seqNo uint8, data []byte) {
		p, err := ParseAuthorPacket(seqNo, data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful parse: %v", err)
		}

		if marshaled == nil {
			t.Fatal("marshal returned nil")
		}
	})
}

func FuzzParseAcctPacket(f *testing.F) {
	req := &AcctRequest{Flags: AcctFlagStart, AuthenMethod: AuthenTypePAP, PrivLevel: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin, User: []byte("user")}
	if data, _ := req.MarshalBinary(); data != nil {
		f.Add(uint8(1), data)
	}

	reply := &AcctReply{Status: AcctStatusSuccess}
	if data, _ := reply.MarshalBinary(); data != nil {
		f.Add(uint8(2), data)
	}

	f.Fuzz(func(t *testing.T, seqNo uint8, data []byte) {
		p, err := ParseAcctPacket(seqNo, data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful parse: %v", err)
		}

		if marshaled == nil {
			t.Fatal("marshal returned nil")
		}
	})
}
