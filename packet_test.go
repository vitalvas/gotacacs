package gotacacs

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
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
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if data == nil {
				t.Fatal("expected non-nil")
			}

			// Test UnmarshalBinary roundtrip
			newPacket := createPacketOfSameType(p)
			err = newPacket.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPacketUnmarshalRejectsTrailingBytes(t *testing.T) {
	packets := []struct {
		name   string
		packet Packet
	}{
		{"AuthenStart", &AuthenStart{}},
		{"AuthenReply", &AuthenReply{}},
		{"AuthenContinue", &AuthenContinue{}},
		{"AuthorRequest", &AuthorRequest{}},
		{"AuthorResponse", &AuthorResponse{}},
		{"AcctRequest", &AcctRequest{}},
		{"AcctReply", &AcctReply{}},
	}

	for _, tc := range packets {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			decoded := createPacketOfSameType(tc.packet)
			err = decoded.UnmarshalBinary(append(data, 0x00))

			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrInvalidPacket) {
				t.Errorf("error %v is not %v", err, ErrInvalidPacket)
			}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAuthenPacket(1, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		start, ok := p.(*AuthenStart)
		if !ok {
			t.Fatal("expected *AuthenStart")
		}
		if !bytes.Equal(start.User, original.User) {
			t.Errorf("got %v, want %v", start.User, original.User)
		}
	})

	t.Run("parse REPLY (seq=2)", func(t *testing.T) {
		original := &AuthenReply{
			Status:    AuthenStatusPass,
			ServerMsg: []byte("Welcome"),
		}
		data, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAuthenPacket(2, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		reply, ok := p.(*AuthenReply)
		if !ok {
			t.Fatal("expected *AuthenReply")
		}
		if reply.Status != original.Status {
			t.Errorf("got %v, want %v", reply.Status, original.Status)
		}
	})

	t.Run("parse CONTINUE (seq=3)", func(t *testing.T) {
		original := &AuthenContinue{
			UserMsg: []byte("password123"),
		}
		data, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAuthenPacket(3, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cont, ok := p.(*AuthenContinue)
		if !ok {
			t.Fatal("expected *AuthenContinue")
		}
		if !bytes.Equal(cont.UserMsg, original.UserMsg) {
			t.Errorf("got %v, want %v", cont.UserMsg, original.UserMsg)
		}
	})

	t.Run("parse REPLY (seq=4)", func(t *testing.T) {
		original := &AuthenReply{
			Status: AuthenStatusGetPass,
			Flags:  AuthenReplyFlagNoEcho,
		}
		data, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAuthenPacket(4, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, ok := p.(*AuthenReply)
		if !ok {
			t.Fatal("expected *AuthenReply for even seq")
		}
	})

	t.Run("parse CONTINUE (seq=5)", func(t *testing.T) {
		original := &AuthenContinue{
			UserMsg: []byte("response"),
		}
		data, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAuthenPacket(5, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, ok := p.(*AuthenContinue)
		if !ok {
			t.Fatal("expected *AuthenContinue for odd seq > 1")
		}
	})

	t.Run("invalid sequence 0", func(t *testing.T) {
		_, err := ParseAuthenPacket(0, []byte{})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
	})

	t.Run("invalid data for START", func(t *testing.T) {
		_, err := ParseAuthenPacket(1, []byte{0x01})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("invalid data for REPLY", func(t *testing.T) {
		_, err := ParseAuthenPacket(2, []byte{0x01})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("invalid data for CONTINUE", func(t *testing.T) {
		_, err := ParseAuthenPacket(3, []byte{0x01})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAuthorPacket(1, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req, ok := p.(*AuthorRequest)
		if !ok {
			t.Fatal("expected *AuthorRequest")
		}
		if !bytes.Equal(req.User, original.User) {
			t.Errorf("got %v, want %v", req.User, original.User)
		}
	})

	t.Run("parse RESPONSE (seq=2)", func(t *testing.T) {
		original := &AuthorResponse{
			Status:    AuthorStatusPassAdd,
			ServerMsg: []byte("Authorized"),
		}
		data, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAuthorPacket(2, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resp, ok := p.(*AuthorResponse)
		if !ok {
			t.Fatal("expected *AuthorResponse")
		}
		if resp.Status != original.Status {
			t.Errorf("got %v, want %v", resp.Status, original.Status)
		}
	})

	t.Run("invalid sequence 0", func(t *testing.T) {
		_, err := ParseAuthorPacket(0, []byte{})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
	})

	t.Run("invalid sequence 3", func(t *testing.T) {
		_, err := ParseAuthorPacket(3, []byte{})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
	})

	t.Run("invalid data for REQUEST", func(t *testing.T) {
		_, err := ParseAuthorPacket(1, []byte{0x01})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("invalid data for RESPONSE", func(t *testing.T) {
		_, err := ParseAuthorPacket(2, []byte{0x01})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAcctPacket(1, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req, ok := p.(*AcctRequest)
		if !ok {
			t.Fatal("expected *AcctRequest")
		}
		if req.Flags != original.Flags {
			t.Errorf("got %v, want %v", req.Flags, original.Flags)
		}
	})

	t.Run("parse REPLY (seq=2)", func(t *testing.T) {
		original := &AcctReply{
			Status:    AcctStatusSuccess,
			ServerMsg: []byte("Recorded"),
		}
		data, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		p, err := ParseAcctPacket(2, data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		reply, ok := p.(*AcctReply)
		if !ok {
			t.Fatal("expected *AcctReply")
		}
		if reply.Status != original.Status {
			t.Errorf("got %v, want %v", reply.Status, original.Status)
		}
	})

	t.Run("invalid sequence 0", func(t *testing.T) {
		_, err := ParseAcctPacket(0, []byte{})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
	})

	t.Run("invalid sequence 3", func(t *testing.T) {
		_, err := ParseAcctPacket(3, []byte{})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
	})

	t.Run("invalid data for REQUEST", func(t *testing.T) {
		_, err := ParseAcctPacket(1, []byte{0x01})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("invalid data for REPLY", func(t *testing.T) {
		_, err := ParseAcctPacket(2, []byte{0x01})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, ok := p.(*AuthenStart)
		if !ok {
			t.Errorf("expected true")
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, ok := p.(*AuthorRequest)
		if !ok {
			t.Errorf("expected true")
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, ok := p.(*AcctRequest)
		if !ok {
			t.Errorf("expected true")
		}
	})

	t.Run("nil header", func(t *testing.T) {
		_, err := ParsePacket(nil, []byte{})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("error %v is not %v", err, ErrInvalidHeader)
		}
	})

	t.Run("invalid packet type", func(t *testing.T) {
		header := &Header{Type: 0xFF, SeqNo: 1}
		_, err := ParsePacket(header, []byte{})
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidType) {
			t.Errorf("error %v is not %v", err, ErrInvalidType)
		}
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
			if got := PacketType(tt.packet); got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}

	t.Run("unknown packet type returns 0", func(t *testing.T) {
		// Use a mock type that implements Packet but isn't one of our types
		if got := PacketType(nil); got != uint8(0) {
			t.Errorf("got %v, want %v", got, uint8(0))
		}
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
			if !IsClientPacket(p) {
				t.Errorf("expected true")
			}
			if IsServerPacket(p) {
				t.Errorf("expected false")
			}
		})
	}

	for _, p := range serverPackets {
		t.Run("server packet", func(t *testing.T) {
			if IsClientPacket(p) {
				t.Errorf("expected false")
			}
			if !IsServerPacket(p) {
				t.Errorf("expected true")
			}
		})
	}

	t.Run("nil returns false", func(t *testing.T) {
		if IsClientPacket(nil) {
			t.Errorf("expected false")
		}
		if IsServerPacket(nil) {
			t.Errorf("expected false")
		}
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
		p := &AcctRequest{
			Flags:        AcctFlagStart,
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypePAP,
			Service:      AuthenServiceLogin,
			User:         []byte("user"),
		}
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
	req := &AcctRequest{
		Flags:        AcctFlagStart,
		AuthenMethod: AuthenTypePAP,
		PrivLevel:    1,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte("user"),
	}
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

func FuzzParsePacket(f *testing.F) {
	start := &AuthenStart{Action: AuthenActionLogin, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin, User: []byte("user")}
	if data, _ := start.MarshalBinary(); data != nil {
		f.Add(uint8(PacketTypeAuthen), uint8(1), data)
	}

	authorReq := &AuthorRequest{AuthenMethod: AuthenTypePAP, PrivLevel: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin, User: []byte("user")}
	if data, _ := authorReq.MarshalBinary(); data != nil {
		f.Add(uint8(PacketTypeAuthor), uint8(1), data)
	}

	acctReq := &AcctRequest{
		Flags:        AcctFlagStart,
		AuthenMethod: AuthenTypePAP,
		PrivLevel:    1,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte("user"),
	}
	if data, _ := acctReq.MarshalBinary(); data != nil {
		f.Add(uint8(PacketTypeAcct), uint8(1), data)
	}

	f.Fuzz(func(t *testing.T, packetType, seqNo uint8, data []byte) {
		h := &Header{
			Version:   MajorVersion<<4 | MinorVersionDefault,
			Type:      packetType,
			SeqNo:     seqNo,
			SessionID: 1,
		}

		p, err := ParsePacket(h, data)
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

func TestArgsFromMap(t *testing.T) {
	t.Run("single pair", func(t *testing.T) {
		args := ArgsFromMap(map[string]string{"priv-lvl": "15"})
		if len(args) != 1 {
			t.Fatalf("len = %d, want %d", len(args), 1)
		}
		if !bytes.Equal(args[0], []byte("priv-lvl=15")) {
			t.Errorf("got %v, want %v", args[0], []byte("priv-lvl=15"))
		}
	})

	t.Run("multiple pairs", func(t *testing.T) {
		args := ArgsFromMap(map[string]string{"priv-lvl": "15", "role": "admin"})
		want := [][]byte{[]byte("priv-lvl=15"), []byte("role=admin")}
		if !reflect.DeepEqual(args, want) {
			t.Errorf("got %v, want %v", args, want)
		}
	})

	t.Run("nil map", func(t *testing.T) {
		if got := ArgsFromMap(nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty map", func(t *testing.T) {
		if got := ArgsFromMap(map[string]string{}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestArgValues(t *testing.T) {
	t.Run("output example", func(t *testing.T) {
		v := ArgValues{"priv-lvl": []string{"15"}}
		v.Add("local-user-name", "remote-readonly")
		v.Add("allow-commands1", "qwerty")
		v.Del("test")

		wantStrings := []string{
			"allow-commands1=qwerty",
			"local-user-name=remote-readonly",
			"priv-lvl=15",
		}
		if got := v.Strings(); !reflect.DeepEqual(got, wantStrings) {
			t.Errorf("got %v, want %v", got, wantStrings)
		}
		wantOutput := [][]byte{
			[]byte("allow-commands1=qwerty"),
			[]byte("local-user-name=remote-readonly"),
			[]byte("priv-lvl=15"),
		}
		if got := v.Output(); !reflect.DeepEqual(got, wantOutput) {
			t.Errorf("got %v, want %v", got, wantOutput)
		}
	})

	t.Run("get set add del has", func(t *testing.T) {
		v := ArgValues{}

		if v.Has("role") {
			t.Errorf("expected false")
		}
		if len(v.Get("role")) != 0 {
			t.Errorf("expected empty, got %v", v.Get("role"))
		}

		v.Set("role", "readonly")
		if !v.Has("role") {
			t.Errorf("expected true")
		}
		if got := v.Get("role"); got != "readonly" {
			t.Errorf("got %v, want %v", got, "readonly")
		}

		v.Add("role", "operator")
		if got := v["role"]; !reflect.DeepEqual(got, []string{"readonly", "operator"}) {
			t.Errorf("got %v, want %v", got, []string{"readonly", "operator"})
		}
		if got := v.Get("role"); got != "readonly" {
			t.Errorf("got %v, want %v", got, "readonly")
		}

		v.Del("role")
		if v.Has("role") {
			t.Errorf("expected false")
		}
		if len(v.Get("role")) != 0 {
			t.Errorf("expected empty, got %v", v.Get("role"))
		}
	})

	t.Run("multiple values preserve value order", func(t *testing.T) {
		v := ArgValues{"cmd-arg": []string{"show", "running-config"}}

		wantStrings := []string{
			"cmd-arg=show",
			"cmd-arg=running-config",
		}
		if got := v.Strings(); !reflect.DeepEqual(got, wantStrings) {
			t.Errorf("got %v, want %v", got, wantStrings)
		}
		wantOutput := [][]byte{
			[]byte("cmd-arg=show"),
			[]byte("cmd-arg=running-config"),
		}
		if got := v.Output(); !reflect.DeepEqual(got, wantOutput) {
			t.Errorf("got %v, want %v", got, wantOutput)
		}
	})

	t.Run("empty value is emitted", func(t *testing.T) {
		v := ArgValues{"optional": []string{""}}

		if got := v.Strings(); !reflect.DeepEqual(got, []string{"optional="}) {
			t.Errorf("got %v, want %v", got, []string{"optional="})
		}
		if got := v.Output(); !reflect.DeepEqual(got, [][]byte{[]byte("optional=")}) {
			t.Errorf("got %v, want %v", got, [][]byte{[]byte("optional=")})
		}
	})

	t.Run("empty and nil values are omitted", func(t *testing.T) {
		if got := ArgValues(nil).Strings(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := (ArgValues{}).Strings(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := (ArgValues{"empty": nil}).Strings(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := (ArgValues{"empty": []string{}}).Strings(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := ArgValues(nil).Output(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := (ArgValues{}).Output(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := (ArgValues{"empty": nil}).Output(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := (ArgValues{"empty": []string{}}).Output(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestArgValuesParsing(t *testing.T) {
	t.Run("from string args", func(t *testing.T) {
		values := ArgValuesFromArgs([]string{
			"service=shell",
			"cmd=show=version",
			"cmd-arg=running-config",
			"cmd-arg=all",
			"optional=",
			"ignored",
		})

		if got := values.Get("service"); got != "shell" {
			t.Errorf("got %v, want %v", got, "shell")
		}
		if got := values["cmd"]; !reflect.DeepEqual(got, []string{"show=version"}) {
			t.Errorf("got %v, want %v", got, []string{"show=version"})
		}
		if got := values["cmd-arg"]; !reflect.DeepEqual(got, []string{"running-config", "all"}) {
			t.Errorf("got %v, want %v", got, []string{"running-config", "all"})
		}
		if got := values["optional"]; !reflect.DeepEqual(got, []string{""}) {
			t.Errorf("got %v, want %v", got, []string{""})
		}
		if values.Has("ignored") {
			t.Errorf("expected false")
		}
	})

	t.Run("from raw args", func(t *testing.T) {
		values := ArgValuesFromRawArgs([][]byte{
			[]byte("priv-lvl=15"),
			nil,
			[]byte("role=readonly"),
			[]byte("role=operator"),
		})

		if got := values.Get("priv-lvl"); got != "15" {
			t.Errorf("got %v, want %v", got, "15")
		}
		if got := values["role"]; !reflect.DeepEqual(got, []string{"readonly", "operator"}) {
			t.Errorf("got %v, want %v", got, []string{"readonly", "operator"})
		}
		if values.Has("") {
			t.Errorf("expected false")
		}
	})

	t.Run("nil empty and malformed", func(t *testing.T) {
		if got := ArgValuesFromArgs(nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := ArgValuesFromArgs([]string{}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := ArgValuesFromArgs([]string{"malformed"}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := ArgValuesFromRawArgs(nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := ArgValuesFromRawArgs([][]byte{}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := ArgValuesFromRawArgs([][]byte{[]byte("malformed")}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestPacketArgValues(t *testing.T) {
	t.Run("authorization request", func(t *testing.T) {
		req := &AuthorRequest{
			RawArgs: [][]byte{
				[]byte("service=shell"),
				[]byte("cmd=show"),
			},
		}

		values := req.ArgValues()
		if got := values.Get("service"); got != "shell" {
			t.Errorf("got %v, want %v", got, "shell")
		}
		if got := values.Get("cmd"); got != "show" {
			t.Errorf("got %v, want %v", got, "show")
		}
	})

	t.Run("authorization response", func(t *testing.T) {
		resp := &AuthorResponse{
			RawArgs: [][]byte{
				[]byte("priv-lvl=15"),
				[]byte("role=readonly"),
				[]byte("role=operator"),
			},
		}

		values := resp.ArgValues()
		if got := values.Get("priv-lvl"); got != "15" {
			t.Errorf("got %v, want %v", got, "15")
		}
		if got := values["role"]; !reflect.DeepEqual(got, []string{"readonly", "operator"}) {
			t.Errorf("got %v, want %v", got, []string{"readonly", "operator"})
		}
	})

	t.Run("accounting request", func(t *testing.T) {
		req := &AcctRequest{
			RawArgs: [][]byte{
				[]byte("task_id=123"),
				[]byte("service=shell"),
			},
		}

		values := req.ArgValues()
		if got := values.Get("task_id"); got != "123" {
			t.Errorf("got %v, want %v", got, "123")
		}
		if got := values.Get("service"); got != "shell" {
			t.Errorf("got %v, want %v", got, "shell")
		}
	})
}
