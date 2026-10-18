package gotacacs

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewAuthenStart(t *testing.T) {
	t.Run("basic creation", func(t *testing.T) {
		p := NewAuthenStart(AuthenActionLogin, AuthenTypeASCII, AuthenServiceLogin, "testuser")
		if p.Action != AuthenActionLogin {
			t.Errorf("got %v, want %v", p.Action, AuthenActionLogin)
		}
		if p.PrivLevel != uint8(1) {
			t.Errorf("got %v, want %v", p.PrivLevel, uint8(1))
		}
		if p.AuthenType != AuthenTypeASCII {
			t.Errorf("got %v, want %v", p.AuthenType, AuthenTypeASCII)
		}
		if p.Service != AuthenServiceLogin {
			t.Errorf("got %v, want %v", p.Service, AuthenServiceLogin)
		}
		if !bytes.Equal(p.User, []byte("testuser")) {
			t.Errorf("got %v, want %v", p.User, []byte("testuser"))
		}
		if p.Port != nil {
			t.Errorf("expected nil, got %v", p.Port)
		}
		if p.RemoteAddr != nil {
			t.Errorf("expected nil, got %v", p.RemoteAddr)
		}
		if p.Data != nil {
			t.Errorf("expected nil, got %v", p.Data)
		}
	})

	t.Run("empty user", func(t *testing.T) {
		p := NewAuthenStart(AuthenActionLogin, AuthenTypePAP, AuthenServiceEnable, "")
		if len(p.User) != 0 {
			t.Errorf("expected empty, got %v", p.User)
		}
	})
}

func TestAuthenStartMarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		p := &AuthenStart{
			Action:     AuthenActionLogin,
			PrivLevel:  1,
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 8 {
			t.Fatalf("len = %d, want %d", len(data), 8)
		}

		if data[0] != uint8(AuthenActionLogin) {
			t.Errorf("got %v, want %v", data[0], uint8(AuthenActionLogin))
		}
		if data[1] != uint8(1) {
			t.Errorf("got %v, want %v", data[1], uint8(1))
		}
		if data[2] != uint8(AuthenTypeASCII) {
			t.Errorf("got %v, want %v", data[2], uint8(AuthenTypeASCII))
		}
		if data[3] != uint8(AuthenServiceLogin) {
			t.Errorf("got %v, want %v", data[3], uint8(AuthenServiceLogin))
		}
		if data[4] != uint8(0) {
			t.Errorf("got %v, want %v", data[4], uint8(0)) // user_len
		}
		if data[5] != uint8(0) {
			t.Errorf("got %v, want %v", data[5], uint8(0)) // port_len
		}
		if data[6] != uint8(0) {
			t.Errorf("got %v, want %v", data[6], uint8(0)) // rem_addr_len
		}
		if data[7] != uint8(0) {
			t.Errorf("got %v, want %v", data[7], uint8(0)) // data_len
		}
	})

	t.Run("with all fields", func(t *testing.T) {
		p := &AuthenStart{
			Action:     AuthenActionChPass,
			PrivLevel:  15,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServicePPP,
			User:       []byte("admin"),
			Port:       []byte("tty0"),
			RemoteAddr: []byte("192.168.1.1"),
			Data:       []byte("password"),
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedLen := 8 + 5 + 4 + 11 + 8
		if len(data) != expectedLen {
			t.Fatalf("len = %d, want %d", len(data), expectedLen)
		}

		if data[4] != uint8(5) {
			t.Errorf("got %v, want %v", data[4], uint8(5)) // user_len
		}
		if data[5] != uint8(4) {
			t.Errorf("got %v, want %v", data[5], uint8(4)) // port_len
		}
		if data[6] != uint8(11) {
			t.Errorf("got %v, want %v", data[6], uint8(11)) // rem_addr_len
		}
		if data[7] != uint8(8) {
			t.Errorf("got %v, want %v", data[7], uint8(8)) // data_len
		}

		offset := 8
		if !bytes.Equal(data[offset:offset+5], []byte("admin")) {
			t.Errorf("got %v, want %v", data[offset:offset+5], []byte("admin"))
		}
		offset += 5
		if !bytes.Equal(data[offset:offset+4], []byte("tty0")) {
			t.Errorf("got %v, want %v", data[offset:offset+4], []byte("tty0"))
		}
		offset += 4
		if !bytes.Equal(data[offset:offset+11], []byte("192.168.1.1")) {
			t.Errorf("got %v, want %v", data[offset:offset+11], []byte("192.168.1.1"))
		}
		offset += 11
		if !bytes.Equal(data[offset:offset+8], []byte("password")) {
			t.Errorf("got %v, want %v", data[offset:offset+8], []byte("password"))
		}
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthenStart{
			User: bytes.Repeat([]byte("x"), 256),
		}

		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})
}

func TestAuthenStartUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if p.Action != 1 {
			t.Errorf("got %v, want %v", p.Action, 1)
		}
		if p.PrivLevel != uint8(1) {
			t.Errorf("got %v, want %v", p.PrivLevel, uint8(1))
		}
		if p.AuthenType != 1 {
			t.Errorf("got %v, want %v", p.AuthenType, 1)
		}
		if p.Service != 1 {
			t.Errorf("got %v, want %v", p.Service, 1)
		}
		if p.User != nil {
			t.Errorf("expected nil, got %v", p.User)
		}
		if p.Port != nil {
			t.Errorf("expected nil, got %v", p.Port)
		}
		if p.RemoteAddr != nil {
			t.Errorf("expected nil, got %v", p.RemoteAddr)
		}
		if p.Data != nil {
			t.Errorf("expected nil, got %v", p.Data)
		}
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x01, 0x01, 0x01}

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for fields", func(t *testing.T) {
		data := []byte{0x01, 0x01, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00} // user_len=5 but no user data

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})
}

func TestAuthenStartMarshalUnmarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		packet *AuthenStart
	}{
		{
			name: "minimal",
			packet: &AuthenStart{
				Action:     AuthenActionLogin,
				PrivLevel:  1,
				AuthenType: AuthenTypeASCII,
				Service:    AuthenServiceLogin,
			},
		},
		{
			name: "with user",
			packet: &AuthenStart{
				Action:     AuthenActionLogin,
				PrivLevel:  15,
				AuthenType: AuthenTypePAP,
				Service:    AuthenServiceEnable,
				User:       []byte("administrator"),
			},
		},
		{
			name: "all fields",
			packet: &AuthenStart{
				Action:     AuthenActionSendAuth,
				PrivLevel:  0,
				AuthenType: AuthenTypeCHAP,
				Service:    AuthenServicePPP,
				User:       []byte("user"),
				Port:       []byte("console"),
				RemoteAddr: []byte("10.0.0.1"),
				Data:       []byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name: "max length fields",
			packet: &AuthenStart{
				Action:     AuthenActionLogin,
				PrivLevel:  1,
				AuthenType: AuthenTypeASCII,
				Service:    AuthenServiceLogin,
				User:       bytes.Repeat([]byte("u"), 255),
				Port:       bytes.Repeat([]byte("p"), 255),
				RemoteAddr: bytes.Repeat([]byte("r"), 255),
				Data:       bytes.Repeat([]byte("d"), 255),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			decoded := &AuthenStart{}
			err = decoded.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decoded.Action != tc.packet.Action {
				t.Errorf("got %v, want %v", decoded.Action, tc.packet.Action)
			}
			if decoded.PrivLevel != tc.packet.PrivLevel {
				t.Errorf("got %v, want %v", decoded.PrivLevel, tc.packet.PrivLevel)
			}
			if decoded.AuthenType != tc.packet.AuthenType {
				t.Errorf("got %v, want %v", decoded.AuthenType, tc.packet.AuthenType)
			}
			if decoded.Service != tc.packet.Service {
				t.Errorf("got %v, want %v", decoded.Service, tc.packet.Service)
			}
			if !bytes.Equal(decoded.User, tc.packet.User) {
				t.Errorf("got %v, want %v", decoded.User, tc.packet.User)
			}
			if !bytes.Equal(decoded.Port, tc.packet.Port) {
				t.Errorf("got %v, want %v", decoded.Port, tc.packet.Port)
			}
			if !bytes.Equal(decoded.RemoteAddr, tc.packet.RemoteAddr) {
				t.Errorf("got %v, want %v", decoded.RemoteAddr, tc.packet.RemoteAddr)
			}
			if !bytes.Equal(decoded.Data, tc.packet.Data) {
				t.Errorf("got %v, want %v", decoded.Data, tc.packet.Data)
			}
		})
	}
}

func TestAuthenReplyMarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		p := &AuthenReply{
			Status: AuthenStatusPass,
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 6 {
			t.Fatalf("len = %d, want %d", len(data), 6)
		}

		if data[0] != uint8(AuthenStatusPass) {
			t.Errorf("got %v, want %v", data[0], uint8(AuthenStatusPass))
		}
		if data[1] != uint8(0) {
			t.Errorf("got %v, want %v", data[1], uint8(0)) // flags
		}
		if !bytes.Equal(data[2:4], []byte{0, 0}) {
			t.Errorf("got %v, want %v", data[2:4], []byte{0, 0}) // server_msg_len
		}
		if !bytes.Equal(data[4:6], []byte{0, 0}) {
			t.Errorf("got %v, want %v", data[4:6], []byte{0, 0}) // data_len
		}
	})

	t.Run("with message and data", func(t *testing.T) {
		p := &AuthenReply{
			Status:    AuthenStatusGetPass,
			Flags:     AuthenReplyFlagNoEcho,
			ServerMsg: []byte("Enter password:"),
			Data:      []byte{0x01, 0x02},
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedLen := 6 + 15 + 2
		if len(data) != expectedLen {
			t.Fatalf("len = %d, want %d", len(data), expectedLen)
		}

		if data[0] != uint8(AuthenStatusGetPass) {
			t.Errorf("got %v, want %v", data[0], uint8(AuthenStatusGetPass))
		}
		if data[1] != uint8(AuthenReplyFlagNoEcho) {
			t.Errorf("got %v, want %v", data[1], uint8(AuthenReplyFlagNoEcho))
		}
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthenReply{
			ServerMsg: bytes.Repeat([]byte("x"), 65536),
		}

		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})
}

func TestAuthenReplyUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}

		p := &AuthenReply{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if p.Status != AuthenStatusPass {
			t.Errorf("got %v, want %v", p.Status, AuthenStatusPass)
		}
		if p.Flags != 0 {
			t.Errorf("got %v, want %v", p.Flags, 0)
		}
		if p.ServerMsg != nil {
			t.Errorf("expected nil, got %v", p.ServerMsg)
		}
		if p.Data != nil {
			t.Errorf("expected nil, got %v", p.Data)
		}
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00}

		p := &AuthenReply{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for fields", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x05, 0x00, 0x00} // server_msg_len=5 but no data

		p := &AuthenReply{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})
}

func TestAuthenReplyMarshalUnmarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		packet *AuthenReply
	}{
		{
			name: "pass",
			packet: &AuthenReply{
				Status: AuthenStatusPass,
			},
		},
		{
			name: "fail with message",
			packet: &AuthenReply{
				Status:    AuthenStatusFail,
				ServerMsg: []byte("Authentication failed"),
			},
		},
		{
			name: "get pass with noecho",
			packet: &AuthenReply{
				Status:    AuthenStatusGetPass,
				Flags:     AuthenReplyFlagNoEcho,
				ServerMsg: []byte("Password: "),
			},
		},
		{
			name: "error with data",
			packet: &AuthenReply{
				Status:    AuthenStatusError,
				ServerMsg: []byte("Server error"),
				Data:      []byte{0x01, 0x02, 0x03},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			decoded := &AuthenReply{}
			err = decoded.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decoded.Status != tc.packet.Status {
				t.Errorf("got %v, want %v", decoded.Status, tc.packet.Status)
			}
			if decoded.Flags != tc.packet.Flags {
				t.Errorf("got %v, want %v", decoded.Flags, tc.packet.Flags)
			}
			if !bytes.Equal(decoded.ServerMsg, tc.packet.ServerMsg) {
				t.Errorf("got %v, want %v", decoded.ServerMsg, tc.packet.ServerMsg)
			}
			if !bytes.Equal(decoded.Data, tc.packet.Data) {
				t.Errorf("got %v, want %v", decoded.Data, tc.packet.Data)
			}
		})
	}
}

func TestAuthenReplyHelperMethods(t *testing.T) {
	t.Run("IsPass", func(t *testing.T) {
		if !(&AuthenReply{Status: AuthenStatusPass}).IsPass() {
			t.Errorf("expected true")
		}
		if (&AuthenReply{Status: AuthenStatusFail}).IsPass() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsFail", func(t *testing.T) {
		if !(&AuthenReply{Status: AuthenStatusFail}).IsFail() {
			t.Errorf("expected true")
		}
		if (&AuthenReply{Status: AuthenStatusPass}).IsFail() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsError", func(t *testing.T) {
		if !(&AuthenReply{Status: AuthenStatusError}).IsError() {
			t.Errorf("expected true")
		}
		if (&AuthenReply{Status: AuthenStatusPass}).IsError() {
			t.Errorf("expected false")
		}
	})

	t.Run("NeedsInput", func(t *testing.T) {
		if !(&AuthenReply{Status: AuthenStatusGetData}).NeedsInput() {
			t.Errorf("expected true")
		}
		if !(&AuthenReply{Status: AuthenStatusGetUser}).NeedsInput() {
			t.Errorf("expected true")
		}
		if !(&AuthenReply{Status: AuthenStatusGetPass}).NeedsInput() {
			t.Errorf("expected true")
		}
		if (&AuthenReply{Status: AuthenStatusPass}).NeedsInput() {
			t.Errorf("expected false")
		}
		if (&AuthenReply{Status: AuthenStatusFail}).NeedsInput() {
			t.Errorf("expected false")
		}
	})

	t.Run("NoEcho", func(t *testing.T) {
		if !(&AuthenReply{Flags: AuthenReplyFlagNoEcho}).NoEcho() {
			t.Errorf("expected true")
		}
		if (&AuthenReply{Flags: 0}).NoEcho() {
			t.Errorf("expected false")
		}
	})
}

func TestNewAuthenContinue(t *testing.T) {
	t.Run("basic creation", func(t *testing.T) {
		p := NewAuthenContinue("password123")
		if !bytes.Equal(p.UserMsg, []byte("password123")) {
			t.Errorf("got %v, want %v", p.UserMsg, []byte("password123"))
		}
		if p.Flags != 0 {
			t.Errorf("got %v, want %v", p.Flags, 0)
		}
		if p.Data != nil {
			t.Errorf("expected nil, got %v", p.Data)
		}
	})

	t.Run("empty message", func(t *testing.T) {
		p := NewAuthenContinue("")
		if len(p.UserMsg) != 0 {
			t.Errorf("expected empty, got %v", p.UserMsg)
		}
	})
}

func TestAuthenContinueMarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		p := &AuthenContinue{}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 5 {
			t.Fatalf("len = %d, want %d", len(data), 5)
		}

		if !bytes.Equal(data[0:2], []byte{0, 0}) {
			t.Errorf("got %v, want %v", data[0:2], []byte{0, 0}) // user_msg_len
		}
		if !bytes.Equal(data[2:4], []byte{0, 0}) {
			t.Errorf("got %v, want %v", data[2:4], []byte{0, 0}) // data_len
		}
		if data[4] != uint8(0) {
			t.Errorf("got %v, want %v", data[4], uint8(0)) // flags
		}
	})

	t.Run("with message", func(t *testing.T) {
		p := &AuthenContinue{
			UserMsg: []byte("mypassword"),
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedLen := 5 + 10
		if len(data) != expectedLen {
			t.Fatalf("len = %d, want %d", len(data), expectedLen)
		}
	})

	t.Run("with abort flag", func(t *testing.T) {
		p := &AuthenContinue{
			Flags:   AuthenContinueFlagAbort,
			UserMsg: []byte("aborting"),
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if data[4] != uint8(AuthenContinueFlagAbort) {
			t.Errorf("got %v, want %v", data[4], uint8(AuthenContinueFlagAbort))
		}
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthenContinue{
			UserMsg: bytes.Repeat([]byte("x"), 65536),
		}

		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})
}

func TestAuthenContinueUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00, 0x00, 0x00}

		p := &AuthenContinue{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if p.UserMsg != nil {
			t.Errorf("expected nil, got %v", p.UserMsg)
		}
		if p.Data != nil {
			t.Errorf("expected nil, got %v", p.Data)
		}
		if p.Flags != 0 {
			t.Errorf("got %v, want %v", p.Flags, 0)
		}
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00}

		p := &AuthenContinue{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for fields", func(t *testing.T) {
		data := []byte{0x00, 0x05, 0x00, 0x00, 0x00} // user_msg_len=5 but no data

		p := &AuthenContinue{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})
}

func TestAuthenContinueMarshalUnmarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		packet *AuthenContinue
	}{
		{
			name:   "empty",
			packet: &AuthenContinue{},
		},
		{
			name: "with message",
			packet: &AuthenContinue{
				UserMsg: []byte("password"),
			},
		},
		{
			name: "with abort",
			packet: &AuthenContinue{
				Flags:   AuthenContinueFlagAbort,
				UserMsg: []byte("cancel"),
			},
		},
		{
			name: "with data",
			packet: &AuthenContinue{
				UserMsg: []byte("response"),
				Data:    []byte{0x01, 0x02, 0x03, 0x04},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			decoded := &AuthenContinue{}
			err = decoded.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decoded.Flags != tc.packet.Flags {
				t.Errorf("got %v, want %v", decoded.Flags, tc.packet.Flags)
			}
			if !bytes.Equal(decoded.UserMsg, tc.packet.UserMsg) {
				t.Errorf("got %v, want %v", decoded.UserMsg, tc.packet.UserMsg)
			}
			if !bytes.Equal(decoded.Data, tc.packet.Data) {
				t.Errorf("got %v, want %v", decoded.Data, tc.packet.Data)
			}
		})
	}
}

func TestAuthenContinueAbortMethods(t *testing.T) {
	t.Run("IsAbort", func(t *testing.T) {
		if !(&AuthenContinue{Flags: AuthenContinueFlagAbort}).IsAbort() {
			t.Errorf("expected true")
		}
		if (&AuthenContinue{Flags: 0}).IsAbort() {
			t.Errorf("expected false")
		}
	})

	t.Run("SetAbort true", func(t *testing.T) {
		p := &AuthenContinue{}
		p.SetAbort(true)
		if !p.IsAbort() {
			t.Errorf("expected true")
		}
		if p.Flags != AuthenContinueFlagAbort {
			t.Errorf("got %v, want %v", p.Flags, AuthenContinueFlagAbort)
		}
	})

	t.Run("SetAbort false", func(t *testing.T) {
		p := &AuthenContinue{Flags: AuthenContinueFlagAbort}
		p.SetAbort(false)
		if p.IsAbort() {
			t.Errorf("expected false")
		}
		if p.Flags != 0 {
			t.Errorf("got %v, want %v", p.Flags, 0)
		}
	})
}

func BenchmarkAuthenStartMarshalBinary(b *testing.B) {
	scenarios := []struct {
		name string
		pkt  *AuthenStart
	}{
		{
			name: "minimal",
			pkt:  &AuthenStart{Action: AuthenActionLogin, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin},
		},
		{
			name: "with_user",
			pkt: &AuthenStart{
				Action:     AuthenActionLogin,
				AuthenType: AuthenTypePAP,
				Service:    AuthenServiceLogin,
				User:       []byte("testuser"),
			},
		},
		{
			name: "full",
			pkt: &AuthenStart{
				Action:     AuthenActionLogin,
				PrivLevel:  15,
				AuthenType: AuthenTypePAP,
				Service:    AuthenServiceLogin,
				User:       []byte("testuser"),
				Port:       []byte("tty0"),
				RemoteAddr: []byte("192.168.1.100"),
				Data:       []byte("password123"),
			},
		},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = sc.pkt.MarshalBinary()
			}
		})
	}
}

func BenchmarkAuthenStartUnmarshalBinary(b *testing.B) {
	pkt := &AuthenStart{
		Action:     AuthenActionLogin,
		PrivLevel:  15,
		AuthenType: AuthenTypePAP,
		Service:    AuthenServiceLogin,
		User:       []byte("testuser"),
		Port:       []byte("tty0"),
		RemoteAddr: []byte("192.168.1.100"),
		Data:       []byte("password123"),
	}
	data, _ := pkt.MarshalBinary()
	target := &AuthenStart{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = target.UnmarshalBinary(data)
	}
}

func BenchmarkAuthenReplyMarshalBinary(b *testing.B) {
	scenarios := []struct {
		name string
		pkt  *AuthenReply
	}{
		{
			name: "pass",
			pkt:  &AuthenReply{Status: AuthenStatusPass},
		},
		{
			name: "with_message",
			pkt: &AuthenReply{
				Status:    AuthenStatusGetPass,
				Flags:     AuthenReplyFlagNoEcho,
				ServerMsg: []byte("Enter password:"),
			},
		},
		{
			name: "full",
			pkt: &AuthenReply{
				Status:    AuthenStatusGetData,
				Flags:     AuthenReplyFlagNoEcho,
				ServerMsg: []byte("Please enter your one-time password"),
				Data:      []byte("challenge-data-here"),
			},
		},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = sc.pkt.MarshalBinary()
			}
		})
	}
}

func BenchmarkAuthenReplyUnmarshalBinary(b *testing.B) {
	pkt := &AuthenReply{
		Status:    AuthenStatusGetData,
		Flags:     AuthenReplyFlagNoEcho,
		ServerMsg: []byte("Please enter your one-time password"),
		Data:      []byte("challenge-data-here"),
	}
	data, _ := pkt.MarshalBinary()
	target := &AuthenReply{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = target.UnmarshalBinary(data)
	}
}

func BenchmarkAuthenContinueMarshalBinary(b *testing.B) {
	pkt := &AuthenContinue{
		UserMsg: []byte("mypassword123"),
		Data:    []byte("additional-data"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pkt.MarshalBinary()
	}
}

func BenchmarkAuthenContinueUnmarshalBinary(b *testing.B) {
	pkt := &AuthenContinue{
		UserMsg: []byte("mypassword123"),
		Data:    []byte("additional-data"),
	}
	data, _ := pkt.MarshalBinary()
	target := &AuthenContinue{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = target.UnmarshalBinary(data)
	}
}

func TestBadSecretDetection(t *testing.T) {
	// Simulate what happens when a packet is deobfuscated with the wrong secret.
	// The length fields become garbage, causing unreasonably large expected lengths.

	t.Run("AuthenStart with garbage lengths", func(t *testing.T) {
		// Create a small valid packet, then corrupt the length fields to simulate bad secret
		data := []byte{
			0x01, 0x01, 0x01, 0x01, // action, priv, authen_type, service
			0xFF, 0xFF, 0xFF, 0xFF, // garbage lengths: user=255, port=255, rem_addr=255, data=255
		}
		// Total expected would be 8 + 255*4 = 1028 bytes, but we only have 8

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})

	t.Run("AuthenStart with normal truncation should not be bad secret", func(t *testing.T) {
		// Normal truncation: expected length slightly larger than actual
		data := []byte{
			0x01, 0x01, 0x01, 0x01, // action, priv, authen_type, service
			0x05, 0x00, 0x00, 0x00, // user_len=5, rest=0, so expected=13 but we have 8
		}

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("expected ErrBufferTooShort for normal truncation, got: %v", err)
		}
		if errors.Is(err, ErrBadSecret) {
			t.Errorf("should not be ErrBadSecret for normal truncation")
		}
	})

	t.Run("AuthenReply with garbage lengths", func(t *testing.T) {
		// status, flags, server_msg_len (2 bytes), data_len (2 bytes)
		data := []byte{
			0x01, 0x00, // status, flags
			0xFF, 0xFF, // server_msg_len = 65535
			0xFF, 0xFF, // data_len = 65535
		}
		// Total expected would be 6 + 65535 + 65535 = 131076 bytes

		p := &AuthenReply{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})

	t.Run("AuthenContinue with garbage lengths", func(t *testing.T) {
		// user_msg_len (2 bytes), data_len (2 bytes), flags (1 byte)
		data := []byte{
			0xFF, 0xFF, // user_msg_len = 65535
			0xFF, 0xFF, // data_len = 65535
			0x00, // flags
		}
		// Total expected would be 5 + 65535 + 65535 = 131075 bytes

		p := &AuthenContinue{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})

	t.Run("bad secret with real obfuscation mismatch", func(t *testing.T) {
		// Create a valid AuthenStart packet
		original := &AuthenStart{
			Action:     AuthenActionLogin,
			PrivLevel:  1,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
			Data:       []byte("password"),
		}
		plaintext, err := original.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Create header for obfuscation
		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 12345,
			Length:    uint32(len(plaintext)),
		}

		// Obfuscate with correct secret
		correctSecret := []byte("correct-secret")
		obfuscated := Obfuscate(header, correctSecret, plaintext)

		// Try to deobfuscate with wrong secret
		wrongSecret := []byte("wrong-secret")
		garbage := Obfuscate(header, wrongSecret, obfuscated)

		// The garbage data should trigger bad secret detection
		p := &AuthenStart{}
		err = p.UnmarshalBinary(garbage)
		// Note: This may or may not trigger ErrBadSecret depending on what
		// garbage values end up in the length fields. The test verifies
		// that parsing fails (either ErrBadSecret or ErrBufferTooShort).
		if err == nil {
			t.Errorf("parsing garbage data should fail")
		}
	})
}

func FuzzAuthenStartUnmarshalBinary(f *testing.F) {
	validPkt := &AuthenStart{
		Action:     AuthenActionLogin,
		PrivLevel:  1,
		AuthenType: AuthenTypePAP,
		Service:    AuthenServiceLogin,
		User:       []byte("testuser"),
		Port:       []byte("tty0"),
		RemoteAddr: []byte("192.168.1.1"),
		Data:       []byte("password"),
	}
	if data, err := validPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	minPkt := &AuthenStart{Action: AuthenActionLogin}
	if data, err := minPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	f.Add([]byte{0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful unmarshal: %v", err)
		}

		p2 := &AuthenStart{}
		if err := p2.UnmarshalBinary(marshaled); err != nil {
			t.Fatalf("second unmarshal failed: %v", err)
		}
	})
}

func FuzzAuthenReplyUnmarshalBinary(f *testing.F) {
	validPkt := &AuthenReply{
		Status:    AuthenStatusPass,
		Flags:     AuthenReplyFlagNoEcho,
		ServerMsg: []byte("Welcome"),
		Data:      []byte("data"),
	}
	if data, err := validPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	minPkt := &AuthenReply{Status: AuthenStatusFail}
	if data, err := minPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &AuthenReply{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful unmarshal: %v", err)
		}

		p2 := &AuthenReply{}
		if err := p2.UnmarshalBinary(marshaled); err != nil {
			t.Fatalf("second unmarshal failed: %v", err)
		}
	})
}

func FuzzAuthenContinueUnmarshalBinary(f *testing.F) {
	validPkt := &AuthenContinue{
		Flags:   0,
		UserMsg: []byte("response"),
		Data:    []byte("extra"),
	}
	if data, err := validPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &AuthenContinue{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful unmarshal: %v", err)
		}

		p2 := &AuthenContinue{}
		if err := p2.UnmarshalBinary(marshaled); err != nil {
			t.Fatalf("second unmarshal failed: %v", err)
		}
	})
}
