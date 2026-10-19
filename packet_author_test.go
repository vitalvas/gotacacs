package gotacacs

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestNewAuthorRequest(t *testing.T) {
	t.Run("basic creation", func(t *testing.T) {
		p := NewAuthorRequest(AuthenMethod(AuthenTypePAP), AuthenTypeASCII, AuthenServiceLogin, "testuser")
		if p.AuthenMethod != AuthenMethod(AuthenTypePAP) {
			t.Errorf("got %v, want %v", p.AuthenMethod, AuthenMethod(AuthenTypePAP))
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
		if p.RawArgs != nil {
			t.Errorf("expected nil, got %v", p.RawArgs)
		}
	})
}

func TestAuthorRequestAddArg(t *testing.T) {
	t.Run("add single arg", func(t *testing.T) {
		p := &AuthorRequest{}
		p.AddArg("service=shell")
		if len(p.RawArgs) != 1 {
			t.Errorf("len = %d, want %d", len(p.RawArgs), 1)
		}
		if !bytes.Equal(p.RawArgs[0], []byte("service=shell")) {
			t.Errorf("got %v, want %v", p.RawArgs[0], []byte("service=shell"))
		}
	})

	t.Run("add multiple args", func(t *testing.T) {
		p := &AuthorRequest{}
		p.AddArg("service=shell")
		p.AddArg("cmd=show")
		p.AddArg("cmd-arg=version")
		if len(p.RawArgs) != 3 {
			t.Errorf("len = %d, want %d", len(p.RawArgs), 3)
		}
	})
}

func TestAuthorRequestArgs(t *testing.T) {
	t.Run("get args as strings", func(t *testing.T) {
		p := &AuthorRequest{
			RawArgs: [][]byte{
				[]byte("service=shell"),
				[]byte("cmd=show"),
			},
		}
		args := p.Args()
		if !reflect.DeepEqual(args, []string{"service=shell", "cmd=show"}) {
			t.Errorf("got %v, want %v", args, []string{"service=shell", "cmd=show"})
		}
	})

	t.Run("empty args", func(t *testing.T) {
		p := &AuthorRequest{}
		args := p.Args()
		if len(args) != 0 {
			t.Errorf("expected empty, got %v", args)
		}
	})
}

func TestAuthorRequestMarshalBinary(t *testing.T) {
	t.Run("empty request encoding", func(t *testing.T) {
		p := &AuthorRequest{
			AuthenMethod: AuthenMethod(AuthenTypePAP),
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify fixed 8-byte header for authorization request
		expected := []byte{byte(AuthenTypePAP), 1, byte(AuthenTypeASCII), byte(AuthenServiceLogin), 0, 0, 0, 0}
		if !bytes.Equal(data, expected) {
			t.Errorf("got %v, want %v", data, expected)
		}
	})

	t.Run("with all fields and args", func(t *testing.T) {
		p := &AuthorRequest{
			AuthenMethod: AuthenMethod(AuthenTypeCHAP),
			PrivLevel:    15,
			AuthenType:   AuthenTypePAP,
			Service:      AuthenServicePPP,
			User:         []byte("admin"),
			Port:         []byte("tty0"),
			RemoteAddr:   []byte("192.168.1.1"),
			RawArgs:      [][]byte{[]byte("service=shell"), []byte("cmd=show")},
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 8 header + 2 arg lens + 5 user + 4 port + 11 rem_addr + 13 + 8 args
		expectedLen := 8 + 2 + 5 + 4 + 11 + 13 + 8
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
		if data[7] != uint8(2) {
			t.Errorf("got %v, want %v", data[7], uint8(2)) // arg_cnt
		}
		if data[8] != uint8(13) {
			t.Errorf("got %v, want %v", data[8], uint8(13)) // arg1 len
		}
		if data[9] != uint8(8) {
			t.Errorf("got %v, want %v", data[9], uint8(8)) // arg2 len
		}
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthorRequest{
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

	t.Run("too many args", func(t *testing.T) {
		p := &AuthorRequest{
			RawArgs: make([][]byte, 256),
		}

		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})

	t.Run("arg too long", func(t *testing.T) {
		p := &AuthorRequest{
			RawArgs: [][]byte{bytes.Repeat([]byte("x"), 256)},
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

func TestAuthorRequestUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if p.AuthenMethod != AuthenMethod(0x02) {
			t.Errorf("got %v, want %v", p.AuthenMethod, AuthenMethod(0x02))
		}
		if p.PrivLevel != uint8(0x01) {
			t.Errorf("got %v, want %v", p.PrivLevel, uint8(0x01))
		}
		if p.User != nil {
			t.Errorf("expected nil, got %v", p.User)
		}
		if p.RawArgs != nil {
			t.Errorf("expected nil, got %v", p.RawArgs)
		}
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x02, 0x01, 0x01}

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for arg lengths", func(t *testing.T) {
		data := []byte{0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02} // arg_cnt=2 but no arg lengths

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for args", func(t *testing.T) {
		// arg_cnt=1, arg1_len=5, but only 2 bytes of arg data
		data := []byte{0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 'a', 'b'}

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})
}

func TestAuthorRequestMarshalUnmarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		packet *AuthorRequest
	}{
		{
			name: "minimal",
			packet: &AuthorRequest{
				AuthenMethod: AuthenMethod(AuthenTypePAP),
				PrivLevel:    1,
				AuthenType:   AuthenTypeASCII,
				Service:      AuthenServiceLogin,
			},
		},
		{
			name: "with user",
			packet: &AuthorRequest{
				AuthenMethod: AuthenMethod(AuthenTypePAP),
				PrivLevel:    15,
				AuthenType:   AuthenTypePAP,
				Service:      AuthenServiceEnable,
				User:         []byte("administrator"),
			},
		},
		{
			name: "with args",
			packet: &AuthorRequest{
				AuthenMethod: AuthenMethod(AuthenTypeCHAP),
				PrivLevel:    1,
				AuthenType:   AuthenTypeASCII,
				Service:      AuthenServiceLogin,
				User:         []byte("user"),
				RawArgs:      [][]byte{[]byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=version")},
			},
		},
		{
			name: "all fields",
			packet: &AuthorRequest{
				AuthenMethod: AuthenMethod(AuthenTypeMSCHAP),
				PrivLevel:    0,
				AuthenType:   AuthenTypeCHAP,
				Service:      AuthenServicePPP,
				User:         []byte("user"),
				Port:         []byte("console"),
				RemoteAddr:   []byte("10.0.0.1"),
				RawArgs:      [][]byte{[]byte("service=ppp"), []byte("protocol=ip")},
			},
		},
		{
			name: "max args",
			packet: func() *AuthorRequest {
				p := &AuthorRequest{
					AuthenMethod: AuthenMethod(AuthenTypePAP),
					PrivLevel:    1,
					AuthenType:   AuthenTypeASCII,
					Service:      AuthenServiceLogin,
				}
				for i := range 255 {
					p.RawArgs = append(p.RawArgs, []byte{byte(i)})
				}
				return p
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal original packet
			data, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("expected non-empty")
			}

			// Unmarshal into new packet and verify all authorization-specific fields
			decoded := &AuthorRequest{}
			if err := decoded.UnmarshalBinary(data); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify authorization request specific structure
			if decoded.AuthenMethod != tc.packet.AuthenMethod {
				t.Errorf("authen_method mismatch: got %v, want %v", decoded.AuthenMethod, tc.packet.AuthenMethod)
			}
			if decoded.PrivLevel != tc.packet.PrivLevel {
				t.Errorf("priv_lvl mismatch: got %v, want %v", decoded.PrivLevel, tc.packet.PrivLevel)
			}
			if decoded.AuthenType != tc.packet.AuthenType {
				t.Errorf("authen_type mismatch: got %v, want %v", decoded.AuthenType, tc.packet.AuthenType)
			}
			if decoded.Service != tc.packet.Service {
				t.Errorf("service mismatch: got %v, want %v", decoded.Service, tc.packet.Service)
			}
			if !bytes.Equal(decoded.User, tc.packet.User) {
				t.Errorf("user mismatch: got %v, want %v", decoded.User, tc.packet.User)
			}
			if !bytes.Equal(decoded.Port, tc.packet.Port) {
				t.Errorf("port mismatch: got %v, want %v", decoded.Port, tc.packet.Port)
			}
			if !bytes.Equal(decoded.RemoteAddr, tc.packet.RemoteAddr) {
				t.Errorf("rem_addr mismatch: got %v, want %v", decoded.RemoteAddr, tc.packet.RemoteAddr)
			}
			if len(decoded.RawArgs) != len(tc.packet.RawArgs) {
				t.Errorf("args count mismatch: got %v, want %v", len(decoded.RawArgs), len(tc.packet.RawArgs))
			}
			for i := range tc.packet.RawArgs {
				if !bytes.Equal(decoded.RawArgs[i], tc.packet.RawArgs[i]) {
					t.Errorf("arg %d mismatch: got %v, want %v", i, decoded.RawArgs[i], tc.packet.RawArgs[i])
				}
			}
		})
	}
}

func TestAuthorResponseAddArg(t *testing.T) {
	t.Run("add args", func(t *testing.T) {
		p := &AuthorResponse{}
		p.AddArg("priv-lvl=15")
		p.AddArg("timeout=60")
		if len(p.RawArgs) != 2 {
			t.Errorf("len = %d, want %d", len(p.RawArgs), 2)
		}
	})
}

func TestAuthorResponseArgs(t *testing.T) {
	t.Run("get args as strings", func(t *testing.T) {
		p := &AuthorResponse{
			RawArgs: [][]byte{
				[]byte("priv-lvl=15"),
				[]byte("timeout=60"),
			},
		}
		args := p.Args()
		if !reflect.DeepEqual(args, []string{"priv-lvl=15", "timeout=60"}) {
			t.Errorf("got %v, want %v", args, []string{"priv-lvl=15", "timeout=60"})
		}
	})
}

func TestAuthorResponseMarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		p := &AuthorResponse{
			Status: AuthorStatusPassAdd,
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 6 {
			t.Fatalf("len = %d, want %d", len(data), 6)
		}

		if data[0] != byte(AuthorStatusPassAdd) {
			t.Errorf("got %v, want %v", data[0], byte(AuthorStatusPassAdd))
		}
		if data[1] != uint8(0) {
			t.Errorf("got %v, want %v", data[1], uint8(0)) // arg_cnt
		}
	})

	t.Run("with message and args", func(t *testing.T) {
		p := &AuthorResponse{
			Status:    AuthorStatusPassRepl,
			ServerMsg: []byte("Authorized"),
			RawArgs:   [][]byte{[]byte("priv-lvl=15")},
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 6 header + 1 arg len + 10 server_msg + 11 arg
		expectedLen := 6 + 1 + 10 + 11
		if len(data) != expectedLen {
			t.Fatalf("len = %d, want %d", len(data), expectedLen)
		}
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthorResponse{
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

	t.Run("too many args", func(t *testing.T) {
		p := &AuthorResponse{
			RawArgs: make([][]byte, 256),
		}

		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})

	t.Run("arg too long", func(t *testing.T) {
		p := &AuthorResponse{
			RawArgs: [][]byte{bytes.Repeat([]byte("x"), 256)},
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

func TestAuthorResponseUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if p.Status != AuthorStatusPassAdd {
			t.Errorf("got %v, want %v", p.Status, AuthorStatusPassAdd)
		}
		if p.RawArgs != nil {
			t.Errorf("expected nil, got %v", p.RawArgs)
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

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for arg lengths", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00} // arg_cnt=2 but no arg lengths

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for fields", func(t *testing.T) {
		// arg_cnt=1, arg1_len=5, server_msg_len=0, data_len=0, but only 2 bytes of arg data
		data := []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 'a', 'b'}

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})
}

func TestAuthorResponseMarshalUnmarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		packet *AuthorResponse
	}{
		{
			name: "pass_add",
			packet: &AuthorResponse{
				Status: AuthorStatusPassAdd,
			},
		},
		{
			name: "pass_repl with args",
			packet: &AuthorResponse{
				Status:  AuthorStatusPassRepl,
				RawArgs: [][]byte{[]byte("priv-lvl=15"), []byte("timeout=60")},
			},
		},
		{
			name: "fail with message",
			packet: &AuthorResponse{
				Status:    AuthorStatusFail,
				ServerMsg: []byte("Authorization denied"),
			},
		},
		{
			name: "error with data",
			packet: &AuthorResponse{
				Status:    AuthorStatusError,
				ServerMsg: []byte("Internal error"),
				Data:      []byte{0x01, 0x02, 0x03},
			},
		},
		{
			name: "all fields",
			packet: &AuthorResponse{
				Status:    AuthorStatusPassAdd,
				RawArgs:   [][]byte{[]byte("service=shell"), []byte("priv-lvl=1")},
				ServerMsg: []byte("Welcome"),
				Data:      []byte("extra"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			decoded := &AuthorResponse{}
			err = decoded.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decoded.Status != tc.packet.Status {
				t.Errorf("got %v, want %v", decoded.Status, tc.packet.Status)
			}
			if !reflect.DeepEqual(decoded.RawArgs, tc.packet.RawArgs) {
				t.Errorf("got %v, want %v", decoded.RawArgs, tc.packet.RawArgs)
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

func TestAuthorResponseHelperMethods(t *testing.T) {
	t.Run("IsPass", func(t *testing.T) {
		if !(&AuthorResponse{Status: AuthorStatusPassAdd}).IsPass() {
			t.Errorf("expected true")
		}
		if !(&AuthorResponse{Status: AuthorStatusPassRepl}).IsPass() {
			t.Errorf("expected true")
		}
		if (&AuthorResponse{Status: AuthorStatusFail}).IsPass() {
			t.Errorf("expected false")
		}
		if (&AuthorResponse{Status: AuthorStatusError}).IsPass() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsPassAdd", func(t *testing.T) {
		if !(&AuthorResponse{Status: AuthorStatusPassAdd}).IsPassAdd() {
			t.Errorf("expected true")
		}
		if (&AuthorResponse{Status: AuthorStatusPassRepl}).IsPassAdd() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsPassRepl", func(t *testing.T) {
		if !(&AuthorResponse{Status: AuthorStatusPassRepl}).IsPassRepl() {
			t.Errorf("expected true")
		}
		if (&AuthorResponse{Status: AuthorStatusPassAdd}).IsPassRepl() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsFail", func(t *testing.T) {
		if !(&AuthorResponse{Status: AuthorStatusFail}).IsFail() {
			t.Errorf("expected true")
		}
		if (&AuthorResponse{Status: AuthorStatusPassAdd}).IsFail() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsError", func(t *testing.T) {
		if !(&AuthorResponse{Status: AuthorStatusError}).IsError() {
			t.Errorf("expected true")
		}
		if (&AuthorResponse{Status: AuthorStatusPassAdd}).IsError() {
			t.Errorf("expected false")
		}
	})
}

func TestAuthorRequestEmptyArgs(t *testing.T) {
	t.Run("zero length arg in list", func(t *testing.T) {
		p := &AuthorRequest{
			AuthenMethod: AuthenMethod(AuthenTypePAP),
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
			RawArgs:      [][]byte{[]byte(""), []byte("test")},
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		decoded := &AuthorRequest{}
		err = decoded.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(decoded.RawArgs) != 2 {
			t.Errorf("len = %d, want %d", len(decoded.RawArgs), 2)
		}
		if decoded.RawArgs[0] != nil { // Empty byte slice becomes nil
			t.Errorf("expected nil, got %v", decoded.RawArgs[0])
		}
		if !bytes.Equal(decoded.RawArgs[1], []byte("test")) {
			t.Errorf("got %v, want %v", decoded.RawArgs[1], []byte("test"))
		}
	})
}

func TestAuthorResponseEmptyArgs(t *testing.T) {
	t.Run("zero length arg in list", func(t *testing.T) {
		p := &AuthorResponse{
			Status:  AuthorStatusPassAdd,
			RawArgs: [][]byte{[]byte(""), []byte("test")},
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		decoded := &AuthorResponse{}
		err = decoded.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(decoded.RawArgs) != 2 {
			t.Errorf("len = %d, want %d", len(decoded.RawArgs), 2)
		}
		if decoded.RawArgs[0] != nil { // Empty byte slice becomes nil
			t.Errorf("expected nil, got %v", decoded.RawArgs[0])
		}
		if !bytes.Equal(decoded.RawArgs[1], []byte("test")) {
			t.Errorf("got %v, want %v", decoded.RawArgs[1], []byte("test"))
		}
	})
}

func TestAuthorBadSecretDetection(t *testing.T) {
	t.Run("AuthorRequest with garbage lengths", func(t *testing.T) {
		// 8-byte header with garbage length fields
		data := []byte{
			0x01, 0x01, 0x01, 0x01, // authen_method, priv, authen_type, service
			0xFF, 0xFF, 0xFF, 0xFF, // garbage: user=255, port=255, rem_addr=255, arg_count=255
		}
		// minLen = 8 + 255 + 255 + 255 + 255 = 1028, but we only have 8

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})

	t.Run("AuthorRequest normal truncation should not be bad secret", func(t *testing.T) {
		data := []byte{
			0x01, 0x01, 0x01, 0x01, // authen_method, priv, authen_type, service
			0x05, 0x00, 0x00, 0x00, // user_len=5, rest=0
		}
		// minLen = 8 + 5 = 13, but we have 8 - close enough not to trigger bad secret

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("expected ErrBufferTooShort, got: %v", err)
		}
		if errors.Is(err, ErrBadSecret) {
			t.Errorf("expected false")
		}
	})

	t.Run("AuthorResponse with garbage lengths", func(t *testing.T) {
		// 6-byte header with garbage length fields
		data := []byte{
			0x01,       // status
			0xFF,       // arg_count = 255
			0xFF, 0xFF, // server_msg_len = 65535
			0xFF, 0xFF, // data_len = 65535
		}
		// minLen = 6 + 255 = 261, but we only have 6

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})

	t.Run("AuthorRequest bad secret on second length check", func(t *testing.T) {
		// Passes first check (minLen = 8 + argCount), but arg length bytes
		// encode huge totalArgsLen triggering isBadSecretError on second check.
		data := []byte{
			0x01, 0x01, 0x01, 0x01, // authen_method, priv, authen_type, service
			0x00, 0x00, 0x00, 0x02, // user=0, port=0, rem_addr=0, arg_count=2
			0xFF, 0xFF, // arg1_len=255, arg2_len=255 => totalArgsLen=510
		}
		// First check: minLen = 8+2+0+0+0 = 10, len(data)=10 => passes
		// Second check: expectedLen = 10+0+0+0+510 = 520, isBadSecretError(10,520) => true

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})

	t.Run("AuthorResponse bad secret on second length check", func(t *testing.T) {
		// Passes first check (minLen = 6 + argCount=1 = 7), but arg length byte
		// encodes huge totalArgsLen triggering isBadSecretError on second check.
		data := []byte{
			0x01,       // status
			0x01,       // arg_count=1
			0x00, 0x00, // server_msg_len=0
			0x00, 0x00, // data_len=0
			0xFF, // arg1_len=255
		}
		// First check: minLen = 6+1 = 7, len(data)=7 => passes
		// Second check: expectedLen = 7+0+0+255 = 262, isBadSecretError(7,262) => true

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})
}

func BenchmarkAuthorRequestMarshalBinary(b *testing.B) {
	scenarios := []struct {
		name string
		pkt  *AuthorRequest
	}{
		{
			name: "minimal",
			pkt: &AuthorRequest{
				AuthenMethod: AuthenMethod(AuthenTypePAP),
				PrivLevel:    1,
				AuthenType:   AuthenTypePAP,
				Service:      AuthenServiceLogin,
				User:         []byte("user"),
			},
		},
		{
			name: "with_args",
			pkt: func() *AuthorRequest {
				p := &AuthorRequest{
					AuthenMethod: AuthenMethod(AuthenTypePAP),
					PrivLevel:    15,
					AuthenType:   AuthenTypePAP,
					Service:      AuthenServiceLogin,
					User:         []byte("admin"),
					Port:         []byte("console"),
					RemoteAddr:   []byte("10.0.0.1"),
				}
				p.AddArg("service=shell")
				p.AddArg("cmd=show")
				p.AddArg("cmd-arg=running-config")
				return p
			}(),
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

func BenchmarkAuthorRequestUnmarshalBinary(b *testing.B) {
	pkt := &AuthorRequest{
		AuthenMethod: AuthenMethod(AuthenTypePAP),
		PrivLevel:    15,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte("admin"),
		Port:         []byte("console"),
		RemoteAddr:   []byte("10.0.0.1"),
	}
	pkt.AddArg("service=shell")
	pkt.AddArg("cmd=show")
	pkt.AddArg("cmd-arg=running-config")
	data, _ := pkt.MarshalBinary()
	target := &AuthorRequest{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = target.UnmarshalBinary(data)
	}
}

func BenchmarkAuthorResponseMarshalBinary(b *testing.B) {
	pkt := &AuthorResponse{
		Status:    AuthorStatusPassAdd,
		ServerMsg: []byte("Authorization successful"),
		Data:      []byte("extra-info"),
	}
	pkt.AddArg("priv-lvl=15")
	pkt.AddArg("timeout=3600")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pkt.MarshalBinary()
	}
}

func BenchmarkAuthorResponseUnmarshalBinary(b *testing.B) {
	pkt := &AuthorResponse{
		Status:    AuthorStatusPassAdd,
		ServerMsg: []byte("Authorization successful"),
		Data:      []byte("extra-info"),
	}
	pkt.AddArg("priv-lvl=15")
	pkt.AddArg("timeout=3600")
	data, _ := pkt.MarshalBinary()
	target := &AuthorResponse{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = target.UnmarshalBinary(data)
	}
}

func FuzzAuthorRequestUnmarshalBinary(f *testing.F) {
	validPkt := &AuthorRequest{
		AuthenMethod: AuthenMethod(AuthenTypePAP),
		PrivLevel:    15,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte("admin"),
		Port:         []byte("console"),
		RemoteAddr:   []byte("10.0.0.1"),
	}
	validPkt.AddArg("service=shell")
	if data, err := validPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	minPkt := &AuthorRequest{AuthenMethod: AuthenMethod(AuthenTypePAP), PrivLevel: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin}
	if data, err := minPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	f.Add([]byte{0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful unmarshal: %v", err)
		}

		p2 := &AuthorRequest{}
		if err := p2.UnmarshalBinary(marshaled); err != nil {
			t.Fatalf("second unmarshal failed: %v", err)
		}
	})
}

func FuzzAuthorResponseUnmarshalBinary(f *testing.F) {
	validPkt := &AuthorResponse{
		Status:    AuthorStatusPassAdd,
		ServerMsg: []byte("Authorized"),
		Data:      []byte("info"),
	}
	validPkt.AddArg("priv-lvl=15")
	if data, err := validPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	minPkt := &AuthorResponse{Status: AuthorStatusFail}
	if data, err := minPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful unmarshal: %v", err)
		}

		p2 := &AuthorResponse{}
		if err := p2.UnmarshalBinary(marshaled); err != nil {
			t.Fatalf("second unmarshal failed: %v", err)
		}
	})
}
