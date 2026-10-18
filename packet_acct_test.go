package gotacacs

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestNewAcctRequest(t *testing.T) {
	t.Run("start request", func(t *testing.T) {
		p := NewAcctRequest(AcctFlagStart, AuthenTypePAP, AuthenTypeASCII, AuthenServiceLogin, "testuser")
		if p.Flags != uint8(AcctFlagStart) {
			t.Errorf("got %v, want %v", p.Flags, uint8(AcctFlagStart))
		}
		if p.AuthenMethod != uint8(AuthenTypePAP) {
			t.Errorf("got %v, want %v", p.AuthenMethod, uint8(AuthenTypePAP))
		}
		if p.PrivLevel != uint8(1) {
			t.Errorf("got %v, want %v", p.PrivLevel, uint8(1))
		}
		if p.AuthenType != uint8(AuthenTypeASCII) {
			t.Errorf("got %v, want %v", p.AuthenType, uint8(AuthenTypeASCII))
		}
		if p.Service != uint8(AuthenServiceLogin) {
			t.Errorf("got %v, want %v", p.Service, uint8(AuthenServiceLogin))
		}
		if !bytes.Equal(p.User, []byte("testuser")) {
			t.Errorf("got %v, want %v", p.User, []byte("testuser"))
		}
	})

	t.Run("stop request", func(t *testing.T) {
		p := NewAcctRequest(AcctFlagStop, AuthenTypeCHAP, AuthenTypePAP, AuthenServiceEnable, "admin")
		if p.Flags != uint8(AcctFlagStop) {
			t.Errorf("got %v, want %v", p.Flags, uint8(AcctFlagStop))
		}
	})

	t.Run("watchdog request", func(t *testing.T) {
		p := NewAcctRequest(AcctFlagWatchdog, AuthenTypePAP, AuthenTypeASCII, AuthenServiceLogin, "user")
		if p.Flags != uint8(AcctFlagWatchdog) {
			t.Errorf("got %v, want %v", p.Flags, uint8(AcctFlagWatchdog))
		}
	})
}

func TestAcctRequestAddArg(t *testing.T) {
	t.Run("add accounting arguments", func(t *testing.T) {
		p := &AcctRequest{}
		p.AddArg("task_id=1234")
		p.AddArg("start_time=1234567890")
		p.AddArg("elapsed_time=3600")
		if len(p.RawArgs) != 3 {
			t.Errorf("len = %d, want %d", len(p.RawArgs), 3)
		}
		if !bytes.Equal(p.RawArgs[0], []byte("task_id=1234")) {
			t.Errorf("got %v, want %v", p.RawArgs[0], []byte("task_id=1234"))
		}
	})
}

func TestAcctRequestArgs(t *testing.T) {
	t.Run("get accounting args as strings", func(t *testing.T) {
		p := &AcctRequest{
			RawArgs: [][]byte{
				[]byte("task_id=1234"),
				[]byte("elapsed_time=60"),
			},
		}
		args := p.Args()
		if !reflect.DeepEqual(args, []string{"task_id=1234", "elapsed_time=60"}) {
			t.Errorf("got %v, want %v", args, []string{"task_id=1234", "elapsed_time=60"})
		}
	})

	t.Run("empty args list", func(t *testing.T) {
		p := &AcctRequest{}
		args := p.Args()
		if len(args) != 0 {
			t.Errorf("expected empty, got %v", args)
		}
	})
}

func TestAcctRequestFlagMethods(t *testing.T) {
	t.Run("IsStart", func(t *testing.T) {
		if !(&AcctRequest{Flags: AcctFlagStart}).IsStart() {
			t.Errorf("expected true")
		}
		if (&AcctRequest{Flags: AcctFlagStop}).IsStart() {
			t.Errorf("expected false")
		}
		if (&AcctRequest{Flags: 0}).IsStart() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsStop", func(t *testing.T) {
		if !(&AcctRequest{Flags: AcctFlagStop}).IsStop() {
			t.Errorf("expected true")
		}
		if (&AcctRequest{Flags: AcctFlagStart}).IsStop() {
			t.Errorf("expected false")
		}
		if (&AcctRequest{Flags: 0}).IsStop() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsWatchdog", func(t *testing.T) {
		if !(&AcctRequest{Flags: AcctFlagWatchdog}).IsWatchdog() {
			t.Errorf("expected true")
		}
		if (&AcctRequest{Flags: AcctFlagStart}).IsWatchdog() {
			t.Errorf("expected false")
		}
		if (&AcctRequest{Flags: 0}).IsWatchdog() {
			t.Errorf("expected false")
		}
	})

	t.Run("combined flags", func(t *testing.T) {
		p := &AcctRequest{Flags: AcctFlagStop | AcctFlagWatchdog}
		if p.IsStart() {
			t.Errorf("expected false")
		}
		if !p.IsStop() {
			t.Errorf("expected true")
		}
		if !p.IsWatchdog() {
			t.Errorf("expected true")
		}
	})
}

func TestAcctRequestMarshalBinary(t *testing.T) {
	t.Run("accounting start packet encoding", func(t *testing.T) {
		p := &AcctRequest{
			Flags:        AcctFlagStart,
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify 9-byte fixed header for accounting request
		expected := []byte{AcctFlagStart, AuthenTypePAP, 1, AuthenTypeASCII, AuthenServiceLogin, 0, 0, 0, 0}
		if !bytes.Equal(data, expected) {
			t.Errorf("got %v, want %v", data, expected)
		}
	})

	t.Run("with all fields and accounting args", func(t *testing.T) {
		p := &AcctRequest{
			Flags:        AcctFlagStop,
			AuthenMethod: AuthenTypeCHAP,
			PrivLevel:    15,
			AuthenType:   AuthenTypePAP,
			Service:      AuthenServicePPP,
			User:         []byte("admin"),
			Port:         []byte("tty0"),
			RemoteAddr:   []byte("192.168.1.1"),
			RawArgs:      [][]byte{[]byte("task_id=1"), []byte("elapsed_time=100")},
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 9 header + 2 arg lens + 5 user + 4 port + 11 rem_addr + 9 + 16 args
		expectedLen := 9 + 2 + 5 + 4 + 11 + 9 + 16
		if len(data) != expectedLen {
			t.Fatalf("len = %d, want %d", len(data), expectedLen)
		}

		// Verify header fields
		if data[0] != uint8(AcctFlagStop) {
			t.Errorf("got %v, want %v", data[0], uint8(AcctFlagStop))
		}
		if data[5] != uint8(5) { // user_len
			t.Errorf("got %v, want %v", data[5], uint8(5))
		}
		if data[6] != uint8(4) { // port_len
			t.Errorf("got %v, want %v", data[6], uint8(4))
		}
		if data[7] != uint8(11) { // rem_addr_len
			t.Errorf("got %v, want %v", data[7], uint8(11))
		}
		if data[8] != uint8(2) { // arg_cnt
			t.Errorf("got %v, want %v", data[8], uint8(2))
		}
	})

	t.Run("user field exceeds limit", func(t *testing.T) {
		p := &AcctRequest{User: bytes.Repeat([]byte("x"), 256)}
		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})

	t.Run("too many accounting args", func(t *testing.T) {
		p := &AcctRequest{RawArgs: make([][]byte, 256)}
		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})

	t.Run("single arg exceeds limit", func(t *testing.T) {
		p := &AcctRequest{RawArgs: [][]byte{bytes.Repeat([]byte("y"), 256)}}
		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})
}

func TestAcctRequestUnmarshalBinary(t *testing.T) {
	t.Run("minimal accounting packet", func(t *testing.T) {
		data := []byte{AcctFlagStart, 0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if p.Flags != uint8(AcctFlagStart) {
			t.Errorf("got %v, want %v", p.Flags, uint8(AcctFlagStart))
		}
		if p.AuthenMethod != uint8(0x02) {
			t.Errorf("got %v, want %v", p.AuthenMethod, uint8(0x02))
		}
		if p.User != nil {
			t.Errorf("expected nil, got %v", p.User)
		}
		if p.RawArgs != nil {
			t.Errorf("expected nil, got %v", p.RawArgs)
		}
	})

	t.Run("buffer shorter than fixed header", func(t *testing.T) {
		data := []byte{0x02, 0x01, 0x01, 0x01}

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for arg lengths", func(t *testing.T) {
		data := []byte{0x02, 0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02}

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for arg data", func(t *testing.T) {
		data := []byte{0x02, 0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10}

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})
}

func TestAcctRequestMarshalUnmarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		packet *AcctRequest
	}{
		{
			name: "start record",
			packet: &AcctRequest{
				Flags:        AcctFlagStart,
				AuthenMethod: AuthenTypePAP,
				PrivLevel:    1,
				AuthenType:   AuthenTypeASCII,
				Service:      AuthenServiceLogin,
			},
		},
		{
			name: "stop record with user",
			packet: &AcctRequest{
				Flags:        AcctFlagStop,
				AuthenMethod: AuthenTypePAP,
				PrivLevel:    15,
				AuthenType:   AuthenTypePAP,
				Service:      AuthenServiceEnable,
				User:         []byte("administrator"),
			},
		},
		{
			name: "watchdog with args",
			packet: &AcctRequest{
				Flags:        AcctFlagWatchdog,
				AuthenMethod: AuthenTypeCHAP,
				PrivLevel:    1,
				AuthenType:   AuthenTypeASCII,
				Service:      AuthenServiceLogin,
				User:         []byte("user"),
				RawArgs:      [][]byte{[]byte("task_id=1"), []byte("bytes_in=1024"), []byte("bytes_out=2048")},
			},
		},
		{
			name: "all fields populated",
			packet: &AcctRequest{
				Flags:        AcctFlagStop | AcctFlagWatchdog,
				AuthenMethod: AuthenTypeMSCHAP,
				PrivLevel:    0,
				AuthenType:   AuthenTypeCHAP,
				Service:      AuthenServicePPP,
				User:         []byte("user"),
				Port:         []byte("console"),
				RemoteAddr:   []byte("10.0.0.1"),
				RawArgs:      [][]byte{[]byte("elapsed_time=120"), []byte("protocol=ip")},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode to binary
			data, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("expected non-empty")
			}

			// Decode and verify accounting-specific structure
			decoded := &AcctRequest{}
			if err := decoded.UnmarshalBinary(data); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decoded.Flags != tc.packet.Flags {
				t.Errorf("flags mismatch: got %v, want %v", decoded.Flags, tc.packet.Flags)
			}
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
				t.Fatalf("args count mismatch: got %v, want %v", len(decoded.RawArgs), len(tc.packet.RawArgs))
			}
			for i := range tc.packet.RawArgs {
				if !bytes.Equal(decoded.RawArgs[i], tc.packet.RawArgs[i]) {
					t.Errorf("arg %d mismatch: got %v, want %v", i, decoded.RawArgs[i], tc.packet.RawArgs[i])
				}
			}
		})
	}
}

func TestAcctReplyMarshalBinary(t *testing.T) {
	t.Run("success reply encoding", func(t *testing.T) {
		p := &AcctReply{Status: AcctStatusSuccess}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 5-byte fixed header: server_msg_len (2) + data_len (2) + status (1)
		expected := []byte{0, 0, 0, 0, AcctStatusSuccess}
		if !bytes.Equal(data, expected) {
			t.Errorf("got %v, want %v", data, expected)
		}
	})

	t.Run("error with server message", func(t *testing.T) {
		p := &AcctReply{
			Status:    AcctStatusError,
			ServerMsg: []byte("Accounting server error"),
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedLen := 5 + 23
		if len(data) != expectedLen {
			t.Fatalf("len = %d, want %d", len(data), expectedLen)
		}
		if data[4] != uint8(AcctStatusError) {
			t.Errorf("got %v, want %v", data[4], uint8(AcctStatusError))
		}
	})

	t.Run("with server message and data", func(t *testing.T) {
		p := &AcctReply{
			Status:    AcctStatusSuccess,
			ServerMsg: []byte("Record accepted"),
			Data:      []byte{0x01, 0x02, 0x03},
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedLen := 5 + 15 + 3
		if len(data) != expectedLen {
			t.Fatalf("len = %d, want %d", len(data), expectedLen)
		}
	})

	t.Run("server message exceeds limit", func(t *testing.T) {
		p := &AcctReply{ServerMsg: bytes.Repeat([]byte("x"), 65536)}
		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})

	t.Run("data exceeds limit", func(t *testing.T) {
		p := &AcctReply{Data: bytes.Repeat([]byte("y"), 65536)}
		_, err := p.MarshalBinary()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
	})
}

func TestAcctReplyUnmarshalBinary(t *testing.T) {
	t.Run("minimal reply", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00, 0x00, AcctStatusSuccess}

		p := &AcctReply{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if p.Status != uint8(AcctStatusSuccess) {
			t.Errorf("got %v, want %v", p.Status, uint8(AcctStatusSuccess))
		}
		if p.ServerMsg != nil {
			t.Errorf("expected nil, got %v", p.ServerMsg)
		}
		if p.Data != nil {
			t.Errorf("expected nil, got %v", p.Data)
		}
	})

	t.Run("buffer shorter than header", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00}

		p := &AcctReply{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})

	t.Run("buffer too short for server message", func(t *testing.T) {
		data := []byte{0x00, 0x10, 0x00, 0x00, AcctStatusSuccess}

		p := &AcctReply{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrBufferTooShort) {
			t.Errorf("error %v is not %v", err, ErrBufferTooShort)
		}
	})
}

func TestAcctReplyMarshalUnmarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		packet *AcctReply
	}{
		{
			name:   "success",
			packet: &AcctReply{Status: AcctStatusSuccess},
		},
		{
			name: "error with message",
			packet: &AcctReply{
				Status:    AcctStatusError,
				ServerMsg: []byte("Failed to record"),
			},
		},
		{
			name: "follow with data",
			packet: &AcctReply{
				Status: AcctStatusFollow,
				Data:   []byte{0x10, 0x00, 0x00, 0x31},
			},
		},
		{
			name: "complete reply",
			packet: &AcctReply{
				Status:    AcctStatusSuccess,
				ServerMsg: []byte("Record stored successfully"),
				Data:      []byte("extra_info"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			decoded := &AcctReply{}
			if err := decoded.UnmarshalBinary(data); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decoded.Status != tc.packet.Status {
				t.Errorf("status mismatch: got %v, want %v", decoded.Status, tc.packet.Status)
			}
			if !bytes.Equal(decoded.ServerMsg, tc.packet.ServerMsg) {
				t.Errorf("server_msg mismatch: got %v, want %v", decoded.ServerMsg, tc.packet.ServerMsg)
			}
			if !bytes.Equal(decoded.Data, tc.packet.Data) {
				t.Errorf("data mismatch: got %v, want %v", decoded.Data, tc.packet.Data)
			}
		})
	}
}

func TestAcctReplyHelperMethods(t *testing.T) {
	t.Run("IsSuccess", func(t *testing.T) {
		if !(&AcctReply{Status: AcctStatusSuccess}).IsSuccess() {
			t.Errorf("expected true")
		}
		if (&AcctReply{Status: AcctStatusError}).IsSuccess() {
			t.Errorf("expected false")
		}
		if (&AcctReply{Status: AcctStatusFollow}).IsSuccess() {
			t.Errorf("expected false")
		}
	})

	t.Run("IsError", func(t *testing.T) {
		if !(&AcctReply{Status: AcctStatusError}).IsError() {
			t.Errorf("expected true")
		}
		if (&AcctReply{Status: AcctStatusSuccess}).IsError() {
			t.Errorf("expected false")
		}
		if (&AcctReply{Status: AcctStatusFollow}).IsError() {
			t.Errorf("expected false")
		}
	})
}

func TestAcctRequestEmptyArgs(t *testing.T) {
	t.Run("zero length accounting arg", func(t *testing.T) {
		p := &AcctRequest{
			Flags:        AcctFlagStart,
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
			RawArgs:      [][]byte{[]byte(""), []byte("task_id=1")},
		}

		data, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		decoded := &AcctRequest{}
		if err := decoded.UnmarshalBinary(data); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(decoded.RawArgs) != 2 {
			t.Errorf("len = %d, want %d", len(decoded.RawArgs), 2)
		}
		if decoded.RawArgs[0] != nil {
			t.Errorf("expected nil, got %v", decoded.RawArgs[0])
		}
		if !bytes.Equal(decoded.RawArgs[1], []byte("task_id=1")) {
			t.Errorf("got %v, want %v", decoded.RawArgs[1], []byte("task_id=1"))
		}
	})
}

func TestAcctBadSecretDetection(t *testing.T) {
	t.Run("AcctRequest with garbage lengths", func(t *testing.T) {
		// 9-byte header with garbage length fields
		data := []byte{
			0x02, 0x01, 0x01, 0x01, 0x01, // flags, authen_method, priv, authen_type, service
			0xFF, 0xFF, 0xFF, 0xFF, // garbage: user=255, port=255, rem_addr=255, arg_count=255
		}
		// minLen = 9 + 255 + 255 + 255 + 255 = 1029, but we only have 9

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})

	t.Run("AcctRequest normal truncation should not be bad secret", func(t *testing.T) {
		data := []byte{
			0x02, 0x01, 0x01, 0x01, 0x01, // flags, authen_method, priv, authen_type, service
			0x05, 0x00, 0x00, 0x00, // user_len=5, rest=0
		}
		// minLen = 9 + 5 = 14, but we have 9 - close enough not to trigger bad secret

		p := &AcctRequest{}
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

	t.Run("AcctRequest bad secret on second length check", func(t *testing.T) {
		// Passes first check (minLen = 9 + argCount + userLen + portLen + remAddrLen),
		// but arg length bytes encode huge totalArgsLen triggering isBadSecretError
		// on second check.
		data := []byte{
			0x02, 0x01, 0x01, 0x01, 0x01, // flags, authen_method, priv, authen_type, service
			0x00, 0x00, 0x00, 0x02, // user=0, port=0, rem_addr=0, arg_count=2
			0xFF, 0xFF, // arg1_len=255, arg2_len=255 => totalArgsLen=510
		}
		// First check: minLen = 9+2+0+0+0 = 11, len(data)=11 => passes
		// Second check: expectedLen = 11+0+0+0+510 = 521, isBadSecretError(11,521) => true

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})

	t.Run("AcctReply with garbage lengths", func(t *testing.T) {
		// 5-byte header with garbage length fields
		data := []byte{
			0xFF, 0xFF, // server_msg_len = 65535
			0xFF, 0xFF, // data_len = 65535
			0x01, // status
		}
		// expectedLen = 5 + 65535 + 65535 = 131075, but we only have 5

		p := &AcctReply{}
		err := p.UnmarshalBinary(data)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBadSecret) {
			t.Errorf("expected ErrBadSecret, got: %v", err)
		}
	})
}

func BenchmarkAcctRequestMarshalBinary(b *testing.B) {
	pkt := &AcctRequest{
		Flags:        AcctFlagStart,
		AuthenMethod: AuthenTypePAP,
		PrivLevel:    15,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte("operator"),
		Port:         []byte("vty1"),
		RemoteAddr:   []byte("172.16.0.50"),
	}
	pkt.AddArg("task_id=12345")
	pkt.AddArg("start_time=1234567890")
	pkt.AddArg("service=shell")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pkt.MarshalBinary()
	}
}

func BenchmarkAcctRequestUnmarshalBinary(b *testing.B) {
	pkt := &AcctRequest{
		Flags:        AcctFlagStart,
		AuthenMethod: AuthenTypePAP,
		PrivLevel:    15,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte("operator"),
		Port:         []byte("vty1"),
		RemoteAddr:   []byte("172.16.0.50"),
	}
	pkt.AddArg("task_id=12345")
	pkt.AddArg("start_time=1234567890")
	pkt.AddArg("service=shell")
	data, _ := pkt.MarshalBinary()
	target := &AcctRequest{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = target.UnmarshalBinary(data)
	}
}

func BenchmarkAcctReplyMarshalBinary(b *testing.B) {
	pkt := &AcctReply{
		Status:    AcctStatusSuccess,
		ServerMsg: []byte("Accounting record accepted"),
		Data:      []byte("record-id=99999"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pkt.MarshalBinary()
	}
}

func BenchmarkAcctReplyUnmarshalBinary(b *testing.B) {
	pkt := &AcctReply{
		Status:    AcctStatusSuccess,
		ServerMsg: []byte("Accounting record accepted"),
		Data:      []byte("record-id=99999"),
	}
	data, _ := pkt.MarshalBinary()
	target := &AcctReply{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = target.UnmarshalBinary(data)
	}
}

func FuzzAcctRequestUnmarshalBinary(f *testing.F) {
	validPkt := &AcctRequest{
		Flags:        AcctFlagStart,
		AuthenMethod: AuthenTypePAP,
		PrivLevel:    15,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte("operator"),
		Port:         []byte("vty1"),
		RemoteAddr:   []byte("172.16.0.50"),
	}
	validPkt.AddArg("task_id=12345")
	if data, err := validPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	minPkt := &AcctRequest{Flags: AcctFlagStop, AuthenMethod: AuthenTypePAP, PrivLevel: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin}
	if data, err := minPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	f.Add([]byte{0x02, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful unmarshal: %v", err)
		}

		p2 := &AcctRequest{}
		if err := p2.UnmarshalBinary(marshaled); err != nil {
			t.Fatalf("second unmarshal failed: %v", err)
		}
	})
}

func FuzzAcctReplyUnmarshalBinary(f *testing.F) {
	validPkt := &AcctReply{
		Status:    AcctStatusSuccess,
		ServerMsg: []byte("Recorded"),
		Data:      []byte("id=123"),
	}
	if data, err := validPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	minPkt := &AcctReply{Status: AcctStatusError}
	if data, err := minPkt.MarshalBinary(); err == nil {
		f.Add(data)
	}

	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x01})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &AcctReply{}
		err := p.UnmarshalBinary(data)
		if err != nil {
			return
		}

		marshaled, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful unmarshal: %v", err)
		}

		p2 := &AcctReply{}
		if err := p2.UnmarshalBinary(marshaled); err != nil {
			t.Fatalf("second unmarshal failed: %v", err)
		}
	})
}
