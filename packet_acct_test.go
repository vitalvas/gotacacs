package gotacacs

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAcctRequest(t *testing.T) {
	t.Run("start request", func(t *testing.T) {
		p := NewAcctRequest(AcctFlagStart, AuthenTypePAP, AuthenTypeASCII, AuthenServiceLogin, "testuser")
		assert.Equal(t, uint8(AcctFlagStart), p.Flags)
		assert.Equal(t, uint8(AuthenTypePAP), p.AuthenMethod)
		assert.Equal(t, uint8(1), p.PrivLevel)
		assert.Equal(t, uint8(AuthenTypeASCII), p.AuthenType)
		assert.Equal(t, uint8(AuthenServiceLogin), p.Service)
		assert.Equal(t, []byte("testuser"), p.User)
	})

	t.Run("stop request", func(t *testing.T) {
		p := NewAcctRequest(AcctFlagStop, AuthenTypeCHAP, AuthenTypePAP, AuthenServiceEnable, "admin")
		assert.Equal(t, uint8(AcctFlagStop), p.Flags)
	})

	t.Run("watchdog request", func(t *testing.T) {
		p := NewAcctRequest(AcctFlagWatchdog, AuthenTypePAP, AuthenTypeASCII, AuthenServiceLogin, "user")
		assert.Equal(t, uint8(AcctFlagWatchdog), p.Flags)
	})
}

func TestAcctRequestAddArg(t *testing.T) {
	t.Run("add accounting arguments", func(t *testing.T) {
		p := &AcctRequest{}
		p.AddArg("task_id=1234")
		p.AddArg("start_time=1234567890")
		p.AddArg("elapsed_time=3600")
		assert.Len(t, p.Args, 3)
		assert.Equal(t, []byte("task_id=1234"), p.Args[0])
	})
}

func TestAcctRequestGetArgs(t *testing.T) {
	t.Run("get accounting args as strings", func(t *testing.T) {
		p := &AcctRequest{
			Args: [][]byte{
				[]byte("task_id=1234"),
				[]byte("elapsed_time=60"),
			},
		}
		args := p.GetArgs()
		assert.Equal(t, []string{"task_id=1234", "elapsed_time=60"}, args)
	})

	t.Run("empty args list", func(t *testing.T) {
		p := &AcctRequest{}
		args := p.GetArgs()
		assert.Empty(t, args)
	})
}

func TestAcctRequestFlagMethods(t *testing.T) {
	t.Run("IsStart", func(t *testing.T) {
		assert.True(t, (&AcctRequest{Flags: AcctFlagStart}).IsStart())
		assert.False(t, (&AcctRequest{Flags: AcctFlagStop}).IsStart())
		assert.False(t, (&AcctRequest{Flags: 0}).IsStart())
	})

	t.Run("IsStop", func(t *testing.T) {
		assert.True(t, (&AcctRequest{Flags: AcctFlagStop}).IsStop())
		assert.False(t, (&AcctRequest{Flags: AcctFlagStart}).IsStop())
		assert.False(t, (&AcctRequest{Flags: 0}).IsStop())
	})

	t.Run("IsWatchdog", func(t *testing.T) {
		assert.True(t, (&AcctRequest{Flags: AcctFlagWatchdog}).IsWatchdog())
		assert.False(t, (&AcctRequest{Flags: AcctFlagStart}).IsWatchdog())
		assert.False(t, (&AcctRequest{Flags: 0}).IsWatchdog())
	})

	t.Run("combined flags", func(t *testing.T) {
		p := &AcctRequest{Flags: AcctFlagStop | AcctFlagWatchdog}
		assert.False(t, p.IsStart())
		assert.True(t, p.IsStop())
		assert.True(t, p.IsWatchdog())
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
		require.NoError(t, err)

		// Verify 9-byte fixed header for accounting request
		expected := []byte{AcctFlagStart, AuthenTypePAP, 1, AuthenTypeASCII, AuthenServiceLogin, 0, 0, 0, 0}
		assert.Equal(t, expected, data)
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
			Args:         [][]byte{[]byte("task_id=1"), []byte("elapsed_time=100")},
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		// 9 header + 2 arg lens + 5 user + 4 port + 11 rem_addr + 9 + 16 args
		expectedLen := 9 + 2 + 5 + 4 + 11 + 9 + 16
		require.Len(t, data, expectedLen)

		// Verify header fields
		assert.Equal(t, uint8(AcctFlagStop), data[0])
		assert.Equal(t, uint8(5), data[5])  // user_len
		assert.Equal(t, uint8(4), data[6])  // port_len
		assert.Equal(t, uint8(11), data[7]) // rem_addr_len
		assert.Equal(t, uint8(2), data[8])  // arg_cnt
	})

	t.Run("user field exceeds limit", func(t *testing.T) {
		p := &AcctRequest{User: bytes.Repeat([]byte("x"), 256)}
		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})

	t.Run("too many accounting args", func(t *testing.T) {
		p := &AcctRequest{Args: make([][]byte, 256)}
		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})

	t.Run("single arg exceeds limit", func(t *testing.T) {
		p := &AcctRequest{Args: [][]byte{bytes.Repeat([]byte("y"), 256)}}
		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})
}

func TestAcctRequestUnmarshalBinary(t *testing.T) {
	t.Run("minimal accounting packet", func(t *testing.T) {
		data := []byte{AcctFlagStart, 0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, uint8(AcctFlagStart), p.Flags)
		assert.Equal(t, uint8(0x02), p.AuthenMethod)
		assert.Nil(t, p.User)
		assert.Nil(t, p.Args)
	})

	t.Run("buffer shorter than fixed header", func(t *testing.T) {
		data := []byte{0x02, 0x01, 0x01, 0x01}

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for arg lengths", func(t *testing.T) {
		data := []byte{0x02, 0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02}

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for arg data", func(t *testing.T) {
		data := []byte{0x02, 0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10}

		p := &AcctRequest{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
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
				Args:         [][]byte{[]byte("task_id=1"), []byte("bytes_in=1024"), []byte("bytes_out=2048")},
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
				Args:         [][]byte{[]byte("elapsed_time=120"), []byte("protocol=ip")},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode to binary
			data, err := tc.packet.MarshalBinary()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Decode and verify accounting-specific structure
			decoded := &AcctRequest{}
			require.NoError(t, decoded.UnmarshalBinary(data))

			assert.Equal(t, tc.packet.Flags, decoded.Flags, "flags mismatch")
			assert.Equal(t, tc.packet.AuthenMethod, decoded.AuthenMethod, "authen_method mismatch")
			assert.Equal(t, tc.packet.PrivLevel, decoded.PrivLevel, "priv_lvl mismatch")
			assert.Equal(t, tc.packet.AuthenType, decoded.AuthenType, "authen_type mismatch")
			assert.Equal(t, tc.packet.Service, decoded.Service, "service mismatch")
			assert.Equal(t, tc.packet.User, decoded.User, "user mismatch")
			assert.Equal(t, tc.packet.Port, decoded.Port, "port mismatch")
			assert.Equal(t, tc.packet.RemoteAddr, decoded.RemoteAddr, "rem_addr mismatch")
			require.Equal(t, len(tc.packet.Args), len(decoded.Args), "args count mismatch")
			for i := range tc.packet.Args {
				assert.Equal(t, tc.packet.Args[i], decoded.Args[i], "arg %d mismatch", i)
			}
		})
	}
}

func TestNewAcctReply(t *testing.T) {
	t.Run("success reply", func(t *testing.T) {
		p := NewAcctReply(AcctStatusSuccess)
		assert.Equal(t, uint8(AcctStatusSuccess), p.Status)
		assert.Nil(t, p.ServerMsg)
		assert.Nil(t, p.Data)
	})

	t.Run("error reply", func(t *testing.T) {
		p := NewAcctReply(AcctStatusError)
		assert.Equal(t, uint8(AcctStatusError), p.Status)
	})
}

func TestAcctReplyMarshalBinary(t *testing.T) {
	t.Run("success reply encoding", func(t *testing.T) {
		p := &AcctReply{Status: AcctStatusSuccess}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		// 5-byte fixed header: server_msg_len (2) + data_len (2) + status (1)
		expected := []byte{0, 0, 0, 0, AcctStatusSuccess}
		assert.Equal(t, expected, data)
	})

	t.Run("error with server message", func(t *testing.T) {
		p := &AcctReply{
			Status:    AcctStatusError,
			ServerMsg: []byte("Accounting server error"),
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		expectedLen := 5 + 23
		require.Len(t, data, expectedLen)
		assert.Equal(t, uint8(AcctStatusError), data[4])
	})

	t.Run("with server message and data", func(t *testing.T) {
		p := &AcctReply{
			Status:    AcctStatusSuccess,
			ServerMsg: []byte("Record accepted"),
			Data:      []byte{0x01, 0x02, 0x03},
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		expectedLen := 5 + 15 + 3
		require.Len(t, data, expectedLen)
	})

	t.Run("server message exceeds limit", func(t *testing.T) {
		p := &AcctReply{ServerMsg: bytes.Repeat([]byte("x"), 65536)}
		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})

	t.Run("data exceeds limit", func(t *testing.T) {
		p := &AcctReply{Data: bytes.Repeat([]byte("y"), 65536)}
		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})
}

func TestAcctReplyUnmarshalBinary(t *testing.T) {
	t.Run("minimal reply", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00, 0x00, AcctStatusSuccess}

		p := &AcctReply{}
		err := p.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, uint8(AcctStatusSuccess), p.Status)
		assert.Nil(t, p.ServerMsg)
		assert.Nil(t, p.Data)
	})

	t.Run("buffer shorter than header", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00}

		p := &AcctReply{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for server message", func(t *testing.T) {
		data := []byte{0x00, 0x10, 0x00, 0x00, AcctStatusSuccess}

		p := &AcctReply{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
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
			require.NoError(t, err)

			decoded := &AcctReply{}
			require.NoError(t, decoded.UnmarshalBinary(data))

			assert.Equal(t, tc.packet.Status, decoded.Status, "status mismatch")
			assert.Equal(t, tc.packet.ServerMsg, decoded.ServerMsg, "server_msg mismatch")
			assert.Equal(t, tc.packet.Data, decoded.Data, "data mismatch")
		})
	}
}

func TestAcctReplyHelperMethods(t *testing.T) {
	t.Run("IsSuccess", func(t *testing.T) {
		assert.True(t, (&AcctReply{Status: AcctStatusSuccess}).IsSuccess())
		assert.False(t, (&AcctReply{Status: AcctStatusError}).IsSuccess())
		assert.False(t, (&AcctReply{Status: AcctStatusFollow}).IsSuccess())
	})

	t.Run("IsError", func(t *testing.T) {
		assert.True(t, (&AcctReply{Status: AcctStatusError}).IsError())
		assert.False(t, (&AcctReply{Status: AcctStatusSuccess}).IsError())
		assert.False(t, (&AcctReply{Status: AcctStatusFollow}).IsError())
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
			Args:         [][]byte{[]byte(""), []byte("task_id=1")},
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		decoded := &AcctRequest{}
		require.NoError(t, decoded.UnmarshalBinary(data))

		assert.Len(t, decoded.Args, 2)
		assert.Nil(t, decoded.Args[0])
		assert.Equal(t, []byte("task_id=1"), decoded.Args[1])
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
