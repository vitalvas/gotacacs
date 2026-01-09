package gotacacs

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthorRequest(t *testing.T) {
	t.Run("basic creation", func(t *testing.T) {
		p := NewAuthorRequest(AuthenTypePAP, AuthenTypeASCII, AuthenServiceLogin, "testuser")
		assert.Equal(t, uint8(AuthenTypePAP), p.AuthenMethod)
		assert.Equal(t, uint8(1), p.PrivLevel)
		assert.Equal(t, uint8(AuthenTypeASCII), p.AuthenType)
		assert.Equal(t, uint8(AuthenServiceLogin), p.Service)
		assert.Equal(t, []byte("testuser"), p.User)
		assert.Nil(t, p.Port)
		assert.Nil(t, p.RemoteAddr)
		assert.Nil(t, p.Args)
	})
}

func TestAuthorRequestAddArg(t *testing.T) {
	t.Run("add single arg", func(t *testing.T) {
		p := &AuthorRequest{}
		p.AddArg("service=shell")
		assert.Len(t, p.Args, 1)
		assert.Equal(t, []byte("service=shell"), p.Args[0])
	})

	t.Run("add multiple args", func(t *testing.T) {
		p := &AuthorRequest{}
		p.AddArg("service=shell")
		p.AddArg("cmd=show")
		p.AddArg("cmd-arg=version")
		assert.Len(t, p.Args, 3)
	})
}

func TestAuthorRequestGetArgs(t *testing.T) {
	t.Run("get args as strings", func(t *testing.T) {
		p := &AuthorRequest{
			Args: [][]byte{
				[]byte("service=shell"),
				[]byte("cmd=show"),
			},
		}
		args := p.GetArgs()
		assert.Equal(t, []string{"service=shell", "cmd=show"}, args)
	})

	t.Run("empty args", func(t *testing.T) {
		p := &AuthorRequest{}
		args := p.GetArgs()
		assert.Empty(t, args)
	})
}

func TestAuthorRequestMarshalBinary(t *testing.T) {
	t.Run("empty request encoding", func(t *testing.T) {
		p := &AuthorRequest{
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		// Verify fixed 8-byte header for authorization request
		expected := []byte{AuthenTypePAP, 1, AuthenTypeASCII, AuthenServiceLogin, 0, 0, 0, 0}
		assert.Equal(t, expected, data)
	})

	t.Run("with all fields and args", func(t *testing.T) {
		p := &AuthorRequest{
			AuthenMethod: AuthenTypeCHAP,
			PrivLevel:    15,
			AuthenType:   AuthenTypePAP,
			Service:      AuthenServicePPP,
			User:         []byte("admin"),
			Port:         []byte("tty0"),
			RemoteAddr:   []byte("192.168.1.1"),
			Args:         [][]byte{[]byte("service=shell"), []byte("cmd=show")},
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		// 8 header + 2 arg lens + 5 user + 4 port + 11 rem_addr + 13 + 8 args
		expectedLen := 8 + 2 + 5 + 4 + 11 + 13 + 8
		require.Len(t, data, expectedLen)

		assert.Equal(t, uint8(5), data[4])  // user_len
		assert.Equal(t, uint8(4), data[5])  // port_len
		assert.Equal(t, uint8(11), data[6]) // rem_addr_len
		assert.Equal(t, uint8(2), data[7])  // arg_cnt
		assert.Equal(t, uint8(13), data[8]) // arg1 len
		assert.Equal(t, uint8(8), data[9])  // arg2 len
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthorRequest{
			User: bytes.Repeat([]byte("x"), 256),
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})

	t.Run("too many args", func(t *testing.T) {
		p := &AuthorRequest{
			Args: make([][]byte, 256),
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})

	t.Run("arg too long", func(t *testing.T) {
		p := &AuthorRequest{
			Args: [][]byte{bytes.Repeat([]byte("x"), 256)},
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})
}

func TestAuthorRequestUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, uint8(0x02), p.AuthenMethod)
		assert.Equal(t, uint8(0x01), p.PrivLevel)
		assert.Nil(t, p.User)
		assert.Nil(t, p.Args)
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x02, 0x01, 0x01}

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for arg lengths", func(t *testing.T) {
		data := []byte{0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02} // arg_cnt=2 but no arg lengths

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for args", func(t *testing.T) {
		// arg_cnt=1, arg1_len=5, but only 2 bytes of arg data
		data := []byte{0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 'a', 'b'}

		p := &AuthorRequest{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
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
				AuthenMethod: AuthenTypePAP,
				PrivLevel:    1,
				AuthenType:   AuthenTypeASCII,
				Service:      AuthenServiceLogin,
			},
		},
		{
			name: "with user",
			packet: &AuthorRequest{
				AuthenMethod: AuthenTypePAP,
				PrivLevel:    15,
				AuthenType:   AuthenTypePAP,
				Service:      AuthenServiceEnable,
				User:         []byte("administrator"),
			},
		},
		{
			name: "with args",
			packet: &AuthorRequest{
				AuthenMethod: AuthenTypeCHAP,
				PrivLevel:    1,
				AuthenType:   AuthenTypeASCII,
				Service:      AuthenServiceLogin,
				User:         []byte("user"),
				Args:         [][]byte{[]byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=version")},
			},
		},
		{
			name: "all fields",
			packet: &AuthorRequest{
				AuthenMethod: AuthenTypeMSCHAP,
				PrivLevel:    0,
				AuthenType:   AuthenTypeCHAP,
				Service:      AuthenServicePPP,
				User:         []byte("user"),
				Port:         []byte("console"),
				RemoteAddr:   []byte("10.0.0.1"),
				Args:         [][]byte{[]byte("service=ppp"), []byte("protocol=ip")},
			},
		},
		{
			name: "max args",
			packet: func() *AuthorRequest {
				p := &AuthorRequest{
					AuthenMethod: AuthenTypePAP,
					PrivLevel:    1,
					AuthenType:   AuthenTypeASCII,
					Service:      AuthenServiceLogin,
				}
				for i := range 255 {
					p.Args = append(p.Args, []byte{byte(i)})
				}
				return p
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal original packet
			data, err := tc.packet.MarshalBinary()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal into new packet and verify all authorization-specific fields
			decoded := &AuthorRequest{}
			require.NoError(t, decoded.UnmarshalBinary(data))

			// Verify authorization request specific structure
			assert.Equal(t, tc.packet.AuthenMethod, decoded.AuthenMethod, "authen_method mismatch")
			assert.Equal(t, tc.packet.PrivLevel, decoded.PrivLevel, "priv_lvl mismatch")
			assert.Equal(t, tc.packet.AuthenType, decoded.AuthenType, "authen_type mismatch")
			assert.Equal(t, tc.packet.Service, decoded.Service, "service mismatch")
			assert.Equal(t, tc.packet.User, decoded.User, "user mismatch")
			assert.Equal(t, tc.packet.Port, decoded.Port, "port mismatch")
			assert.Equal(t, tc.packet.RemoteAddr, decoded.RemoteAddr, "rem_addr mismatch")
			assert.Equal(t, len(tc.packet.Args), len(decoded.Args), "args count mismatch")
			for i := range tc.packet.Args {
				assert.Equal(t, tc.packet.Args[i], decoded.Args[i], "arg %d mismatch", i)
			}
		})
	}
}

func TestNewAuthorResponse(t *testing.T) {
	t.Run("basic creation", func(t *testing.T) {
		p := NewAuthorResponse(AuthorStatusPassAdd)
		assert.Equal(t, uint8(AuthorStatusPassAdd), p.Status)
		assert.Nil(t, p.Args)
		assert.Nil(t, p.ServerMsg)
		assert.Nil(t, p.Data)
	})
}

func TestAuthorResponseAddArg(t *testing.T) {
	t.Run("add args", func(t *testing.T) {
		p := &AuthorResponse{}
		p.AddArg("priv-lvl=15")
		p.AddArg("timeout=60")
		assert.Len(t, p.Args, 2)
	})
}

func TestAuthorResponseGetArgs(t *testing.T) {
	t.Run("get args as strings", func(t *testing.T) {
		p := &AuthorResponse{
			Args: [][]byte{
				[]byte("priv-lvl=15"),
				[]byte("timeout=60"),
			},
		}
		args := p.GetArgs()
		assert.Equal(t, []string{"priv-lvl=15", "timeout=60"}, args)
	})
}

func TestAuthorResponseMarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		p := &AuthorResponse{
			Status: AuthorStatusPassAdd,
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)
		require.Len(t, data, 6)

		assert.Equal(t, uint8(AuthorStatusPassAdd), data[0])
		assert.Equal(t, uint8(0), data[1]) // arg_cnt
	})

	t.Run("with message and args", func(t *testing.T) {
		p := &AuthorResponse{
			Status:    AuthorStatusPassRepl,
			ServerMsg: []byte("Authorized"),
			Args:      [][]byte{[]byte("priv-lvl=15")},
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		// 6 header + 1 arg len + 10 server_msg + 11 arg
		expectedLen := 6 + 1 + 10 + 11
		require.Len(t, data, expectedLen)
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthorResponse{
			ServerMsg: bytes.Repeat([]byte("x"), 65536),
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})

	t.Run("too many args", func(t *testing.T) {
		p := &AuthorResponse{
			Args: make([][]byte, 256),
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})

	t.Run("arg too long", func(t *testing.T) {
		p := &AuthorResponse{
			Args: [][]byte{bytes.Repeat([]byte("x"), 256)},
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})
}

func TestAuthorResponseUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, uint8(AuthorStatusPassAdd), p.Status)
		assert.Nil(t, p.Args)
		assert.Nil(t, p.ServerMsg)
		assert.Nil(t, p.Data)
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00}

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for arg lengths", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00} // arg_cnt=2 but no arg lengths

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for fields", func(t *testing.T) {
		// arg_cnt=1, arg1_len=5, server_msg_len=0, data_len=0, but only 2 bytes of arg data
		data := []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 'a', 'b'}

		p := &AuthorResponse{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
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
				Status: AuthorStatusPassRepl,
				Args:   [][]byte{[]byte("priv-lvl=15"), []byte("timeout=60")},
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
				Args:      [][]byte{[]byte("service=shell"), []byte("priv-lvl=1")},
				ServerMsg: []byte("Welcome"),
				Data:      []byte("extra"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.packet.MarshalBinary()
			require.NoError(t, err)

			decoded := &AuthorResponse{}
			err = decoded.UnmarshalBinary(data)
			require.NoError(t, err)

			assert.Equal(t, tc.packet.Status, decoded.Status)
			assert.Equal(t, tc.packet.Args, decoded.Args)
			assert.Equal(t, tc.packet.ServerMsg, decoded.ServerMsg)
			assert.Equal(t, tc.packet.Data, decoded.Data)
		})
	}
}

func TestAuthorResponseHelperMethods(t *testing.T) {
	t.Run("IsPass", func(t *testing.T) {
		assert.True(t, (&AuthorResponse{Status: AuthorStatusPassAdd}).IsPass())
		assert.True(t, (&AuthorResponse{Status: AuthorStatusPassRepl}).IsPass())
		assert.False(t, (&AuthorResponse{Status: AuthorStatusFail}).IsPass())
		assert.False(t, (&AuthorResponse{Status: AuthorStatusError}).IsPass())
	})

	t.Run("IsPassAdd", func(t *testing.T) {
		assert.True(t, (&AuthorResponse{Status: AuthorStatusPassAdd}).IsPassAdd())
		assert.False(t, (&AuthorResponse{Status: AuthorStatusPassRepl}).IsPassAdd())
	})

	t.Run("IsPassRepl", func(t *testing.T) {
		assert.True(t, (&AuthorResponse{Status: AuthorStatusPassRepl}).IsPassRepl())
		assert.False(t, (&AuthorResponse{Status: AuthorStatusPassAdd}).IsPassRepl())
	})

	t.Run("IsFail", func(t *testing.T) {
		assert.True(t, (&AuthorResponse{Status: AuthorStatusFail}).IsFail())
		assert.False(t, (&AuthorResponse{Status: AuthorStatusPassAdd}).IsFail())
	})

	t.Run("IsError", func(t *testing.T) {
		assert.True(t, (&AuthorResponse{Status: AuthorStatusError}).IsError())
		assert.False(t, (&AuthorResponse{Status: AuthorStatusPassAdd}).IsError())
	})
}

func TestAuthorRequestEmptyArgs(t *testing.T) {
	t.Run("zero length arg in list", func(t *testing.T) {
		p := &AuthorRequest{
			AuthenMethod: AuthenTypePAP,
			PrivLevel:    1,
			AuthenType:   AuthenTypeASCII,
			Service:      AuthenServiceLogin,
			Args:         [][]byte{[]byte(""), []byte("test")},
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		decoded := &AuthorRequest{}
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Len(t, decoded.Args, 2)
		assert.Nil(t, decoded.Args[0]) // Empty byte slice becomes nil
		assert.Equal(t, []byte("test"), decoded.Args[1])
	})
}

func TestAuthorResponseEmptyArgs(t *testing.T) {
	t.Run("zero length arg in list", func(t *testing.T) {
		p := &AuthorResponse{
			Status: AuthorStatusPassAdd,
			Args:   [][]byte{[]byte(""), []byte("test")},
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		decoded := &AuthorResponse{}
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Len(t, decoded.Args, 2)
		assert.Nil(t, decoded.Args[0]) // Empty byte slice becomes nil
		assert.Equal(t, []byte("test"), decoded.Args[1])
	})
}
