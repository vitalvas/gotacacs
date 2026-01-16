package gotacacs

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthenStart(t *testing.T) {
	t.Run("basic creation", func(t *testing.T) {
		p := NewAuthenStart(AuthenActionLogin, AuthenTypeASCII, AuthenServiceLogin, "testuser")
		assert.Equal(t, uint8(AuthenActionLogin), p.Action)
		assert.Equal(t, uint8(1), p.PrivLevel)
		assert.Equal(t, uint8(AuthenTypeASCII), p.AuthenType)
		assert.Equal(t, uint8(AuthenServiceLogin), p.Service)
		assert.Equal(t, []byte("testuser"), p.User)
		assert.Nil(t, p.Port)
		assert.Nil(t, p.RemoteAddr)
		assert.Nil(t, p.Data)
	})

	t.Run("empty user", func(t *testing.T) {
		p := NewAuthenStart(AuthenActionLogin, AuthenTypePAP, AuthenServiceEnable, "")
		assert.Empty(t, p.User)
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
		require.NoError(t, err)
		require.Len(t, data, 8)

		assert.Equal(t, uint8(AuthenActionLogin), data[0])
		assert.Equal(t, uint8(1), data[1])
		assert.Equal(t, uint8(AuthenTypeASCII), data[2])
		assert.Equal(t, uint8(AuthenServiceLogin), data[3])
		assert.Equal(t, uint8(0), data[4]) // user_len
		assert.Equal(t, uint8(0), data[5]) // port_len
		assert.Equal(t, uint8(0), data[6]) // rem_addr_len
		assert.Equal(t, uint8(0), data[7]) // data_len
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
		require.NoError(t, err)

		expectedLen := 8 + 5 + 4 + 11 + 8
		require.Len(t, data, expectedLen)

		assert.Equal(t, uint8(5), data[4])  // user_len
		assert.Equal(t, uint8(4), data[5])  // port_len
		assert.Equal(t, uint8(11), data[6]) // rem_addr_len
		assert.Equal(t, uint8(8), data[7])  // data_len

		offset := 8
		assert.Equal(t, []byte("admin"), data[offset:offset+5])
		offset += 5
		assert.Equal(t, []byte("tty0"), data[offset:offset+4])
		offset += 4
		assert.Equal(t, []byte("192.168.1.1"), data[offset:offset+11])
		offset += 11
		assert.Equal(t, []byte("password"), data[offset:offset+8])
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthenStart{
			User: bytes.Repeat([]byte("x"), 256),
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})
}

func TestAuthenStartUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, uint8(1), p.Action)
		assert.Equal(t, uint8(1), p.PrivLevel)
		assert.Equal(t, uint8(1), p.AuthenType)
		assert.Equal(t, uint8(1), p.Service)
		assert.Nil(t, p.User)
		assert.Nil(t, p.Port)
		assert.Nil(t, p.RemoteAddr)
		assert.Nil(t, p.Data)
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x01, 0x01, 0x01}

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for fields", func(t *testing.T) {
		data := []byte{0x01, 0x01, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00} // user_len=5 but no user data

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
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
			require.NoError(t, err)

			decoded := &AuthenStart{}
			err = decoded.UnmarshalBinary(data)
			require.NoError(t, err)

			assert.Equal(t, tc.packet.Action, decoded.Action)
			assert.Equal(t, tc.packet.PrivLevel, decoded.PrivLevel)
			assert.Equal(t, tc.packet.AuthenType, decoded.AuthenType)
			assert.Equal(t, tc.packet.Service, decoded.Service)
			assert.Equal(t, tc.packet.User, decoded.User)
			assert.Equal(t, tc.packet.Port, decoded.Port)
			assert.Equal(t, tc.packet.RemoteAddr, decoded.RemoteAddr)
			assert.Equal(t, tc.packet.Data, decoded.Data)
		})
	}
}

func TestNewAuthenReply(t *testing.T) {
	t.Run("basic creation", func(t *testing.T) {
		p := NewAuthenReply(AuthenStatusPass)
		assert.Equal(t, uint8(AuthenStatusPass), p.Status)
		assert.Equal(t, uint8(0), p.Flags)
		assert.Nil(t, p.ServerMsg)
		assert.Nil(t, p.Data)
	})
}

func TestAuthenReplyMarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		p := &AuthenReply{
			Status: AuthenStatusPass,
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)
		require.Len(t, data, 6)

		assert.Equal(t, uint8(AuthenStatusPass), data[0])
		assert.Equal(t, uint8(0), data[1])       // flags
		assert.Equal(t, []byte{0, 0}, data[2:4]) // server_msg_len
		assert.Equal(t, []byte{0, 0}, data[4:6]) // data_len
	})

	t.Run("with message and data", func(t *testing.T) {
		p := &AuthenReply{
			Status:    AuthenStatusGetPass,
			Flags:     AuthenReplyFlagNoEcho,
			ServerMsg: []byte("Enter password:"),
			Data:      []byte{0x01, 0x02},
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		expectedLen := 6 + 15 + 2
		require.Len(t, data, expectedLen)

		assert.Equal(t, uint8(AuthenStatusGetPass), data[0])
		assert.Equal(t, uint8(AuthenReplyFlagNoEcho), data[1])
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthenReply{
			ServerMsg: bytes.Repeat([]byte("x"), 65536),
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})
}

func TestAuthenReplyUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}

		p := &AuthenReply{}
		err := p.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, uint8(AuthenStatusPass), p.Status)
		assert.Equal(t, uint8(0), p.Flags)
		assert.Nil(t, p.ServerMsg)
		assert.Nil(t, p.Data)
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00}

		p := &AuthenReply{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for fields", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x05, 0x00, 0x00} // server_msg_len=5 but no data

		p := &AuthenReply{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
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
			require.NoError(t, err)

			decoded := &AuthenReply{}
			err = decoded.UnmarshalBinary(data)
			require.NoError(t, err)

			assert.Equal(t, tc.packet.Status, decoded.Status)
			assert.Equal(t, tc.packet.Flags, decoded.Flags)
			assert.Equal(t, tc.packet.ServerMsg, decoded.ServerMsg)
			assert.Equal(t, tc.packet.Data, decoded.Data)
		})
	}
}

func TestAuthenReplyHelperMethods(t *testing.T) {
	t.Run("IsPass", func(t *testing.T) {
		assert.True(t, (&AuthenReply{Status: AuthenStatusPass}).IsPass())
		assert.False(t, (&AuthenReply{Status: AuthenStatusFail}).IsPass())
	})

	t.Run("IsFail", func(t *testing.T) {
		assert.True(t, (&AuthenReply{Status: AuthenStatusFail}).IsFail())
		assert.False(t, (&AuthenReply{Status: AuthenStatusPass}).IsFail())
	})

	t.Run("IsError", func(t *testing.T) {
		assert.True(t, (&AuthenReply{Status: AuthenStatusError}).IsError())
		assert.False(t, (&AuthenReply{Status: AuthenStatusPass}).IsError())
	})

	t.Run("NeedsInput", func(t *testing.T) {
		assert.True(t, (&AuthenReply{Status: AuthenStatusGetData}).NeedsInput())
		assert.True(t, (&AuthenReply{Status: AuthenStatusGetUser}).NeedsInput())
		assert.True(t, (&AuthenReply{Status: AuthenStatusGetPass}).NeedsInput())
		assert.False(t, (&AuthenReply{Status: AuthenStatusPass}).NeedsInput())
		assert.False(t, (&AuthenReply{Status: AuthenStatusFail}).NeedsInput())
	})

	t.Run("NoEcho", func(t *testing.T) {
		assert.True(t, (&AuthenReply{Flags: AuthenReplyFlagNoEcho}).NoEcho())
		assert.False(t, (&AuthenReply{Flags: 0}).NoEcho())
	})
}

func TestNewAuthenContinue(t *testing.T) {
	t.Run("basic creation", func(t *testing.T) {
		p := NewAuthenContinue("password123")
		assert.Equal(t, []byte("password123"), p.UserMsg)
		assert.Equal(t, uint8(0), p.Flags)
		assert.Nil(t, p.Data)
	})

	t.Run("empty message", func(t *testing.T) {
		p := NewAuthenContinue("")
		assert.Empty(t, p.UserMsg)
	})
}

func TestAuthenContinueMarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		p := &AuthenContinue{}

		data, err := p.MarshalBinary()
		require.NoError(t, err)
		require.Len(t, data, 5)

		assert.Equal(t, []byte{0, 0}, data[0:2]) // user_msg_len
		assert.Equal(t, []byte{0, 0}, data[2:4]) // data_len
		assert.Equal(t, uint8(0), data[4])       // flags
	})

	t.Run("with message", func(t *testing.T) {
		p := &AuthenContinue{
			UserMsg: []byte("mypassword"),
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		expectedLen := 5 + 10
		require.Len(t, data, expectedLen)
	})

	t.Run("with abort flag", func(t *testing.T) {
		p := &AuthenContinue{
			Flags:   AuthenContinueFlagAbort,
			UserMsg: []byte("aborting"),
		}

		data, err := p.MarshalBinary()
		require.NoError(t, err)

		assert.Equal(t, uint8(AuthenContinueFlagAbort), data[4])
	})

	t.Run("field too long", func(t *testing.T) {
		p := &AuthenContinue{
			UserMsg: bytes.Repeat([]byte("x"), 65536),
		}

		_, err := p.MarshalBinary()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidPacket))
	})
}

func TestAuthenContinueUnmarshalBinary(t *testing.T) {
	t.Run("minimal packet", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00, 0x00, 0x00}

		p := &AuthenContinue{}
		err := p.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Nil(t, p.UserMsg)
		assert.Nil(t, p.Data)
		assert.Equal(t, uint8(0), p.Flags)
	})

	t.Run("buffer too short for header", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00}

		p := &AuthenContinue{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
	})

	t.Run("buffer too short for fields", func(t *testing.T) {
		data := []byte{0x00, 0x05, 0x00, 0x00, 0x00} // user_msg_len=5 but no data

		p := &AuthenContinue{}
		err := p.UnmarshalBinary(data)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort))
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
			require.NoError(t, err)

			decoded := &AuthenContinue{}
			err = decoded.UnmarshalBinary(data)
			require.NoError(t, err)

			assert.Equal(t, tc.packet.Flags, decoded.Flags)
			assert.Equal(t, tc.packet.UserMsg, decoded.UserMsg)
			assert.Equal(t, tc.packet.Data, decoded.Data)
		})
	}
}

func TestAuthenContinueAbortMethods(t *testing.T) {
	t.Run("IsAbort", func(t *testing.T) {
		assert.True(t, (&AuthenContinue{Flags: AuthenContinueFlagAbort}).IsAbort())
		assert.False(t, (&AuthenContinue{Flags: 0}).IsAbort())
	})

	t.Run("SetAbort true", func(t *testing.T) {
		p := &AuthenContinue{}
		p.SetAbort(true)
		assert.True(t, p.IsAbort())
		assert.Equal(t, uint8(AuthenContinueFlagAbort), p.Flags)
	})

	t.Run("SetAbort false", func(t *testing.T) {
		p := &AuthenContinue{Flags: AuthenContinueFlagAbort}
		p.SetAbort(false)
		assert.False(t, p.IsAbort())
		assert.Equal(t, uint8(0), p.Flags)
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
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBadSecret), "expected ErrBadSecret, got: %v", err)
	})

	t.Run("AuthenStart with normal truncation should not be bad secret", func(t *testing.T) {
		// Normal truncation: expected length slightly larger than actual
		data := []byte{
			0x01, 0x01, 0x01, 0x01, // action, priv, authen_type, service
			0x05, 0x00, 0x00, 0x00, // user_len=5, rest=0, so expected=13 but we have 8
		}

		p := &AuthenStart{}
		err := p.UnmarshalBinary(data)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBufferTooShort), "expected ErrBufferTooShort for normal truncation, got: %v", err)
		assert.False(t, errors.Is(err, ErrBadSecret), "should not be ErrBadSecret for normal truncation")
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
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBadSecret), "expected ErrBadSecret, got: %v", err)
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
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBadSecret), "expected ErrBadSecret, got: %v", err)
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
		require.NoError(t, err)

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
		assert.Error(t, err, "parsing garbage data should fail")
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
