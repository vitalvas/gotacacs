package gotacacs

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObfuscate(t *testing.T) {
	t.Run("basic obfuscation", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		secret := []byte("testsecret")
		body := []byte("hello world")

		obfuscated := Obfuscate(header, secret, body)

		assert.NotNil(t, obfuscated)
		assert.Len(t, obfuscated, len(body))
		assert.NotEqual(t, body, obfuscated)
	})

	t.Run("empty secret returns unchanged body", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		body := []byte("hello world")

		obfuscated := Obfuscate(header, nil, body)
		assert.Equal(t, body, obfuscated)

		obfuscated = Obfuscate(header, []byte{}, body)
		assert.Equal(t, body, obfuscated)
	})

	t.Run("unencrypted flag returns unchanged body", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			Flags:     FlagUnencrypted,
			SessionID: 0x12345678,
		}
		secret := []byte("testsecret")
		body := []byte("hello world")

		obfuscated := Obfuscate(header, secret, body)
		assert.Equal(t, body, obfuscated)
	})

	t.Run("empty body returns empty", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		secret := []byte("testsecret")

		obfuscated := Obfuscate(header, secret, []byte{})
		assert.Equal(t, []byte{}, obfuscated)

		obfuscated = Obfuscate(header, secret, nil)
		assert.Nil(t, obfuscated)
	})
}

func TestObfuscateRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		header *Header
		secret []byte
		body   []byte
	}{
		{
			name: "short body",
			header: &Header{
				Version:   0xc0,
				SeqNo:     1,
				SessionID: 0x12345678,
			},
			secret: []byte("secret"),
			body:   []byte("hi"),
		},
		{
			name: "exactly MD5 block size",
			header: &Header{
				Version:   0xc0,
				SeqNo:     1,
				SessionID: 0xDEADBEEF,
			},
			secret: []byte("mysecret"),
			body:   bytes.Repeat([]byte("x"), md5.Size),
		},
		{
			name: "longer than MD5 block",
			header: &Header{
				Version:   0xc1,
				SeqNo:     5,
				SessionID: 0xCAFEBABE,
			},
			secret: []byte("longsecretkey"),
			body:   bytes.Repeat([]byte("a"), md5.Size+10),
		},
		{
			name: "multiple MD5 blocks",
			header: &Header{
				Version:   0xc0,
				SeqNo:     255,
				SessionID: 0x00000001,
			},
			secret: []byte("s"),
			body:   bytes.Repeat([]byte("b"), md5.Size*3+5),
		},
		{
			name: "binary data",
			header: &Header{
				Version:   0xc0,
				SeqNo:     100,
				SessionID: 0xFFFFFFFF,
			},
			secret: []byte("binarysecret"),
			body:   []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x80, 0x7F},
		},
		{
			name: "large body",
			header: &Header{
				Version:   0xc0,
				SeqNo:     1,
				SessionID: 0x87654321,
			},
			secret: []byte("bigsecret"),
			body:   bytes.Repeat([]byte("large"), 1000),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obfuscated := Obfuscate(tc.header, tc.secret, tc.body)
			require.NotNil(t, obfuscated)
			require.Len(t, obfuscated, len(tc.body))

			deobfuscated := Obfuscate(tc.header, tc.secret, obfuscated)
			assert.Equal(t, tc.body, deobfuscated)
		})
	}
}

func TestObfuscateDifferentInputsProduceDifferentOutputs(t *testing.T) {
	t.Run("different session IDs", func(t *testing.T) {
		h1 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x11111111}
		h2 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x22222222}
		secret := []byte("secret")
		body := []byte("test data")

		o1 := Obfuscate(h1, secret, body)
		o2 := Obfuscate(h2, secret, body)

		assert.NotEqual(t, o1, o2)
	})

	t.Run("different secrets", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		body := []byte("test data")

		o1 := Obfuscate(header, []byte("secret1"), body)
		o2 := Obfuscate(header, []byte("secret2"), body)

		assert.NotEqual(t, o1, o2)
	})

	t.Run("different sequence numbers", func(t *testing.T) {
		h1 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		h2 := &Header{Version: 0xc0, SeqNo: 2, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("test data")

		o1 := Obfuscate(h1, secret, body)
		o2 := Obfuscate(h2, secret, body)

		assert.NotEqual(t, o1, o2)
	})

	t.Run("different versions", func(t *testing.T) {
		h1 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		h2 := &Header{Version: 0xc1, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("test data")

		o1 := Obfuscate(h1, secret, body)
		o2 := Obfuscate(h2, secret, body)

		assert.NotEqual(t, o1, o2)
	})
}

func TestGeneratePseudoPad(t *testing.T) {
	t.Run("known vector verification", func(t *testing.T) {
		// Manually compute expected pseudo-pad for verification
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		secret := []byte("secret")

		// Compute expected first block:
		// MD5(session_id || secret || version || seq_no)
		sessionIDBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sessionIDBytes, header.SessionID)

		h := md5.New()
		h.Write(sessionIDBytes)
		h.Write(secret)
		h.Write([]byte{header.Version})
		h.Write([]byte{header.SeqNo})
		expectedFirstBlock := h.Sum(nil)

		// Generate pad and verify first 16 bytes match
		pad := generatePseudoPad(header, secret, 16)
		assert.Equal(t, expectedFirstBlock, pad)
	})

	t.Run("pad length matches requested length", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")

		for _, length := range []int{1, 5, 15, 16, 17, 32, 48, 100, 1000} {
			pad := generatePseudoPad(header, secret, length)
			assert.Len(t, pad, length)
		}
	})

	t.Run("zero length returns nil", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")

		pad := generatePseudoPad(header, secret, 0)
		assert.Nil(t, pad)
	})

	t.Run("consecutive blocks are chained", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")

		// Get 32 bytes (2 MD5 blocks)
		pad := generatePseudoPad(header, secret, 32)

		// First block
		sessionIDBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sessionIDBytes, header.SessionID)

		h1 := md5.New()
		h1.Write(sessionIDBytes)
		h1.Write(secret)
		h1.Write([]byte{header.Version})
		h1.Write([]byte{header.SeqNo})
		firstBlock := h1.Sum(nil)

		// Second block should include first block
		h2 := md5.New()
		h2.Write(sessionIDBytes)
		h2.Write(secret)
		h2.Write([]byte{header.Version})
		h2.Write([]byte{header.SeqNo})
		h2.Write(firstBlock)
		secondBlock := h2.Sum(nil)

		expected := make([]byte, 0, 32)
		expected = append(expected, firstBlock...)
		expected = append(expected, secondBlock...)
		assert.Equal(t, expected, pad)
	})
}

func TestObfuscateDoesNotModifyOriginal(t *testing.T) {
	t.Run("original body unchanged", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		original := []byte("test data")
		bodyCopy := make([]byte, len(original))
		copy(bodyCopy, original)

		_ = Obfuscate(header, secret, original)

		assert.Equal(t, bodyCopy, original)
	})

	t.Run("original secret unchanged", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		secretCopy := make([]byte, len(secret))
		copy(secretCopy, secret)
		body := []byte("test data")

		_ = Obfuscate(header, secret, body)

		assert.Equal(t, secretCopy, secret)
	})
}

func TestObfuscateXORProperties(t *testing.T) {
	t.Run("double obfuscation returns original", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("original data here")

		doubleObfuscated := Obfuscate(header, secret, Obfuscate(header, secret, body))
		assert.Equal(t, body, doubleObfuscated)
	})

	t.Run("obfuscating zeros reveals pad", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		zeros := make([]byte, 32)

		obfuscated := Obfuscate(header, secret, zeros)
		pad := generatePseudoPad(header, secret, 32)

		assert.Equal(t, pad, obfuscated)
	})
}

func TestObfuscateEdgeCases(t *testing.T) {
	t.Run("single byte body", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte{0x42}

		obfuscated := Obfuscate(header, secret, body)
		assert.Len(t, obfuscated, 1)

		deobfuscated := Obfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})

	t.Run("single byte secret", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("x")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})

	t.Run("long secret", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := bytes.Repeat([]byte("verylongsecret"), 100)
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})

	t.Run("session ID zero", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0}
		secret := []byte("secret")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})

	t.Run("max session ID", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0xFFFFFFFF}
		secret := []byte("secret")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})
}

// Test vectors from https://github.com/facebookincubator/tacquito/blob/main/crypt_test.go
// These provide interoperability validation with another TACACS+ implementation.

// getTacquitoEncryptedBytes returns an encrypted TACACS+ packet's bytes
// (52 bytes total: 12-byte header + 40-byte body), encrypted with secret "fooman"
func getTacquitoEncryptedBytes() []byte {
	return []byte{
		0xc1, 0x01, 0x01, 0x00, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x2c, // header
		0x9c, 0xed, 0x73, 0xaa, 0x3d, 0x6d, 0x2f, 0x1f, 0xef, 0x62, 0x98, 0x73, // body
		0xf0, 0xac, 0x2f, 0x11, 0x8a, 0xe2, 0x89, 0x8a, 0xcb, 0x50, 0x72, 0xb2,
		0x6d, 0xd2, 0xec, 0xab, 0xe1, 0x4e, 0x22, 0x64, 0x4c, 0x7c, 0xb2, 0x0e,
		0x43, 0x0e, 0x33, 0x92, 0x85, 0x47, 0xca, 0xfc,
	}
}

// getTacquitoDecryptedBytes returns the decrypted TACACS+ body (44 bytes, no header)
// This is an AuthenStart with: action=LOGIN, priv=USER, type=ASCII, service=LOGIN
// user="admin", port="command-api", rem_addr="2001:4860:4860::8888"
func getTacquitoDecryptedBytes() []byte {
	return []byte{
		0x01, 0x01, 0x01, 0x01, // action, priv_lvl, authen_type, service
		0x05, 0x0b, 0x14, 0x00, // user_len=5, port_len=11, rem_addr_len=20, data_len=0
		0x61, 0x64, 0x6d, 0x69, 0x6e, // "admin"
		0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x2d, 0x61, 0x70, 0x69, // "command-api"
		0x32, 0x30, 0x30, 0x31, 0x3a, 0x34, 0x38, 0x36, 0x30, 0x3a, // "2001:4860:4860::8888"
		0x34, 0x38, 0x36, 0x30, 0x3a, 0x3a, 0x38, 0x38, 0x38, 0x38,
	}
}

func TestTacquitoInteroperability(t *testing.T) {
	// Test vectors from tacquito project for interoperability validation
	encrypted := getTacquitoEncryptedBytes()
	decrypted := getTacquitoDecryptedBytes()
	secret := []byte("fooman")

	// Parse the header from encrypted bytes
	header := &Header{}
	err := header.UnmarshalBinary(encrypted[:HeaderLength])
	require.NoError(t, err)

	// Verify header values
	assert.Equal(t, uint8(0xc1), header.Version)
	assert.Equal(t, uint8(PacketTypeAuthen), header.Type)
	assert.Equal(t, uint8(1), header.SeqNo)
	assert.Equal(t, uint8(0), header.Flags)
	assert.Equal(t, uint32(12345), header.SessionID) // 0x3039 = 12345
	assert.Equal(t, uint32(44), header.Length)       // 0x2c = 44

	t.Run("decrypt tacquito encrypted packet", func(t *testing.T) {
		encryptedBody := encrypted[HeaderLength:]
		result := Obfuscate(header, secret, encryptedBody)
		assert.Equal(t, decrypted, result, "decrypted body should match tacquito test vector")
	})

	t.Run("encrypt to match tacquito ciphertext", func(t *testing.T) {
		result := Obfuscate(header, secret, decrypted)
		expectedCiphertext := encrypted[HeaderLength:]
		assert.Equal(t, expectedCiphertext, result, "encrypted body should match tacquito ciphertext")
	})

	t.Run("roundtrip with tacquito data", func(t *testing.T) {
		encryptedBody := encrypted[HeaderLength:]
		decryptedResult := Obfuscate(header, secret, encryptedBody)
		reencrypted := Obfuscate(header, secret, decryptedResult)
		assert.Equal(t, encryptedBody, reencrypted, "re-encrypted should match original ciphertext")
	})

	t.Run("parse decrypted as AuthenStart", func(t *testing.T) {
		encryptedBody := encrypted[HeaderLength:]
		decryptedBody := Obfuscate(header, secret, encryptedBody)

		start := &AuthenStart{}
		err := start.UnmarshalBinary(decryptedBody)
		require.NoError(t, err)

		assert.Equal(t, uint8(AuthenActionLogin), start.Action)
		assert.Equal(t, uint8(1), start.PrivLevel) // PrivLvlUser
		assert.Equal(t, uint8(AuthenTypeASCII), start.AuthenType)
		assert.Equal(t, uint8(AuthenServiceLogin), start.Service)
		assert.Equal(t, "admin", string(start.User))
		assert.Equal(t, "command-api", string(start.Port))
		assert.Equal(t, "2001:4860:4860::8888", string(start.RemoteAddr))
		assert.Nil(t, start.Data)
	})

	t.Run("create matching packet from scratch", func(t *testing.T) {
		// Create the same AuthenStart packet and verify it produces the same output
		start := &AuthenStart{
			Action:     AuthenActionLogin,
			PrivLevel:  1, // PrivLvlUser
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
			User:       []byte("admin"),
			Port:       []byte("command-api"),
			RemoteAddr: []byte("2001:4860:4860::8888"),
		}

		body, err := start.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, decrypted, body, "marshaled body should match tacquito decrypted bytes")

		// Encrypt with the same header and secret
		ciphertext := Obfuscate(header, secret, body)
		expectedCiphertext := encrypted[HeaderLength:]
		assert.Equal(t, expectedCiphertext, ciphertext, "ciphertext should match tacquito encrypted bytes")
	})
}

func TestTacquitoSecretMismatch(t *testing.T) {
	// Based on tacquito's TestEncryptDecryptSecretMismatch
	// This tests that wrong secrets produce malformed packets

	body := &AuthenReply{
		Status:    AuthenStatusGetUser,
		ServerMsg: []byte("\nUser Access Verification\n\nUsername:"),
	}
	plaintext, err := body.MarshalBinary()
	require.NoError(t, err)

	header := &Header{
		Version:   0xc1,
		Type:      PacketTypeAuthen,
		SeqNo:     2,
		SessionID: 12345,
		Length:    uint32(len(plaintext)),
	}

	// Encrypt with correct secret
	correctSecret := []byte("chilled cow")
	encrypted := Obfuscate(header, correctSecret, plaintext)

	// Decrypt with wrong secret
	wrongSecret := []byte("imma bad secret")
	garbage := Obfuscate(header, wrongSecret, encrypted)

	// Try to unmarshal the garbage - should fail or produce wrong data
	decrypted := &AuthenReply{}
	err = decrypted.UnmarshalBinary(garbage)

	// The packet might parse but will have wrong values
	if err == nil {
		// If it parsed, the values should be wrong
		assert.NotEqual(t, body.Status, decrypted.Status,
			"wrong secret should produce different status")
	}
	// If it didn't parse, that's also correct behavior (bad secret detected)
}

func TestTacquitoUnencryptedFlag(t *testing.T) {
	// Based on tacquito's TestPacketEncryptDecryptUnencryptFlagSet
	// This tests that UnencryptedFlag prevents obfuscation

	body := &AuthenReply{
		Status:    AuthenStatusGetUser,
		ServerMsg: []byte("\nUser Access Verification\n\nUsername:"),
	}
	plaintext, err := body.MarshalBinary()
	require.NoError(t, err)

	header := &Header{
		Version:   0xc1,
		Type:      PacketTypeAuthen,
		SeqNo:     2,
		Flags:     FlagUnencrypted,
		SessionID: 12345,
		Length:    uint32(len(plaintext)),
	}

	secret := []byte("chilled cow")

	// With UnencryptedFlag set, body should remain unchanged
	result := Obfuscate(header, secret, plaintext)
	assert.Equal(t, plaintext, result, "UnencryptedFlag should prevent obfuscation")

	// Double-apply should still return original
	result2 := Obfuscate(header, secret, result)
	assert.Equal(t, plaintext, result2, "UnencryptedFlag should prevent obfuscation on second call")
}

func byteSizeName(size int) string {
	switch {
	case size >= 1024:
		return string(rune('0'+size/1024)) + "KB"
	default:
		return string(rune('0'+size/100)) + string(rune('0'+(size%100)/10)) + string(rune('0'+size%10)) + "B"
	}
}

func BenchmarkObfuscate(b *testing.B) {
	sizes := []int{16, 64, 256, 1024, 4096}

	for _, size := range sizes {
		b.Run(byteSizeName(size), func(b *testing.B) {
			header := &Header{
				Version:   0xc0,
				SeqNo:     1,
				SessionID: 0x12345678,
			}
			secret := []byte("testsecret123456")
			body := bytes.Repeat([]byte("x"), size)

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = Obfuscate(header, secret, body)
			}
		})
	}
}

func BenchmarkGeneratePseudoPad(b *testing.B) {
	sizes := []int{md5.Size, md5.Size * 2, md5.Size * 4, md5.Size * 16}

	for _, size := range sizes {
		b.Run(byteSizeName(size), func(b *testing.B) {
			header := &Header{
				Version:   0xc0,
				SeqNo:     1,
				SessionID: 0x12345678,
			}
			secret := []byte("testsecret123456")

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = generatePseudoPad(header, secret, size)
			}
		})
	}
}

func FuzzObfuscateRoundtrip(f *testing.F) {
	f.Add([]byte("secret"), []byte("hello world"), uint8(0xc0), uint8(1), uint32(0x12345678))
	f.Add([]byte("s"), []byte("x"), uint8(0xc1), uint8(255), uint32(0xFFFFFFFF))
	f.Add([]byte("longsecretkey12345"), []byte("longer body data here that spans multiple md5 blocks"), uint8(0xc0), uint8(100), uint32(0xDEADBEEF))

	f.Fuzz(func(t *testing.T, secret, body []byte, version, seqNo uint8, sessionID uint32) {
		if len(secret) == 0 || len(body) == 0 {
			return
		}

		header := &Header{
			Version:   version,
			SeqNo:     seqNo,
			SessionID: sessionID,
		}

		obfuscated := Obfuscate(header, secret, body)
		if obfuscated == nil {
			t.Fatal("obfuscate returned nil for non-empty body")
		}

		if len(obfuscated) != len(body) {
			t.Fatalf("obfuscated length mismatch: got %d, want %d", len(obfuscated), len(body))
		}

		deobfuscated := Obfuscate(header, secret, obfuscated)
		if len(deobfuscated) != len(body) {
			t.Fatalf("deobfuscated length mismatch: got %d, want %d", len(deobfuscated), len(body))
		}

		for i := range body {
			if deobfuscated[i] != body[i] {
				t.Fatalf("roundtrip mismatch at byte %d: got %02x, want %02x", i, deobfuscated[i], body[i])
			}
		}
	})
}
