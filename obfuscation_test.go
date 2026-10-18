package gotacacs

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"testing"
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

		if obfuscated == nil {
			t.Errorf("expected non-nil")
		}
		if len(obfuscated) != len(body) {
			t.Errorf("len = %d, want %d", len(obfuscated), len(body))
		}
		if bytes.Equal(body, obfuscated) {
			t.Errorf("should not equal %v", body)
		}
	})

	t.Run("empty secret returns unchanged body", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		body := []byte("hello world")

		obfuscated := Obfuscate(header, nil, body)
		if !bytes.Equal(obfuscated, body) {
			t.Errorf("got %v, want %v", obfuscated, body)
		}

		obfuscated = Obfuscate(header, []byte{}, body)
		if !bytes.Equal(obfuscated, body) {
			t.Errorf("got %v, want %v", obfuscated, body)
		}
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
		if !bytes.Equal(obfuscated, body) {
			t.Errorf("got %v, want %v", obfuscated, body)
		}
	})

	t.Run("empty body returns empty", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		secret := []byte("testsecret")

		obfuscated := Obfuscate(header, secret, []byte{})
		if !bytes.Equal(obfuscated, []byte{}) {
			t.Errorf("got %v, want %v", obfuscated, []byte{})
		}

		obfuscated = Obfuscate(header, secret, nil)
		if obfuscated != nil {
			t.Errorf("expected nil, got %v", obfuscated)
		}
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
			if obfuscated == nil {
				t.Fatal("expected non-nil")
			}
			if len(obfuscated) != len(tc.body) {
				t.Fatalf("len = %d, want %d", len(obfuscated), len(tc.body))
			}

			deobfuscated := Obfuscate(tc.header, tc.secret, obfuscated)
			if !bytes.Equal(deobfuscated, tc.body) {
				t.Errorf("got %v, want %v", deobfuscated, tc.body)
			}
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

		if bytes.Equal(o1, o2) {
			t.Errorf("should not equal %v", o1)
		}
	})

	t.Run("different secrets", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		body := []byte("test data")

		o1 := Obfuscate(header, []byte("secret1"), body)
		o2 := Obfuscate(header, []byte("secret2"), body)

		if bytes.Equal(o1, o2) {
			t.Errorf("should not equal %v", o1)
		}
	})

	t.Run("different sequence numbers", func(t *testing.T) {
		h1 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		h2 := &Header{Version: 0xc0, SeqNo: 2, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("test data")

		o1 := Obfuscate(h1, secret, body)
		o2 := Obfuscate(h2, secret, body)

		if bytes.Equal(o1, o2) {
			t.Errorf("should not equal %v", o1)
		}
	})

	t.Run("different versions", func(t *testing.T) {
		h1 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		h2 := &Header{Version: 0xc1, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("test data")

		o1 := Obfuscate(h1, secret, body)
		o2 := Obfuscate(h2, secret, body)

		if bytes.Equal(o1, o2) {
			t.Errorf("should not equal %v", o1)
		}
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
		if !bytes.Equal(pad, expectedFirstBlock) {
			t.Errorf("got %v, want %v", pad, expectedFirstBlock)
		}
	})

	t.Run("pad length matches requested length", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")

		for _, length := range []int{1, 5, 15, 16, 17, 32, 48, 100, 1000} {
			pad := generatePseudoPad(header, secret, length)
			if len(pad) != length {
				t.Errorf("len = %d, want %d", len(pad), length)
			}
		}
	})

	t.Run("zero length returns nil", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")

		pad := generatePseudoPad(header, secret, 0)
		if pad != nil {
			t.Errorf("expected nil, got %v", pad)
		}
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
		if !bytes.Equal(pad, expected) {
			t.Errorf("got %v, want %v", pad, expected)
		}
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

		if !bytes.Equal(original, bodyCopy) {
			t.Errorf("got %v, want %v", original, bodyCopy)
		}
	})

	t.Run("original secret unchanged", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		secretCopy := make([]byte, len(secret))
		copy(secretCopy, secret)
		body := []byte("test data")

		_ = Obfuscate(header, secret, body)

		if !bytes.Equal(secret, secretCopy) {
			t.Errorf("got %v, want %v", secret, secretCopy)
		}
	})
}

func TestObfuscateXORProperties(t *testing.T) {
	t.Run("double obfuscation returns original", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("original data here")

		doubleObfuscated := Obfuscate(header, secret, Obfuscate(header, secret, body))
		if !bytes.Equal(doubleObfuscated, body) {
			t.Errorf("got %v, want %v", doubleObfuscated, body)
		}
	})

	t.Run("obfuscating zeros reveals pad", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		zeros := make([]byte, 32)

		obfuscated := Obfuscate(header, secret, zeros)
		pad := generatePseudoPad(header, secret, 32)

		if !bytes.Equal(obfuscated, pad) {
			t.Errorf("got %v, want %v", obfuscated, pad)
		}
	})
}

func TestObfuscateEdgeCases(t *testing.T) {
	t.Run("single byte body", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte{0x42}

		obfuscated := Obfuscate(header, secret, body)
		if len(obfuscated) != 1 {
			t.Errorf("len = %d, want %d", len(obfuscated), 1)
		}

		deobfuscated := Obfuscate(header, secret, obfuscated)
		if !bytes.Equal(deobfuscated, body) {
			t.Errorf("got %v, want %v", deobfuscated, body)
		}
	})

	t.Run("single byte secret", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("x")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		if !bytes.Equal(deobfuscated, body) {
			t.Errorf("got %v, want %v", deobfuscated, body)
		}
	})

	t.Run("long secret", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := bytes.Repeat([]byte("verylongsecret"), 100)
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		if !bytes.Equal(deobfuscated, body) {
			t.Errorf("got %v, want %v", deobfuscated, body)
		}
	})

	t.Run("session ID zero", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0}
		secret := []byte("secret")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		if !bytes.Equal(deobfuscated, body) {
			t.Errorf("got %v, want %v", deobfuscated, body)
		}
	})

	t.Run("max session ID", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0xFFFFFFFF}
		secret := []byte("secret")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Obfuscate(header, secret, obfuscated)
		if !bytes.Equal(deobfuscated, body) {
			t.Errorf("got %v, want %v", deobfuscated, body)
		}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify header values
	if header.Version != uint8(0xc1) {
		t.Errorf("got %v, want %v", header.Version, uint8(0xc1))
	}
	if header.Type != uint8(PacketTypeAuthen) {
		t.Errorf("got %v, want %v", header.Type, uint8(PacketTypeAuthen))
	}
	if header.SeqNo != uint8(1) {
		t.Errorf("got %v, want %v", header.SeqNo, uint8(1))
	}
	if header.Flags != uint8(0) {
		t.Errorf("got %v, want %v", header.Flags, uint8(0))
	}
	if header.SessionID != uint32(12345) { // 0x3039 = 12345
		t.Errorf("got %v, want %v", header.SessionID, uint32(12345))
	}
	if header.Length != uint32(44) { // 0x2c = 44
		t.Errorf("got %v, want %v", header.Length, uint32(44))
	}

	t.Run("decrypt tacquito encrypted packet", func(t *testing.T) {
		encryptedBody := encrypted[HeaderLength:]
		result := Obfuscate(header, secret, encryptedBody)
		if !bytes.Equal(result, decrypted) {
			t.Errorf("decrypted body should match tacquito test vector: got %v, want %v", result, decrypted)
		}
	})

	t.Run("encrypt to match tacquito ciphertext", func(t *testing.T) {
		result := Obfuscate(header, secret, decrypted)
		expectedCiphertext := encrypted[HeaderLength:]
		if !bytes.Equal(result, expectedCiphertext) {
			t.Errorf("encrypted body should match tacquito ciphertext: got %v, want %v", result, expectedCiphertext)
		}
	})

	t.Run("roundtrip with tacquito data", func(t *testing.T) {
		encryptedBody := encrypted[HeaderLength:]
		decryptedResult := Obfuscate(header, secret, encryptedBody)
		reencrypted := Obfuscate(header, secret, decryptedResult)
		if !bytes.Equal(reencrypted, encryptedBody) {
			t.Errorf("re-encrypted should match original ciphertext: got %v, want %v", reencrypted, encryptedBody)
		}
	})

	t.Run("parse decrypted as AuthenStart", func(t *testing.T) {
		encryptedBody := encrypted[HeaderLength:]
		decryptedBody := Obfuscate(header, secret, encryptedBody)

		start := &AuthenStart{}
		err := start.UnmarshalBinary(decryptedBody)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if start.Action != uint8(AuthenActionLogin) {
			t.Errorf("got %v, want %v", start.Action, uint8(AuthenActionLogin))
		}
		if start.PrivLevel != uint8(1) { // PrivLvlUser
			t.Errorf("got %v, want %v", start.PrivLevel, uint8(1))
		}
		if start.AuthenType != uint8(AuthenTypeASCII) {
			t.Errorf("got %v, want %v", start.AuthenType, uint8(AuthenTypeASCII))
		}
		if start.Service != uint8(AuthenServiceLogin) {
			t.Errorf("got %v, want %v", start.Service, uint8(AuthenServiceLogin))
		}
		if string(start.User) != "admin" {
			t.Errorf("got %v, want %v", string(start.User), "admin")
		}
		if string(start.Port) != "command-api" {
			t.Errorf("got %v, want %v", string(start.Port), "command-api")
		}
		if string(start.RemoteAddr) != "2001:4860:4860::8888" {
			t.Errorf("got %v, want %v", string(start.RemoteAddr), "2001:4860:4860::8888")
		}
		if start.Data != nil {
			t.Errorf("expected nil, got %v", start.Data)
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(body, decrypted) {
			t.Errorf("marshaled body should match tacquito decrypted bytes: got %v, want %v", body, decrypted)
		}

		// Encrypt with the same header and secret
		ciphertext := Obfuscate(header, secret, body)
		expectedCiphertext := encrypted[HeaderLength:]
		if !bytes.Equal(ciphertext, expectedCiphertext) {
			t.Errorf("ciphertext should match tacquito encrypted bytes: got %v, want %v", ciphertext, expectedCiphertext)
		}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
		if body.Status == decrypted.Status {
			t.Errorf("wrong secret should produce different status: should not equal %v", body.Status)
		}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if !bytes.Equal(result, plaintext) {
		t.Errorf("UnencryptedFlag should prevent obfuscation: got %v, want %v", result, plaintext)
	}

	// Double-apply should still return original
	result2 := Obfuscate(header, secret, result)
	if !bytes.Equal(result2, plaintext) {
		t.Errorf("UnencryptedFlag should prevent obfuscation on second call: got %v, want %v", result2, plaintext)
	}
}

func byteSizeName(size int) string {
	switch {
	case size >= 1024:
		return fmt.Sprintf("%dKB", size/1024)
	default:
		return fmt.Sprintf("%dB", size)
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
