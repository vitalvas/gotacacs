package gotacacs

import (
	"bytes"
	"crypto/md5"
	"errors"
	"testing"
)

func TestCHAPResponse(t *testing.T) {
	// RFC 1994 Section 4.1 (the PPP CHAP hash RFC 8907 Section 5.4.2.3 uses):
	// Response = MD5(Identifier || secret || Challenge), 16 octets.
	id := byte(0x42)
	secret := []byte("s3cr3t")
	challenge := []byte("random-challenge-bytes")

	got := CHAPResponse(id, secret, challenge)
	if len(got) != CHAPResponseLength {
		t.Fatalf("response length = %d, want %d", len(got), CHAPResponseLength)
	}

	want := make([]byte, 0, 1+len(secret)+len(challenge))
	want = append(want, id)
	want = append(want, secret...)
	want = append(want, challenge...)
	sum := md5.Sum(want)
	if !bytes.Equal(got, sum[:]) {
		t.Errorf("response = %x, want %x", got, sum[:])
	}
}

func TestBuildAndParseCHAPData(t *testing.T) {
	id := byte(0x07)
	secret := []byte("password")
	challenge := []byte("0123456789abcdef") // 16 bytes, >= recommended 8

	data := BuildCHAPData(id, secret, challenge)

	// Layout: id (1) || challenge (len) || response (16).
	if len(data) != 1+len(challenge)+CHAPResponseLength {
		t.Fatalf("data length = %d, want %d", len(data), 1+len(challenge)+CHAPResponseLength)
	}
	if data[0] != id {
		t.Errorf("data[0] = %#x, want id %#x", data[0], id)
	}

	gotID, gotChallenge, gotResponse, err := ParseCHAPData(data)
	if err != nil {
		t.Fatalf("ParseCHAPData: %v", err)
	}
	if gotID != id {
		t.Errorf("parsed id = %#x, want %#x", gotID, id)
	}
	if !bytes.Equal(gotChallenge, challenge) {
		t.Errorf("parsed challenge = %q, want %q", gotChallenge, challenge)
	}
	if !bytes.Equal(gotResponse, CHAPResponse(id, secret, challenge)) {
		t.Errorf("parsed response does not match recomputed response")
	}
}

func TestParseCHAPData_TooShort(t *testing.T) {
	// Need at least id (1) + response (16) = 17 octets; challenge may be empty.
	for _, n := range []int{0, 1, 16} {
		if _, _, _, err := ParseCHAPData(make([]byte, n)); !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("ParseCHAPData(%d bytes) = %v, want ErrInvalidPacket", n, err)
		}
	}
	// Exactly 17 bytes is valid: empty challenge.
	id, challenge, response, err := ParseCHAPData(make([]byte, 17))
	if err != nil {
		t.Fatalf("17-byte data: %v", err)
	}
	if id != 0 || len(challenge) != 0 || len(response) != CHAPResponseLength {
		t.Errorf("17-byte data split wrong: id=%#x challenge=%d response=%d", id, len(challenge), len(response))
	}
}

func TestVerifyCHAP(t *testing.T) {
	id := byte(0x5a)
	secret := []byte("correct-horse")
	challenge := []byte("a-sufficiently-long-challenge")

	t.Run("accepts the matching response", func(t *testing.T) {
		data := BuildCHAPData(id, secret, challenge)
		ok, err := VerifyCHAP(secret, data)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Error("VerifyCHAP rejected a valid response")
		}
	})

	t.Run("rejects the wrong secret", func(t *testing.T) {
		data := BuildCHAPData(id, secret, challenge)
		ok, err := VerifyCHAP([]byte("wrong-secret"), data)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("VerifyCHAP accepted a response computed with a different secret")
		}
	})

	t.Run("errors on malformed data", func(t *testing.T) {
		if _, err := VerifyCHAP(secret, []byte{0x01}); !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("got %v, want ErrInvalidPacket", err)
		}
	})
}

func TestNewCHAPStart(t *testing.T) {
	// Client helper: builds a START with the RFC 8907 Section 5.4.2.3 shape.
	id := byte(0x11)
	secret := []byte("pw")
	challenge := []byte("challenge-value!")

	start := NewCHAPStart("alice", id, secret, challenge)
	if start.Action != AuthenActionLogin {
		t.Errorf("action = %#x, want LOGIN", start.Action)
	}
	if start.AuthenType != AuthenTypeCHAP {
		t.Errorf("authen_type = %#x, want CHAP", start.AuthenType)
	}
	if string(start.User) != "alice" {
		t.Errorf("user = %q, want alice", start.User)
	}
	if !bytes.Equal(start.Data, BuildCHAPData(id, secret, challenge)) {
		t.Error("start.Data is not the CHAP data field")
	}

	// Round-trips through the server-side verifier.
	ok, err := VerifyCHAP(secret, start.Data)
	if err != nil || !ok {
		t.Errorf("VerifyCHAP on NewCHAPStart data: ok=%v err=%v", ok, err)
	}
}

func FuzzParseCHAPData(f *testing.F) {
	f.Add(BuildCHAPData(1, []byte("s"), []byte("chal")))
	f.Add(make([]byte, 17))
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		id, challenge, response, err := ParseCHAPData(data)
		if err != nil {
			return
		}
		// A successful parse must reconstruct the exact input layout.
		if len(response) != CHAPResponseLength {
			t.Fatalf("response length %d", len(response))
		}
		rebuilt := append([]byte{id}, challenge...)
		rebuilt = append(rebuilt, response...)
		if !bytes.Equal(rebuilt, data) {
			t.Fatalf("parse not lossless: %x != %x", rebuilt, data)
		}
	})
}
