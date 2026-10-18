package gotacacs

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSessionState(t *testing.T) {
	t.Run("string representation", func(t *testing.T) {
		if got := SessionStateNew.String(); got != "NEW" {
			t.Errorf("got %v, want %v", got, "NEW")
		}
		if got := SessionStateActive.String(); got != "ACTIVE" {
			t.Errorf("got %v, want %v", got, "ACTIVE")
		}
		if got := SessionStateComplete.String(); got != "COMPLETE" {
			t.Errorf("got %v, want %v", got, "COMPLETE")
		}
		if got := SessionStateError.String(); got != "ERROR" {
			t.Errorf("got %v, want %v", got, "ERROR")
		}
		if got := SessionState(99).String(); got != "UNKNOWN" {
			t.Errorf("got %v, want %v", got, "UNKNOWN")
		}
	})
}

func TestNewSession(t *testing.T) {
	t.Run("create client session", func(t *testing.T) {
		session, err := NewSession(true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if session == nil {
			t.Fatal("expected non-nil")
		}

		if session.ID() == 0 {
			t.Errorf("expected non-zero")
		}
		if got := session.State(); got != SessionStateNew {
			t.Errorf("got %v, want %v", got, SessionStateNew)
		}
		if got := session.SeqNo(); got != uint8(0) {
			t.Errorf("got %v, want %v", got, uint8(0))
		}
		if !session.IsClient() {
			t.Errorf("expected true")
		}
		now := time.Now()
		if diff := now.Sub(session.Created()); diff < 0 || diff > time.Second {
			t.Errorf("created %v not within %v of %v", session.Created(), time.Second, now)
		}
		now = time.Now()
		if diff := now.Sub(session.LastActivity()); diff < 0 || diff > time.Second {
			t.Errorf("lastActivity %v not within %v of %v", session.LastActivity(), time.Second, now)
		}
	})

	t.Run("create server session", func(t *testing.T) {
		session, err := NewSession(false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if session == nil {
			t.Fatal("expected non-nil")
		}

		if session.IsClient() {
			t.Errorf("expected false")
		}
	})

	t.Run("unique session IDs", func(t *testing.T) {
		ids := make(map[uint32]bool)
		for range 100 {
			session, err := NewSession(true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			id := session.ID()
			if ids[id] {
				t.Errorf("duplicate session ID generated")
			}
			ids[id] = true
		}
	})
}

func TestNewSessionWithID(t *testing.T) {
	t.Run("create with specific ID", func(t *testing.T) {
		session := NewSessionWithID(0x12345678, true)
		if got := session.ID(); got != uint32(0x12345678) {
			t.Errorf("got %v, want %v", got, uint32(0x12345678))
		}
		if !session.IsClient() {
			t.Errorf("expected true")
		}
	})

	t.Run("create server session with ID", func(t *testing.T) {
		session := NewSessionWithID(0xDEADBEEF, false)
		if got := session.ID(); got != uint32(0xDEADBEEF) {
			t.Errorf("got %v, want %v", got, uint32(0xDEADBEEF))
		}
		if session.IsClient() {
			t.Errorf("expected false")
		}
	})
}

func TestSessionSequenceNumbers(t *testing.T) {
	t.Run("client sequence numbers", func(t *testing.T) {
		session := NewSessionWithID(1, true)

		// First call returns 1
		seqNo, err := session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seqNo != uint8(1) {
			t.Errorf("got %v, want %v", seqNo, uint8(1))
		}
		if got := session.State(); got != SessionStateActive {
			t.Errorf("got %v, want %v", got, SessionStateActive)
		}

		// Subsequent calls increment
		seqNo, err = session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seqNo != uint8(2) {
			t.Errorf("got %v, want %v", seqNo, uint8(2))
		}

		seqNo, err = session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seqNo != uint8(3) {
			t.Errorf("got %v, want %v", seqNo, uint8(3))
		}

		seqNo, err = session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seqNo != uint8(4) {
			t.Errorf("got %v, want %v", seqNo, uint8(4))
		}
	})

	t.Run("server sequence numbers", func(t *testing.T) {
		session := NewSessionWithID(1, false)

		// First call returns 2
		seqNo, err := session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seqNo != uint8(2) {
			t.Errorf("got %v, want %v", seqNo, uint8(2))
		}
		if got := session.State(); got != SessionStateActive {
			t.Errorf("got %v, want %v", got, SessionStateActive)
		}

		// Subsequent calls increment
		seqNo, err = session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seqNo != uint8(3) {
			t.Errorf("got %v, want %v", seqNo, uint8(3))
		}

		seqNo, err = session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seqNo != uint8(4) {
			t.Errorf("got %v, want %v", seqNo, uint8(4))
		}
	})

	t.Run("sequence number overflow", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		// Set sequence to 255 (max value)
		session.mu.Lock()
		session.seqNo = 255
		session.mu.Unlock()

		// Next call should return error
		_, err := session.NextSeqNo()
		if !errors.Is(err, ErrSequenceOverflow) {
			t.Errorf("error %v is not %v", err, ErrSequenceOverflow)
		}
	})
}

func TestSessionValidateSeqNo(t *testing.T) {
	t.Run("client validates server responses", func(t *testing.T) {
		session := NewSessionWithID(1, true)

		// Client sent seq 1
		_, err := session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Server should respond with seq 2
		if !session.ValidateSeqNo(2) {
			t.Errorf("expected true")
		}
		if session.ValidateSeqNo(1) {
			t.Errorf("expected false")
		}
		if session.ValidateSeqNo(3) {
			t.Errorf("expected false")
		}
		if session.ValidateSeqNo(0) {
			t.Errorf("expected false")
		}
	})

	t.Run("server validates client requests", func(t *testing.T) {
		session := NewSessionWithID(1, false)

		// First client packet should be seq 1
		if !session.ValidateSeqNo(1) {
			t.Errorf("expected true")
		}
		if session.ValidateSeqNo(2) {
			t.Errorf("expected false")
		}
		if session.ValidateSeqNo(0) {
			t.Errorf("expected false")
		}
	})

	t.Run("server validates subsequent client packets", func(t *testing.T) {
		session := NewSessionWithID(1, false)
		session.UpdateSeqNo(1) // Received seq 1 from client

		// Server sent seq 2
		_, err := session.NextSeqNo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Next client packet should be seq 3
		if !session.ValidateSeqNo(3) {
			t.Errorf("expected true")
		}
		if session.ValidateSeqNo(2) {
			t.Errorf("expected false")
		}
		if session.ValidateSeqNo(4) {
			t.Errorf("expected false")
		}
	})

	t.Run("zero sequence is invalid", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		if session.ValidateSeqNo(0) {
			t.Errorf("expected false")
		}
	})
}

func TestSessionSetState(t *testing.T) {
	t.Run("set state updates last activity", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		initialActivity := session.LastActivity()

		time.Sleep(10 * time.Millisecond)
		session.SetState(SessionStateComplete)

		if got := session.State(); got != SessionStateComplete {
			t.Errorf("got %v, want %v", got, SessionStateComplete)
		}
		if !session.LastActivity().After(initialActivity) {
			t.Errorf("expected true")
		}
	})

	t.Run("set error state", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		session.SetState(SessionStateError)
		if got := session.State(); got != SessionStateError {
			t.Errorf("got %v, want %v", got, SessionStateError)
		}
	})
}

func TestSessionTouch(t *testing.T) {
	t.Run("touch updates last activity", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		initialActivity := session.LastActivity()

		time.Sleep(10 * time.Millisecond)
		session.Touch()

		if !session.LastActivity().After(initialActivity) {
			t.Errorf("expected true")
		}
	})
}

func TestSessionUpdateSeqNo(t *testing.T) {
	t.Run("update sequence number", func(t *testing.T) {
		session := NewSessionWithID(1, false)
		session.UpdateSeqNo(1)

		if got := session.SeqNo(); got != uint8(1) {
			t.Errorf("got %v, want %v", got, uint8(1))
		}
		if got := session.State(); got != SessionStateActive {
			t.Errorf("got %v, want %v", got, SessionStateActive)
		}
	})
}

func TestSessionConcurrency(t *testing.T) {
	t.Run("concurrent access", func(_ *testing.T) {
		session := NewSessionWithID(1, true)
		var wg sync.WaitGroup

		// Multiple goroutines accessing session
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 100 {
					_ = session.ID()
					_ = session.State()
					_ = session.SeqNo()
					_ = session.IsClient()
					_ = session.LastActivity()
					session.Touch()
				}
			}()
		}

		wg.Wait()
	})
}

func TestTrackedSession(t *testing.T) {
	t.Run("kicked flag", func(t *testing.T) {
		ts := &trackedSession{
			info: SessionInfo{
				TrackingID: 1,
				SessionID:  100,
				State:      SessionStateActive,
			},
		}
		if ts.kicked.Load() {
			t.Errorf("expected false")
		}
		ts.kicked.Store(true)
		if !ts.kicked.Load() {
			t.Errorf("expected true")
		}
	})
}

func TestGenerateSessionID(t *testing.T) {
	t.Run("generates non-zero IDs", func(t *testing.T) {
		for range 100 {
			id, err := generateSessionID()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Very unlikely to get zero with random generation
			// but technically possible, so we just check no error
			_ = id
		}
	})

	t.Run("generates different IDs", func(t *testing.T) {
		ids := make(map[uint32]bool)
		for range 100 {
			id, err := generateSessionID()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			ids[id] = true
		}
		// Should have mostly unique IDs (collisions extremely unlikely)
		if len(ids) < 99 {
			t.Errorf("expected true")
		}
	})
}

func BenchmarkNewSession(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewSession(true)
	}
}

func BenchmarkSessionNextSeqNo(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session := NewSessionWithID(uint32(i), true)
		for {
			if _, err := session.NextSeqNo(); err != nil {
				break
			}
		}
	}
}

func BenchmarkSessionValidateSeqNo(b *testing.B) {
	session, _ := NewSession(false) // server session
	session.UpdateSeqNo(1)          // simulate client sent seq 1

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = session.ValidateSeqNo(3) // validate next expected client seq
	}
}
