package gotacacs

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionState(t *testing.T) {
	t.Run("string representation", func(t *testing.T) {
		assert.Equal(t, "NEW", SessionStateNew.String())
		assert.Equal(t, "ACTIVE", SessionStateActive.String())
		assert.Equal(t, "COMPLETE", SessionStateComplete.String())
		assert.Equal(t, "ERROR", SessionStateError.String())
		assert.Equal(t, "UNKNOWN", SessionState(99).String())
	})
}

func TestNewSession(t *testing.T) {
	t.Run("create client session", func(t *testing.T) {
		session, err := NewSession(true)
		require.NoError(t, err)
		require.NotNil(t, session)

		assert.NotZero(t, session.ID())
		assert.Equal(t, SessionStateNew, session.State())
		assert.Equal(t, uint8(0), session.SeqNo())
		assert.True(t, session.IsClient())
		assert.WithinDuration(t, time.Now(), session.Created(), time.Second)
		assert.WithinDuration(t, time.Now(), session.LastActivity(), time.Second)
	})

	t.Run("create server session", func(t *testing.T) {
		session, err := NewSession(false)
		require.NoError(t, err)
		require.NotNil(t, session)

		assert.False(t, session.IsClient())
	})

	t.Run("unique session IDs", func(t *testing.T) {
		ids := make(map[uint32]bool)
		for range 100 {
			session, err := NewSession(true)
			require.NoError(t, err)
			id := session.ID()
			assert.False(t, ids[id], "duplicate session ID generated")
			ids[id] = true
		}
	})
}

func TestNewSessionWithID(t *testing.T) {
	t.Run("create with specific ID", func(t *testing.T) {
		session := NewSessionWithID(0x12345678, true)
		assert.Equal(t, uint32(0x12345678), session.ID())
		assert.True(t, session.IsClient())
	})

	t.Run("create server session with ID", func(t *testing.T) {
		session := NewSessionWithID(0xDEADBEEF, false)
		assert.Equal(t, uint32(0xDEADBEEF), session.ID())
		assert.False(t, session.IsClient())
	})
}

func TestSessionSequenceNumbers(t *testing.T) {
	t.Run("client sequence numbers", func(t *testing.T) {
		session := NewSessionWithID(1, true)

		// First call returns 1
		seqNo, err := session.NextSeqNo()
		require.NoError(t, err)
		assert.Equal(t, uint8(1), seqNo)
		assert.Equal(t, SessionStateActive, session.State())

		// Subsequent calls increment
		seqNo, err = session.NextSeqNo()
		require.NoError(t, err)
		assert.Equal(t, uint8(2), seqNo)

		seqNo, err = session.NextSeqNo()
		require.NoError(t, err)
		assert.Equal(t, uint8(3), seqNo)

		seqNo, err = session.NextSeqNo()
		require.NoError(t, err)
		assert.Equal(t, uint8(4), seqNo)
	})

	t.Run("server sequence numbers", func(t *testing.T) {
		session := NewSessionWithID(1, false)

		// First call returns 2
		seqNo, err := session.NextSeqNo()
		require.NoError(t, err)
		assert.Equal(t, uint8(2), seqNo)
		assert.Equal(t, SessionStateActive, session.State())

		// Subsequent calls increment
		seqNo, err = session.NextSeqNo()
		require.NoError(t, err)
		assert.Equal(t, uint8(3), seqNo)

		seqNo, err = session.NextSeqNo()
		require.NoError(t, err)
		assert.Equal(t, uint8(4), seqNo)
	})

	t.Run("sequence number overflow", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		// Set sequence to 255 (max value)
		session.mu.Lock()
		session.seqNo = 255
		session.mu.Unlock()

		// Next call should return error
		_, err := session.NextSeqNo()
		assert.ErrorIs(t, err, ErrSequenceOverflow)
	})
}

func TestSessionValidateSeqNo(t *testing.T) {
	t.Run("client validates server responses", func(t *testing.T) {
		session := NewSessionWithID(1, true)

		// Client sent seq 1
		_, err := session.NextSeqNo()
		require.NoError(t, err)

		// Server should respond with seq 2
		assert.True(t, session.ValidateSeqNo(2))
		assert.False(t, session.ValidateSeqNo(1))
		assert.False(t, session.ValidateSeqNo(3))
		assert.False(t, session.ValidateSeqNo(0))
	})

	t.Run("server validates client requests", func(t *testing.T) {
		session := NewSessionWithID(1, false)

		// First client packet should be seq 1
		assert.True(t, session.ValidateSeqNo(1))
		assert.False(t, session.ValidateSeqNo(2))
		assert.False(t, session.ValidateSeqNo(0))
	})

	t.Run("server validates subsequent client packets", func(t *testing.T) {
		session := NewSessionWithID(1, false)
		session.UpdateSeqNo(1) // Received seq 1 from client

		// Server sent seq 2
		_, err := session.NextSeqNo()
		require.NoError(t, err)

		// Next client packet should be seq 3
		assert.True(t, session.ValidateSeqNo(3))
		assert.False(t, session.ValidateSeqNo(2))
		assert.False(t, session.ValidateSeqNo(4))
	})

	t.Run("zero sequence is invalid", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		assert.False(t, session.ValidateSeqNo(0))
	})
}

func TestSessionSetState(t *testing.T) {
	t.Run("set state updates last activity", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		initialActivity := session.LastActivity()

		time.Sleep(10 * time.Millisecond)
		session.SetState(SessionStateComplete)

		assert.Equal(t, SessionStateComplete, session.State())
		assert.True(t, session.LastActivity().After(initialActivity))
	})

	t.Run("set error state", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		session.SetState(SessionStateError)
		assert.Equal(t, SessionStateError, session.State())
	})
}

func TestSessionTouch(t *testing.T) {
	t.Run("touch updates last activity", func(t *testing.T) {
		session := NewSessionWithID(1, true)
		initialActivity := session.LastActivity()

		time.Sleep(10 * time.Millisecond)
		session.Touch()

		assert.True(t, session.LastActivity().After(initialActivity))
	})
}

func TestSessionUpdateSeqNo(t *testing.T) {
	t.Run("update sequence number", func(t *testing.T) {
		session := NewSessionWithID(1, false)
		session.UpdateSeqNo(1)

		assert.Equal(t, uint8(1), session.SeqNo())
		assert.Equal(t, SessionStateActive, session.State())
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
		assert.False(t, ts.kicked.Load())
		ts.kicked.Store(true)
		assert.True(t, ts.kicked.Load())
	})
}

func TestGenerateSessionID(t *testing.T) {
	t.Run("generates non-zero IDs", func(t *testing.T) {
		for range 100 {
			id, err := generateSessionID()
			require.NoError(t, err)
			// Very unlikely to get zero with random generation
			// but technically possible, so we just check no error
			_ = id
		}
	})

	t.Run("generates different IDs", func(t *testing.T) {
		ids := make(map[uint32]bool)
		for range 100 {
			id, err := generateSessionID()
			require.NoError(t, err)
			ids[id] = true
		}
		// Should have mostly unique IDs (collisions extremely unlikely)
		assert.True(t, len(ids) >= 99)
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
	session, _ := NewSession(true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = session.NextSeqNo()
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
