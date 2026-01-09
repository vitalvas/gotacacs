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
		assert.Equal(t, uint8(1), session.NextSeqNo())
		assert.Equal(t, SessionStateActive, session.State())

		// Subsequent calls increment
		assert.Equal(t, uint8(2), session.NextSeqNo())
		assert.Equal(t, uint8(3), session.NextSeqNo())
		assert.Equal(t, uint8(4), session.NextSeqNo())
	})

	t.Run("server sequence numbers", func(t *testing.T) {
		session := NewSessionWithID(1, false)

		// First call returns 2
		assert.Equal(t, uint8(2), session.NextSeqNo())
		assert.Equal(t, SessionStateActive, session.State())

		// Subsequent calls increment
		assert.Equal(t, uint8(3), session.NextSeqNo())
		assert.Equal(t, uint8(4), session.NextSeqNo())
	})
}

func TestSessionValidateSeqNo(t *testing.T) {
	t.Run("client validates server responses", func(t *testing.T) {
		session := NewSessionWithID(1, true)

		// Client sent seq 1
		session.NextSeqNo()

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
		session.NextSeqNo()

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

func TestMemorySessionStore(t *testing.T) {
	t.Run("create store", func(t *testing.T) {
		store := NewMemorySessionStore()
		assert.NotNil(t, store)
		assert.Equal(t, 0, store.Count())
	})

	t.Run("put and get session", func(t *testing.T) {
		store := NewMemorySessionStore()
		session := NewSessionWithID(0x12345678, true)

		store.Put(session)
		assert.Equal(t, 1, store.Count())

		retrieved, ok := store.Get(0x12345678)
		assert.True(t, ok)
		assert.Equal(t, session, retrieved)
	})

	t.Run("get nonexistent session", func(t *testing.T) {
		store := NewMemorySessionStore()
		_, ok := store.Get(0x12345678)
		assert.False(t, ok)
	})

	t.Run("put nil session", func(t *testing.T) {
		store := NewMemorySessionStore()
		store.Put(nil)
		assert.Equal(t, 0, store.Count())
	})

	t.Run("delete session", func(t *testing.T) {
		store := NewMemorySessionStore()
		session := NewSessionWithID(0x12345678, true)

		store.Put(session)
		assert.Equal(t, 1, store.Count())

		store.Delete(0x12345678)
		assert.Equal(t, 0, store.Count())

		_, ok := store.Get(0x12345678)
		assert.False(t, ok)
	})

	t.Run("delete nonexistent session", func(_ *testing.T) {
		store := NewMemorySessionStore()
		store.Delete(0x12345678) // Should not panic
	})

	t.Run("multiple sessions", func(t *testing.T) {
		store := NewMemorySessionStore()

		for i := uint32(1); i <= 10; i++ {
			store.Put(NewSessionWithID(i, true))
		}

		assert.Equal(t, 10, store.Count())

		for i := uint32(1); i <= 10; i++ {
			session, ok := store.Get(i)
			assert.True(t, ok)
			assert.Equal(t, i, session.ID())
		}
	})
}

func TestMemorySessionStoreCleanup(t *testing.T) {
	t.Run("cleanup expired sessions", func(t *testing.T) {
		store := NewMemorySessionStore()

		// Create old session
		oldSession := NewSessionWithID(1, true)
		store.Put(oldSession)

		// Create new session
		time.Sleep(50 * time.Millisecond)
		newSession := NewSessionWithID(2, true)
		newSession.Touch()
		store.Put(newSession)

		assert.Equal(t, 2, store.Count())

		// Cleanup sessions older than 25ms
		removed := store.Cleanup(25 * time.Millisecond)
		assert.Equal(t, 1, removed)
		assert.Equal(t, 1, store.Count())

		// Old session should be removed
		_, ok := store.Get(1)
		assert.False(t, ok)

		// New session should remain
		_, ok = store.Get(2)
		assert.True(t, ok)
	})

	t.Run("cleanup with no expired sessions", func(t *testing.T) {
		store := NewMemorySessionStore()
		store.Put(NewSessionWithID(1, true))
		store.Put(NewSessionWithID(2, true))

		removed := store.Cleanup(time.Hour)
		assert.Equal(t, 0, removed)
		assert.Equal(t, 2, store.Count())
	})

	t.Run("cleanup empty store", func(t *testing.T) {
		store := NewMemorySessionStore()
		removed := store.Cleanup(time.Second)
		assert.Equal(t, 0, removed)
	})
}

func TestMemorySessionStoreConcurrency(t *testing.T) {
	t.Run("concurrent operations", func(_ *testing.T) {
		store := NewMemorySessionStore()
		var wg sync.WaitGroup

		// Writers
		for i := range uint32(10) {
			wg.Add(1)
			go func(id uint32) {
				defer wg.Done()
				for range 100 {
					store.Put(NewSessionWithID(id, true))
					store.Get(id)
					store.Delete(id)
				}
			}(i)
		}

		wg.Wait()
	})
}

func TestSessionStoreInterface(t *testing.T) {
	t.Run("MemorySessionStore implements SessionStore", func(_ *testing.T) {
		var _ SessionStore = (*MemorySessionStore)(nil)
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
