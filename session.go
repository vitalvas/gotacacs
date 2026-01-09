package gotacacs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// SessionState represents the current state of a TACACS+ session.
type SessionState uint8

const (
	// SessionStateNew indicates a newly created session.
	SessionStateNew SessionState = iota

	// SessionStateActive indicates an active session with ongoing communication.
	SessionStateActive

	// SessionStateComplete indicates a successfully completed session.
	SessionStateComplete

	// SessionStateError indicates a session that ended with an error.
	SessionStateError
)

// String returns a string representation of the session state.
func (s SessionState) String() string {
	switch s {
	case SessionStateNew:
		return "NEW"
	case SessionStateActive:
		return "ACTIVE"
	case SessionStateComplete:
		return "COMPLETE"
	case SessionStateError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Session represents a TACACS+ session.
// A session is identified by a unique session ID and tracks the sequence of packets.
type Session struct {
	mu           sync.RWMutex
	id           uint32
	state        SessionState
	seqNo        uint8
	isClient     bool
	created      time.Time
	lastActivity time.Time
}

// NewSession creates a new session with a randomly generated session ID.
// If isClient is true, the session is for a client (odd sequence numbers).
// If isClient is false, the session is for a server (even sequence numbers).
func NewSession(isClient bool) (*Session, error) {
	id, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	return NewSessionWithID(id, isClient), nil
}

// NewSessionWithID creates a new session with the specified session ID.
func NewSessionWithID(id uint32, isClient bool) *Session {
	now := time.Now()
	return &Session{
		id:           id,
		state:        SessionStateNew,
		seqNo:        0,
		isClient:     isClient,
		created:      now,
		lastActivity: now,
	}
}

// ID returns the session ID.
func (s *Session) ID() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.id
}

// State returns the current session state.
func (s *Session) State() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// SetState sets the session state.
func (s *Session) SetState(state SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	s.lastActivity = time.Now()
}

// SeqNo returns the current sequence number.
func (s *Session) SeqNo() uint8 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seqNo
}

// NextSeqNo returns the next sequence number and increments the internal counter.
// For clients: 1, 3, 5, ... (odd numbers)
// For servers: 2, 4, 6, ... (even numbers)
// Returns ErrSequenceOverflow if the sequence number would wrap around.
func (s *Session) NextSeqNo() (uint8, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.seqNo == 0 {
		// First packet
		if s.isClient {
			s.seqNo = 1
		} else {
			s.seqNo = 2
		}
	} else {
		// Check for overflow before incrementing
		if s.seqNo == 255 {
			return 0, ErrSequenceOverflow
		}
		// Subsequent packets increment by 1 for each side
		s.seqNo++
	}

	s.lastActivity = time.Now()

	if s.state == SessionStateNew {
		s.state = SessionStateActive
	}

	return s.seqNo, nil
}

// ValidateSeqNo validates an incoming sequence number.
// Returns true if the sequence number is valid for the current session state.
func (s *Session) ValidateSeqNo(seqNo uint8) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if seqNo == 0 {
		return false
	}

	// For incoming packets, we expect the opposite parity
	if s.isClient {
		// Client expects even sequence numbers from server
		return seqNo%2 == 0 && seqNo == s.seqNo+1
	}
	// Server expects odd sequence numbers from client
	if s.seqNo == 0 {
		// First packet should be seq 1
		return seqNo == 1
	}
	return seqNo%2 == 1 && seqNo == s.seqNo+1
}

// Created returns the time when the session was created.
func (s *Session) Created() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.created
}

// LastActivity returns the time of the last activity on this session.
func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

// IsClient returns true if this is a client session.
func (s *Session) IsClient() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isClient
}

// Touch updates the last activity time.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()
}

// UpdateSeqNo updates the sequence number after receiving a packet.
func (s *Session) UpdateSeqNo(seqNo uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seqNo = seqNo
	s.lastActivity = time.Now()
	if s.state == SessionStateNew {
		s.state = SessionStateActive
	}
}

// generateSessionID generates a cryptographically random session ID.
func generateSessionID() (uint32, error) {
	var buf [4]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

// SessionStore is the interface for session storage.
type SessionStore interface {
	// Get retrieves a session by ID.
	Get(id uint32) (*Session, bool)

	// Put stores a session.
	Put(session *Session)

	// Delete removes a session by ID.
	Delete(id uint32)

	// Cleanup removes expired sessions older than the given duration.
	Cleanup(maxAge time.Duration) int
}

// MemorySessionStore is an in-memory implementation of SessionStore.
type MemorySessionStore struct {
	sessions sync.Map
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{}
}

// Get retrieves a session by ID.
func (s *MemorySessionStore) Get(id uint32) (*Session, bool) {
	value, ok := s.sessions.Load(id)
	if !ok {
		return nil, false
	}
	session, ok := value.(*Session)
	return session, ok
}

// Put stores a session.
func (s *MemorySessionStore) Put(session *Session) {
	if session != nil {
		s.sessions.Store(session.ID(), session)
	}
}

// Delete removes a session by ID.
func (s *MemorySessionStore) Delete(id uint32) {
	s.sessions.Delete(id)
}

// Cleanup removes expired sessions older than the given duration.
// Returns the number of sessions removed.
func (s *MemorySessionStore) Cleanup(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	s.sessions.Range(func(key, value any) bool {
		session, ok := value.(*Session)
		if ok && session.LastActivity().Before(cutoff) {
			s.sessions.Delete(key)
			removed++
		}
		return true
	})

	return removed
}

// Count returns the number of sessions in the store.
func (s *MemorySessionStore) Count() int {
	count := 0
	s.sessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
