package gotacacs

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
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
// The session ID is immutable after construction, so no lock is needed.
func (s *Session) ID() uint32 {
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

// NextSeqNo returns the next outgoing sequence number for this session side.
// Per RFC 8907, sequence numbers increment by 1 for each packet across both
// sides: client sends 1, server sends 2, client sends 3, etc.
// This method returns the next number for this side (odd for clients, even
// for servers) assuming UpdateSeqNo is called between sends with the peer's
// sequence number.
// Returns ErrSequenceOverflow if the sequence number would exceed 255.
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
// The creation time is immutable after construction, so no lock is needed.
func (s *Session) Created() time.Time {
	return s.created
}

// LastActivity returns the time of the last activity on this session.
func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

// IsClient returns true if this is a client session.
// The client flag is immutable after construction, so no lock is needed.
func (s *Session) IsClient() bool {
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

// SessionInfo contains metadata about an active session tracked by the server.
// TrackingID is unique server-wide; SessionID is the TACACS+ session ID from the
// NAS which may collide across connections.
type SessionInfo struct {
	// TrackingID is a unique monotonic identifier assigned by the server.
	TrackingID uint64
	// SessionID is the TACACS+ session ID from the client (NAS).
	SessionID uint32
	// RemoteAddr is the client address.
	RemoteAddr net.Addr
	// LocalAddr is the server address.
	LocalAddr net.Addr
	// UserData is custom metadata from the SecretProvider.
	UserData map[string]string
	// TLSState is the TLS connection state. Nil for non-TLS connections.
	TLSState *tls.ConnectionState
	// PacketType is the TACACS+ packet type (authen, author, acct).
	PacketType uint8
	// State is the current session state.
	State SessionState
	// StartedAt is when the session was created.
	StartedAt time.Time
}

// trackedSession is the internal representation of a tracked session.
type trackedSession struct {
	info   SessionInfo
	state  atomic.Uint32
	kicked atomic.Bool
}
