// Package controller implements the session controller.
package controller

import (
	"fmt"
	"sync"

	"dnscat2/pkg/protocol"
	"dnscat2/pkg/session"
)

var (
	MaxRetransmits = 20
)

// Controller manages sessions
type Controller struct {
	sessions       []*session.Session
	currentIndex   int
	mu             sync.Mutex
}

// Global controller instance
var globalController = &Controller{}

// AddSession adds a session to the controller
func AddSession(s *session.Session) {
	globalController.mu.Lock()
	defer globalController.mu.Unlock()
	globalController.sessions = append(globalController.sessions, s)
}

// OpenSessionCount returns the number of non-shutdown sessions
func OpenSessionCount() int {
	globalController.mu.Lock()
	defer globalController.mu.Unlock()

	count := 0
	for _, s := range globalController.sessions {
		if !s.IsShutdown() {
			count++
		}
	}
	return count
}

// getByID finds a session by ID
func getByID(sessionID uint16) *session.Session {
	for _, s := range globalController.sessions {
		if s.ID == sessionID {
			return s
		}
	}
	return nil
}

// getNextActive returns the next active session in round-robin fashion
func getNextActive() *session.Session {
	globalController.mu.Lock()
	defer globalController.mu.Unlock()

	if len(globalController.sessions) == 0 {
		return nil
	}

	startIndex := globalController.currentIndex

	for {
		globalController.currentIndex = (globalController.currentIndex + 1) % len(globalController.sessions)
		s := globalController.sessions[globalController.currentIndex]

		if !s.IsShutdown() {
			return s
		}

		if globalController.currentIndex == startIndex {
			break
		}
	}

	return nil
}

// DataIncoming processes incoming data
func DataIncoming(data []byte) bool {
	sessionID, err := protocol.PeekSessionID(data)
	if err != nil {
		fmt.Printf("Error peeking session ID: %v\n", err)
		return false
	}

	globalController.mu.Lock()
	s := getByID(sessionID)
	globalController.mu.Unlock()

	if s == nil {
		fmt.Printf("Tried to access a non-existent session: %d\n", sessionID)
		return false
	}

	return s.DataIncoming(data)
}

// GetOutgoing returns outgoing data from the next active session
// Returns: data, hasActiveSessions
// - nil, false: no active sessions
// - nil, true: has sessions but no data ready
// - data, true: has data to send
func GetOutgoing(maxLength int) ([]byte, bool) {
	s := getNextActive()

	if s == nil {
		return nil, false
	}

	return s.GetOutgoing(maxLength), true
}

// killIgnoredSessions kills sessions that haven't received responses
func killIgnoredSessions() {
	if MaxRetransmits < 0 {
		return
	}

	globalController.mu.Lock()
	defer globalController.mu.Unlock()

	for _, s := range globalController.sessions {
		if !s.IsShutdown() && s.MissedTransmissions > MaxRetransmits {
			fmt.Printf("The server hasn't returned a valid response in the last %d attempts.. closing session.\n",
				s.MissedTransmissions-1)
			s.Kill()
		}
	}
}

// KillAllSessions kills all sessions
func KillAllSessions() {
	globalController.mu.Lock()
	defer globalController.mu.Unlock()

	for _, s := range globalController.sessions {
		if !s.IsShutdown() {
			s.Kill()
		}
	}
}

// Heartbeat should be called periodically
func Heartbeat() {
	killIgnoredSessions()
}

// SetMaxRetransmits sets the max retransmit count
func SetMaxRetransmits(retransmits int) {
	MaxRetransmits = retransmits
}

// Destroy cleans up all sessions
func Destroy() {
	globalController.mu.Lock()
	defer globalController.mu.Unlock()

	for _, s := range globalController.sessions {
		if !s.IsShutdown() {
			s.Kill()
		}
		s.Destroy()
	}
	globalController.sessions = nil
}

