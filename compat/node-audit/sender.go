package audit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

// unixgramSender writes one frame per datagram to the agent's socket.
//
// unixgram (not a FIFO) is used deliberately: with no reader present the send
// fails immediately rather than blocking the emitter, and a datagram boundary
// keeps frames independent so a partial write cannot corrupt the stream.
//
// The sender is reconnect-capable. A UNIX datagram peer identified by path is not
// a durable connection: when the agent restarts it unlinks and re-creates the
// socket, and a connected datagram socket keeps pointing at the old inode. A
// sender that only dials once therefore stops delivering forever after the first
// agent restart, which is exactly the outage this type exists to survive.
type unixgramSender struct {
	path    string
	timeout time.Duration

	mu   sync.Mutex
	conn *net.UnixConn

	// Reconnect policy. Bounded and non-blocking for callers: the emitter's
	// sender goroutine is the only user, so a short dial attempt here delays at
	// most the audit stream, never a proxy request.
	minBackoff time.Duration
	maxBackoff time.Duration

	nextAttempt time.Time
	backoff     time.Duration

	dials    uint64
	failures uint64
}

func newUnixgramSender(path string, timeout time.Duration) (*unixgramSender, error) {
	s := &unixgramSender{
		path:       path,
		timeout:    timeout,
		minBackoff: 100 * time.Millisecond,
		maxBackoff: 2 * time.Second,
		backoff:    100 * time.Millisecond,
	}
	conn, err := dialUnixgram(path)
	if err != nil {
		return nil, err
	}
	s.conn = conn
	s.dials = 1
	return s, nil
}

// newUnixgramSenderLazy builds a sender without requiring the socket to exist
// yet. The emitter starts its worker either way, so events are consumed (and
// counted as send failures) instead of piling up in the queue waiting for a
// socket that may appear later.
func newUnixgramSenderLazy(path string, timeout time.Duration) *unixgramSender {
	return &unixgramSender{
		path:       path,
		timeout:    timeout,
		minBackoff: 100 * time.Millisecond,
		maxBackoff: 2 * time.Second,
		backoff:    100 * time.Millisecond,
	}
}

func dialUnixgram(path string) (*net.UnixConn, error) {
	raddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial audit socket: %w", err)
	}
	return conn, nil
}

// Send writes one frame. A per-call deadline means a wedged agent slows the
// sender goroutine at most by the configured timeout, and never the proxy.
//
// On failure the current connection is dropped so the next call re-dials. Reconnection
// is rate limited by an exponential backoff, so an agent that stays down costs a
// bounded number of dial attempts rather than one per event.
func (s *unixgramSender) Send(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		if time.Now().Before(s.nextAttempt) {
			return errNotConnected
		}
		conn, err := dialUnixgram(s.path)
		if err != nil {
			s.noteFailureLocked()
			return err
		}
		s.conn = conn
		s.dials++
		s.backoff = s.minBackoff
	}

	if err := s.conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		s.dropConnLocked()
		s.noteFailureLocked()
		return err
	}
	if _, err := s.conn.Write(frame); err != nil {
		// A connected UNIX datagram socket keeps targeting the old inode after
		// the peer re-binds; the only recovery is to discard it and re-dial.
		s.dropConnLocked()
		s.noteFailureLocked()
		return err
	}
	s.failures = 0
	return nil
}

func (s *unixgramSender) dropConnLocked() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

func (s *unixgramSender) noteFailureLocked() {
	s.failures++
	s.nextAttempt = time.Now().Add(s.backoff)
	s.backoff *= 2
	if s.backoff > s.maxBackoff {
		s.backoff = s.maxBackoff
	}
}

// Stats reports connect state for health surfacing.
func (s *unixgramSender) Stats() senderStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return senderStats{
		Connected:     s.conn != nil,
		Dials:         s.dials,
		Failures:      s.failures,
		BackoffMillis: s.backoff.Milliseconds(),
	}
}

type senderStats struct {
	Connected     bool
	Dials         uint64
	Failures      uint64
	BackoffMillis int64
}

func (s *unixgramSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// errNotConnected reports that the socket is currently unavailable and the
// reconnect backoff has not elapsed.
var errNotConnected = fmt.Errorf("audit socket not connected")

// newRunID mints a per-process backend run id. It is generated once at startup:
// flow ids derived from it are stable for the life of the process, and a restart
// deliberately starts a new sequence space.
func newRunID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A time-based fallback still yields a usable, unique-enough run id; it is
		// never used as a credential.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
