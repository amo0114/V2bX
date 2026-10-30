package audit

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// recordingSender captures frames instead of writing them to a socket.
type recordingSender struct {
	frames     [][]byte
	frameCount atomic.Int64
}

func (r *recordingSender) Send(frame []byte) error {
	r.frameCount.Add(1)
	r.frames = append(r.frames, append([]byte(nil), frame...))
	return nil
}

func (r *recordingSender) Close() error { return nil }

// waitFrames blocks until at least n frames were handed to the sender. Sending is
// asynchronous by design (a worker goroutine), so assertions must wait rather
// than sample immediately after Observe*.
func (r *recordingSender) waitFrames(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if int(r.frameCount.Load()) >= n {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return int(r.frameCount.Load()) >= n
}

func enabledConfig() Config {
	c := NewConfig()
	c.Enabled = true
	c.SourceID = "test-source"
	c.NodeIDs = []int64{133}
	c.InboundNodeIDs = map[string]int64{"vless-133": 133}
	c.SocketPath = "/tmp/does-not-matter.sock"
	c.CaptureMode = "allowlist"
	return *c
}

// TestR01EmptyAllowlistAdmitsNobody is the regression for REVIEW R01.
//
// The pilot boundary is "only these user ids". An empty list previously skipped
// the filter entirely, so every mapped user was collected. It must now mean
// "collect nobody".
func TestR01EmptyAllowlistAdmitsNobody(t *testing.T) {
	cfg := enabledConfig()
	cfg.EmitAllowUserIDs = nil // empty allowlist

	e := New(cfg, func(string) (int64, bool) { return 101, true })
	rec := &recordingSender{}
	e.SetSender(rec)

	e.ObserveAccept("vless-133|synthetic-uuid", "vless-133", "tcp", "example.org", "", 443)

	time.Sleep(50 * time.Millisecond) // give any (wrong) worker a chance to send
	st := e.Snapshot()
	if st.Emitted != 0 || rec.frameCount.Load() != 0 {
		t.Fatalf("empty allowlist admitted events: emitted=%d frames=%d", st.Emitted, len(rec.frames))
	}
	if st.NotAllowlisted != 1 {
		t.Fatalf("expected the event to be counted as not-allowlisted, got %d", st.NotAllowlisted)
	}
}

// TestR01AllowlistFiltersByUser verifies both the admit and the deny side, so the
// fix cannot regress into "deny everything".
func TestR01AllowlistFiltersByUser(t *testing.T) {
	cfg := enabledConfig()
	cfg.EmitAllowUserIDs = []int64{101}

	e := New(cfg, func(email string) (int64, bool) {
		switch email {
		case "vless-133|user-a":
			return 101, true
		case "vless-133|user-b":
			return 102, true
		}
		return 0, false
	})
	rec := &recordingSender{}
	e.SetSender(rec)

	e.ObserveAccept("vless-133|user-a", "vless-133", "tcp", "a.example.org", "", 443)
	e.ObserveAccept("vless-133|user-b", "vless-133", "tcp", "b.example.org", "", 443)
	// An unmapped identity must never slip through an active allowlist.
	e.ObserveAccept("vless-133|unknown", "vless-133", "tcp", "c.example.org", "", 443)

	if !rec.waitFrames(1, 2*time.Second) {
		t.Fatalf("the allowed event was never delivered to the sender")
	}
	st := e.Snapshot()
	if st.Emitted != 1 || rec.frameCount.Load() != 1 {
		t.Fatalf("allowlist admitted %d events, want 1 (delivered=%d)", st.Emitted, rec.frameCount.Load())
	}
	if st.NotAllowlisted != 2 {
		t.Fatalf("expected 2 refusals (other user + unmapped), got %d", st.NotAllowlisted)
	}
}

// TestR03SenderReconnectsAfterPeerRestart is the regression for REVIEW R03.
//
// A connected UNIX datagram socket keeps targeting the old inode after the peer
// unlinks and re-binds. The sender must re-dial instead of writing forever into a
// dead socket.
func TestR03SenderReconnectsAfterPeerRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.sock")

	recv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s, err := newUnixgramSender(path, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("new sender: %v", err)
	}
	defer s.Close()

	if err := s.Send([]byte("first")); err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Simulate an agent restart: close the receiver and re-create the socket at
	// the same path. The old connection now targets a stale inode.
	recv.Close()
	_ = os.Remove(path)

	// Until the peer is back, sends fail (and must not panic or block forever).
	if err := s.Send([]byte("while-down")); err == nil {
		t.Fatalf("send unexpectedly succeeded with no receiver")
	}

	recv2, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("re-listen: %v", err)
	}
	defer recv2.Close()
	recv2.SetReadDeadline(time.Now().Add(3 * time.Second))

	// The sender rate-limits reconnects, so allow a few attempts.
	var sent bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := s.Send([]byte("after-restart")); err == nil {
			sent = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sent {
		t.Fatalf("sender never recovered after the peer re-bound the socket")
	}

	buf := make([]byte, 64)
	n, _, err := recv2.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("new receiver got nothing: %v", err)
	}
	if got := string(buf[:n]); got != "after-restart" {
		t.Fatalf("new receiver got %q, want %q", got, "after-restart")
	}

	st := s.Stats()
	if st.Dials < 2 {
		t.Fatalf("expected at least 2 dials (initial + reconnect), got %d", st.Dials)
	}
}

// TestR03StartWithoutSocketKeepsWorker confirms the emitter still drains its
// queue when the socket does not exist at Start time. Events are counted as send
// errors rather than silently filling the channel forever.
func TestR03StartWithoutSocketKeepsWorker(t *testing.T) {
	cfg := enabledConfig()
	cfg.EmitAllowUserIDs = []int64{101}
	cfg.SocketPath = filepath.Join(t.TempDir(), "absent.sock")

	e := New(cfg, func(string) (int64, bool) { return 101, true })
	if err := e.Start(); err != nil {
		t.Fatalf("Start must not fail when the socket is absent: %v", err)
	}
	defer e.Close()

	for i := 0; i < 5; i++ {
		e.ObserveAccept("vless-133|u", "vless-133", "tcp", fmt.Sprintf("d%d.example.org", i), "", 443)
	}
	// The worker must consume the queue even with no peer available.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.Snapshot().QueueLen == 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	st := e.Snapshot()
	if st.SocketConnected {
		t.Fatalf("sender reports connected with no peer")
	}
	if st.SendErrors == 0 {
		t.Fatalf("expected send errors to be counted while the socket is absent")
	}
}

// TestR08AcceptedOnlyAfterPolicy documents the intended stage ordering at the
// adapter level: rejected must not also produce an accepted observation for the
// same request. The dispatcher guarantees the ordering; here we assert the two
// stages stay distinct and separately counted.
func TestR08RejectIsNotAlsoAccepted(t *testing.T) {
	cfg := enabledConfig()
	cfg.EmitAllowUserIDs = []int64{101}
	e := New(cfg, func(string) (int64, bool) { return 101, true })
	rec := &recordingSender{}
	e.SetSender(rec)

	e.ObserveReject("vless-133|u", "vless-133", "tcp", "policy_rejected")

	if !rec.waitFrames(1, 2*time.Second) {
		t.Fatalf("rejection was never delivered to the sender")
	}
	time.Sleep(100 * time.Millisecond) // catch an unwanted second frame
	st := e.Snapshot()
	if st.Emitted != 1 {
		t.Fatalf("expected exactly one observation, got %d", st.Emitted)
	}
	if rec.frameCount.Load() != 1 {
		t.Fatalf("expected one frame, got %d", rec.frameCount.Load())
	}
	if !contains(string(rec.frames[0]), `"phase":"proxy_rejected"`) {
		t.Fatalf("frame is not a proxy_rejected stage: %s", rec.frames[0])
	}
	if contains(string(rec.frames[0]), "proxy_accepted") {
		t.Fatalf("rejected request also carried an accepted stage")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// TestB10ClosedEmitterDropIsCounted is the regression for REVIEW-R2 B10.
//
// A request can load the emitter and then be delayed past Close. Enqueuing after
// the worker exited left events with no consumer. The terminal state must be an
// explicit, counted drop.
func TestB10ClosedEmitterDropIsCounted(t *testing.T) {
	cfg := enabledConfig()
	cfg.EmitAllowUserIDs = []int64{101}
	e := New(cfg, func(string) (int64, bool) { return 101, true })
	rec := &recordingSender{}
	e.SetSender(rec)

	// Close detaches the worker.
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A late observation must not enqueue.
	e.ObserveAccept("vless-133|u", "vless-133", "tcp", "late.example.org", "", 443)

	st := e.Snapshot()
	if st.DroppedClosed == 0 {
		t.Fatalf("observation after Close was not counted as dropped_closed")
	}
	if st.Emitted != 0 {
		t.Fatalf("observation after Close was admitted (emitted=%d)", st.Emitted)
	}
	if st.QueueLen != 0 {
		t.Fatalf("event was left in the queue with no consumer (len=%d)", st.QueueLen)
	}
}

// TestB05EmitterReportsControlFrame proves the backend actually publishes its
// loss counters. Without a control frame the centre cannot distinguish a broken
// emitter from an idle user.
func TestB05EmitterReportsControlFrame(t *testing.T) {
	cfg := enabledConfig()
	cfg.EmitAllowUserIDs = []int64{101}
	e := New(cfg, func(string) (int64, bool) { return 101, true })
	rec := &recordingSender{}
	e.SetSender(rec)

	// Force a counted loss so the report has something distinct to carry.
	e.droppedQueue.Add(3)
	e.sendControl()

	if !rec.waitFrames(1, 2*time.Second) {
		t.Fatalf("no control frame was sent")
	}
	frame := string(rec.frames[0])
	if !contains(frame, `"kind":"control"`) {
		t.Fatalf("frame is not a control frame: %s", frame)
	}
	if !contains(frame, `"dropped_queue":3`) {
		t.Fatalf("control frame does not carry the loss counters: %s", frame)
	}
	if !contains(frame, `"backend_run_id"`) {
		t.Fatalf("control frame lacks the backend run id")
	}
}

// TestD07CloseRejectsEnqueueBeforeFinalDrain is the regression for REVIEW-R4 D07.
//
// The terminal "no more enqueue" flag used to be set in the worker's defer, AFTER
// the final drain decided the queue was empty. An enqueuer that already held RLock
// could then add an event that no consumer would ever read. The flag must be set
// before the drain.
func TestD07CloseRejectsEnqueueBeforeFinalDrain(t *testing.T) {
	cfg := enabledConfig()
	cfg.EmitAllowUserIDs = []int64{101}
	e := New(cfg, func(string) (int64, bool) { return 101, true })
	rec := &recordingSender{}
	e.SetSender(rec)

	// Close and immediately attempt many enqueues; every attempt must be counted
	// as dropped_closed or genuinely consumed, never left queued.
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for i := 0; i < 50; i++ {
		e.ObserveAccept("vless-133|u", "vless-133", "tcp", "late.example.org", "", 443)
	}
	time.Sleep(200 * time.Millisecond)

	st := e.Snapshot()
	if st.QueueLen != 0 {
		t.Fatalf("%d events left queued with no consumer after Close", st.QueueLen)
	}
	if st.DroppedClosed == 0 {
		t.Fatalf("post-Close enqueues were not counted as dropped_closed")
	}
	if st.Emitted+st.DroppedClosed < 50 {
		t.Fatalf("accounting gap: emitted=%d dropped_closed=%d for 50 attempts",
			st.Emitted, st.DroppedClosed)
	}
}

// TestG02AbandonedCountIsExact is the regression for REVIEW-R7 G02.
//
// flushAbandoned incremented once in the default branch, so clearing 3 events and
// clearing 0 both reported a loss of 1.
func TestG02AbandonedCountIsExact(t *testing.T) {
	cfg := enabledConfig()
	cfg.EmitAllowUserIDs = []int64{101}
	e := New(cfg, func(string) (int64, bool) { return 101, true })
	// No worker started: the channel is ours to fill and drain deterministically.
	for i := 0; i < 3; i++ {
		e.ch <- observation{phase: phaseProxyAccepted, sourceID: "s"}
		e.bytesNow.Add(512)
	}
	if got := e.flushAbandoned(); got != 3 {
		t.Fatalf("flushAbandoned reported %d removed, want 3", got)
	}
	if got := e.Snapshot().DroppedClosed; got != 3 {
		t.Fatalf("dropped count is %d after clearing 3, want 3", got)
	}
	// An already-empty queue must add nothing.
	if got := e.flushAbandoned(); got != 0 {
		t.Fatalf("flushAbandoned on an empty queue reported %d", got)
	}
	if got := e.Snapshot().DroppedClosed; got != 3 {
		t.Fatalf("empty flush changed the dropped count to %d", got)
	}
}
