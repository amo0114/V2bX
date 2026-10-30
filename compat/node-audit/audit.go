// Package audit is the minimal non-blocking structured event outlet for the
// V2bX cores.
//
// Design rules enforced here, matching the implementation plan:
//
//   - The proxy hot path only builds a small fixed struct and performs a
//     non-blocking channel send. No HTTP, no fsync, no DNS, no SQL, no retry and
//     no wait of any kind happens on the request goroutine.
//   - A full queue drops the audit event and increments a counter. It never
//     blocks forwarding, and it never lies about having collected everything.
//   - The authenticated user label (Xray's `tag|uuid`) never leaves this
//     package: it is resolved to a numeric panel user id in-process, and only
//     that number is encoded.
//   - Capture is disabled by default and, when enabled, defaults to an
//     allowlist of user ids.
package audit

import (
	"encoding/json"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Config is the `Audit` block of a core's JSON configuration.
type Config struct {
	// ObservationPoint is set by the core adapter, never by untrusted metadata.
	// Empty preserves the historical Xray default.
	ObservationPoint string `json:"-"`
	Enabled          bool   `json:"enabled"`
	SourceID         string `json:"source_id"`
	// NodeIDs lists the backend nodes this process actually serves. An event
	// whose node is not listed is not emitted.
	NodeIDs []int64 `json:"node_ids"`
	// InboundNodeIDs is the explicit, versioned registration of inbound tag to
	// backend node id. It is never derived from digits in the tag: a wrong guess
	// would attribute traffic to the wrong node.
	InboundNodeIDs map[string]int64 `json:"inbound_node_ids"`
	SocketPath     string           `json:"socket_path"`
	// CaptureMode is "allowlist", "authenticated" or "off". Collection of all
	// authenticated, mapped users requires the explicit authenticated mode.
	// In allowlist mode an empty EmitAllowUserIDs still admits nobody.
	CaptureMode string `json:"capture_mode"`
	// EmitAllowUserIDs is the pilot allowlist. An empty list with
	// CaptureMode=allowlist emits nothing at all (see enqueue).
	EmitAllowUserIDs     []int64 `json:"emit_allow_user_ids"`
	QueueMaxEvents       int     `json:"queue_max_events"`
	QueueMaxBytes        int     `json:"queue_max_bytes"`
	MaxFrameBytes        int     `json:"max_frame_bytes"`
	SocketWriteTimeoutMS int     `json:"socket_write_timeout_ms"`
	CollectClientIP      bool    `json:"collect_client_ip"`
	CollectPayload       bool    `json:"collect_payload"`
}

// NewConfig returns defaults matching the documented fragment.
func NewConfig() *Config {
	return &Config{
		Enabled:              false,
		CaptureMode:          "allowlist",
		QueueMaxEvents:       1024,
		QueueMaxBytes:        2 << 20,
		MaxFrameBytes:        4096,
		SocketWriteTimeoutMS: 50,
		CollectClientIP:      false,
		CollectPayload:       false,
	}
}

type configError string

func (e configError) Error() string { return string(e) }
func errConfig(s string) error      { return configError(s) }

// Validate enforces the bounds the hot path depends on.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch c.ObservationPoint {
	case "", "xray_dispatcher_pre_dial", "sing_router_pre_outbound":
	default:
		return errConfig("unsupported audit observation point")
	}
	if c.SourceID == "" || len(c.SourceID) > 64 {
		return errConfig("audit.source_id must be 1..64 bytes")
	}
	if len(c.SocketPath) == 0 || c.SocketPath[0] != '/' {
		return errConfig("audit.socket_path must be absolute")
	}
	if len(c.NodeIDs) == 0 {
		return errConfig("audit.node_ids must not be empty when audit is enabled")
	}
	for _, id := range c.NodeIDs {
		if id <= 0 {
			return errConfig("audit.node_ids entries must be positive")
		}
	}
	switch c.CaptureMode {
	case "allowlist", "authenticated", "off":
	default:
		return errConfig(`audit.capture_mode must be "allowlist", "authenticated" or "off"`)
	}
	if c.QueueMaxEvents <= 0 || c.QueueMaxEvents > 8192 {
		return errConfig("audit.queue_max_events must be within 1..8192")
	}
	if c.QueueMaxBytes <= 0 || c.QueueMaxBytes > 16<<20 {
		return errConfig("audit.queue_max_bytes must be within 1..16MiB")
	}
	if c.MaxFrameBytes <= 0 || c.MaxFrameBytes > 4096 {
		return errConfig("audit.max_frame_bytes must be within 1..4096")
	}
	if c.SocketWriteTimeoutMS <= 0 || c.SocketWriteTimeoutMS > 1000 {
		return errConfig("audit.socket_write_timeout_ms must be within 1..1000")
	}
	if c.CollectPayload {
		return errConfig("audit.collect_payload must stay false: payload capture is out of scope")
	}
	if c.CollectClientIP {
		return errConfig("audit.collect_client_ip must stay false until the proxy chain is verified")
	}
	return nil
}

// Phase mirrors the wire enum without importing the shared module: the adapter
// must stay a thin, independently revertable patch.
type phase string

const (
	phaseProxyAccepted phase = "proxy_accepted"
	phaseProxyRejected phase = "proxy_rejected"
)

// observation is the internal event the hot path builds. It is a fixed struct
// with no slices or maps so a per-request allocation stays tiny.
type observation struct {
	occurredAtMS int64
	nodeID       int64
	userID       int64
	userKnown    bool
	phase        phase
	transport    string
	domain       string
	ip           string
	port         int32
	errorCode    string
	inboundTag   string
	runID        string
	flowSeq      uint64
	sourceID     string
	point        string
}

// sender transports one encoded frame. Implementations must honour the write
// deadline and must not retry: retry and persistence belong to the agent.
type sender interface {
	Send(frame []byte) error
	Close() error
}

// Emitter owns the bounded queue and the single sender goroutine.
type Emitter struct {
	cfg      Config
	ch       chan observation
	byteCap  int64
	bytesNow atomic.Int64
	runID    string

	emitted      atomic.Uint64
	droppedQueue atomic.Uint64
	droppedBytes atomic.Uint64
	sendErrors   atomic.Uint64
	sent         atomic.Uint64
	framesTooBig atomic.Uint64
	unmapped     atomic.Uint64
	notAllowed   atomic.Uint64
	notOurNode   atomic.Uint64
	// droppedClosed counts observations that arrived after Close. It is a
	// lifecycle gap, not a queue overflow, so it is counted separately.
	droppedClosed    atomic.Uint64
	droppedAbandoned atomic.Uint64
	// controlComplete starts true so ordinary periodic reports are not marked
	// incomplete; only the shutdown-timeout path clears it.
	controlComplete     atomic.Bool
	abandonedAtShutdown atomic.Uint64
	// shutdownWait bounds how long the reporter waits for the worker to drain.
	shutdownWait time.Duration

	flowSeq atomic.Uint64

	allow map[int64]struct{}
	nodes map[int64]struct{}

	// resolve maps an Xray user email to the panel user id. It is supplied by
	// the core wiring, which already maintains that map.
	resolve func(email string) (int64, bool)

	mu sync.Mutex
	// sendMu coordinates the final queue hand-off with worker shutdown.
	sendMu     sync.RWMutex
	workerUp   atomic.Bool
	reportDone chan struct{}
	writer     sender
	stopCh     chan struct{}
	done       chan struct{}
	started    bool
	closeOnce  sync.Once
}

// New builds an emitter. resolve may be nil, in which case every event is
// unmapped and nothing is attributed to a user.
func New(cfg Config, resolve func(string) (int64, bool)) *Emitter {
	if cfg.QueueMaxEvents <= 0 {
		cfg.QueueMaxEvents = 1024
	}
	if cfg.QueueMaxBytes <= 0 {
		cfg.QueueMaxBytes = 2 << 20
	}
	e := &Emitter{
		cfg:          cfg,
		ch:           make(chan observation, cfg.QueueMaxEvents),
		byteCap:      int64(cfg.QueueMaxBytes),
		stopCh:       make(chan struct{}),
		done:         make(chan struct{}),
		shutdownWait: time.Second,
		allow:        make(map[int64]struct{}, len(cfg.EmitAllowUserIDs)),
		nodes:        make(map[int64]struct{}, len(cfg.NodeIDs)),
		resolve:      resolve,
		runID:        newRunID(),
	}
	// Periodic reports describe a live process, so they are complete by default;
	// only the shutdown-timeout path marks a frame incomplete.
	e.controlComplete.Store(true)
	for _, id := range cfg.EmitAllowUserIDs {
		e.allow[id] = struct{}{}
	}
	for _, id := range cfg.NodeIDs {
		e.nodes[id] = struct{}{}
	}
	return e
}

// Start binds the socket and launches exactly one sender goroutine. A bind
// failure is returned to the caller, which decides whether to keep running:
// audit must never prevent the proxy from starting.
func (e *Emitter) Start() error {
	if !e.Enabled() {
		return nil
	}
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return nil
	}
	// Lazy sender: the worker starts regardless of whether the agent socket
	// exists yet. A missing socket used to abort Start before the goroutine
	// existed, while the dispatcher already held the emitter — the queue then
	// filled and dropped forever because nothing was left to drain it.
	e.writer = newUnixgramSenderLazy(e.cfg.SocketPath, time.Duration(e.cfg.SocketWriteTimeoutMS)*time.Millisecond)
	e.started = true
	e.workerUp.Store(true)
	e.mu.Unlock()
	e.reportDone = make(chan struct{})
	go e.run()
	go func() {
		defer close(e.reportDone)
		e.reportLoop()
	}()
	return nil
}

// workerAlive reports whether the sender goroutine is still consuming.
func (e *Emitter) workerAlive() bool { return e.workerUp.Load() }

// SetSender installs an alternative sender (tests only) and marks it started.
// controlInterval is how often the backend self-reports its loss counters.
// Deliberately slow: these are cumulative counters, and the frame must cost
// nothing measurable on the forwarding path.
const controlInterval = 30 * time.Second

// reportLoop periodically writes a control frame carrying the emitter counters.
//
// Without this, a full queue or a dead socket loses events *before* the agent
// ever sees them, so the centre cannot distinguish "collection is broken" from
// "the user was not active". The counters are cumulative, so a missed report
// merely delays visibility rather than losing information.
func (e *Emitter) reportLoop() {
	t := time.NewTicker(controlInterval)
	defer t.Stop()
	for {
		select {
		case <-e.done:
			// The worker has finished draining: this snapshot is the true final
			// state and is safe to publish.
			e.sendControl()
			return
		case <-e.stopCh:
			// The worker may still be draining. Wait, but keep the shutdown bounded.
			drained := false
			select {
			case <-e.done:
				drained = true
			case <-time.After(e.shutdownWait):
			}
			if !drained {
				// The shutdown deadline expired with events still queued. Reporting
				// this as the "final" count would understate what was actually sent,
				// so the snapshot is explicitly marked incomplete AND the abandoned
				// events are counted as a loss.
				//
				// The abandoned count is what was ACTUALLY removed, not the queue
				// length sampled beforehand: the worker drains the same channel, so a
				// pre-read length is not a loss figure.
				abandoned := e.flushAbandoned()
				e.sendControlMarked(false, abandoned)
				return
			}
			// Drained: this snapshot is the true final state.
			e.sendControl()
			return
		case <-t.C:
			e.sendControl()
		}
	}
}

// flushAbandoned counts the events left in the queue when shutdown timed out.
//
// Those events will never be sent, so they are a loss, not a deferral. Counting
// them keeps `emitted` reconcilable with `sent + dropped`.
func (e *Emitter) flushAbandoned() uint64 {
	var removed uint64
	for {
		select {
		case <-e.ch:
			e.bytesNow.Add(-512)
			removed++
			e.droppedAbandoned.Add(1)
		default:
			// Return the ACTUAL number removed. The previous version incremented
			// once in this branch, so clearing 3 events and clearing 0 both reported
			// a loss of 1.
			return removed
		}
	}
}

// sendControlMarked sends a control frame that declares whether the counters are a
// complete final state.
func (e *Emitter) sendControlMarked(complete bool, abandoned uint64) {
	e.controlComplete.Store(complete)
	e.abandonedAtShutdown.Store(abandoned)
	e.sendControl()
}

// sendControl encodes and sends one control frame. Failure is silent by design:
// a control frame must never affect forwarding, and the counters it carries are
// re-sent next tick.
func (e *Emitter) sendControl() {
	st := e.Snapshot()
	cf := controlFrame{
		SchemaVersion:       1,
		Kind:                "control",
		SourceID:            e.cfg.SourceID,
		BackendRunID:        st.RunID,
		ReportedAtMS:        time.Now().UnixMilli(),
		Emitted:             st.Emitted,
		Sent:                st.Sent,
		DroppedQueue:        st.DroppedQueue,
		DroppedBytes:        st.DroppedBytes,
		SendErrors:          st.SendErrors,
		FramesTooBig:        st.FramesTooBig,
		Unmapped:            st.Unmapped,
		NotAllowlisted:      st.NotAllowlisted,
		NotOurNode:          st.NotOurNode,
		DroppedClosed:       st.DroppedClosed,
		FinalComplete:       e.controlComplete.Load(),
		AbandonedAtShutdown: e.abandonedAtShutdown.Load(),
		QueueLen:            st.QueueLen,
		QueueBytes:          st.QueueBytes,
		SocketConnected:     st.SocketConnected,
		SocketDials:         st.SocketDials,
	}
	frame, err := json.Marshal(cf)
	if err != nil {
		return
	}
	e.mu.Lock()
	w := e.writer
	e.mu.Unlock()
	if w == nil {
		return
	}
	_ = w.Send(frame)
}

// controlFrame mirrors pkg/event.ControlFrame. The adapter keeps a local copy so
// patching V2bX never requires vendoring the audit module.
type controlFrame struct {
	SchemaVersion  int    `json:"schema_version"`
	Kind           string `json:"kind"`
	SourceID       string `json:"source_id"`
	BackendRunID   string `json:"backend_run_id"`
	ReportedAtMS   int64  `json:"reported_at_ms"`
	Emitted        uint64 `json:"emitted"`
	Sent           uint64 `json:"sent"`
	DroppedQueue   uint64 `json:"dropped_queue"`
	DroppedBytes   uint64 `json:"dropped_bytes"`
	SendErrors     uint64 `json:"send_errors"`
	FramesTooBig   uint64 `json:"frames_too_big"`
	Unmapped       uint64 `json:"unmapped"`
	NotAllowlisted uint64 `json:"not_allowlisted"`
	NotOurNode     uint64 `json:"not_our_node"`
	DroppedClosed  uint64 `json:"dropped_closed"`
	// FinalComplete reports whether this frame describes a fully drained shutdown.
	FinalComplete bool `json:"final_complete"`
	// AbandonedAtShutdown counts events discarded because the drain deadline
	// expired. Non-zero means the counters are NOT a complete final state.
	AbandonedAtShutdown uint64 `json:"abandoned_at_shutdown"`
	QueueLen            int    `json:"queue_len"`
	QueueBytes          int64  `json:"queue_bytes"`
	SocketConnected     bool   `json:"socket_connected"`
	SocketDials         uint64 `json:"socket_dials"`
}

// SetSender installs an alternative sender (tests) and makes sure the worker is
// running. Without starting run() here, injected senders would be recorded as
// "started" while nothing ever drained the queue.
func (e *Emitter) SetSender(s sender) {
	e.mu.Lock()
	e.writer = s
	alreadyStarted := e.started
	e.started = true
	e.mu.Unlock()
	if !alreadyStarted {
		e.workerUp.Store(true)
		go e.run()
	}
}

// Enabled reports whether the outlet is active.
func (e *Emitter) Enabled() bool {
	return e != nil && e.cfg.Enabled && (e.cfg.CaptureMode == "allowlist" || e.cfg.CaptureMode == "authenticated")
}

// nodeForTag resolves the inbound tag to a registered node id.
func (e *Emitter) nodeForTag(tag string) (int64, bool) {
	id, ok := e.cfg.InboundNodeIDs[tag]
	if !ok || id <= 0 {
		return 0, false
	}
	if _, ok := e.nodes[id]; !ok {
		return 0, false
	}
	return id, true
}

// ObserveAccept is called from the dispatcher once a request has been
// authenticated and a valid destination is known. It never blocks.
func (e *Emitter) ObserveAccept(email, inboundTag string, network, domain, ip string, port int32) {
	if !e.Enabled() {
		return
	}
	nodeID, ok := e.nodeForTag(inboundTag)
	if !ok {
		e.notOurNode.Add(1)
		return
	}
	obs := observation{
		occurredAtMS: time.Now().UnixMilli(),
		nodeID:       nodeID,
		phase:        phaseProxyAccepted,
		transport:    network,
		domain:       domain,
		ip:           ip,
		port:         port,
		inboundTag:   inboundTag,
		runID:        e.runID,
		flowSeq:      e.flowSeq.Add(1),
		sourceID:     e.cfg.SourceID,
		point:        e.cfg.ObservationPoint,
	}
	e.resolveUser(&obs, email)
	e.enqueue(obs)
}

// ObserveReject is called when an authenticated request is rejected by a policy
// check (rate/device limit). Unauthenticated rejects are not attributable to a
// user and are therefore only counted by the caller, never attributed here.
func (e *Emitter) ObserveReject(email, inboundTag, network, errorCode string) {
	if !e.Enabled() {
		return
	}
	nodeID, ok := e.nodeForTag(inboundTag)
	if !ok {
		e.notOurNode.Add(1)
		return
	}
	obs := observation{
		occurredAtMS: time.Now().UnixMilli(),
		nodeID:       nodeID,
		phase:        phaseProxyRejected,
		transport:    network,
		errorCode:    errorCode,
		inboundTag:   inboundTag,
		runID:        e.runID,
		flowSeq:      e.flowSeq.Add(1),
		sourceID:     e.cfg.SourceID,
		point:        e.cfg.ObservationPoint,
	}
	e.resolveUser(&obs, email)
	e.enqueue(obs)
}

// resolveUser turns the internal label into a panel user id. The capture policy
// is applied by enqueue. The label itself is discarded here and never stored.
func (e *Emitter) resolveUser(obs *observation, email string) {
	if email == "" || e.resolve == nil {
		e.unmapped.Add(1)
		return
	}
	uid, ok := e.resolve(email)
	if !ok || uid <= 0 {
		// Missing/deleted identities must not produce a destination event under
		// either capture policy; only the aggregate counter is retained.
		e.unmapped.Add(1)
		return
	}
	obs.userID = uid
	obs.userKnown = true
}

// enqueue performs the single non-blocking hand-off. Both byte and count limits
// apply; whichever is exhausted first drops the event and counts it.
//
// In allowlist mode the user must be explicitly listed. An EMPTY list admits
// nobody: "no pilot users configured" must never degrade into "collect every
// mapped user". Unattributable events are equally inadmissible, because they
// cannot be proven to belong to a listed user. Authenticated mode also rejects
// unknown identities, but does not require a per-user allowlist.
func (e *Emitter) enqueue(obs observation) {
	// A request may have loaded the emitter just before Close detached it. Once
	// the worker has stopped, enqueuing would leave events with no consumer, so
	// the terminal state is an explicit, counted drop.
	select {
	case <-e.stopCh:
		e.droppedClosed.Add(1)
		return
	default:
	}

	if !obs.userKnown || obs.userID <= 0 {
		e.notAllowed.Add(1)
		return
	}
	switch e.cfg.CaptureMode {
	case "authenticated":
	case "allowlist":
		if _, ok := e.allow[obs.userID]; !ok {
			e.notAllowed.Add(1)
			return
		}
	default:
		e.notAllowed.Add(1)
		return
	}

	// In-flight accounting uses a fixed per-item estimate: the hot path stays
	// allocation-free while still bounding total memory, because the encoded
	// frame size is capped by MaxFrameBytes.
	const perItemEstimate = 512
	if e.bytesNow.Add(perItemEstimate) > e.byteCap {
		e.bytesNow.Add(-perItemEstimate)
		e.droppedBytes.Add(1)
		return
	}
	// The worker may exit between the stopCh check above and this send. Holding
	// the send lock while checking the closed flag makes the hand-off and the
	// worker's exit mutually exclusive, so an event can never be left queued
	// without a consumer.
	e.sendMu.RLock()
	defer e.sendMu.RUnlock()
	if !e.workerAlive() {
		e.bytesNow.Add(-perItemEstimate)
		e.droppedClosed.Add(1)
		return
	}
	select {
	case e.ch <- obs:
		e.emitted.Add(1)
	default:
		e.bytesNow.Add(-perItemEstimate)
		e.droppedQueue.Add(1)
	}
}

// run is the single sender goroutine.
func (e *Emitter) run() {
	defer close(e.done)
	for {
		select {
		case obs := <-e.ch:
			e.bytesNow.Add(-512)
			e.sendOne(obs)
		case <-e.stopCh:
			// Close the door FIRST, under the exclusive side of sendMu, so every
			// enqueuer either completed before this point or will be counted as
			// dropped_closed. Only then is it safe to decide the queue is empty:
			// marking the worker dead after the drain left a window where an
			// enqueuer holding RLock could add an event with no consumer.
			e.sendMu.Lock()
			e.workerUp.Store(false)
			e.sendMu.Unlock()
			// Drain what is already queued, then return.
			for {
				select {
				case obs := <-e.ch:
					e.bytesNow.Add(-512)
					e.sendOne(obs)
				default:
					return
				}
			}
		}
	}
}

func (e *Emitter) sendOne(obs observation) {
	frame, err := encodeObservation(obs, e.cfg.MaxFrameBytes)
	if err != nil {
		e.framesTooBig.Add(1)
		return
	}
	e.mu.Lock()
	w := e.writer
	e.mu.Unlock()
	if w == nil {
		e.sendErrors.Add(1)
		return
	}
	if err := w.Send(frame); err != nil {
		// Never retry an old frame: the agent owns durability. A failed send is a
		// counted gap, not a stalled proxy.
		e.sendErrors.Add(1)
		return
	}
	e.sent.Add(1)
}

// Stats is the emitter health surface. These numbers are what the agent folds
// into source health; without them "no errors logged" would be mistaken for
// "nothing lost".
type Stats struct {
	RunID          string
	Emitted        uint64
	Sent           uint64
	DroppedQueue   uint64
	DroppedBytes   uint64
	SendErrors     uint64
	FramesTooBig   uint64
	Unmapped       uint64
	NotAllowlisted uint64
	NotOurNode     uint64
	DroppedClosed  uint64
	QueueLen       int
	QueueBytes     int64
	// SocketConnected reports whether a datagram peer is currently bound. False
	// means events are being counted as send errors while the sender retries.
	SocketConnected bool
	SocketDials     uint64
}

// Snapshot returns the current counters.
func (e *Emitter) Snapshot() Stats {
	if e == nil {
		return Stats{}
	}
	// Load the writer once so the snapshot cannot mix two senders.
	e.mu.Lock()
	writer := e.writer
	e.mu.Unlock()
	st := Stats{
		RunID:          e.runID,
		Emitted:        e.emitted.Load(),
		Sent:           e.sent.Load(),
		DroppedQueue:   e.droppedQueue.Load(),
		DroppedBytes:   e.droppedBytes.Load(),
		SendErrors:     e.sendErrors.Load(),
		FramesTooBig:   e.framesTooBig.Load(),
		Unmapped:       e.unmapped.Load(),
		NotAllowlisted: e.notAllowed.Load(),
		NotOurNode:     e.notOurNode.Load(),
		DroppedClosed:  e.droppedClosed.Load() + e.droppedAbandoned.Load(),
		QueueLen:       len(e.ch),
		QueueBytes:     e.bytesNow.Load(),
	}
	if ss, ok := writer.(*unixgramSender); ok {
		s := ss.Stats()
		st.SocketConnected = s.Connected
		st.SocketDials = s.Dials
	}
	return st
}

// Close stops the sender and releases the socket.
func (e *Emitter) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		started := e.started
		e.mu.Unlock()
		if !started {
			return
		}
		close(e.stopCh)
		// Wait for BOTH the sender worker and the control reporter before closing
		// the writer. Closing the socket while the reporter is mid-send was a
		// use-after-close window; the reporter also gets a final chance to publish
		// its counters.
		waitDone := func(deadline time.Duration) {
			done := make(chan struct{})
			go func() {
				select {
				case <-e.done:
				case <-time.After(deadline):
				}
				close(done)
			}()
			<-done
		}
		// The reporter's own wait must expire first, so it can publish its marked
		// final frame while the writer is still open.
		waitDone(e.shutdownWait + 100*time.Millisecond)
		if e.reportDone != nil {
			select {
			case <-e.reportDone:
			case <-time.After(e.shutdownWait + 200*time.Millisecond):
			}
		}
		e.mu.Lock()
		w := e.writer
		e.writer = nil
		e.mu.Unlock()
		if w != nil {
			_ = w.Close()
		}
	})
	return nil
}

// wireEvent is the encoded frame. Field names match the shared schema; the
// adapter keeps a local copy so patching V2bX never requires vendoring the audit
// module into the backend repository.
type wireEvent struct {
	SchemaVersion    int     `json:"schema_version"`
	EventID          string  `json:"event_id"`
	SourceID         string  `json:"source_id"`
	BackendRunID     string  `json:"backend_run_id"`
	SourceSequence   string  `json:"source_sequence"`
	FlowID           string  `json:"flow_id"`
	OccurredAtMS     int64   `json:"occurred_at_ms"`
	BackendNodeID    int64   `json:"backend_node_id"`
	EntryNodeID      *int64  `json:"entry_node_id"`
	EntryAttribution string  `json:"entry_attribution"`
	UserID           *int64  `json:"user_id"`
	IdentityStatus   string  `json:"identity_status"`
	Transport        string  `json:"transport"`
	RequestedDomain  *string `json:"requested_domain"`
	RequestedIP      *string `json:"requested_ip"`
	DestinationPort  *int    `json:"destination_port"`
	ResolvedTargetIP *string `json:"resolved_target_ip"`
	Phase            string  `json:"phase"`
	ObservationPoint string  `json:"observation_point"`
	ErrorCode        *string `json:"error_code"`
	UploadBytes      *int64  `json:"observed_upload_bytes"`
	DownloadBytes    *int64  `json:"observed_download_bytes"`
	DurationMS       *int64  `json:"duration_ms"`
}

// encodeObservation renders one frame. Field-level validation mirrors the
// agent's, so a value the agent would reject never reaches the wire.
func encodeObservation(obs observation, maxFrame int) ([]byte, error) {
	ev := wireEvent{
		SchemaVersion:    1,
		SourceID:         obs.sourceID,
		BackendRunID:     obs.runID,
		SourceSequence:   strconv.FormatUint(obs.flowSeq, 10),
		OccurredAtMS:     obs.occurredAtMS,
		BackendNodeID:    obs.nodeID,
		EntryAttribution: "unknown",
		Transport:        normalizeTransport(obs.transport),
		Phase:            string(obs.phase),
		ObservationPoint: obs.point,
	}
	if ev.ObservationPoint == "" {
		ev.ObservationPoint = observationPoint(obs.phase)
	}
	// The identity invariant is enforced here as well as on the agent: an
	// unverified identity is never encoded as a user.
	if obs.userKnown && obs.userID > 0 {
		uid := obs.userID
		ev.UserID = &uid
		ev.IdentityStatus = "authenticated"
	} else {
		ev.IdentityStatus = "unmapped"
	}
	// requested_domain / requested_ip: exactly one of the two, and only when the
	// value is a bare host or literal IP. A destination that is neither is
	// omitted rather than guessed.
	if d := cleanHost(obs.domain); d != "" {
		ev.RequestedDomain = &d
	} else if ip := cleanHost(obs.ip); ip != "" {
		ev.RequestedIP = &ip
	}
	if obs.port > 0 && obs.port <= 65535 {
		p := int(obs.port)
		ev.DestinationPort = &p
	}
	if obs.errorCode != "" {
		c := obs.errorCode
		ev.ErrorCode = &c
	}
	// A rejected phase with no destination is still meaningful; an accepted
	// phase without a destination is not, and is dropped as incomplete.
	if obs.phase == phaseProxyAccepted && ev.RequestedDomain == nil && ev.RequestedIP == nil {
		return nil, errConfig("accepted observation without a destination")
	}

	// Stable identity: run id + flow sequence + phase determines event_id, so a
	// replay is byte-identical and never recounted.
	ev.EventID = obs.runID + ":" + ev.SourceSequence + ":" + string(obs.phase)
	ev.FlowID = obs.runID + ":" + ev.SourceSequence

	frame, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	if len(frame) > maxFrame {
		return nil, errConfig("encoded frame exceeds max_frame_bytes")
	}
	return frame, nil
}

func normalizeTransport(network string) string {
	switch network {
	case "udp", "UDP":
		return "udp"
	default:
		return "tcp"
	}
}

func observationPoint(p phase) string {
	switch p {
	case phaseProxyAccepted, phaseProxyRejected:
		// This is the Xray dispatcher, after authentication and before the
		// outbound dial. It is NOT a dial result.
		return "xray_dispatcher_pre_dial"
	}
	return "unknown"
}

// cleanHost keeps only a bare hostname or IP literal; anything that looks like a
// URL, path, port suffix or credential is dropped instead of rewritten.
func cleanHost(h string) string {
	if h == "" || len(h) > 253 {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c <= ' ' || c == '/' || c == '?' || c == '#' || c == '@' || c == '\\' {
			return ""
		}
	}
	if h[0] == '[' {
		if h[len(h)-1] != ']' {
			return ""
		}
		return h[1 : len(h)-1]
	}
	return h
}
