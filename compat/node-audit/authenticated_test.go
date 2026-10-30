package audit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestAuthenticatedCaptureRequiresMappedPositiveIdentity(t *testing.T) {
	cfg := enabledConfig()
	cfg.CaptureMode = "authenticated"
	cfg.EmitAllowUserIDs = nil
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	e := New(cfg, func(label string) (int64, bool) {
		switch label {
		case "private-label-a":
			return 101, true
		case "private-label-b":
			return 102, true
		case "zero":
			return 0, true
		case "negative":
			return -1, true
		}
		return 0, false
	})
	rec := &recordingSender{}
	e.SetSender(rec)
	e.ObserveAccept("private-label-a", "vless-133", "tcp", "a.example.org", "", 443)
	e.ObserveAccept("private-label-b", "vless-133", "tcp", "b.example.org", "", 443)
	e.ObserveReject("private-label-b", "vless-133", "tcp", "policy_denied")
	for _, label := range []string{"", "unknown", "zero", "negative"} {
		e.ObserveAccept(label, "vless-133", "tcp", "must-not-emit.example.org", "", 443)
	}
	e.ObserveAccept("private-label-a", "wrong-node", "tcp", "wrong.example.org", "", 443)
	if !rec.waitFrames(3, 2*time.Second) {
		t.Fatal("mapped users were not emitted")
	}
	e.Close()
	st := e.Snapshot()
	if st.Emitted != 3 || st.NotAllowlisted != 4 || st.Unmapped != 4 || st.NotOurNode != 1 || st.QueueLen != 0 {
		t.Fatalf("unexpected counters: %+v", st)
	}
	ids := map[int64]int{}
	for _, frame := range rec.frames {
		if bytes.Contains(frame, []byte("private-label")) || bytes.Contains(frame, []byte("must-not-emit")) {
			t.Fatal("identity label or unmapped destination leaked")
		}
		var wire struct {
			UserID int64 `json:"user_id"`
		}
		if err := json.Unmarshal(frame, &wire); err != nil {
			t.Fatal(err)
		}
		ids[wire.UserID]++
	}
	if ids[101] != 1 || ids[102] != 2 || len(ids) != 2 {
		t.Fatal(ids)
	}
	// A missing resolver must never broaden collection.
	u := New(cfg, nil)
	r := &recordingSender{}
	u.SetSender(r)
	u.ObserveAccept("unknown", "vless-133", "tcp", "unknown.example.org", "", 443)
	u.Close()
	if u.Snapshot().Emitted != 0 || r.frameCount.Load() != 0 {
		t.Fatal("nil resolver admitted identity")
	}
}

func TestCaptureModesRemainExplicit(t *testing.T) {
	for _, mode := range []string{"allowlist", "authenticated", "off", "all", "", "typo"} {
		cfg := enabledConfig()
		cfg.CaptureMode = mode
		valid := mode == "allowlist" || mode == "authenticated" || mode == "off"
		if (cfg.Validate() == nil) != valid {
			t.Fatalf("mode %q validation", mode)
		}
		e := New(cfg, func(string) (int64, bool) { return 101, true })
		if e.Enabled() != (mode == "allowlist" || mode == "authenticated") {
			t.Fatalf("mode %q enabled", mode)
		}
	}
	if NewConfig().Enabled || NewConfig().CaptureMode != "allowlist" {
		t.Fatal("defaults broadened")
	}
}
