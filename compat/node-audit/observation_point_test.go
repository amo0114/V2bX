package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCoreObservationPoints(t *testing.T) {
	for _, point := range []string{"", "sing_router_pre_outbound"} {
		cfg := enabledConfig()
		cfg.CaptureMode = "authenticated"
		cfg.ObservationPoint = point
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		e := New(cfg, func(string) (int64, bool) { return 101, true })
		rec := &recordingSender{}
		e.SetSender(rec)
		e.ObserveAccept("private", "vless-133", "tcp", "example.org", "", 443)
		e.ObserveReject("private", "vless-133", "udp", "policy_rejected")
		if !rec.waitFrames(2, 2*time.Second) {
			t.Fatal("missing frames")
		}
		e.Close()
		want := point
		if want == "" {
			want = "xray_dispatcher_pre_dial"
		}
		for _, f := range rec.frames {
			var ev wireEvent
			if err := json.Unmarshal(f, &ev); err != nil {
				t.Fatal(err)
			}
			if ev.ObservationPoint != want {
				t.Fatal(ev.ObservationPoint)
			}
		}
	}
	cfg := enabledConfig()
	cfg.ObservationPoint = "fabricated"
	if cfg.Validate() == nil {
		t.Fatal("untrusted observation point accepted")
	}
}
