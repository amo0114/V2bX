package xray

import (
	"testing"

	"github.com/InazumaV/V2bX/conf"
	"github.com/deadloop/node-audit/adapters/v2bx/audit"
)

// enabledAuditConfig attaches a minimal enabled emitter so the snapshot paths
// run their real code instead of short-circuiting on a nil emitter.
func enabledAuditConfig(t *testing.T, x *Xray) *conf.AuditConfig {
	t.Helper()
	c := audit.NewConfig()
	c.Enabled = true
	c.SourceID = "test"
	c.NodeIDs = []int64{1}
	c.InboundNodeIDs = map[string]int64{"vless-133": 1}
	c.SocketPath = "/tmp/b01-test.sock"
	c.CaptureMode = "allowlist"
	c.EmitAllowUserIDs = []int64{101, 102}
	x.audit = audit.New(*c, x.resolveAuditUser)
	return &conf.AuditConfig{Enabled: true}
}
