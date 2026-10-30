package sing

import (
	"sync"
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/InazumaV/V2bX/core"
	"github.com/deadloop/node-audit/adapters/v2bx/audit"
)

const testUUID = "00000000-0000-0000-0000-000000000101"

func auditTestCore(t *testing.T) (*Sing, *panel.NodeInfo) {
	t.Helper()
	cc := conf.NewSingConfig()
	cc.LogConfig.Disabled = true
	c, err := New(&conf.CoreConfig{SingConfig: cc})
	if err != nil {
		t.Fatal(err)
	}
	b := c.(*Sing)
	cfg := audit.NewConfig()
	cfg.Enabled = true
	cfg.SourceID = "sing-test"
	cfg.NodeIDs = []int64{13}
	cfg.SocketPath = t.TempDir() + "/missing.sock"
	cfg.CaptureMode = "authenticated"
	b.audit = audit.New(*cfg, b.resolveAuditUser)
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	info := &panel.NodeInfo{Type: "vmess", Common: &panel.CommonNode{ServerPort: 0}, VAllss: &panel.VAllssNode{Network: "tcp"}}
	for _, tag := range []string{"a|b", "a"} {
		opt := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}
		if err := b.AddNode(tag, info, opt); err != nil {
			t.Fatal(err)
		}
	}
	return b, info
}
func addAuditTestUser(t *testing.T, b *Sing, info *panel.NodeInfo, tag string, id int) {
	t.Helper()
	n, err := b.AddUsers(&core.AddUsersParams{Tag: tag, NodeInfo: info, Users: []panel.UserInfo{{Uuid: testUUID, Id: id}}})
	if err != nil || n != 1 {
		t.Fatalf("add: %d %v", n, err)
	}
}
func wantIdentity(t *testing.T, b *Sing, tag, user string, id int64) {
	t.Helper()
	got, ok := b.resolveAuditUser(auditUserKey(tag, user))
	if got != id || ok != (id > 0) {
		t.Fatalf("identity got (%d,%v) want %d", got, ok, id)
	}
}
func TestSingAuditRealAddDeleteAndInboundIsolation(t *testing.T) {
	b, info := auditTestCore(t)
	addAuditTestUser(t, b, info, "a|b", 101)
	addAuditTestUser(t, b, info, "a", 202)
	wantIdentity(t, b, "a|b", testUUID, 101)
	wantIdentity(t, b, "a", testUUID, 202)
	if err := b.DelUsers([]panel.UserInfo{{Uuid: testUUID, Id: 101}}, "a|b", info); err != nil {
		t.Fatal(err)
	}
	wantIdentity(t, b, "a|b", testUUID, 0)
	wantIdentity(t, b, "a", testUUID, 202)
	if err := b.DelNode("a"); err != nil {
		t.Fatal(err)
	}
	wantIdentity(t, b, "a", testUUID, 0)
}
func TestSingAuditRealPartialFailureInvalidatesAffectedOnly(t *testing.T) {
	b, info := auditTestCore(t)
	addAuditTestUser(t, b, info, "a", 202)
	info = &panel.NodeInfo{Type: "shadowsocks", Common: &panel.CommonNode{ServerPort: 0}, Shadowsocks: &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}}
	if err := b.AddNode("ss", info, &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions()}); err != nil {
		t.Fatal(err)
	}
	addAuditTestUser(t, b, info, "ss", 101)
	n, err := b.AddUsers(&core.AddUsersParams{Tag: "ss", NodeInfo: info, Users: []panel.UserInfo{{Uuid: testUUID, Id: 303}, {Uuid: "", Id: 404}}})
	if err == nil || n != 0 {
		t.Fatalf("expected real Shadowsocks partial failure, got %d %v", n, err)
	}
	wantIdentity(t, b, "ss", testUUID, 0)
	wantIdentity(t, b, "ss", "", 0)
	wantIdentity(t, b, "a", testUUID, 202)
	// Billing remains upstream's UUID-only map; audit must not consult it.
	if b.users.uidMap[testUUID] != 303 {
		t.Fatal("audit changed billing behavior")
	}
}
func TestSingAuditMissingInboundFailureAndNonpositiveIDs(t *testing.T) {
	b, info := auditTestCore(t)
	addAuditTestUser(t, b, info, "a", 202)
	b.users.mapLock.Lock()
	b.updateAuditUsersLocked("absent", []panel.UserInfo{{Uuid: testUUID, Id: 999}}, true)
	b.users.mapLock.Unlock()
	_, err := b.AddUsers(&core.AddUsersParams{Tag: "absent", NodeInfo: info, Users: []panel.UserInfo{{Uuid: testUUID, Id: 303}}})
	if err == nil {
		t.Fatal("missing inbound succeeded")
	}
	wantIdentity(t, b, "absent", testUUID, 0)
	if err = b.DelUsers([]panel.UserInfo{{Uuid: testUUID}}, "absent", info); err == nil {
		t.Fatal("missing delete succeeded")
	}
	b.users.mapLock.Lock()
	b.updateAuditUsersLocked("a", []panel.UserInfo{{Uuid: "negative", Id: -1}, {Uuid: "zero", Id: 0}, {Uuid: "ambiguous", Id: 7}, {Uuid: "ambiguous", Id: 8}}, true)
	b.users.mapLock.Unlock()
	for _, u := range []string{"negative", "zero", "ambiguous"} {
		wantIdentity(t, b, "a", u, 0)
	}
	wantIdentity(t, b, "a", testUUID, 202)
	if auditUserKey("a|b", "c") == auditUserKey("a", "b|c") {
		t.Fatal("composite key collision")
	}
}
func TestSingAuditSnapshotsConcurrentReaders(t *testing.T) {
	b := &Sing{users: &UserMap{uidMap: make(map[string]int)}}
	b.audit = audit.New(*audit.NewConfig(), b.resolveAuditUser)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 1000; k++ {
				b.resolveAuditUser(auditUserKey("a", testUUID))
			}
		}()
	}
	for k := 0; k < 100; k++ {
		b.users.mapLock.Lock()
		b.updateAuditUsersLocked("a", []panel.UserInfo{{Uuid: testUUID, Id: k + 1}}, true)
		b.users.mapLock.Unlock()
	}
	wg.Wait()
	wantIdentity(t, b, "a", testUUID, 100)
}
