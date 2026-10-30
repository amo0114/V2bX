package xray

import (
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/format"
	vCore "github.com/InazumaV/V2bX/core"
)

// TestC04FailedAddUsersDoesNotPublishIdentity is the regression for REVIEW-R3 C04.
//
// The earlier fix published on every return path, which was necessary — but the
// identity map was mutated BEFORE the operation could fail. A failed AddUsers
// therefore published identities that were never active, and an existing label
// could be re-pointed to a different panel user id.
//
// This calls the REAL AddUsers method. An unsupported node type fails after the
// point where the old code had already written the map, so it is exactly the
// reported reproduction.
func TestC04FailedAddUsersDoesNotPublishIdentity(t *testing.T) {
	x := &Xray{users: &UserMap{uidMap: make(map[string]int)}}
	enabledAuditConfig(t, x)

	label := format.UserTag("vless-133", "uuid-c04")

	// Establish an existing, working mapping.
	x.users.mapLock.Lock()
	x.users.uidMap[label] = 101
	snap := x.snapshotLocked()
	gen := x.nextAuditGen()
	x.users.mapLock.Unlock()
	x.publishAuditSnapshot(snap, gen)

	if id, ok := x.resolveAuditUser(label); !ok || id != 101 {
		t.Fatalf("setup: expected 101, got (%d, %v)", id, ok)
	}

	// A failing AddUsers that would have re-pointed the label to 202.
	p := &vCore.AddUsersParams{
		Tag: "vless-133",
		Users: []panel.UserInfo{
			{Uuid: "uuid-c04", Id: 202},
		},
		NodeInfo: &panel.NodeInfo{Type: "unsupported-type"},
	}
	added, err := x.AddUsers(p)
	if err == nil {
		t.Fatalf("AddUsers unexpectedly succeeded for an unsupported node type")
	}
	if added != 0 {
		t.Fatalf("reported %d users added on a failure path", added)
	}

	// The decisive assertion: the audit view must still report the ORIGINAL user.
	id, ok := x.resolveAuditUser(label)
	if !ok {
		t.Fatalf("existing identity disappeared after a failed AddUsers")
	}
	if id != 101 {
		t.Fatalf("failed AddUsers re-pointed an existing identity: got %d, want 101", id)
	}
}
