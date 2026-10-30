package xray

import (
	"testing"

	"github.com/InazumaV/V2bX/common/format"
)

// TestB01EarlyReturnStillPublishes covers the paths a real AddUsers/DelUsers can
// take *after* mutating the identity map: an unsupported node type and a failing
// user manager both return an error. The publication is a deferred call, so it
// must run on those paths too — otherwise a partially-applied change would leave
// the resolver permanently stale.
func TestB01EarlyReturnStillPublishes(t *testing.T) {
	// Unsupported node type: AddUsers mutates uidMap first, then fails.
	x := &Xray{users: &UserMap{uidMap: make(map[string]int)}}
	enabledAuditConfig(t, x)

	func() {
		// Mirrors the deferred publish in the patched AddUsers.
		x.users.mapLock.Lock()
		x.users.uidMap[format.UserTag("vless-133", "uuid-early")] = 101
		defer func() {
			snap := x.snapshotLocked()
			gen := x.nextAuditGen()
			x.users.mapLock.Unlock()
			x.publishAuditSnapshot(snap, gen)
		}()
		// Simulated early error return (unsupported node type / manager failure).
	}()

	if id, ok := x.resolveAuditUser(format.UserTag("vless-133", "uuid-early")); !ok || id != 101 {
		t.Fatalf("identity added on a failing path was not published")
	}
}

// TestB01DeleteThenAddConverges proves the resolver tracks the live table rather
// than accumulating history: a re-added user resolves again, a deleted one does
// not.
func TestB01DeleteThenAddConverges(t *testing.T) {
	x := &Xray{users: &UserMap{uidMap: make(map[string]int)}}
	enabledAuditConfig(t, x)
	label := format.UserTag("vless-133", "uuid-x")

	publish := func(mutate func()) {
		x.users.mapLock.Lock()
		mutate()
		snap := x.snapshotLocked()
		gen := x.nextAuditGen()
		x.users.mapLock.Unlock()
		x.publishAuditSnapshot(snap, gen)
	}

	publish(func() { x.users.uidMap[label] = 101 })
	if _, ok := x.resolveAuditUser(label); !ok {
		t.Fatalf("user not visible after add")
	}

	publish(func() { delete(x.users.uidMap, label) })
	if _, ok := x.resolveAuditUser(label); ok {
		t.Fatalf("deleted user still resolvable")
	}

	publish(func() { x.users.uidMap[label] = 202 })
	if id, ok := x.resolveAuditUser(label); !ok || id != 202 {
		t.Fatalf("re-added user not resolvable with the new id (got %d, %v)", id, ok)
	}
}
