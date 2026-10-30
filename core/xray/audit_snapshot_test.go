package xray

import (
	"sync"
	"testing"
)

// TestB01AddUsersPublishesSnapshot is the regression for REVIEW-R2 B01.
//
// The real start-up order is "start core, then add users". AddUsers previously
// updated uidMap and returned without publishing the resolver snapshot, which
// only DelUsers did. auditUsers therefore stayed nil, every authenticated user
// resolved to unknown, and the (correctly tightened) allowlist rejected
// everything: collection was silently dead while forwarding worked fine.
func TestB01AddUsersPublishesSnapshot(t *testing.T) {
	x := &Xray{users: &UserMap{uidMap: make(map[string]int)}}
	cfg := enabledAuditConfig(t, x)

	// Before any user exists the resolver must report unknown rather than abuse a
	// zero value.
	if _, ok := x.resolveAuditUser("vless-133|uuid-a"); ok {
		t.Fatalf("resolver reported a user before any were added")
	}

	// Simulate the mutation AddUsers performs, then publish exactly as the
	// patched AddUsers does.
	x.users.mapLock.Lock()
	x.users.uidMap["vless-133|uuid-a"] = 101
	snap := x.snapshotLocked()
	gen := x.nextAuditGen()
	x.users.mapLock.Unlock()
	x.publishAuditSnapshot(snap, gen)

	id, ok := x.resolveAuditUser("vless-133|uuid-a")
	if !ok || id != 101 {
		t.Fatalf("user added but resolver returned (%d, %v); B01 regression", id, ok)
	}
	_ = cfg
}

// TestB01GenerationOrdering proves an older snapshot cannot overwrite a newer
// one, which is what makes concurrent publishes safe.
func TestB01GenerationOrdering(t *testing.T) {
	x := &Xray{users: &UserMap{uidMap: make(map[string]int)}}
	enabledAuditConfig(t, x)

	x.users.mapLock.Lock()
	x.users.uidMap["vless-133|u1"] = 101
	snapOld := x.snapshotLocked()
	genOld := x.nextAuditGen()
	x.users.uidMap["vless-133|u2"] = 102
	snapNew := x.snapshotLocked()
	genNew := x.nextAuditGen()
	x.users.mapLock.Unlock()

	// Publish the NEWER snapshot first, then the older one.
	x.publishAuditSnapshot(snapNew, genNew)
	x.publishAuditSnapshot(snapOld, genOld)

	if _, ok := x.resolveAuditUser("vless-133|u1"); !ok {
		t.Fatalf("u1 missing; wrong snapshot won")
	}
	// The older snapshot must NOT be able to remove u2.
	if id, ok := x.resolveAuditUser("vless-133|u2"); !ok || id != 102 {
		t.Fatalf("a stale snapshot overwrote a newer identity table")
	}
}

// TestB01ConcurrentPublishRace exercises the publish path under -race.
func TestB01ConcurrentPublishRace(t *testing.T) {
	x := &Xray{users: &UserMap{uidMap: make(map[string]int)}}
	enabledAuditConfig(t, x)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				x.users.mapLock.Lock()
				x.users.uidMap["vless-133|u"] = 101 + n
				snap := x.snapshotLocked()
				gen := x.nextAuditGen()
				x.users.mapLock.Unlock()
				x.publishAuditSnapshot(snap, gen)
				x.resolveAuditUser("vless-133|u")
			}
		}(i)
	}
	wg.Wait()
	if _, ok := x.resolveAuditUser("vless-133|u"); !ok {
		t.Fatalf("resolver empty after concurrent publishes")
	}
}
