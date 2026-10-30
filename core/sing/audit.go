package sing

import (
	"strconv"
	"strings"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/deadloop/node-audit/adapters/v2bx/audit"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func (b *Sing) configureAudit(ac *conf.AuditConfig) {
	if ac == nil || !ac.Enabled {
		return
	}
	cfg := audit.Config{Enabled: ac.Enabled, SourceID: ac.SourceID, NodeIDs: ac.NodeIDs,
		InboundNodeIDs: ac.InboundNodeIDs, SocketPath: ac.SocketPath, CaptureMode: ac.CaptureMode,
		EmitAllowUserIDs: ac.EmitAllowUserIDs, QueueMaxEvents: ac.QueueMaxEvents,
		QueueMaxBytes: ac.QueueMaxBytes, MaxFrameBytes: ac.MaxFrameBytes,
		SocketWriteTimeoutMS: ac.SocketWriteTimeoutMS, CollectClientIP: ac.CollectClientIP,
		CollectPayload: ac.CollectPayload, ObservationPoint: "sing_router_pre_outbound"}
	if err := cfg.Validate(); err != nil {
		log.Error("sing audit config rejected; audit stays disabled")
		return
	}
	b.audit = audit.New(cfg, b.resolveAuditUser)
}

// Length-prefixed inbound avoids delimiter collisions. This credential-bearing
// internal key never goes onto the event queue, socket, spool or audit database.
func auditUserKey(tag, user string) string { return strconv.Itoa(len(tag)) + ":" + tag + user }
func (b *Sing) resolveAuditUser(key string) (int64, bool) {
	snap := b.auditUsers.Load()
	if snap == nil {
		return 0, false
	}
	id, ok := (*snap)[key]
	return id, ok && id > 0
}
func auditProtocol(protocol string) bool {
	switch protocol {
	case "vless", "vmess", "shadowsocks", "trojan", "tuic", "hysteria", "hysteria2", "anytls":
		return true
	}
	return false
}

// All audit identity mutations and stores run while users.mapLock is held, so
// publication cannot reorder. Billing's UUID-only map is deliberately untouched.
// Invalidating BEFORE an upstream mutation also covers partial failures.
func (b *Sing) updateAuditUsersLocked(tag string, users []panel.UserInfo, add bool) {
	if b.audit == nil {
		return
	}
	snap := make(map[string]int64)
	if old := b.auditUsers.Load(); old != nil {
		for k, v := range *old {
			snap[k] = v
		}
	}
	bad := make(map[string]bool)
	seen := make(map[string]int)
	if add {
		for _, u := range users {
			if id, ok := seen[u.Uuid]; ok && id != u.Id {
				bad[u.Uuid] = true
			}
			seen[u.Uuid] = u.Id
		}
	}
	for _, u := range users {
		k := auditUserKey(tag, u.Uuid)
		delete(snap, k)
		if add && u.Uuid != "" && u.Id > 0 && !bad[u.Uuid] {
			snap[k] = int64(u.Id)
		}
	}
	b.auditUsers.Store(&snap)
}
func (b *Sing) forgetAuditInboundLocked(tag string) {
	if b.audit == nil {
		return
	}
	snap := make(map[string]int64)
	prefix := auditUserKey(tag, "")
	if old := b.auditUsers.Load(); old != nil {
		for k, v := range *old {
			if !strings.HasPrefix(k, prefix) {
				snap[k] = v
			}
		}
	}
	b.auditUsers.Store(&snap)
}
func (h *HookServer) observeAudit(m adapter.InboundContext, network string, rejected bool) {
	e := h.audit.Load()
	if e == nil {
		return
	}
	key := auditUserKey(m.Inbound, m.User)
	if rejected {
		e.ObserveReject(key, m.Inbound, network, "policy_rejected")
		return
	}
	domain, ip := "", ""
	if m.Destination.IsFqdn() {
		domain = m.Destination.Fqdn
	} else if m.Destination.Addr.IsValid() {
		ip = m.Destination.Addr.String()
	}
	e.ObserveAccept(key, m.Inbound, network, domain, ip, int32(m.Destination.Port))
}
