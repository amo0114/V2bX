# Node 137 audited canary candidate

This local branch extends core-only commit b3feb8e with the existing production
node-audit integration. It does not change core pins, XMUX, SNI, CDN, panel node
settings, or production audit capture scope. No production configuration or
credentials are included.

The integration was ported from the locally maintained v0.4.0 production tree.
The emitter module is vendored at `compat/node-audit`, with a relative replace.
Xray publishes immutable identity snapshots only after actual AddUser success,
including partial-success error returns, ordered by generation. Sing retains
its inbound-scoped identity snapshot and conservative invalidation on updates.
Unknown identities are never attributed to a guessed user. `proxy_accepted`
means authentication/policy acceptance before dialing, not dial success.

Audit package, Xray/dispatcher, and Sing tests pass, including race checks.
The isolated XHTTP packet-up integration passes real forwarding, wrong UUID
rejection, device-policy rejection, dynamic addition and revocation, mapped
identity, domain/IP preservation, health control frame delivery, and credential
absence from the event database/spool. Measured bytes/duration remain unknown.

The current Xray now blocks private destinations by default. The old loopback
test fails under that intentional behavior. The isolated lab alone uses a
custom freedom outbound with an allow rule restricted to its single ephemeral
loopback destination, plus deterministic localhost DNS. Production retains its
existing config; deployment probes use an owned public HTTPS health endpoint.
The old lab audit-agent binary predated control frames; the passing run uses
agent/server rebuilt from the current local node-audit source.

Shutdown detaches the Xray emitter before closing the core; in-flight audit
observations may be counted as closed drops. A short restart interrupts active
connections. Sing's conservative invalidation can omit observations after an
upstream update failure rather than misattribute them.

Production rollout is separate from this source commit. Only node 137's
independent `V2bX-xhttp.service` is eligible. It requires a fresh backup, baseline
authenticated forwarding/audit proof, a versioned binary and one new systemd
override, plus a single-service rollback watchdog. Main V2bX and the shared
audit agent must retain their PIDs and binary hashes. This candidate is not a
full-fleet rollout or proof of GFW resistance. The pilot uses Xray; production
Sing/HY2 behavior is not established by this canary.
