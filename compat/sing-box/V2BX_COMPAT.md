# wyx sing-box compatibility snapshot

Base: `github.com/wyx2685/sing-box_mod`
`v1.13.0-alpha.5.0.20251202212447-8d054dcd8bfe`
(commit `8d054dcd8bfec013c675eb2d246fcb98f5c9c870`).

Copied from the verified Go module cache; upstream source and license retained.
This is the latest wyx commit verified on 2026-10-30, with local compatibility
changes. It is not an official newer sing-box release.

The newer wyx Xray requires sing v0.9.6 and Go 1.27. To build both cores in the
same module, the following changes are applied to the wyx sing-box baseline:

- DNS caches use pointer Cache fields and `freelru.New(..., true)`, preserving
  sharding, TTL, response copying and cache clearing.
- SOCKS, mixed and Tor pass zero for the new UDP timeout argument, preserving
  the previous absence of a SOCKS-level timeout.
- STD, uTLS and Reality configs implement the new TLS handshake timeout API;
  defaults stay zero, Clone preserves settings, Reality client delegates to
  its uTLS config. Existing outer handshake deadlines remain in place.
- HTTP/2 client shutdown tracks and closes owned connections through public
  interfaces. The removed private http2 connection pool is no longer accessed
  using linkname/unsafe. The wrapper forwards TLS ConnectionState.

`../sing-box.patch` records every modified upstream file. Added regression tests
cover DNS cache behavior, TLS timeout/Clone and active HTTP/2 shutdown/redial.
Run them from the root module with `scripts/verify-wyx-cores.sh` so the root
module's selected dependency versions and relative replacements are used.

This snapshot retains wyx's dynamic user APIs, GetCtx, LogFactory and Reality
Xver. It does not backport the official sing-box 1.14 release series.
