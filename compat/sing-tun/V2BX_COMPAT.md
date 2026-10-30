# V2bX dependency compatibility

Source: github.com/sagernet/sing-tun v0.8.0-beta.11, copied from the verified Go
module cache. Original source and license are retained.

The current wyx2685/sing-box_mod commit uses this version's direct-route
interfaces, which were removed in sing-tun v0.9.0. The current wyx2685/xray-core
commit requires sing v0.9.6, where the LRU API changed. To combine those exact
wyx core commits without downgrading sing, this local dependency changes only
route_direct.go: use the pointer Cache type and New(..., true) to preserve
sharded-cache behavior. Other upstream files are unchanged.

This replacement is deliberately repository-relative so source archives,
GitHub Actions, and Docker builds do not depend on a developer's module cache.
