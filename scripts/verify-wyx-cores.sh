#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=go1.27.0 GOEXPERIMENT=jsonv2 CGO_ENABLED=0
core_tags='sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor'
artifact_dir="${1:-output/wyx-core-review}"
mkdir -p "$artifact_dir"
go mod verify
go test -p 4 -timeout 120s -count=1 -tags "$core_tags" ./core/... github.com/sagernet/sing-box/common/tls github.com/sagernet/sing-box/dns github.com/sagernet/sing-box/transport/v2rayhttp
for target_arch in amd64 arm64; do
 GOOS=linux GOARCH="$target_arch" go build -p 4 -trimpath -tags "$core_tags" \
  -ldflags "-X github.com/InazumaV/V2bX/cmd.version=wyx-core-review-20261030" \
  -o "$artifact_dir/V2bX-wyx-latest-linux-$target_arch" .
 go version -m "$artifact_dir/V2bX-wyx-latest-linux-$target_arch" > "$artifact_dir/linux-$target_arch.buildinfo.txt"
done
