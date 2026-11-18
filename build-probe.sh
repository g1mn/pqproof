#!/bin/bash
# build-probe.sh: tls_probe 정적 바이너리 3종을 인터넷 없이 만든다(맥 arm64, 리눅스 amd64·arm64).
#   bash build-probe.sh                         → bin/tls_probe-{darwin-arm64,linux-amd64,linux-arm64}, bin/SHA256SUMS, bin/BUILDINFO
#   PROBE_BIN_DIR=/다른/폴더 bash build-probe.sh   → 그 폴더에 만든다(prove.sh도 같은 PROBE_BIN_DIR로 찾는다)
# Go 표준 라이브러리만 쓴다: GOPROXY=off CGO_ENABLED=0 GOTOOLCHAIN=local(깔린 go만, 내려받기 없음). Go 1.27 이상(crypto/mldsa).
# 인텔 맥이면 아래 목록에 darwin/amd64를 보탠다.
# bash 3.2 호환. 지우는 명령 없음(같은 이름 바이너리는 go build가 덮어쓴다).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
command -v go >/dev/null || { echo "go 없음: Go 1.27 이상이 있어야 한다(crypto/mldsa)" >&2; exit 2; }
OUT=${PROBE_BIN_DIR:-$HERE/bin}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
for t in darwin/arm64 linux/amd64 linux/arm64; do
  os=${t%/*}; arch=${t#*/}
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=mod GOWORK=off \
    go build -C "$HERE/probe" -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$OUT/tls_probe-$os-$arch" .
  echo "built $OUT/tls_probe-$os-$arch"
done
if command -v shasum >/dev/null; then SUM="shasum -a 256"; else SUM="sha256sum"; fi
( cd "$OUT" && $SUM tls_probe-darwin-arm64 tls_probe-linux-amd64 tls_probe-linux-arm64 > SHA256SUMS )
{
  echo "go: $(go version)"
  echo "flags: GOPROXY=off CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=mod -trimpath -buildvcs=false -ldflags=-s -w -buildid="
  ( cd "$HERE/probe" && $SUM go.mod tls_probe.go | sed 's/^/source: /' )
} > "$OUT/BUILDINFO"
cat "$OUT/SHA256SUMS"
