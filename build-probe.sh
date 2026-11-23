#!/bin/bash
# build-probe.sh: tls_probe 정적 바이너리 4종을 인터넷 없이 만든다(맥 arm64·amd64, 리눅스 amd64·arm64).
#   bash build-probe.sh                         → bin/tls_probe-{darwin-arm64,darwin-amd64,linux-amd64,linux-arm64}, bin/SHA256SUMS, bin/BUILDINFO
#   PROBE_BIN_DIR=/다른/폴더 bash build-probe.sh   → 그 폴더에 만든다(prove.sh도 같은 PROBE_BIN_DIR로 찾는다)
#   GOFLAGS=... bash build-probe.sh               → Go 표준 변수 GOFLAGS 를 -mod=mod 뒤에 덧붙인다
#   PROBE_LDFLAGS='-s=false -w=false' bash build-probe.sh → 링커 옵션을 덧붙인다(뒤 옵션이 이기므로 이 값이면 디버그 정보를 남긴다)
#   둘 다 없으면 릴리스와 같은 바이트를 만든다. 덧붙인 값은 BUILDINFO 의 flags 줄에 적힌다.
# Go 표준 라이브러리만 쓴다: GOPROXY=off CGO_ENABLED=0 GOTOOLCHAIN=local(깔린 go만, 내려받기 없음). Go 1.27 이상(crypto/mldsa).
# bash 3.2 호환. 지우는 명령 없음(같은 이름 바이너리는 go build가 덮어쓴다).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
command -v go >/dev/null || { echo "go 없음: Go 1.27 이상이 있어야 한다(crypto/mldsa)" >&2; exit 2; }
OUT=${PROBE_BIN_DIR:-$HERE/bin}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
gofl=-mod=mod; [ -n "${GOFLAGS:-}" ] && gofl="$gofl $GOFLAGS"
ldf='-s -w -buildid='; [ -n "${PROBE_LDFLAGS:-}" ] && ldf="$ldf $PROBE_LDFLAGS"
for t in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
  os=${t%/*}; arch=${t#*/}
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local GOFLAGS="$gofl" GOWORK=off \
    go build -C "$HERE/probe" -trimpath -buildvcs=false -ldflags="$ldf" -o "$OUT/tls_probe-$os-$arch" .
  echo "built $OUT/tls_probe-$os-$arch"
done
if command -v shasum >/dev/null; then SUM="shasum -a 256"; else SUM="sha256sum"; fi
( cd "$OUT" && $SUM tls_probe-darwin-arm64 tls_probe-darwin-amd64 tls_probe-linux-amd64 tls_probe-linux-arm64 > SHA256SUMS )
{
  echo "go: $(go version)"
  echo "flags: GOPROXY=off CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=$gofl -trimpath -buildvcs=false -ldflags=$ldf"
  ( cd "$HERE/probe" && $SUM go.mod tls_probe.go | sed 's/^/source: /' )
} > "$OUT/BUILDINFO"
cat "$OUT/SHA256SUMS"
