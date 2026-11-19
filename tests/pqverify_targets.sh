#!/bin/bash
# pqverify_targets.sh: tests/test_pqverify.py 의 실측 시험(Live)이 pq-verify 로 감사할 ML-KEM-768 공유 라이브러리 둘을 만든다.
# CI 와 개발용이다(PQ-Proof 런타임은 이것을 쓰지 않고, 검사 대상 코드를 빌드하지 않는다).
#   bash tests/pqverify_targets.sh <새 출력 폴더> [mlkem-native 소스 묶음 .tar.gz]
# mlkem-native(pq-code-package, Apache-2.0 OR ISC OR MIT) 고정 커밋의 소스 묶음을 내려받아(파일을 주면 그것) SHA-256 을 맞춘 뒤 이식 가능한
# C 판(mlkem/mlkem_native.c)을 공유 라이브러리로 빌드한다: good(그대로)과 bad(decaps 끝에서 공유 비밀 첫 바이트를 바꾼 것). randombytes 는
# 고정 값을 내는 함수다(pq-verify 는 derand 진입점만 감사한다). 끝에 PQPROOF_PQV_LIB=·PQPROOF_PQV_BAD_LIB= 두 줄을 찍는다.
set -euo pipefail
OUT=${1:?usage: bash tests/pqverify_targets.sh <new out dir> [mlkem-native tar.gz]}
COMMIT=fc269bc2d1068486625a3775310c2c1f28d74732
SHA=eaf1bc1196bb8fd9c8589b6d42454ec3e8faf4349f71c25a31d530d62cee470b
URL=https://github.com/pq-code-package/mlkem-native/archive/$COMMIT.tar.gz
mkdir "$OUT"
TAR=${2:-$OUT/mlkem-native-$COMMIT.tar.gz}
[ -n "${2:-}" ] || curl -sSfL -o "$TAR" "$URL"
echo "$SHA  $TAR" | shasum -a 256 -c - >/dev/null || { echo "pqverify_targets.sh: $TAR does not match the pinned SHA-256 of mlkem-native $COMMIT. GitHub generates archive downloads and has changed their bytes before: if the commit is right, compare the unpacked files with a clone of that commit before you pin a new SHA-256" >&2; exit 1; }
mkdir "$OUT/src"
tar -xzf "$TAR" -C "$OUT/src" --strip-components=1
ext=so
[ "$(uname -s)" = Darwin ] && ext=dylib
printf '#include <stdint.h>\n#include <stddef.h>\nint randombytes(uint8_t *o, size_t n){for(size_t i=0;i<n;i++)o[i]=(uint8_t)i;return 0;}\n' > "$OUT/rb.c"
for v in good bad; do
  mkdir "$OUT/$v"
  cp -R "$OUT/src/mlkem" "$OUT/$v/mlkem"
done
python3 -I - "$OUT/bad/mlkem/src/kem.c" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
anchor = "  mlk_ct_cmov_zero(ss, kr, MLKEM_SYMBYTES, fail);\n"
assert s.count(anchor) == 1, "anchor not found exactly once"
open(p, "w", encoding="utf-8").write(s.replace(anchor, anchor + "  ss[0] ^= 0xFF; /* planted defect */\n"))
PY
for v in good bad; do
  "${CC:-cc}" -O2 -fPIC -shared -DMLK_CONFIG_PARAMETER_SET=768 -I"$OUT/$v/mlkem" -o "$OUT/libmlkem768_$v.$ext" \
    "$OUT/$v/mlkem/mlkem_native.c" "$OUT/rb.c"
done
echo "PQPROOF_PQV_LIB=$OUT/libmlkem768_good.$ext"
echo "PQPROOF_PQV_BAD_LIB=$OUT/libmlkem768_bad.$ext"
