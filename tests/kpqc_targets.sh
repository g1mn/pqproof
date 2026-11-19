#!/bin/bash
# kpqc_targets.sh: KpqC 참조 구현 고정 판을 내려받아(파일을 주면 그것) SHA-256 을 맞춘 뒤 NIST API 공유 라이브러리로 빌드한다.
# 선택 CI(.github/workflows/kpqc-e2e.yml)와 개발용이다. PQ-Proof 런타임은 이것을 쓰지 않고, 검사 대상 코드를 빌드하거나 실행하지 않는다.
#   bash tests/kpqc_targets.sh <새 출력 폴더> [내려받은 zip 또는 tar.gz ...]
# 판: GitHub 에 있는 것만(tools/make_kat_manifest.py SOURCES 와 같은 URL·SHA-256). SMAUG-T 1.2.0·1.1.1, HAETAE 1.1.2, NTRU+ 2026-01,
#   AIMer 3.0. HAETAE 1.2.0 은 공식 쪽 Google Drive 에만 있어 넣지 않았다. 파일을 주면 SHA-256 으로 어느 판인지 가린다(이름은 상관없다).
# 라이브러리: <출력>/lib/<판>/lib<알고리즘>-<파라미터>.<so|dylib>. KAT 용 rng.c(NIST AES-256-CTR DRBG)를 넣어 randombytes_init 을
#   내보낸다(문제지의 derand 문항). 내보내는 심볼은 NIST API 와 DRBG 뿐이다(맥 -exported_symbols_list, 리눅스 --version-script).
#   wrong/libsmaugt-mode3: SMAUG-T 1.2.0 mode3 에서 decaps 결과 첫 바이트를 감싸개가 바꾼 것(일부러 틀린 빌드, 실패해야 한다).
# PQCgenKAT: SMAUG-T 1.2.0 mode3 의 참조 KAT 프로그램을 빈 폴더에서 돌려 <출력>/rsp/PQCkemKAT_smaugt_mode3.rsp 를 만든다.
# PQClean ML-KEM-768 clean(pq-verify 감사 대상, i-nist): 고정 커밋 소스 묶음을 SHA-256 으로 맞춰 <출력>/pqclean/ 에 빌드한다.
# 끝에 KPQC_LIBS=·KPQC_RSP=·KPQC_PQCLEAN_LIB= 세 줄을 찍는다(GITHUB_ENV 에 붙인다). 받은 압축 파일은 남이 만든 데이터라
# 판마다 빈 새 폴더에 두고 python zipfile·tar 로 푼다(절대 경로·'..' 는 zipfile 이 막는다). 빌드는 한 번에 하나씩(-j 없음).
set -euo pipefail
OUT=${1:?usage: bash tests/kpqc_targets.sh <new out dir> [downloaded archives ...]}
shift
HERE=$(cd "$(dirname "$0")" && pwd)
WRAP=$HERE/kpqc
CC=${CC:-cc}
NAMES="smaug-t-1.2.0 smaug-t-1.1.1 haetae-1.1.2 ntruplus-2026-01 aimer-3.0 pqclean"
url() {
  case $1 in
  smaug-t-1.2.0) echo https://raw.githubusercontent.com/CryptoLabInc/SMAUG-T/ae7197960f5097c96e3218013f5c28d33dc271d1/SMAUG-T.zip;;
  smaug-t-1.1.1) echo https://raw.githubusercontent.com/CryptoLabInc/SMAUG-T/bbc463cd788eae36c6d155cef667ac9dbd9054cd/SMAUG-T.zip;;
  haetae-1.1.2) echo https://raw.githubusercontent.com/CryptoLabInc/HAETAE/743c31df48183fc8c8a39a4f50a634da1c4af03a/HAETAE.zip;;
  ntruplus-2026-01) echo https://raw.githubusercontent.com/ntruplus/reference/7166f57807899de407458fa46ce8929ac6491903/NTRU+.zip;;
  aimer-3.0) echo https://raw.githubusercontent.com/samsungsds-opensource/AIMer/734cc76fa4695ca8c8eaa070508db8ff62205e68/AIMer.zip;;
  pqclean) echo https://github.com/PQClean/PQClean/archive/0586a824fc0d49df0b6b6e9179d8d15d06d0974f.tar.gz;;
  esac
}
sha() {
  case $1 in
  smaug-t-1.2.0) echo ccb58f42043296174e10fc7af520f0a49076d8c2245bd8e66d1b88bcae568c90;;
  smaug-t-1.1.1) echo d7213f1618282cbcb4090abe808a164f9689062f2b65b34fd86496b9923200d7;;
  haetae-1.1.2) echo 9b69afb55ed96a20d9626b3ea729c291f9e4bfd8d880b740fcb30f6955c4ca72;;
  ntruplus-2026-01) echo 44fa5b5b6edbb2849322f41e6b0e808874caa9f6efcaa83ba72dce0d47512615;;
  aimer-3.0) echo 4b67f9bd41005de6789bc24b86279f1c0ecf685b9de80397d8cb459bcd1bee81;;
  pqclean) echo 5269325009c2de0fa48750174ae5ed6bc47f9f1e8c16b1184c9d5d4a3e828e8e;;
  esac
}
sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

mkdir "$OUT"
mkdir "$OUT/dl" "$OUT/src" "$OUT/lib" "$OUT/rsp" "$OUT/pqclean"
for f in "$@"; do  # 준 파일: SHA-256 으로 판을 가린다
  h=$(sha256_of "$f") hit=
  for n in $NAMES; do [ "$h" = "$(sha "$n")" ] && hit=$n; done
  [ -n "$hit" ] || { echo "kpqc_targets.sh: $f is none of the pinned archives (sha256 $h)" >&2; exit 2; }
  mkdir -p "$OUT/dl/$hit"
  cp "$f" "$OUT/dl/$hit/archive"
done
for n in $NAMES; do
  if [ ! -e "$OUT/dl/$n/archive" ]; then
    mkdir -p "$OUT/dl/$n"
    curl -sSfL --retry 3 -o "$OUT/dl/$n/archive" "$(url "$n")"
  fi
  echo "$(sha "$n")  $OUT/dl/$n/archive" | shasum -a 256 -c - >/dev/null || { echo "kpqc_targets.sh: $n archive does not match its pinned SHA-256 (for a GitHub archive/<commit>.tar.gz, GitHub can regenerate the bytes: compare the unpacked files with a clone of that commit before you pin a new SHA-256)" >&2; exit 1; }
  mkdir "$OUT/src/$n"
  if [ "$n" = pqclean ]; then
    tar -xzf "$OUT/dl/$n/archive" -C "$OUT/src/$n" --strip-components=1
  else
    python3 -I -m zipfile -e "$OUT/dl/$n/archive" "$OUT/src/$n"
  fi
done

if [ "$(uname -s)" = Darwin ]; then
  ext=dylib
  OSSL=${OPENSSL_PREFIX:-$(brew --prefix openssl@3)}
  CRYPTO=(-I"$OSSL/include" -L"$OSSL/lib" -lcrypto)
else
  ext=so
  CRYPTO=(-lcrypto)
fi
# exports <파일> <심볼...>: 내보낼 심볼 목록(맥은 밑줄 붙인 목록, 리눅스는 버전 스크립트)
exports() {
  local f=$1; shift
  if [ "$ext" = dylib ]; then printf '_%s\n' "$@" > "$f"; else { printf '{ global: '; printf '%s; ' "$@"; printf 'local: *; };\n'; } > "$f"; fi
}
KEM_SYMS=(crypto_kem_keypair crypto_kem_enc crypto_kem_dec randombytes_init randombytes)
SIG_SYMS=(crypto_sign_keypair crypto_sign_signature crypto_sign crypto_sign_verify crypto_sign_open randombytes_init randombytes)
exports "$OUT/kem.exp" "${KEM_SYMS[@]}"
exports "$OUT/sign.exp" "${SIG_SYMS[@]}"
exports "$OUT/haetae.exp" "${SIG_SYMS[@]}" crypto_sign_keypair_internal crypto_sign_signature_internal crypto_sign_verify_internal
# shlib <출력 .so|.dylib> <심볼 목록> <cc 인자...>
shlib() {
  local out=$1 exp=$2; shift 2
  if [ "$ext" = dylib ]; then
    "$CC" -O2 -fPIC -std=gnu11 -dynamiclib -Wl,-exported_symbols_list,"$exp" -install_name "@rpath/$(basename "$out")" -o "$out" "$@"
  else
    "$CC" -O2 -fPIC -std=gnu11 -shared -Wl,--version-script,"$exp" -Wl,--no-undefined -o "$out" "$@" -lm
  fi
  echo "kpqc_targets.sh: $out" >&2
}

for v in 1.2.0 1.1.1; do  # SMAUG-T: rng.c 가 OpenSSL libcrypto 의 AES 를 쓴다
  R=$OUT/src/smaug-t-$v/SMAUG-T-$v/reference_implementation
  mkdir "$OUT/lib/smaug-t-$v"
  for m in mode1 mode3 mode5 modet; do
    M=$(echo "$m" | tr '[:lower:]' '[:upper:]')
    shlib "$OUT/lib/smaug-t-$v/libsmaugt-$m.$ext" "$OUT/kem.exp" -DSMAUGT_CONFIG_MODE="SMAUGT_$M" -DWRAP_PREFIX="cryptolab_smaugt_${m}_" \
      -I"$R/include" -I"$R/kat" "$R"/src/{cbd,ciphertext,dg,hash,hwt,indcpa,kem,key,pack,packring,poly,toomcook,verify,fips202}.c \
      "$R/kat/rng.c" "$WRAP/nist_kem_wrap.c" "${CRYPTO[@]}"
  done
done
R=$OUT/src/smaug-t-1.2.0/SMAUG-T-1.2.0/reference_implementation
mkdir "$OUT/lib/wrong"
shlib "$OUT/lib/wrong/libsmaugt-mode3.$ext" "$OUT/kem.exp" -DSMAUGT_CONFIG_MODE=SMAUGT_MODE3 -DWRAP_PREFIX=cryptolab_smaugt_mode3_ \
  -DWRAP_PLANT_DEFECT -I"$R/include" -I"$R/kat" "$R"/src/{cbd,ciphertext,dg,hash,hwt,indcpa,kem,key,pack,packring,poly,toomcook,verify,fips202}.c \
  "$R/kat/rng.c" "$WRAP/nist_kem_wrap.c" "${CRYPTO[@]}"
# PQCgenKAT(SMAUG-T 1.2.0 mode3): 참조 KAT 프로그램을 빌드해 빈 폴더에서 돌린다(.req 와 .rsp 를 그 폴더에 쓴다)
mkdir "$OUT/rsp/genkat"
"$CC" -O2 -std=gnu11 -DSMAUGT_CONFIG_MODE=SMAUGT_MODE3 -I"$R/include" -I"$R/kat" -o "$OUT/rsp/genkat/PQCgenKAT_smaugt_mode3" \
  "$R"/src/{cbd,ciphertext,dg,hash,hwt,indcpa,kem,key,pack,packring,poly,toomcook,verify,fips202}.c "$R"/kat/{kat_kem,PQCgenKAT_kem,rng}.c "${CRYPTO[@]}"
(cd "$OUT/rsp/genkat" && ./PQCgenKAT_smaugt_mode3 > run.log 2>&1)
cp "$OUT/rsp/genkat/PQCkemKAT_smaugt_mode3.rsp" "$OUT/rsp/PQCkemKAT_smaugt_mode3.rsp"

R=$OUT/src/haetae-1.1.2/HAETAE-1.1.2/reference_implementation  # HAETAE 1.1.2: rng.c 가 libcrypto 를 쓴다
mkdir "$OUT/lib/haetae-1.1.2"
for m in mode2 mode3 mode5; do
  M=$(echo "$m" | tr '[:lower:]' '[:upper:]')
  shlib "$OUT/lib/haetae-1.1.2/libhaetae-$m.$ext" "$OUT/haetae.exp" -DHAETAE_CONFIG_MODE="HAETAE_$M" -DWRAP_STYLE_HAETAE \
    -DWRAP_PREFIX="cryptolab_haetae_${m}_" -I"$R/include" -I"$R/kat" \
    "$R"/src/{decompose,encoding,fft,fixpoint,ntt,packing,poly,polyvec,polymat,polyfix,reduce,sampler,sign,fips202,symmetric-shake}.c \
    "$R/kat/rng.c" "$WRAP/nist_sign_wrap.c" "${CRYPTO[@]}"
done

mkdir "$OUT/lib/ntruplus-2026-01"  # NTRU+: 함수 이름이 원래 crypto_kem_* 이고 자체 aes.c 를 쓴다(감싸개·OpenSSL 없음)
for n in 768 864 1152; do
  R=$OUT/src/ntruplus-2026-01/NTRU+$n
  shlib "$OUT/lib/ntruplus-2026-01/libntruplus-$n.$ext" "$OUT/kem.exp" -I"$R" \
    "$R"/{kem,poly,ntt,symmetric}.c "$R/fips202/fips202.c" "$R/kat/aes.c" "$R/kat/rng.c"
done

R=$OUT/src/aimer-3.0/Reference_Implementation  # AIMer 3.0: 자체 aes.c, 리틀엔디언 전용
mkdir "$OUT/lib/aimer-3.0"
for p in 128f 128s 192f 192s 256f 256s; do
  shlib "$OUT/lib/aimer-3.0/libaimer-$p.$ext" "$OUT/sign.exp" -I"$R" -DPARAMS="$p" -DWRAP_STYLE_AIMER -DWRAP_PREFIX="samsungsds_aimer_${p}_ref_" \
    "$R"/{aim3,field_common,hash,sign,tree}.c "$R/field${p%[fs]}.c" "$R"/common/{aes,fips202,rng}.c "$WRAP/nist_sign_wrap.c"
done

# PQClean ML-KEM-768 clean: pq-verify AUDITS.md 와 같은 방법(필요한 심볼만 고르지 않는다: pq-verify 가 이름으로 찾는다)
P=$OUT/src/pqclean
"$CC" -O2 -fPIC -shared -I"$P/common" -o "$OUT/pqclean/libpqclean_mlkem768.$ext" \
  "$P"/crypto_kem/ml-kem-768/clean/*.c "$P/common/fips202.c" "$P/common/randombytes.c"
echo "kpqc_targets.sh: $OUT/pqclean/libpqclean_mlkem768.$ext" >&2

echo "KPQC_LIBS=$OUT/lib"
echo "KPQC_RSP=$OUT/rsp/PQCkemKAT_smaugt_mode3.rsp"
echo "KPQC_PQCLEAN_LIB=$OUT/pqclean/libpqclean_mlkem768.$ext"
