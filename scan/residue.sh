#!/bin/bash
# residue.sh <폴더>: 고전 공개키 '잔재' 집계(일반판). 읽기만 한다. prove.sh 의 (c) 단계가 원본과 고친 판에 한 번씩 돌린다.
#   [1] SITE   : 서비스별 '전환 대상 자리'(파일, 고전 흔적 정규식) 쌍. 일반판에는 없다. 서비스에 맞춘 판을 RESIDUE= 로 줄 때만 쓴다.
#   [2] GEN    : 일반 고전 패턴(RSA·EC·곡선·OAEP/PKCS1·고전 서명·JWT RS/ES/PS·EdDSA·X25519 단독·DH/DSA·AES-128·NIST 보안레벨 3 미만 PQC)
#                폴더 안 모든 텍스트 파일. 앞의 아홉 줄(G-RSA ~ G-DH-DSA)이 prove.sh 가 세는 '공개키 9계열'이다.
#   [3] LWRITE : 이름 규칙 레거시 파일(Legacy*.java) 안 쓰기 경로(암호화·서명·키 생성·파일 쓰기). 있으면 LEFT.
#   [4] EXPECT : 코드 줄(시험 경로 밖)의 PQC 사용 흔적(ML-KEM-768·1024, ML-DSA-65·87, KpqC). 자산 칸이 묶음(kem·sig·kpqc-kem·kpqc-sig)이다.
#                단독 실행 판정은 kem·sig 묶음마다 한 줄 이상. prove.sh 의 c-expect 는 프로필(scan/profiles.json)이 고른 규칙만 센다.
# 분류: code=코드 줄 LEFT / allow=이름 규칙 허용 / comment=주석·문서 줄 / test=시험 경로의 코드 줄(comment·test 는 따로 센다, LEFT 아님).
# 이름 규칙 허용(ALLOW, LEFT 로 세지 않음. 상세 줄은 사람이 다시 본다):
#   - Legacy*.java 파일 안(옛 데이터 읽기·검증 전용으로 떼어 낸 파일)
#   - 주석을 뺀 코드에 'legacy'(대소문자 무관)가 있는 줄. 주석의 legacy 는 세지 않는다(교차 리뷰 X01)
#   - G-X25519 의 같은 줄 ML-KEM(주석을 뺀 코드에서) = 하이브리드
#   이름 규칙은 새 키·서명·암호화(RES_ALLOW_WRITEOPS, Java·Python·Go·Node)가 있는 줄을 허용하지 않는다. 같은 줄 ML-KEM 허용은
#   Java 쓰기 연산(RES_WRITEOPS)이 있는 줄을 허용하지 않는다.
#   prove.sh 는 이 출력의 ALLOW 줄을 같은 규칙(아래 3줄의 쓰기 경로까지)으로 다시 보고, LEFT 줄에서 허용 목록(ALLOW=)과 같은 함수 안
#   하이브리드 결합을 따로 뺀다.
# 시험 경로는 scan/test-paths.ere 한 곳에 두고 cbom-scan.sh 와 같이 쓴다(TEST_PATHS=<파일>로 바꿀 수 있다). 그 경로의 코드 줄은
#   TEST 로 따로 세고 줄마다 적는다(판정에 안 넣지만 숨기지 않는다).
#   목록 첫 줄은 시험 경로 규칙, 둘째 줄은 본 소스 표시(/src/main/)다. 표시가 있는 경로는 그 앞부분만 첫 줄에 맞춰 본다.
# 건너뜀: 폴더는 scan/skip-dirs 한 곳(SKIP_DIRS=<파일>로 바꿀 수 있다, cbom-scan.sh·pqlite/skipdirs.py 와 같은 규칙). .git·node_modules
#   같은 이름은 어느 깊이든, vendor·build·target·dist 는 트리 맨 위나 빌드 파일 옆일 때만이고 src/main 아래는 본다(교차 리뷰 X02·X03·X09).
#   키·DB·비밀 모양 파일(.pem .key .p12 .jks .der .crt .sqlite3 .env)은 내용은 읽지 않고 이름 개수만.
# 파일 목록은 임시 파일로 awk 에 넘긴다(파일 수천 개 저장소에서 인자 한도를 넘지 않게, 교차 리뷰 X08).
# 종료 코드: 0=CLEAN(잔재 0·PQC 흔적 모두 있음) 1=RESIDUE 2=사용법 오류. bash 3.2·BWK awk 호환.
ROOT=${1:?사용법: bash residue.sh <폴더>}
ROOT=${ROOT%/}
[ -d "$ROOT" ] || { echo "폴더 없음: $ROOT" >&2; exit 2; }
case "$ROOT" in /*) ;; *) ROOT=$(cd "$ROOT" && pwd) ;; esac  # awk 가 파일 이름을 var=값 대입으로 읽지 않게 절대 경로로
HERE=$(cd "$(dirname "$0")" && pwd)
TESTRE_FILE=${TEST_PATHS:-$HERE/test-paths.ere}
SKIP_FILE=${SKIP_DIRS:-$HERE/skip-dirs}
RES_TESTRE=$(grep -v -e '^#' -e '^[[:space:]]*$' "$TESTRE_FILE" 2>/dev/null | sed -n 1p)
RES_MAINRE=$(grep -v -e '^#' -e '^[[:space:]]*$' "$TESTRE_FILE" 2>/dev/null | sed -n 2p)
[ -n "$RES_TESTRE" ] || { echo "시험 경로 목록 없음: $TESTRE_FILE (TEST_PATHS=<파일>로 준다)" >&2; exit 2; }
[ -r "$SKIP_FILE" ] || { echo "건너뛰는 폴더 목록 없음: $SKIP_FILE (SKIP_DIRS=<파일>로 준다)" >&2; exit 2; }
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/residue.XXXXXX") || exit 2
trap 'rm -f "$TMPD"/* 2>/dev/null; rmdir "$TMPD" 2>/dev/null' EXIT
# --- 건너뛰는 폴더(scan/skip-dirs). residue.sh 와 cbom-scan.sh 에 같은 글로 있고 pqlite/skipdirs.py 와 같은 규칙이다
# (tests/test_rule_sync.py 가 세 곳을 대조한다). any 이름은 어느 깊이든 건너뛰되 경로에 main 표시가 있으면 같은 폴더에 buildfile 이
# 있을 때만 건너뛴다. output 이름은 트리 맨 위이거나 같은 폴더에 buildfile 이 있을 때만, 경로에 main 표시가 없을 때만 건너뛴다.
# 건너뛴 폴더 안은 보지 않는다.
skip_load() { # SKIP_FILE → SK_ANYX·SK_OUTX(find 식), SK_ANYL(이름 목록), SK_BFS(빌드 파일), SK_MAIN, SK_MAINP(find -path 꼴)
  local k v n
  SK_ANYX=""; SK_OUTX=""; SK_ANYL=" "; SK_BFS=""; SK_MAIN=""
  while read -r k v n; do
    { [ -n "$v" ] && [ -z "$n" ]; } || { echo "skip-dirs 줄 꼴이 틀림: $k $v $n" >&2; return 2; }
    case "$k" in
      any) SK_ANYX="${SK_ANYX:+$SK_ANYX -o }-name $v"; SK_ANYL="$SK_ANYL$v ";;
      output) SK_OUTX="${SK_OUTX:+$SK_OUTX -o }-name $v";;
      buildfile) SK_BFS="$SK_BFS $v";;
      main) SK_MAIN=$v;;
      *) echo "skip-dirs 모르는 종류: $k" >&2; return 2;;
    esac
  done < <(grep -v -e '^#' -e '^[[:space:]]*$' "$SKIP_FILE")
  SK_ANYX=${SK_ANYX:--name /}; SK_OUTX=${SK_OUTX:--name /}   # 빈 목록: '/' 는 이름에 없어 아무것도 안 맞는다
  SK_MAINP=/; [ -n "$SK_MAIN" ] && SK_MAINP="*$SK_MAIN*"     # main 표시가 없으면 '/' 는 어느 하위 경로에도 안 맞는다
}
skip_dirs() { # $1=ROOT → 건너뛸 폴더의 전체 경로를 한 줄에 하나씩(LC_ALL=C 순)
  local root=$1 d rel parent b p cut="" hit inmain bf
  # main 표시 아래 any 이름 폴더는 잘라 내지 않고 들어가 본다(빌드 파일 옆이 아니면 운영 소스다). 판단은 아래에서 트리 안 경로로 한다
  # shellcheck disable=SC2086  # SK_ANYX·SK_OUTX 는 '-name 이름 -o ...' 식이라 나눠 넘긴다(이름에 공백·글롭 문자가 없다)
  find "$root" -mindepth 1 -type d \( $SK_ANYX \) \( -path "$SK_MAINP" -print -o -prune -print \) -o -type d \( $SK_OUTX \) -print 2>/dev/null |
  LC_ALL=C sort | while IFS= read -r d; do
    hit=0
    while IFS= read -r p; do [ -n "$p" ] && case "$d/" in "$p"/*) hit=1;; esac; done <<< "$cut"
    [ $hit = 1 ] && continue
    rel=${d#"$root"/}; parent=${d%/*}; inmain=0; bf=0
    [ -n "$SK_MAIN" ] && case "/$rel/" in *"$SK_MAIN"*) inmain=1;; esac
    if [ "$parent" != "$root" ]; then
      for b in $SK_BFS; do p="$parent/$b"; { [ -L "$p" ] || [ -e "$p" ]; } && [ ! -d "$p" ] && { bf=1; break; }; done
    fi
    case "$SK_ANYL" in
      *" ${d##*/} "*) [ $inmain = 1 ] && [ $bf = 0 ] && continue;;
      *) [ $inmain = 1 ] && continue; [ "$parent" != "$root" ] && [ $bf = 0 ] && continue;;
    esac
    cut="$cut$d"$'\n'; printf '%s\n' "$d"
  done
}
skip_names() { # $1=ROOT → SK_PRUNEL·SK_PRUNEX: find·grep 이 이름만 보고 잘라 낼 any 이름. main 표시 아래에 같은 이름 폴더가 있는
  # 이름은 빼고(그 폴더를 읽어야 할 수 있다), 그 이름의 다른 폴더는 skip_out 이 skip_dirs 목록으로 거른다
  local keep x
  # shellcheck disable=SC2086
  keep=" $(find "$1" -mindepth 1 -type d \( $SK_ANYX \) \( -path "$SK_MAINP" -print -o -prune \) 2>/dev/null | sed 's#.*/##' | LC_ALL=C sort -u | tr '\n' ' ')"
  SK_PRUNEL=""; SK_PRUNEX=""
  for x in $SK_ANYL; do case "$keep" in *" $x "*) ;; *) SK_PRUNEL="$SK_PRUNEL $x"; SK_PRUNEX="${SK_PRUNEX:+$SK_PRUNEX -o }-name $x";; esac; done
  SK_PRUNEX=${SK_PRUNEX:--name /}
}
skip_out() { # $1=skip_dirs 목록 파일. 표준 입력 줄 중 그 폴더 아래 경로로 시작하는 줄을 뺀다
  LC_ALL=C awk -v L="$1" 'BEGIN { while ((getline l < L) > 0) if (l != "") p[++n] = l "/"; close(L) }
    { for (i = 1; i <= n; i++) if (index($0, p[i]) == 1) next; print }'
}
# --- 건너뛰는 폴더 끝

IFS= read -r -d '' RES_RULES <<'RULES'
# KIND@@ID@@자산@@파일(SITE=파일 이름, 나머지 *)@@정규식(ERE)@@설명@@규칙별 허용 정규식(선택)
GEN@@G-RSA@@-@@*@@(^|[^A-Za-z])[Rr][Ss][Aa]@@RSA 전반(Cipher·KeyFactory·라벨·변수)
GEN@@G-EC@@-@@*@@(^|[^A-Za-z0-9#])EC(DSA|DH|IES|PrivateKey|PublicKey|Point|GenParameterSpec|NamedCurve|ParameterSpec|Curve|[^A-Za-z0-9:]|$)|(^|[^A-Za-z])ecdsa([^A-Za-z]|$)@@EC/ECDSA/ECDH 전반(EC 단독은 낱말일 때만: EC2·#EC4899·0x00EC·AWS::EC2 는 아님)
GEN@@G-CURVE@@-@@*@@[Ss][Ee][Cc][Pp][0-9]+[RrKk]1|[Pp][Rr][Ii][Mm][Ee][0-9]+[Vv]1|P-?(256|384|521)([^0-9]|$)|[Bb][Rr][Aa][Ii][Nn][Pp][Oo][Oo][Ll]|1\.2\.840\.10045|1\.3\.132\.0|[Nn][Ii][Ss][Tt][Pp](256|384|521)|Curve\.P_(256|384|521)@@고전 곡선 이름·OID(대소문자 무관, SSH nistp·Nimbus Curve.P_)@@[Mm][Ll][-_]?[Kk][Ee][Mm]
GEN@@G-OAEP-PKCS1@@-@@*@@OAEP|MGF1|PKCS#?1([^0-9]|$)|PSource@@RSA 패딩
GEN@@G-CLASSIC-SIG@@-@@*@@with(RSA|ECDSA|DSA|PLAIN-ECDSA)|NONEwith|RSASSA|RSA-?PSS@@고전 서명 알고리즘 이름(SHA256withRSA·SHA256withECDSA 등)
GEN@@G-JWT-ALG@@-@@*@@(^|[^A-Za-z0-9])(RS|ES|PS)(256|384|512)([^0-9]|$)@@JWT/JOSE 고전 alg(RS256·ES256·PS256)
GEN@@G-EDDSA@@-@@*@@Ed25519|Ed448|EdDSA|Curve25519|(^|[^A-Za-z0-9])(ed25519|ed448|eddsa|curve25519|ED25519|ED448)@@EdDSA 서명(소문자 ed25519·ssh-ed25519 포함)
GEN@@G-X25519@@-@@*@@X25519|X448|XDH|ECDH|KeyAgreement|(^|[^A-Za-z0-9])(x25519|x448|ecdh)@@X25519/ECDH 단독(같은 줄 ML-KEM 이면 하이브리드 허용)@@[Mm][Ll][-_]?[Kk][Ee][Mm]
GEN@@G-DH-DSA@@-@@*@@[Dd]iffie-?[Hh]ellman|"DH"|"DHE"|"DSA"|'(DH|DHE|DSA|dh|dhe|dsa)'|"(dh|dhe|dsa)"|ssh-dss|ElGamal|ECIES@@DH·DSA·ElGamal(diffie-hellman·ssh-dss·작은따옴표 'dh' 포함)
GEN@@G-AES128@@-@@*@@AES-?128|AES_128|[Aa]es-?128|\.init\(128\)@@AES-128(보안레벨 1)
GEN@@G-WEAK-PQC@@-@@*@@[Mm][Ll][-_]?[Kk][Ee][Mm][-_]?512|[Mm][Ll][-_]?[Dd][Ss][Aa][-_]?44|[Kk][Yy][Bb][Ee][Rr][-_]?512|[Dd][Ii][Ll][Ii][Tt][Hh][Ii][Uu][Mm][-_]?2([^0-9]|$)|[Ss][Ll][Hh][-_]?[Dd][Ss][Aa][-_]?([Ss][Hh][Aa]2|[Ss][Hh][Aa][Kk][Ee])[-_]?128@@보안레벨 3 미만 PQC(대소문자·구분자 무관, SLH-DSA 128 은 규칙 묶음 4)
LWRITE@@LW-legacy-write@@-@@*@@ENCRYPT_MODE|WRAP_MODE|initSign|KeyPairGenerator|generateKeyPair|Files\.(write|writeString|move|copy)@@Legacy*.java 는 읽기·검증 전용이어야 함
EXPECT@@E-MLKEM768@@kem@@*@@[Mm][Ll][-_]?[Kk][Ee][Mm][-_]?768@@ML-KEM-768 사용(대소문자·구분자 무관)
EXPECT@@E-MLKEM1024@@kem@@*@@[Mm][Ll][-_]?[Kk][Ee][Mm][-_]?1024@@ML-KEM-1024 사용(보안레벨 5)
EXPECT@@E-MLDSA65@@sig@@*@@[Mm][Ll][-_]?[Dd][Ss][Aa][-_]?65@@ML-DSA-65 사용(대소문자·구분자 무관)
EXPECT@@E-MLDSA87@@sig@@*@@[Mm][Ll][-_]?[Dd][Ss][Aa][-_]?87@@ML-DSA-87 사용(보안레벨 5)
EXPECT@@E-SLHDSA@@sig@@*@@[Ss][Ll][Hh][-_]?[Dd][Ss][Aa][-_]?([Ss][Hh][Aa]2|[Ss][Hh][Aa][Kk][Ee])[-_]?(192|256)@@SLH-DSA 192·256 사용(FIPS 205, 보안레벨 3·5, 해시 이름이 붙은 FIPS 205 이름만. SPHINCS+ 는 세지 않음)
EXPECT@@E-KPQC-KEM@@kpqc-kem@@*@@[Ss][Mm][Aa][Uu][Gg]-?[Tt]|NTRU\+|[Nn][Tt][Rr][Uu]_?[Pp][Ll][Uu][Ss]@@KpqC KEM 사용(SMAUG-T·NTRU+, 국내 표준, NIST 비승인)
EXPECT@@E-KPQC-SIG@@kpqc-sig@@*@@[Hh][Aa][Ee][Tt][Aa][Ee]|(^|[^A-Za-z])(AIMer|AIMER|aimer)([^a-z]|$)@@KpqC 서명 사용(HAETAE·AIMer, 국내 표준, NIST 비승인)
RULES
export RES_RULES RES_ROOT="$ROOT" RES_TESTRE RES_MAINRE
export RES_ALLOWLINE='[Ll][Ee][Gg][Aa][Cc][Yy]'
# 복합 서명 이름(ML-DSA 와 고전 서명을 한 키로 묶은 IETF LAMPS·BouncyCastle 이름, 교차 리뷰 X26). 공개키 9계열에서 LEFT 로 세지 않고
# ALLOW 로 두면 prove.sh 가 '복합 서명'으로 따로 세어 검토 필요로 올린다(pqlite/rules.py COMPOSITE 와 같은 뜻). ML-DSA-44 를 묶은 것은
# 보안레벨 3 미만이라 허용하지 않고(LEFT), G-WEAK-PQC 도 그대로 센다
export RES_COMPOSITE='[Mm][Ll][-_]?[Dd][Ss][Aa][-_]?(65|87)[-_](RSA|rsa|ECDSA|ecdsa|Ed25519|ed25519|Ed448|ed448)'
export RES_WRITEOPS='ENCRYPT_MODE|WRAP_MODE|initSign|KeyPairGenerator|generateKeyPair'
# 이름 규칙의 쓰기 연산: RES_WRITEOPS 에 Python·Go·Node 의 새 서명·새 암호화·새 키 생성과 토큰·인증서 서명 API 를 보탠다
# (pqlite/rules.py ALLOW_WRITEOPS 와 같은 뜻의 ERE)
export RES_ALLOW_WRITEOPS='ENCRYPT_MODE|WRAP_MODE|initSign|KeyPairGenerator|generateKeyPair|\.sign[[:space:]]*\(|(^|[^A-Za-z0-9_])Sign(PKCS1v15|PSS|ASN1)?[[:space:]]*\(|\.encrypt[[:space:]]*\(|(^|[^A-Za-z0-9_])Encrypt(OAEP|PKCS1v15)[[:space:]]*\(|generate_private_key|(^|[^A-Za-z0-9_])GenerateKey[[:space:]]*\(|\.generate[[:space:]]*\(|createSign[[:space:]]*\(|publicEncrypt[[:space:]]*\(|generateKeyPair(Sync)?[[:space:]]*\(|(^|[^A-Za-z0-9_])jwt\.encode[[:space:]]*\(|\.SignedString[[:space:]]*\(|\.signWith[[:space:]]*\(|(^|[^A-Za-z0-9_])CreateCertificate[[:space:]]*\('

skip_load || exit 2
skip_dirs "$ROOT" > "$TMPD/skip" || exit 2
skip_names "$ROOT"
find_files() { # 건너뛰는 폴더를 뺀 일반 파일(이름 순)
  # shellcheck disable=SC2086  # SK_PRUNEX 는 '-name 이름 -o ...' 식이라 나눠 넘긴다(이름에 공백·글롭 문자가 없다)
  find "$ROOT" -mindepth 1 \( -type d \( $SK_PRUNEX \) \) -prune -o -type f -print | skip_out "$TMPD/skip" | LC_ALL=C sort
}
FILES=(); SKIP=0; SKIPN=""
while IFS= read -r f; do
  b=${f##*/}
  case "$b" in
    *.pem|*.key|*.p12|*.pfx|*.jks|*.der|*.crt|*.cer|*.sqlite3|*.sqlite3-*|*.db|.env|*.class|*.jar|*.zip)
      SKIP=$((SKIP+1)); SKIPN="$SKIPN ${f#$ROOT/}"; continue ;;
  esac
  grep -Iq . "$f" 2>/dev/null || continue   # 바이너리·빈 파일 제외
  FILES+=("$f")
done < <(find_files)

echo "== residue $ROOT  ($(date '+%F %T %Z'))"
echo "INFO 검사 파일 ${#FILES[@]}개 · 건너뛴 키·DB·비밀 모양 파일 ${SKIP}개(내용 미열람)${SKIPN:+:$SKIPN}"
LC=$(grep -rnE '[Ll]egacy[A-Z][A-Za-z]*\(' "$ROOT/src" 2>/dev/null | grep -v '^Binary' | sed "s#^$ROOT/##" | head -20)
if [ -n "$LC" ]; then echo "INFO 레거시 호출처(쓰기 경로에서 부르면 안 됨, 사람이 확인):"; echo "$LC" | sed 's/^/      /'; else echo "INFO 레거시 호출처 없음"; fi
[ ${#FILES[@]} -gt 0 ] || { echo "검사할 파일 없음"; exit 2; }
printf '%s\n' "${FILES[@]}" > "$TMPD/files"

LC_ALL=C awk -v RES_LIST="$TMPD/files" '
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function short(s) { s = trim(s); if (length(s) > 150) s = substr(s, 1, 147) "..."; return s }
function ftype(b) {
  if (b ~ /\.(java|js|mjs|cjs|jsx|ts|tsx|kt|kts|go|c|h|cc|cpp|cxx|hpp|hh|cs|php|scala|groovy|dart|m|mm|css|scss|gradle|jsonc|rs|swift)$/ || b ~ /^Jenkinsfile/) return "c"
  if (b ~ /\.py$/) return "py"
  if (b ~ /\.(sh|bash|zsh|ya?ml|toml|conf|r|rb|tf|tfvars|hcl)$/ || b ~ /^(Dockerfile|Makefile|sshd_config|ssh_config|known_hosts|authorized_keys)/) return "hashtail"
  if (b ~ /\.(properties|cfg|ini|env|example)$/ || b ~ /^(\.dockerignore|\.gitignore|\.env)/) return "hash"
  if (b ~ /\.(xml|html|htm|svg|vue)$/) return "xml"
  if (b ~ /\.sql$/) return "sql"
  if (b ~ /\.(md|txt|adoc|rst)$/) return "doc"
  return "code"
}
function splitc(s,   i, n, c, two, code, com, instr, q) {
  code = ""; com = ""; instr = 0; n = length(s); i = 1
  while (i <= n) {
    c = substr(s, i, 1)
    if (INBLOCK) { if (substr(s, i, 2) == "*/") { INBLOCK = 0; com = com "*/"; i += 2; continue } com = com c; i++; continue }
    if (instr) { code = code c; if (c == "\\") { code = code substr(s, i + 1, 1); i += 2; continue } if (c == q) instr = 0; i++; continue }
    if (c == "\"" || c == "\047" || c == "`") { instr = 1; q = c; code = code c; i++; continue }
    two = substr(s, i, 2)
    if (two == "//") { com = com substr(s, i); break }
    if (two == "/*") { INBLOCK = 1; com = com two; i += 2; continue }
    code = code c; i++
  }
  CODE = code; COM = com
}
function splitx(s,   p, code, com, rest) {
  code = ""; com = ""; rest = s
  while (rest != "") {
    if (INBLOCK) { p = index(rest, "-->"); if (p == 0) { com = com rest; rest = ""; break } com = com substr(rest, 1, p + 2); rest = substr(rest, p + 3); INBLOCK = 0; continue }
    p = index(rest, "<!--"); if (p == 0) { code = code rest; rest = ""; break }
    code = code substr(rest, 1, p - 1); rest = substr(rest, p + 4); com = com "<!--"; INBLOCK = 1
  }
  CODE = code; COM = com
}
function splith(s,   i, n, c, q, code) {  # 줄 끝 # 주석: 따옴표 밖이고 줄 머리나 공백 뒤일 때만(교차 리뷰 X22)
  code = ""; q = ""; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (q != "") { if (c == "\\") { code = code c substr(s, i + 1, 1); i++; continue } if (c == q) q = ""; code = code c; continue }
    if (c == "\"" || c == "\047") { q = c; code = code c; continue }
    if (c == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t]/)) { CODE = code; COM = substr(s, i); return }
    code = code c
  }
  CODE = code; COM = ""
}
function splitpy(s,   t, d, p) {  # 파이썬: 줄 끝 # 주석, 문장 자리의 세 따옴표 글(독스트링)은 주석으로 본다(교차 리뷰 X22)
  if (INDOC != "") { p = index(s, INDOC); if (p == 0) { CODE = ""; COM = s; return } INDOC = ""; CODE = ""; COM = s; return }
  t = trim(s); sub(/^[rRuUbB]/, "", t); d = substr(t, 1, 3)
  if (d == "\"\"\"" || d == "\047\047\047") {
    if (index(substr(t, 4), d) == 0) INDOC = d
    CODE = ""; COM = s; return
  }
  splith(s)
}
function add(r, t, ln, txt) {
  CNT[r, t]++
  if (CNT[r, t] <= MAXD) DET[r, t] = DET[r, t] "      " t " " REL ":" ln ": " short(txt) "\n"
  if (CNT[r, t] <= 14) LOC[r, t] = LOC[r, t] (LOC[r, t] == "" ? "" : ",") ln
}
BEGIN {
  while ((getline f < RES_LIST) > 0) ARGV[ARGC++] = f   # 파일 목록은 임시 파일로 받는다(인자 한도, 교차 리뷰 X08)
  close(RES_LIST)
  ROOT = ENVIRON["RES_ROOT"]; ALLOWLINE = ENVIRON["RES_ALLOWLINE"]; COMPOSITE = ENVIRON["RES_COMPOSITE"]; WRITEOPS = ENVIRON["RES_WRITEOPS"]; ALLOWWR = ENVIRON["RES_ALLOW_WRITEOPS"]; TESTRE = ENVIRON["RES_TESTRE"]; MAINRE = ENVIRON["RES_MAINRE"]; MAXD = 100000
  n = split(ENVIRON["RES_RULES"], LN, "\n"); NRULE = 0
  for (i = 1; i <= n; i++) {
    if (LN[i] == "" || substr(LN[i], 1, 1) == "#") continue
    m = split(LN[i], F, "@@"); NRULE++
    KIND[NRULE] = F[1]; ID[NRULE] = F[2]; AS[NRULE] = F[3]; FG[NRULE] = F[4]; RE[NRULE] = F[5]; NOTE[NRULE] = F[6]; ALW[NRULE] = (m >= 7 ? F[7] : "")
  }
}
FNR == 1 {
  INBLOCK = 0; INDOC = ""; REL = FILENAME; if (index(REL, ROOT "/") == 1) REL = substr(REL, length(ROOT) + 2)
  BASE = FILENAME; sub(/.*\//, "", BASE); TYP = ftype(BASE)
  TP = "/" REL; if (MAINRE != "" && match(TP, MAINRE)) TP = substr(TP, 1, RSTART); ISTEST = (TP ~ TESTRE)  # 본 소스 표시 앞부분만 본다
  ISLEG = (BASE ~ /^Legacy[A-Za-z0-9_]*\.java$/); SEEN[BASE] = 1; NFILES++
}
{
  s = $0
  if (TYP == "c") splitc(s)
  else if (TYP == "xml") splitx(s)
  else if (TYP == "py") splitpy(s)
  else if (TYP == "hashtail") splith(s)
  else if (TYP == "hash") { if (substr(trim(s), 1, 1) == "#") { CODE = ""; COM = s } else { CODE = s; COM = "" } }
  else if (TYP == "sql") { if (substr(trim(s), 1, 2) == "--") { CODE = ""; COM = s } else { CODE = s; COM = "" } }
  else if (TYP == "doc") { CODE = ""; COM = s }
  else { CODE = s; COM = "" }
  for (r = 1; r <= NRULE; r++) {
    k = KIND[r]
    if (k == "SITE" && BASE != FG[r]) continue
    if (k == "LWRITE" && !ISLEG) continue
    if (k == "EXPECT") { if (!ISTEST && CODE ~ RE[r]) add(r, "P", FNR, s); continue }
    if (CODE ~ RE[r]) {
      if (ISTEST) { add(r, "TEST", FNR, s); continue }
      if (k == "LWRITE") { add(r, "LEFT", FNR, s); continue }
      wr = (CODE ~ WRITEOPS)
      if (COMPOSITE != "" && ID[r] != "G-WEAK-PQC" && ID[r] != "G-AES128" && CODE ~ COMPOSITE) add(r, "ALLOW", FNR, s)   # 복합 서명(X26)
      else if ((ISLEG || CODE ~ ALLOWLINE) && CODE !~ ALLOWWR) add(r, "ALLOW", FNR, s)
      else if (!wr && ALW[r] != "" && CODE ~ ALW[r]) add(r, "ALLOW", FNR, s)   # 같은 줄 ML-KEM 도 코드에서만(주석 속 이름은 아님, X58)
      else add(r, "LEFT", FNR, s)
    } else if (COM != "" && COM ~ RE[r]) add(r, "COMMENT", FNR, s)
  }
}
END {
  sL = sA = sG = 0; gL = gN = gc = ga = gm = gt = 0; lw = 0; eM = eN = 0
  print ""
  print "[1] 서비스별 전환 대상 자리(SITE 규칙이 있을 때만). 전환 뒤 전부 GONE 또는 ALLOW 여야 한다"
  for (r = 1; r <= NRULE; r++) if (KIND[r] == "SITE") {
    L = CNT[r, "LEFT"] + 0; A = CNT[r, "ALLOW"] + 0; C = CNT[r, "COMMENT"] + 0; T = CNT[r, "TEST"] + 0
    if (!(FG[r] in SEEN)) st = "GONE(파일 없음)"; else if (L > 0) st = "LEFT"; else if (A > 0) st = "ALLOW"; else st = (C > 0 ? "GONE(주석 " C ")" : "GONE")
    if (L > 0) sL++; else if (A > 0) sA++; else sG++
    printf "SITE %-18s %-10s %-24s %-6s code=%d allow=%d comment=%d test=%d  L%s  - %s\n", ID[r], AS[r], FG[r], st, L, A, C, T, (L > 0 ? LOC[r, "LEFT"] : (A > 0 ? LOC[r, "ALLOW"] : "-")), NOTE[r]
    printf "%s%s%s", DET[r, "LEFT"], DET[r, "ALLOW"], DET[r, "TEST"]
  }
  print ""
  print "[2] 일반 고전 패턴: 폴더 전체(주석·문서 줄은 comment, 시험 경로 코드 줄은 test 로 따로)"
  for (r = 1; r <= NRULE; r++) if (KIND[r] == "GEN") {
    L = CNT[r, "LEFT"] + 0; A = CNT[r, "ALLOW"] + 0; C = CNT[r, "COMMENT"] + 0; T = CNT[r, "TEST"] + 0; gN++
    st = (L > 0 ? "LEFT" : (A > 0 ? "ALLOW" : "GONE")); if (L > 0) gL++
    gc += L; ga += A; gm += C; gt += T
    printf "GEN  %-18s %-6s code=%d allow=%d comment=%d test=%d  - %s\n", ID[r], st, L, A, C, T, NOTE[r]
    printf "%s%s%s", DET[r, "LEFT"], DET[r, "ALLOW"], DET[r, "TEST"]
    if (C > 0) { split(DET[r, "COMMENT"], CD, "\n"); for (j = 1; j <= 3 && CD[j] != ""; j++) print CD[j] }
  }
  print ""
  print "[3] 레거시 파일(Legacy*.java) 쓰기 경로"
  for (r = 1; r <= NRULE; r++) if (KIND[r] == "LWRITE") {
    L = CNT[r, "LEFT"] + 0; lw += L
    printf "LWRITE %-16s %-6s code=%d  - %s\n", ID[r], (L > 0 ? "LEFT" : "OK"), L, NOTE[r]
    printf "%s", DET[r, "LEFT"]
  }
  print ""
  print "[4] PQC 실사용 흔적(시험 경로 밖 코드 줄)"
  for (r = 1; r <= NRULE; r++) if (KIND[r] == "EXPECT") {
    P = CNT[r, "P"] + 0; EG[AS[r]] += P
    printf "EXPECT %-16s %-8s n=%d  L%s  - %s\n", ID[r], (P > 0 ? "PRESENT" : "MISSING"), P, (P > 0 ? LOC[r, "P"] : "-"), NOTE[r]
  }
  eN = 2; eM = (EG["kem"] + 0 == 0) + (EG["sig"] + 0 == 0)   # 단독 실행 판정: kem(ML-KEM-768·1024)과 sig(ML-DSA-65·87) 묶음마다 한 줄 이상
  verdict = (sL == 0 && gL == 0 && lw == 0 && eM == 0) ? "CLEAN" : "RESIDUE"
  print ""
  printf "SUMMARY files=%d sites=%d LEFT=%d ALLOW=%d GONE=%d | gen_rules=%d LEFT=%d (code=%d allow=%d comment=%d test=%d) | legacy_write=%d | pqc_expect MISSING=%d/%d | VERDICT=%s\n", NFILES, sL + sA + sG, sL, sA, sG, gN, gL, gc, ga, gm, gt, lw, eM, eN, verdict
  exit (verdict == "CLEAN" ? 0 : 1)
}' < /dev/null
