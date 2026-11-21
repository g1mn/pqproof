#!/usr/bin/env bash
# cbom-scan.sh: 암호 자산 목록(CBOM) 스캐너. 같은 입력이면 같은 CBOM 표가 나오게(재현 가능하게) 뽑는다.
#   ./cbom-scan.sh DIR [host:port ...] [hosts.txt]   DIR을 훑고 엔드포인트에 붙어 본 뒤 evidence/cbom-<시각>.md/.csv
#   ./cbom-scan.sh --selftest                        scan/fixtures/를 스캔해 기대 탐지를 단언(하나라도 틀리면 exit 1)
# 찾는 것: 개인키·인증서(PEM·DER·OpenSSH)·키스토어(.jks/.p12) · TLS 설정(nginx·apache·haproxy·openssl.cnf·PostgreSQL·설정 파일 *protocols 키, 업스트림 proxy_ssl_* 포함) · sshd_config
#          · 소스(Java·Python·Node·Go)와 셸의 암호 API · 약한 암호(MD5·SHA1·DES·3DES·RC4·ECB) · 의존성 버전 · 살아 있는 TLS 엔드포인트
# 환경변수: OPENSSL(기본 brew → PATH) KEYTOOL STOREPASS(키스토어 비밀번호 후보, 공백 구분) OUT(출력 폴더) TEST_PATHS(시험 경로 목록, 기본 scan/test-paths.ere)
#          SKIP_DIRS(건너뛰는 폴더 목록, 기본 scan/skip-dirs) HOST_FILES=1(설정이 가리키는 DIR 밖 인증서·호스트 키도 읽는다. 단독 실행용.
#          prove.sh 는 넘기지 않는다: 판정은 머신과 상관없이 같아야 한다, 교차 리뷰 X05)
# bash 3.2(macOS)·GNU/BSD 공용: grep -P·연관 배열·sed -i 안 씀. 주석·테스트 경로는 비고에 표시하고 표 아래로 내린다(시험 경로는 test-paths.ere 한 곳, residue.sh 와 같은 목록).
#   인증서 10개 넘는 묶음(공용 CA 번들)은 한 행 · 읽기 권한 없는 키·sshd_config는 '확인' 행(sudo로 다시) · 고전·PQC 혼재 줄은 고전 쪽으로 판정
#   못 여는 키스토어도 행(같은 폴더 비밀번호 후보는 이름만) · 같은 공개키 인증서가 있는 개인키는 인증서 서명키(P2)
export LC_ALL=C
umask 077
set -f
HERE=$(cd "$(dirname "$0")" && pwd)
TAB=$(printf '\t')

runs() { [ -n "$1" ] && [ -x "$1" ] && "$@" >/dev/null 2>&1; }
# 시험·예제 경로(residue.sh·pqlite/scan.py·prove.py 와 같은 목록). prove.sh 는 증적에 남긴 사본을 TEST_PATHS 로 준다
# 첫 줄은 시험 경로 규칙, 둘째 줄은 본 소스 표시(/src/main/): 표시가 있으면 그 앞부분만 첫 줄에 맞춰 본다(flag_of)
TESTRE_FILE=${TEST_PATHS:-$HERE/test-paths.ere}
TESTRE=$(grep -v -e '^#' -e '^[[:space:]]*$' "$TESTRE_FILE" 2>/dev/null | sed -n 1p)
MAINRE=$(grep -v -e '^#' -e '^[[:space:]]*$' "$TESTRE_FILE" 2>/dev/null | sed -n 2p)
[ -n "$TESTRE" ] || { echo "시험 경로 목록 없음: $TESTRE_FILE (TEST_PATHS=<파일>로 준다)" >&2; exit 2; }
SKIP_FILE=${SKIP_DIRS:-$HERE/skip-dirs}
[ -r "$SKIP_FILE" ] || { echo "건너뛰는 폴더 목록 없음: $SKIP_FILE (SKIP_DIRS=<파일>로 준다)" >&2; exit 2; }
# --- 건너뛰는 폴더(scan/skip-dirs). any 이름은 어느 깊이든 건너뛰되 경로에 main 표시가 있으면 같은 폴더에 buildfile 이
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
skip_load || exit 2
O=${OPENSSL:-}; KT=${KEYTOOL:-}
[ -z "$O" ] && for c in /opt/homebrew/bin/openssl /usr/local/opt/openssl/bin/openssl "$(command -v openssl)"; do runs "$c" version && { O=$c; break; }; done
[ -z "$KT" ] && for c in "$(command -v keytool)" "${JAVA_HOME:-/none}/bin/keytool" /opt/homebrew/opt/openjdk/bin/keytool; do runs "$c" -help && { KT=$c; break; }; done
[ -n "$KT" ] && ! runs "$KT" -help && KT=""
[ -n "$O" ] || { echo "openssl 없음" >&2; exit 2; }
SK=$(command -v ssh-keygen); TO=$(command -v timeout || command -v gtimeout)
MLKEM=0; "$O" list -kem-algorithms 2>/dev/null | grep -qi 'ml-kem' && MLKEM=1
TMP=$(mktemp -d "${TMPDIR:-/tmp}/cbom.XXXXXX") || exit 2
trap 'set +f; rm -f "$TMP"/* 2>/dev/null; rmdir "$TMP" 2>/dev/null' EXIT
ROWS=$TMP/rows; SEEN=$TMP/seen; : > "$ROWS"; : > "$SEEN"

# find 가 잘라 낼 any 이름 폴더(PRUNE)와 grep -r 이 들어가지 않을 이름(GX)은 scan() 이 트리마다 skip_names 로 정한다. output 이름
# 폴더(vendor·build·target·dist)와 main 표시 아래 같은 이름이 있는 any 폴더는 조건이 있어 결과를 skip_out 으로 거른다
PRUNE=""; GX=""
CODE='--include=*.java --include=*.kt --include=*.scala --include=*.groovy --include=*.py --include=*.js --include=*.mjs --include=*.cjs --include=*.ts --include=*.jsx --include=*.tsx --include=*.go --include=*.rb --include=*.php --include=*.cs --include=*.c --include=*.h --include=*.cc --include=*.cpp --include=*.rs --include=*.swift'
CFG='--include=*.yml --include=*.yaml --include=*.properties --include=*.toml --include=*.ini --include=*.env --include=.env* --include=*.tf --include=*.tfvars --include=*.xml --include=*.json --include=*.conf --include=*.cfg --include=*.cnf --include=*.sh --include=*.bash --include=Dockerfile* --include=Makefile'
NOLOCK='--exclude=package-lock.json --exclude=yarn.lock --exclude=pnpm-lock.yaml --exclude=*.min.js --exclude=*.lock'
JAVA='--include=*.java --include=*.kt --include=*.scala --include=*.groovy'; PY='--include=*.py'
JS='--include=*.js --include=*.mjs --include=*.cjs --include=*.ts --include=*.jsx --include=*.tsx'; GO='--include=*.go'
SH='--include=*.sh --include=*.bash --include=Dockerfile* --include=Makefile --include=*.yml --include=*.yaml'
Q="['\"]"
# 호환은 '/' 튜플: ':' 목록이면 X25519 키 공유를 먼저 보낸 PQC 가능 클라이언트도 X25519로 끝난다(OpenSSL 3.5.9 s_server·nginx 1.30.6에서 확인)
GRPRP="호환 X25519MLKEM768/X25519:P-256 · 엄격 X25519MLKEM768(OpenSSL 3.5+)"
TLSRP="X25519MLKEM768 하이브리드(TLS 1.3): $GRPRP"
DEFRP="그룹 명시($GRPRP): 3.5.0부터 기본 keyshare X25519MLKEM768·X25519(OpenSSL NEWS)"
PGRP="설정 불가: PG18 ssl_groups 또는 구간 보호(PQC 앞단·터널)"
SSHKX="mlkem768x25519-sha256(OpenSSH 9.9+) · sntrup761x25519-sha512@openssh.com(9.0+)"
SSHRP="kex 하이브리드 먼저(서명은 소급 위험 없음) · 호스트키 ssh-mldsa44-ed25519(OpenSSH 10.6+ 기본 활성 · 10.4~10.5는 실험용 …@openssh.com 이름·기본 꺼짐, 그 키는 10.6에서 재생성: OpenSSH 릴리스 노트) · ML-DSA-44 는 NIST 보안레벨 2라 PQ-Proof c-classic 은 막는다"
NISTRP="NIST IR 8547 최종(2026-10): RSA·ECDSA·EdDSA·ECDH·DH 2030 이후 비권장·2035 이후 금지"

# ---------- 공통 ----------
lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }
note() { local o="" x; for x in "$@"; do [ -n "$x" ] && o="${o:+$o · }$x"; done; printf '%s' "$o"; }
# 근거 줄 발췌. 키·토큰일 수 있는 긴 base64 덩어리는 가린다(증거 파일이 보고서에 그대로 붙으므로)
# --- 가림(mask) 시작: residue.sh 와 cbom-scan.sh 에 같은 글로 있다. prove.py REDACT 와 같은 값을 *** 로 가린다(교차 리뷰 X33)
MASKFN='function mskv(re, vre,   o, p) {
  o = ""
  while (match(MS_L, re)) {
    p = RSTART + RLENGTH - 1; o = o substr(MS_S, 1, p); MS_S = substr(MS_S, p + 1); MS_L = substr(MS_L, p + 1)
    if (match(MS_L, vre)) { o = o "***"; MS_S = substr(MS_S, RLENGTH + 1); MS_L = substr(MS_L, RLENGTH + 1) }
  }
  MS_S = o MS_S; MS_L = tolower(MS_S)
}
function mskn(vre,   i, o, r, p) {
  i = index(MS_L, "ssh-keygen")
  if (!i) return
  o = substr(MS_S, 1, i + 9); r = substr(MS_S, i + 10)
  if (match(r, "[ \t]-N[ \t]+")) {
    p = RSTART + RLENGTH - 1; o = o substr(r, 1, p); r = substr(r, p + 1)
    if (match(r, vre)) { o = o "***"; r = substr(r, RLENGTH + 1) }
  }
  MS_S = o r; MS_L = tolower(MS_S)
}
function mskt(re,   o) {
  o = ""
  while (match(MS_S, re)) {
    if (substr(MS_S, RSTART, 1) ~ /[A-Za-z0-9_]/) o = o substr(MS_S, 1, RSTART - 1) "***"
    else o = o substr(MS_S, 1, RSTART) "***"
    MS_S = substr(MS_S, RSTART + RLENGTH)
  }
  MS_S = o MS_S; MS_L = tolower(MS_S)
}
function mask(s,   w, v, k, b, t) {
  MS_S = s; MS_L = tolower(s); w = "(^|[^a-z0-9_])"
  v = "^(\"[^\"]*\"|\047[^\047]*\047|[^ \t\"\047`]+)"; k = "^(\"[^\"]*\"|\047[^\047]*\047|[^ \t\"\047`,;)]+)"
  b = "[a-z0-9._~+/=-]"; b = "^" b b b b b b b b b "*"
  t = "[A-Za-z0-9_-]"; t = t t t t t t t t t t t "*"
  mskv("-(src|dest)?(storepass|keypass)[ \t]+", v)
  mskv(w "pass:", v)
  mskn(v)
  mskv(w "(password|passwd|passphrase|pwd|secret|client_secret|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|token|(access|refresh|auth|api|bearer)[_-]?token)[\"\047]?[ \t]*[:=][ \t]*", k)
  mskv(w "bearer[ \t]+", b)
  mskt("(^|[^A-Za-z0-9_])(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|sk-|AKIA|ASIA|AIza)" t)
  return MS_S
}'
# --- 가림 끝
MASKAWK="$MASKFN"'
{ print mask($0) }'
snip() { local s; s=$(trim "$1" | sed -E 's#[A-Za-z0-9+/=]{40,}#<가림>#g' | awk "$MASKAWK"); s=${s//$TAB/ }; [ ${#s} -gt 90 ] && s="${s:0:90}…"; printf '%s' "\`$s\`"; }
# ROOT 안에서 '.'을 찾는다: GNU grep의 --exclude-dir는 명령줄 디렉터리 이름(예: 루트가 build)에도 걸리기 때문
# shellcheck disable=SC2086  # GX 는 --exclude-dir=이름 목록(이름에 공백·글롭 문자가 없다, set -f)
G() { ( cd "$ROOT" && grep -rnIE "$@" $GX --exclude=cbom-scan.sh . 2>/dev/null ) |
  awk -v r="$ROOT" 'substr($0,1,2)=="./" {$0 = r substr($0,2)} {print}' | skip_out "$SKIPL"; }
seen() { grep -Fxq -- "$1" "$SEEN"; }
add() { # 위치 용도 알고리즘 위협 우선순위 권장 비고
  local k; case "$5" in P1) k=1;; P2) k=2;; P3) k=3;; 확인) k=4;; *) k=5;; esac
  case "$7" in 주석|"주석 · "*|테스트·예제|"테스트·예제 · "*) k=$((k+10));; esac   # flag_of 표시는 비고 맨 앞(원본 발췌의 낱말은 보지 않는다)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$ROWS"; printf '%s\n' "$1" >> "$SEEN"
}
flag_of() { # $1=상대경로 $2=줄 → FL. 주석 표시는 파일 언어를 본다(교차 리뷰 X22): '#'는 #-주석 언어에서만(C 의 #include·Rust 의 #[...]는
  # 코드), '*'는 C 계열 블록 주석 이음 줄, '--'는 SQL·Lua·Haskell, ';'는 ini·어셈블리·Lisp 에서만
  local t=${2#"${2%%[![:space:]]*}"} b=${1##*/}; FL=""
  case "$t" in
    '//'*|'/*'*|'<!--'*) FL="주석";;
    '#'*) case "$b" in *.java|*.kt|*.kts|*.scala|*.groovy|*.js|*.mjs|*.cjs|*.jsx|*.ts|*.tsx|*.go|*.c|*.h|*.cc|*.cpp|*.cxx|*.hpp|*.hh|*.cs|*.rs|*.swift|*.m|*.mm|*.dart) ;; *) FL="주석";; esac;;
    '*'*) case "$b" in *.java|*.kt|*.kts|*.scala|*.groovy|*.js|*.mjs|*.cjs|*.jsx|*.ts|*.tsx|*.go|*.c|*.h|*.cc|*.cpp|*.cxx|*.hpp|*.hh|*.cs|*.php|*.rs|*.swift|*.css|*.scss|*.dart) FL="주석";; esac;;
    '--'*) case "$b" in *.sql|*.lua|*.hs) FL="주석";; esac;;
    ';'*) case "$b" in *.ini|*.asm|*.s|*.lisp|*.clj|*.el|*.scm) FL="주석";; esac;;
  esac
  local p="/$1"
  if [ -n "$MAINRE" ] && [[ $p =~ $MAINRE ]]; then p=${p%%"${BASH_REMATCH[0]}"*}/; fi  # 본 소스 표시 앞부분만 본다
  [[ $p =~ $TESTRE ]] && FL=$(note "$FL" "테스트·예제")
  return 0
}
autouse() { case "$(lc "$1")" in
  [rpe]s[0-9][0-9][0-9]*|jwt*) echo 서명;;   # JWS 알고리즘 이름(RS256·PS384·ES512)
  *ml-kem*|*mlkem*|*ecdh*|*x25519*|*x448*|*xdh*|*diffie*|*ffdhe*|dh|dh[!a-z]*) echo 키교환;;
  *ml-dsa*|*slh-dsa*|*ecdsa*|*ed25519*|*ed448*|*eddsa*|*dsa*|*with*|*rsassa*|*pss*) echo 서명;;
  *rsa*) echo 서명·암호화;;
  ec|ec[!a-z]*|ecc*|*secp*|*prime*v1*|p-[0-9]*) echo 서명·키교환;;
  *md5*|*sha*) echo 해시;;
  tls*|ssl*) echo 프로토콜;;
  *) echo 암호화;; esac; }

# 위협·우선순위·권장 판정 → TH PR RP WN. P1=키교환·암호화(HNDL 직접 노출) P2=서명·인증서·고전 취약 P3=그로버 약화
WEAKPQ='ml[-_]?kem[-_]?512|ml[-_]?dsa[-_]?44|kyber[-_]?512|dilithium[-_]?2([^0-9]|$)|slh[-_]?dsa[-_]?(sha2|shake)[-_]?128'   # NIST 보안레벨 3 미만 PQC(교차 리뷰 X07, SLH-DSA 128 은 규칙 묶음 4)
# 복합 서명(ML-DSA 와 고전 서명을 한 키로 묶은 IETF LAMPS·BC 이름, 교차 리뷰 X26)
COMPRE='ml[-_]?dsa[-_]?(44|65|87)[-_](rsa|ecdsa|ed25519|ed448)'
COMPTH="복합 서명(PQC+고전)"; COMPRP="복합 서명은 허용 여부를 정책으로 정하고 사람이 확인(목표는 ML-DSA-65 단독)"
verdict() {
  local u=$1 a; a=$(lc "$2"); WN=""
  if [[ $a =~ $WEAKPQ ]]; then TH="보안레벨 3 미만(PQC)"; PR=P2; RP="ML-KEM-768 · ML-DSA-65(NIST 보안레벨 3)"; return; fi
  if [[ $a =~ $COMPRE ]]; then TH=$COMPTH; PR=P2; RP=$COMPRP; return; fi
  case "$a" in *mlkem*|*ml-kem*|*ml_kem*|*ml-dsa*|*mldsa*|*slh-dsa*|*sntrup761*|*kyber*|*dilithium*|*falcon*|*sphincs*|*smaug*|*haetae*|*aimer*|*ntru*|*hqc*)
    TH="안전(PQC)"; PR="참고"; RP="유지"; return;; esac
  case "$a" in *rsa*|*ecdsa*|*ecdh*|*dsa*|*ed25519*|*ed448*|*x25519*|*x448*|*xdh*|*curve25519*|*secp*|*prime1*|*prime2*|*prime3*|*brainpool*|*p-256*|*p-384*|*p-521*|*p256*|*p384*|*p521*|*nistp*|*diffie*|*ffdhe*|*dhe*|dh|dh[!a-z]*|*[!a-z]dh|*[!a-z]dh[!a-z]*|ec|ec[!a-z]*|ecc*|*[!a-z]ec|*[!a-z]ec[!a-z]*|[rpe]s[0-9][0-9][0-9]*|*[!a-z][rpe]s[0-9][0-9][0-9]*|*elgamal*)
    TH="쇼어로 깨짐"; RP=""
    case "$u" in *키교환*|*암호화*) PR=P1;; *) PR=P2;; esac
    case "$u" in *키교환*) RP="ML-KEM-768 하이브리드(TLS X25519MLKEM768 · SSH mlkem768x25519-sha256)";; esac
    case "$u" in *암호화*) RP=$(note "$RP" "ML-KEM-768 캡슐화 + AES-256-GCM");; esac
    case "$u" in *서명*|*인증서*|*개인키*) RP=$(note "$RP" "ML-DSA-65(FIPS 204)");; esac
    case "$a" in *jwt*) RP="ML-DSA JWS(IETF 초안: 라이브러리 지원 확인) 또는 발급·검증이 같은 서비스면 HS512";; esac
    [ -z "$RP" ] && RP="ML-KEM-768(키교환) · ML-DSA-65(서명)"
    case "$a" in *md5*|*sha1*|*sha-1*) WN="약한 해시(MD5/SHA-1) 함께 사용";; esac
    return;; esac
  case "$a" in *md5*|*sha1*|*sha-1*|*rc4*|*arcfour*|*3des*|*des-ede*|*desede*|*tripledes*|*des-cbc*|*des_cbc*|des|des[!a-z]*|*[!a-z]des|*[!a-z]des[!a-z]*|*rc2*|*blowfish*)
    TH="그로버로 약화(이미 고전 취약)"
    case "$u" in *암호화*|*키교환*) PR=P1;; *) PR=P2;; esac
    case "$a" in *md5*|*sha1*|*sha-1*) RP="SHA-256 이상(SHA-384 권장)";; *) RP="AES-256-GCM";; esac
    return;; esac
  case "$a" in *ecb*|*null*|*export*|*sslv2*|*sslv3*|tlsv1|tlsv1[!.0-9]*|*[!a-z]tlsv1|*tlsv1.0*|*tlsv1.1*|*tlsv1_[01]*|*tls1_[01]*|*versiontls1[01]*)
    TH="고전 취약(양자 무관)"; PR=P2
    case "$a" in *tls*|*ssl*) RP="TLS 1.3만 허용(하이브리드 그룹 전제)";; *) RP="AES-256-GCM(인증 암호 모드)";; esac
    return;; esac
  case "$a" in *aes128*|*aes-128*|*aes_128*) TH="그로버로 약화"; PR=P3; RP="AES-256-GCM"; return;; esac
  case "$a" in *aes256*|*aes-256*|*aes_256*|*chacha20*|*sha256*|*sha-256*|*sha2*|*sha384*|*sha-384*|*sha512*|*sha-512*|*sha3*|*hmac*|*hs256*|*hs384*|*hs512*|*blake2*|*poly1305*)
    TH="안전(그로버 고려해도 충분)"; PR="참고"; RP="유지"; return;; esac
  case "$a" in *aes*) TH="그로버로 약화(키 길이 확인)"; PR=P3; RP="AES-256-GCM"; return;; esac
  TH="미확인"; PR="확인"; RP="수동 확인"
}

# 줄 근처(+3줄)에서 키 길이·곡선을 보탠다 → ALG
refine() {
  local a=$3 la w n c; la=$(lc "$a")
  w=$(sed -n "$2,$(( $2 + 3 ))p" "$1" 2>/dev/null)
  case "$la" in *rsa*|*dsa*|dh|*diffie*|aes|*aes) case "$a" in *[0-9][0-9][0-9]*) ;; *)
    n=$(printf '%s\n' "$w" | grep -o -i -E '(key_?size|modulusLength|initialize|\.init|GenerateKey\(rand\.Reader,|\.generate\(|bits|-b)[^0-9a-z]{0,6}[0-9]{3,5}' | head -1 | grep -o -E '[0-9]{3,5}$')
    [ -n "$n" ] && a="$a-$n";; esac;; esac
  case "$la" in ec|ec[!a-z]*|ecc*|*ecdsa*|*ecdh*) case "$la" in *secp*|*prime*|*p-[235]*|*p256*|*p384*|*p521*|*25519*|*448*|*brainpool*) ;; *)
    c=$(printf '%s\n' "$w" | grep -o -i -E 'secp[0-9]+[rk]1|prime[0-9]+v1|brainpoolP[0-9]+[rt]1|P-?(256|384|521)' | head -1)
    [ -n "$c" ] && a="$a $c";; esac;; esac
  ALG=$a
}

# 코드 규칙 공통 처리. stdin=grep 결과. $1=용도(auto) $2=알고리즘 틀(@=추출값) $3=추출 ERE(캡처 1개) $4=후처리 함수
each() {
  local h f rest ln txt r v use alg n oT oP oR
  while IFS= read -r h; do
    f=${h%%:*}; rest=${h#*:}; ln=${rest%%:*}; txt=${rest#*:}; r=${f#"$ROOT"/}
    seen "$r:$ln" && continue
    v=""; [ -n "$3" ] && v=$(printf '%s\n' "$txt" | sed -n -E "s#.*$3.*#\\1#p" | head -1)
    alg=$(trim "${2//@/$v}"); use=$1; n=""; oT=""; oP=""; oR=""
    [ -n "$4" ] && "$4" "$f" "$ln" "$txt" "$v"
    refine "$f" "$ln" "$alg"; alg=$ALG
    [ "$use" = auto ] && use=$(autouse "$alg")
    flag_of "$r" "$txt"; verdict "$use" "$alg"
    [ -n "$oT" ] && TH=$oT; [ -n "$oP" ] && PR=$oP; [ -n "$oR" ] && RP=$oR
    add "$r:$ln" "$use" "$alg" "$TH" "$PR" "$RP" "$(note "$FL" "$n" "$WN" "$(snip "$txt")")"
  done
}
win() { sed -n "$2,$(( $2 + 3 ))p" "$1" 2>/dev/null; }
h_jcipher() { case "$4" in AES|DES|DESede|Blowfish) alg="$4 (모드 미지정 → SunJCE 기본 ECB)";; esac; }
h_jwt() {
  local x; x=$(win "$1" "$2" | grep -o -E "algorithms?${Q}?[[:space:]]*[:=][[:space:]]*\[?[[:space:]]*${Q}[A-Za-z0-9]+" | head -1 | grep -o -E '[A-Za-z0-9]+$')
  if [ -n "$x" ]; then alg="JWT $x"; else alg="JWT(알고리즘 미지정)"; n="라이브러리 기본값·키 종류 확인(jsonwebtoken 기본 HS256: README)"; fi
}
h_gocurves() {
  local x; x=$(win "$1" "$2" | grep -o -E 'tls\.(Curve[A-Za-z0-9]+|X25519[A-Za-z0-9]*|SecP[A-Za-z0-9]+)' | sed 's/^tls\.//' | grep -v '^CurveID$' | tr '\n' ':' | sed 's/:$//')
  alg="CurvePreferences ${x:-(목록 확인)}"
  case "$x" in *MLKEM*) oT="안전(PQC 하이브리드)"; oP=참고; oR=유지;; *) oR="tls.X25519MLKEM768 추가 또는 CurvePreferences 비움(Go 1.24+ 기본값)";; esac
}
h_nodesign() { oT="미확인(키 종류가 정함)"; oP=확인; oR="같은 파일의 키 생성(generateKeyPair·createPrivateKey) 행으로 판정"; n="알고리즘 인자가 null 이면 키 종류(RSA·EC·Ed25519·ML-DSA)를 따른다"; }
h_cap() { oT="쇼어로 깨짐"; oP=P1; oR="상한을 TLS 1.3 으로(또는 설정 삭제): X25519MLKEM768 은 TLS 1.3 전용"; n="TLS 1.3 꺼짐 → ML-KEM 하이브리드 불가"; }
h_wolf() { case "$4" in wc_ecc*|wc_Ecc*) alg="ECC(wolfSSL $4)";; wc_ed25519*) alg="Ed25519(wolfSSL $4)";; wc_curve25519*) alg="X25519(wolfSSL $4)";; *) alg="RSA(wolfSSL $4)";; esac; use=$(autouse "$alg"); }
h_nimbus() { case "$4" in ECKeyGenerator|P_*|SECP256K1) alg="EC $4(Nimbus)";; RSAKeyGenerator) alg="RSA(Nimbus RSAKeyGenerator)";; Ed25519|Ed448) alg="$4(Nimbus)";; X25519|X448) alg="$4(Nimbus)";; *) alg="Ed25519·X25519(Nimbus OKP)";; esac; use=$(autouse "$alg"); }
h_xssh() { n="x/crypto v0.38.0+를 Go 1.24+로 빌드하면 기본 kex 1순위 mlkem768x25519-sha256(ssh/mlkem.go): go.mod 버전과 Config.KeyExchanges 직접 지정 여부 확인"; }
h_osslcmd() {
  local t=$3 k=""
  k=$(printf '%s' "$t" | sed -n -E 's/.*-newkey[[:space:]]+([A-Za-z0-9-]+)(:([0-9]+))?.*/\1 \3/p')
  [ -z "$k" ] && k=$(printf '%s' "$t" | sed -n -E 's/.*-algorithm[[:space:]]+([A-Za-z0-9-]+).*/\1/p')
  [ -z "$k" ] && case "$t" in
    *genrsa*) k="RSA $(printf '%s' "$t" | grep -o -E '[[:space:]][0-9]{4}([[:space:]]|$)' | tr -d ' ' | head -1)";;
    *ecparam*) k="EC $(printf '%s' "$t" | sed -n -E 's/.*-name[[:space:]]+([A-Za-z0-9-]+).*/\1/p')";;
    *dhparam*) k=DH;; *gendsa*) k=DSA;; esac
  k=$(trim "$k"); case "$(lc "$k")" in rsa\ [0-9]*) k="RSA-${k#* }";; esac
  alg=${k:-"openssl(알고리즘 미지정)"}; use=$(autouse "$alg"); case "$t" in *" req "*|*x509*) use="인증서";; esac
}
h_pomver() {
  local x; x=$(win "$1" "$2" | sed -n -E 's#.*<version>([^<]+)</version>.*#\1#p' | head -1)
  alg="$4${x:+ $x}"; oT="간접(라이브러리)"; oP=확인
  case "$4" in *bc*|*bouncycastle*) local v=${x:-${4##*:}} mi; mi=${v#1.}; mi=${mi%%.*}   # gradle 좌표는 끝이 버전
      oR="bcprov 1.79+: ML-KEM·ML-DSA JCA 스펙(MLKEMParameterSpec·MLDSAParameterSpec)이 bc-java r1rv79 태그부터 있음"
      case "$v" in 1.[0-9]*) [ "$mi" -lt 79 ] 2>/dev/null && oP=P2 || oP=참고;; esac;;
    *) oR="PQC(ML-DSA) JWS 지원 여부 확인";; esac
}
h_pydep() {
  local lt nm ver; lt=$(lc "$3")
  nm=$(printf '%s' "$lt" | grep -o -E 'cryptography|pycryptodomex?|pyjwt|pyopenssl|paramiko|python-jose|ecdsa|pynacl|libnacl' | head -1)
  ver=$(printf '%s' "$lt" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -1); alg="$nm${ver:+ $ver}"; oT="간접(라이브러리)"; oP=확인; oR="PQC 지원 여부 확인"
  if [ "$nm" = cryptography ]; then
    if [ -n "$ver" ] && [ "${ver%%.*}" -lt 48 ]; then oP=P2; oR="cryptography 48.0.0+ (OpenSSL 3.5+ 위 ML-KEM·ML-DSA: pyca CHANGELOG)"; else oP=참고; oR="48.0.0+면 ML-KEM·ML-DSA 사용 가능(OpenSSL 3.5+)"; fi
  fi
}
h_npm() {
  local ver; ver=$(printf '%s' "$3" | sed -n -E 's/.*:[[:space:]]*"([^"]+)".*/\1/p'); alg="$4${ver:+ $ver}"; oT="간접(라이브러리)"; oP=확인; oR="PQC 지원 여부 확인"
  case "$4" in jsonwebtoken) oP=P2; oR="PQC 알고리즘 없음(HS/RS/PS/ES·none만: README) → ML-DSA JWS 라이브러리 또는 HS512";;
    @noble/post-quantum) oT="안전(PQC 라이브러리)"; oP=참고; oR=유지;; esac
}
h_cargo() { local ver; ver=$(printf '%s' "$3" | grep -o -E '[0-9]+(\.[0-9]+)+' | head -1); alg="$4${ver:+ $ver}(Rust)"; oT="간접(라이브러리)"; oP=확인; oR="PQC 지원 여부 확인(ml-kem·ml-dsa 크레이트)"; }
h_gomod() {
  local t; t=$(trim "$3")
  case "$t" in
    go\ *) local ver=${t#go }; local mi=${ver#1.}; mi=${mi%%.*}; alg="go $ver (go.mod)"; use=키교환
      if [ "$mi" -lt 24 ] 2>/dev/null; then oT="쇼어로 깨짐(기본 TLS 그룹 고전)"; oP=P1; oR="go.mod를 go 1.24+로: 1.24 미만이면 새 툴체인도 tlsmlkem=0(go list -f '{{.DefaultGODEBUG}}'로 확인)"
      else oT="안전(PQC)"; oP=참고; oR="Go 1.24+ 기본 X25519MLKEM768(CurvePreferences 미지정 시)"; fi;;
    *circl*) alg="cloudflare/circl"; oT="안전(PQC 라이브러리)"; oP=참고; oR=유지;;
    *) local xv; xv=$(printf '%s' "$t" | grep -o -E 'v0\.[0-9]+' | head -1); alg="golang.org/x/crypto $(printf '%s' "$t" | grep -o -E 'v[0-9][0-9.]*' | head -1)"; oT="간접(라이브러리)"; oP=확인
       oR="x/crypto/ssh를 쓰면 v0.38.0+·Go 1.24+ 빌드: 기본 kex 1순위 mlkem768x25519-sha256(v0.38.0 ssh/mlkem.go)"
       [ -n "$xv" ] && { [ "${xv#v0.}" -lt 38 ] && oP=P2 || oP=참고; };;
  esac
}

scan_code() {
  # Java/Kotlin JCA
  G $JAVA -e 'KeyPairGenerator\.getInstance\(' | each auto '@' 'getInstance\([[:space:]]*"([^"]+)"'
  G $JAVA -e 'KeyAgreement\.getInstance\(' | each 키교환 '@' 'getInstance\([[:space:]]*"([^"]+)"'
  G $JAVA -e 'Signature\.getInstance\(' | each 서명 '@' 'getInstance\([[:space:]]*"([^"]+)"'
  G $JAVA -e 'Cipher\.getInstance\(' | each 암호화 '@' 'getInstance\([[:space:]]*"([^"]+)"' h_jcipher
  G $JAVA -e '(MessageDigest|Mac)\.getInstance\(' | each 해시 '@' 'getInstance\([[:space:]]*"([^"]+)"'
  G $JAVA -e 'KeyGenerator\.getInstance\(' | each 암호화 '@' 'getInstance\([[:space:]]*"([^"]+)"'
  # Python (cryptography·pycryptodome·hashlib)
  G $PY -e 'rsa\.generate_private_key\(' | each 서명·암호화 RSA
  G $PY -e 'ec\.generate_private_key\(' | each 서명·키교환 EC
  G $PY -e '(Ed25519|Ed448|X25519|X448)PrivateKey\.generate' | each auto '@' '(Ed25519|Ed448|X25519|X448)PrivateKey'
  G $PY -e 'ec\.ECDH\(' | each 키교환 ECDH
  G $PY -e 'dh\.generate_parameters\(' | each 키교환 DH
  G $PY -e 'padding\.OAEP\(' | each 암호화 RSA-OAEP
  G $PY -e 'padding\.PKCS1v15\(' | each 서명·암호화 'RSA PKCS#1 v1.5'
  G $PY -e '(RSA|DSA|ECC)\.(generate|import_key|construct)\(' | each auto '@' '(RSA|DSA|ECC)\.(generate|import_key|construct)\('
  G $PY -e 'PKCS1_(OAEP|v1_5)\.new' | each 암호화 'RSA @' 'PKCS1_(OAEP|v1_5)'
  G $PY -e "hashlib\.(md5|sha1)\(|hashlib\.new\([[:space:]]*${Q}(md5|sha1)" | each 해시 '@' '(md5|sha1)'
  G $PY -e '(DES3?|ARC4|ARC2|Blowfish)\.new\(|algorithms\.(TripleDES|ARC4|Blowfish|CAST5|IDEA|SEED)\(' | each 암호화 '@' '(DES3|DES|ARC4|ARC2|Blowfish|TripleDES|CAST5|IDEA|SEED)'
  G $PY -e 'MODE_ECB|modes\.ECB\(' | each 암호화 'ECB 모드'
  G $PY $JS -e 'jwt\.(encode|decode|sign|verify)\(' | each 서명 JWT '' h_jwt
  # Node crypto
  G $JS -e "generateKeyPair(Sync)?\([[:space:]]*${Q}" | each auto '@' "KeyPair[A-Za-z]*\\([[:space:]]*${Q}([^'\"]+)"
  G $JS -e 'createECDH\(' | each 키교환 'ECDH @' "createECDH\\([[:space:]]*${Q}([^'\"]+)"
  G $JS -e 'createDiffieHellman' | each 키교환 DH
  G $JS -e '(publicEncrypt|privateDecrypt)\(' | each 암호화 'RSA(publicEncrypt)'
  G $JS -e 'createSign\(' | each 서명 'RSA/ECDSA 서명 @' "createSign\\([[:space:]]*${Q}([^'\"]+)"
  # crypto.sign(null, ...)·crypto.verify 는 키 종류가 알고리즘을 정한다(Ed25519·ML-DSA 도 이 꼴): '확인' 행, 판정은 같은 파일 키 생성 행(교차 리뷰 X25)
  G $JS -e 'crypto\.(sign|verify)\(' | each 서명 'crypto.sign·verify(알고리즘은 키 종류)' '' h_nodesign
  G $JS -e "createHash\([[:space:]]*${Q}(md5|sha1)" | each 해시 '@' "createHash\\([[:space:]]*${Q}([^'\"]+)"
  G $JS -e "create(Cipheriv|Decipheriv|Cipher)\([[:space:]]*${Q}" | each 암호화 '@' "[Cc]ipher[a-z]*\\([[:space:]]*${Q}([^'\"]+)"
  G $JS -e "maxVersion[[:space:]]*:[[:space:]]*${Q}TLSv1(\\.[0-2])?${Q}|secureProtocol[[:space:]]*:[[:space:]]*${Q}(TLSv1(_[12])?|SSLv23)_(client_|server_)?method" | each 프로토콜 'Node TLS 상한' '' h_cap
  G $PY -e 'maximum_version[[:space:]]*=[[:space:]]*(ssl\.)?TLSVersion\.(TLSv1(_[0-2])?|SSLv3)|OP_NO_TLSv1_3|PROTOCOL_TLSv1(_[12])?([^_0-9A-Za-z]|$)' | each 프로토콜 'Python TLS 상한' '' h_cap
  # 이름이 API 에 안 드러나는 라이브러리(PyNaCl·tweetnacl·libsodium·Go x/crypto/nacl·wolfSSL·Nimbus, 교차 리뷰 X20)
  G $PY -e '(^|[^A-Za-z_.])nacl\.public|from[[:space:]]+nacl\.public[[:space:]]+import|from[[:space:]]+nacl[[:space:]]+import.*public' | each 키교환 'X25519(PyNaCl Box)'
  G $PY -e '(^|[^A-Za-z_.])nacl\.signing|from[[:space:]]+nacl\.signing[[:space:]]+import|from[[:space:]]+nacl[[:space:]]+import.*signing' | each 서명 'Ed25519(PyNaCl signing)'
  G $JS -e 'nacl\.box(\.keyPair|\.before)?\(|nacl\.scalarMult\(' | each 키교환 'X25519(tweetnacl box)'
  G $JS -e 'nacl\.sign(\.keyPair|\.detached)?\(' | each 서명 'Ed25519(tweetnacl sign)'
  G $JS $PY $GO --include=*.c --include=*.h --include=*.cc --include=*.cpp --include=*.rs -e 'crypto_(box|kx|scalarmult)_?[a-z0-9_]*\(' | each 키교환 'X25519(libsodium crypto_box·kx)'
  G $JS $PY $GO --include=*.c --include=*.h --include=*.cc --include=*.cpp --include=*.rs -e 'crypto_sign_?[a-z0-9_]*\(' | each 서명 'Ed25519(libsodium crypto_sign)'
  G $GO -e '"golang\.org/x/crypto/(nacl/box|curve25519)"' | each 키교환 'X25519(Go x/crypto/@)' '"golang\.org/x/crypto/([a-z0-9/]+)"'
  G $GO -e '"golang\.org/x/crypto/(nacl/sign|ed25519)"' | each 서명 'Ed25519(Go x/crypto/@)' '"golang\.org/x/crypto/([a-z0-9/]+)"'
  G --include=*.c --include=*.h --include=*.cc --include=*.cpp -e 'wc_(ecc_|EccPrivateKey|ed25519_|curve25519_|RsaPublicEncrypt|RsaSSL_Sign|MakeRsaKey|InitRsaKey)' | each auto 'wolfSSL @' '(wc_[A-Za-z0-9]+)' h_wolf
  G $JAVA -e '(ECKeyGenerator|RSAKeyGenerator|OctetKeyPairGenerator)[[:space:]]*\(' | each auto 'Nimbus @' '(ECKeyGenerator|RSAKeyGenerator|OctetKeyPairGenerator)' h_nimbus
  G $JAVA -e 'Curve\.(P_256|P_384|P_521|SECP256K1|Ed25519|Ed448|X25519|X448)([^A-Za-z0-9_]|$)' | each auto 'Nimbus Curve.@' 'Curve\.([A-Za-z0-9_]+)' h_nimbus
  # Go
  G $GO -e '"crypto/(rsa|ecdsa|ecdh|ed25519|dsa|md5|sha1|des|rc4|mlkem)"' | each auto 'Go crypto/@' '"crypto/([a-z0-9]+)"'
  G $GO -e 'rsa\.GenerateKey\(' | each 서명·암호화 RSA
  G $GO -e 'rsa\.(Encrypt|Decrypt)(OAEP|PKCS1v15)' | each 암호화 'RSA @' 'rsa\.([A-Za-z0-9]+)'
  G $GO -e 'rsa\.Sign(PKCS1v15|PSS)|ecdsa\.Sign' | each 서명 '@' '(rsa|ecdsa)\.Sign'
  G $GO -e 'ecdsa\.GenerateKey\(' | each 서명 ECDSA
  G $GO -e 'ecdh\.(P256|P384|P521|X25519)\(' | each 키교환 'ECDH @' 'ecdh\.([A-Za-z0-9]+)\('
  G $GO -e 'CurvePreferences' | each 키교환 'TLS 그룹' '' h_gocurves
  # 코드에서 TLS 1.3 을 끄는 상한(X25519MLKEM768 은 TLS 1.3 전용, 교차 리뷰 X18). 설정 파일의 ssl_protocols 와 같은 판정
  G $GO -e 'MaxVersion[[:space:]]*(:|=|:=)[[:space:]]*(tls\.)?VersionTLS1[0-2]([^0-9]|$)' | each 프로토콜 'Go MaxVersion @' 'Version(TLS1[0-2])' h_cap
  G $GO -e 'tls\.VersionTLS1[01]' | each 프로토콜 'tls.Version@' 'tls\.Version(TLS1[01])'
  G $GO -e 'golang\.org/x/crypto/ssh"' | each 키교환·서명 'SSH(x/crypto/ssh)' '' h_xssh
  # 코드 속 TLS 그룹 지정(Node tls ecdhCurve · Python ssl set_ecdh_curve): 설정 파일과 같은 판정. 따옴표 없는 인자(변수)는 값을 모르니 '확인' 행
  G $JS $PY -e "ecdhCurve[[:space:]]*:|set_ecdh_curve\\(" | while IFS= read -r h; do
    local f=${h%%:*} rest=${h#*:} ln txt r v; ln=${rest%%:*}; txt=${rest#*:}; r=${f#"$ROOT"/}; seen "$r:$ln" && continue
    flag_of "$r" "$txt"
    if printf '%s\n' "$txt" | grep -q -E "(ecdhCurve[[:space:]]*:|set_ecdh_curve\\()[[:space:]]*${Q}"; then
      v=$(printf '%s\n' "$txt" | sed -n -E "s#.*(ecdhCurve[[:space:]]*:|set_ecdh_curve\\()[[:space:]]*${Q}([^'\"]*).*#\\2#p" | head -1)
      group_row "$r:$ln" "$v" "$(note "$FL" "$(snip "$txt")")"
    else v=$(printf '%s\n' "$txt" | sed -n -E 's#.*(ecdhCurve[[:space:]]*:|set_ecdh_curve\()[[:space:]]*([A-Za-z_$][A-Za-z0-9_.$]*).*#\2#p' | head -1)
      add "$r:$ln" 키교환 "TLS 그룹(변수 ${v:-?})" "미확인(값이 코드 밖)" 확인 "변수 값을 따라가 판정: $GRPRP" "$(note "$FL" "$(snip "$txt")")"; fi
  done
  # 셸·도커·CI 의 키 생성 명령
  G $SH -e 'openssl[[:space:]]+(genrsa|genpkey|req|ecparam|dhparam|gendsa)' | each auto openssl '' h_osslcmd
  G $SH -e 'ssh-keygen[[:space:]].*-t[[:space:]]*[a-z0-9-]+' | each 서명 'SSH @' '-t[[:space:]]*([a-z0-9-]+)'
  G $SH -e 'keytool[[:space:]].*-keyalg[[:space:]]+[A-Za-z]+' | each auto '@' '-keyalg[[:space:]]+([A-Za-z]+)'
  # 의존성
  G --include=pom.xml -e '<artifactId>(bcprov|bcpkix|bcutil|bctls|bcpg|bc-fips|bcfips|jjwt|java-jwt|nimbus-jose-jwt)[^<]*</artifactId>' | each 라이브러리 '@' '<artifactId>([^<]+)</artifactId>' h_pomver
  G --include=*.gradle --include=*.gradle.kts -e 'org\.bouncycastle:[a-z0-9-]+:[0-9.]+' | each 라이브러리 '@' '(org\.bouncycastle:[a-z0-9-]+:[0-9.]+)' h_pomver
  G -i --include=requirements*.txt --include=pyproject.toml --include=Pipfile --include=setup.py --include=setup.cfg \
    -e "(^|[[:space:]\"'])(cryptography|pycryptodomex?|pyjwt|pyopenssl|paramiko|python-jose|ecdsa|pynacl|libnacl)([[:space:]]*[=<>~!]=?[[:space:]]*[0-9][0-9.]*)?([[:space:]\"',;]|\$)" | each 라이브러리 '' '' h_pydep
  G --include=package.json -e '"(jsonwebtoken|jose|node-forge|node-rsa|elliptic|crypto-js|jsrsasign|@noble/post-quantum|openpgp|tweetnacl|libsodium-wrappers|sodium-native|@noble/curves|@noble/ed25519|@noble/secp256k1)"[[:space:]]*:' | each 라이브러리 '@' '"([^"]+)"[[:space:]]*:' h_npm
  G --include=Cargo.toml -e '^[[:space:]]*(ed25519-dalek|x25519-dalek|curve25519-dalek|p256|p384|k256|rsa|ring)[[:space:]]*=' | each 라이브러리 '@' '^[[:space:]]*([a-z0-9-]+)' h_cargo
  G --include=go.mod -e '^go[[:space:]]+[0-9]+\.[0-9]+|golang\.org/x/crypto[[:space:]]|cloudflare/circl[[:space:]]' | each 라이브러리 '' '' h_gomod
}

# ---------- TLS 설정 ----------
group_row() { # 위치 값 비고
  local t pq="" cl=""
  case "$(lc "$2")" in auto|"") add "$1" 키교환 "그룹 auto(기본값)" "미확인(OpenSSL 버전 의존)" P1 "$DEFRP" "$3"; return;; esac
  for t in $(printf '%s' "$2" | tr ':,/' '   '); do case "$(lc "$t")" in *mlkem*|*kyber*) pq="${pq:+$pq:}$t";; *) cl="${cl:+$cl:}$t";; esac; done
  if [ -n "$pq" ]; then add "$1" 키교환 "$2" "안전(PQC 하이브리드)" 참고 유지 "$(note "$3" "${cl:+고전 폴백 허용($cl): 구형 클라이언트 경로는 HNDL 노출}")"
  else add "$1" 키교환 "$2" "쇼어로 깨짐" P1 "$GRPRP" "$3"; fi
}
pgver() { # postgresql*.conf → PV = 주 버전(같은 폴더 PG_VERSION → 경로 …/postgresql/16/·…/pgsql/16/), 못 찾으면 '?', PG 파일 아니면 빈 값
  PV=""; case "${1##*/}" in postgresql*.conf) ;; *) case "$1" in */postgresql/*.conf|*/pgsql/*.conf) ;; *) return;; esac;; esac   # 파일 이름이나 postgresql/·pgsql/ 폴더(conf.d)
  [ -r "${1%/*}/PG_VERSION" ] && PV=$(tr -dc '0-9.' < "${1%/*}/PG_VERSION")
  [ -z "$PV" ] && PV=$(printf '%s\n' "$1" | sed -n -E 's#.*/(postgresql|pgsql)/([0-9]+)/.*#\2#p')
  PV=${PV%%.*}; [ -n "$PV" ] || PV="?"
}
tls_kv() { # 위치 지시어 값 비고
  local d=$2 v=$3 fl=$4 t wk=0 has13=0 weak="" a128=""
  case "$d" in
    ssl_protocols|sslprotocol|minprotocol|ssl_min_protocol_version)
      for t in $(lc "$v" | tr ':,' '  '); do case "$t" in -*|!*) continue;; esac; t=${t#+}
        case "$t" in all) wk=1; has13=1;; sslv2|sslv3|tlsv1|tlsv1.0|tlsv1.1) wk=1;; tlsv1.3) has13=1;; esac; done
      case "$d" in minprotocol|ssl_min_protocol_version) has13=1;; esac
      if [ $wk = 1 ]; then add "$1" 프로토콜 "$v" "고전 취약(양자 무관)" P2 "TLSv1.2 TLSv1.3만(1.3 필수: 하이브리드 그룹은 TLS 1.3 전용)" "$(note "$fl" "TLS 1.0/1.1 허용")"
      elif [ $has13 = 0 ]; then add "$1" 프로토콜 "$v" "쇼어로 깨짐" P1 "TLSv1.3 활성화 후 X25519MLKEM768" "$(note "$fl" "TLS 1.3 없음 → ML-KEM 하이브리드 불가")"
      else add "$1" 프로토콜 "$v" "해당 없음" 참고 유지 "$(note "$fl" "TLS 1.3 허용")"; fi;;
    ssl_ciphers|sslciphersuite|ssl-default-bind-ciphers|ssl-default-server-ciphers|cipherstring|ciphers)
      for t in $(lc "$v" | tr ':, ' '   '); do case "$t" in -*|!*) continue;; esac; t=${t#+}
        case "$t" in *rc4*|*des*|*md5*|*null*|*export*|low|medium|*idea*|*seed*|*rc2*) weak="${weak:+$weak,}$t";; esac
        case "$t" in *aes128*) a128=1;; esac; done
      add "$1" "키교환·암호화(TLS1.2 스위트)" "$v" "쇼어로 깨짐" P1 "TLS 1.3 + X25519MLKEM768(1.2 스위트의 ECDHE·DHE·RSA 키교환은 PQC 불가)" \
        "$(note "$fl" "${weak:+고전 취약 허용: $weak}" "${a128:+AES-128 포함(그로버)}")";;
    ssl-default-bind-ciphersuites|ssl-default-server-ciphersuites|ciphersuites)
      verdict 암호화 "$v"; add "$1" "암호화(TLS1.3 스위트)" "$v" "$TH" "$PR" "$RP" "$fl";;
    maxprotocol|ssl_max_protocol_version)
      case "$(lc "$v")" in ""|*tlsv1.3*) add "$1" 프로토콜 "$v" "해당 없음" 참고 유지 "$(note "$fl" "상한에 TLS 1.3 포함")";;
        *) add "$1" 프로토콜 "$v" "쇼어로 깨짐" P1 "상한을 TLSv1.3으로(또는 지시어 삭제)" "$(note "$fl" "TLS 1.3 없음 → ML-KEM 하이브리드 불가")";; esac;;
    ssl_ecdh_curve|ssl_groups|curves|groups|ssl-default-bind-curves|ssl-default-server-curves)
      pgver "$ROOT/${1%:*}"   # PG ≤17 ssl_ecdh_curve는 OBJ_sn2nid로 곡선 이름 하나만, PG18은 ssl_groups(옛 이름 그대로 됨)로 목록: be-secure-openssl.c·guc.c REL_17/18
      case "$PV" in
        "") group_row "$1" "$v" "$fl";;
        \?) group_row "$1" "$v" "$(note "$fl" "PG 버전 미확인: 17 이하면 곡선 하나만($PGRP)")";;
        *) if [ "$PV" -ge 18 ]; then group_row "$1" "$v" "$(note "$fl" "PG $PV ssl_groups: '/' 튜플은 PG에서 실행 미확인")"
           else case "$(lc "$v")" in
             *mlkem*|*:*|*,*|*/*) add "$1" 키교환 "$v" "미확인(설정 오류)" 확인 "$PGRP" "$(note "$fl" "PG $PV: 목록·ML-KEM 이름은 'ECDH: unrecognized curve name'으로 기동 실패")";;
             *) add "$1" 키교환 "$v" "쇼어로 깨짐" P1 "$PGRP" "$(note "$fl" "PG $PV: ssl_ecdh_curve는 곡선 하나만")";; esac; fi;;
      esac;;
    ssl_dhparam|dhparameters) add "$1" 키교환 "DH 파라미터($v)" "쇼어로 깨짐" P1 "DHE 스위트 제거 → TLS 1.3 + X25519MLKEM768" "$fl";;
    *) verdict 키교환 "$v"; add "$1" "TLS 설정($d)" "$v" "$TH" "$PR" "$RP" "$fl";;
  esac
}
tls_line() { # 위치 줄 비고
  local t d v k x up=""; t=$(trim "$2"); t=${t%%;*}
  d=$(lc "${t%%[[:space:]=]*}"); v=$(trim "${t#*[[:space:]=]}"); v=$(trim "${v#=}"); v=${v//\'/}; v=${v//\"/}; v=${v//\[/}; v=${v//\]/}; v=${v%,}
  d=${d//\"/}; d=${d//\'/}; d=${d%:}
  case "$d" in
    proxy_ssl_*|grpc_ssl_*) d=ssl_${d#*_ssl_}; up="업스트림(nginx→백엔드, 클라이언트 측)";;
    sslproxyprotocol|sslproxyciphersuite) d=ssl${d#sslproxy}; up="업스트림(Apache→백엔드, 클라이언트 측)";;
    *disabl*|*exclud*) case "$(lc "$v")" in   # excludeProtocols·disabledProtocols 는 끄는 목록
        *tlsv1.3*) add "$1" 프로토콜 "$v" "쇼어로 깨짐" P1 "제외 목록에서 TLSv1.3 빼기" "$(note "$3" "제외 목록: TLS 1.3 꺼짐 → ML-KEM 하이브리드 불가")";;
        *) add "$1" 프로토콜 "$v" "해당 없음" 참고 유지 "$(note "$3" "제외 목록(허용 목록 아님)")";; esac; return;;
    *protocols) d=ssl_protocols;;   # enabled-protocols: · tls.protocols= 도 프로토콜 목록
  esac
  case "$d" in
    ssl_conf_command|sslopensslconfcmd) d=$(lc "${v%%[[:space:]]*}"); v=$(trim "${v#*[[:space:]]}");;
    sslciphersuite) case "$(lc "$v")" in tlsv1.3[[:space:]]*) d=ciphersuites; v=$(trim "${v#*[[:space:]]}");; ssl[[:space:]]*) v=$(trim "${v#*[[:space:]]}");; esac;;
    bind) for k in curves ciphersuites ciphers; do
        x=$(printf ' %s ' "$v" | sed -n -E "s/.*[[:space:]]${k}[[:space:]]+([^[:space:]]+).*/\\1/p")
        [ -n "$x" ] && tls_kv "$1" "$k" "$x" "$3"; done; return;;
  esac
  tls_kv "$1" "$d" "$v" "$(note "$3" "$up")"
}
scan_tls() {
  local h f rest ln r TRE
  TRE='^[[:space:]]*(ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_groups|ssl_conf_command|ssl_dhparam|ssl_(min|max)_protocol_version|(proxy|grpc)_ssl_(protocols|ciphers|conf_command)|SSLProxy(Protocol|CipherSuite)|SSLProtocol|SSLCipherSuite|SSLOpenSSLConfCmd|ssl-default-(bind|server)-(curves|ciphers|ciphersuites)|bind[[:space:]].*[[:space:]](curves|ciphers|ciphersuites))[[:space:]=]'
  { G -i --exclude=*.md --exclude=*.html --exclude=*.rst --exclude=*.csv -e "$TRE"
    G -i --include=*.cnf --include=*.conf -e '^[[:space:]]*(Groups|Curves|MinProtocol|MaxProtocol|CipherString|Ciphersuites)[[:space:]]*='
    G -i --include=*.properties --include=*.yml --include=*.yaml --include=*.toml --include=*.ini --include=*.env --include=*.json --include=*.conf --include=*.cfg \
      -e "^[[:space:]]*[\"']?[A-Za-z0-9_.-]*protocols[\"']?[[:space:]]*[:=][^#]*tlsv1"; } |
  while IFS= read -r h; do
    f=${h%%:*}; rest=${h#*:}; ln=${rest%%:*}; r=${f#"$ROOT"/}; seen "$r:$ln" && continue
    flag_of "$r" "${rest#*:}"; tls_line "$r:$ln" "${rest#*:}" "$FL"
  done
  # TLS 서버인데 그룹 지시어가 없는 파일 → 링크된 OpenSSL 기본값을 따른다
  local ON='^[[:space:]]*(ssl_certificate[[:space:]]|sslengine[[:space:]]+on|sslcertificatefile[[:space:]]|listen[^#;]*[[:space:]]ssl)|^[[:space:]]*bind[[:space:]].*[[:space:]]ssl([[:space:]]|$)'
  G -l -i --exclude=*.md --exclude=*.html -e "$ON" | while IFS= read -r f; do
    grep -q -i -E '^[[:space:]]*(ssl_ecdh_curve|ssl_groups|ssl_conf_command[[:space:]]+(groups|curves)|sslopensslconfcmd[[:space:]]+(groups|curves)|ssl-default-bind-curves)|[[:space:]]curves[[:space:]]' "$f" && continue
    ln=$(grep -n -i -E "$ON" "$f" | head -1 | cut -d: -f1); r=${f#"$ROOT"/}
    add "$r:$ln" 키교환 "그룹 미지정 → 링크된 OpenSSL 기본값" "미확인(OpenSSL 버전 의존)" P1 "$DEFRP" "TLS 서버인데 그룹 지시어 없음"
  done
  # DIR 밖 참조 인증서는 열지 않고 '확인' 행만 남긴다(머신마다 판정이 달라지지 않게, 교차 리뷰 X05). HOST_FILES=1 이면 읽는다(단독 실행용)
  G -i -e '^[[:space:]]*(ssl_certificate|sslcertificatefile|ssl_trusted_certificate)[[:space:]]+/' | while IFS= read -r h; do
    f=${h%%:*}; rest=${h#*:}; ln=${rest%%:*}; r=${f#"$ROOT"/}
    x=$(trim "${rest#*:}"); x=${x#*[[:space:]]}; x=$(trim "${x%%;*}")
    case "$x" in "$ROOT"/*) continue;; esac
    if [ "${HOST_FILES:-0}" = 1 ]; then [ -r "$x" ] && scan_file "$x" "$x" "참조: $r:$ln"
    else flag_of "$r" "${rest#*:}"
      add "$r:$ln" "인증서(트리 밖 참조)" "$x" 미확인 확인 "실행 중인 서비스에서 확인(TLS_TARGETS 또는 openssl s_client)" "$(note "$FL" "트리 밖 파일은 열지 않음")"
    fi
  done
}

# ---------- sshd_config ----------
hostkey_alg() { # DIR 밖 호스트 키는 HOST_FILES=1 일 때만 연다(아니면 파일 이름으로 추정, 교차 리뷰 X05)
  local o
  case "$1" in "$ROOT"/*) ;; *) [ "${HOST_FILES:-0}" = 1 ] || { hostkey_name "$1"; return; };; esac
  if [ -r "$1" ] && [ -n "$SK" ] && o=$("$SK" -l -f "$1" 2>/dev/null </dev/null); then
    printf '%s' "$o" | awk '{t=$NF; gsub(/[()]/,"",t); print t"-"$1; exit}'; return; fi
  [ -r "$1.pub" ] && o=$(awk '{print $1; exit}' "$1.pub") && [ -n "$o" ] && { echo "$o"; return; }   # 이 ssh-keygen이 모르는 형식
  hostkey_name "$1"
}
hostkey_name() { case "$(lc "${1##*/}")" in *mldsa*) echo "ML-DSA(파일 이름 추정)";; *ecdsa*) echo ECDSA;; *ed25519*) echo Ed25519;; *rsa*) echo RSA;; *dsa*) echo DSA;; *) echo "미확인($1)";; esac; }
scan_ssh() {
  find "$ROOT" $PRUNE -type f \( -name 'sshd_config*' -o -name ssh_config -o -path '*/sshd_config.d/*' -o -path '*/ssh_config.d/*' -o -path '*/.ssh/config' \) -print 2>/dev/null | skip_out "$SKIPL" |
  while IFS= read -r f; do
    local r=${f#"$ROOT"/} dn="" ; case "$r" in */*_config.d/*) dn="드롭인: 먼저 읽힌 값 적용(sshd -T로 실효값 확인)";; esac
    [ -r "$f" ] || { add "$r" "키교환·서명(SSH)" "SSH 설정(읽기 권한 없음)" 미확인 확인 "sudo로 다시 스캔 또는 sudo sshd -T" "RHEL 계열은 sshd_config 0600·sshd_config.d 0700(CentOS Stream 9 openssh.spec)"; continue; }
    grep -n -i -E '^[[:space:]]*(hostkey|kexalgorithms|ciphers|macs|hostkeyalgorithms|pubkeyacceptedalgorithms|pubkeyacceptedkeytypes|casignaturealgorithms)[[:space:]=]' "$f" |
    while IFS= read -r h; do
      local ln=${h%%:*} t d v lv a pq="" cl="" x; t=$(trim "${h#*:}"); d=$(lc "${t%%[[:space:]=]*}"); v=$(trim "${t#*[[:space:]=]}"); v=$(trim "${v#=}"); lv=$(lc "$v")
      case "$d" in
        hostkey) a=$(hostkey_alg "$v"); verdict 서명 "$a"; x=""
          case "$v" in "$ROOT"/*) ;; *) [ "${HOST_FILES:-0}" = 1 ] || x="트리 밖 파일은 열지 않음(이름으로 추정)";; esac
          add "$r:$ln" "서명(SSH 호스트키)" "$a" "$TH" "$PR" "$SSHRP" "$(note "$dn" "$x" "$v")";;
        kexalgorithms)
          for x in $(printf '%s' "${lv#[-+^]}" | tr ',' ' '); do case "$x" in *mlkem*|*sntrup*) pq="${pq:+$pq,}$x";; *) cl="${cl:+$cl,}$x";; esac; done
          case "$lv" in -*) add "$r:$ln" "키교환(SSH)" "$v" "미확인(기본값에서 제거)" 확인 "sshd -T로 실효값 확인" "$dn";;
            *) if [ -n "$pq" ]; then add "$r:$ln" "키교환(SSH)" "$v" "안전(PQC 하이브리드)" 참고 유지 "$(note "$dn" "${cl:+고전 폴백 허용($cl)}")"
               else add "$r:$ln" "키교환(SSH)" "$v" "쇼어로 깨짐" P1 "$SSHKX" "$dn"; fi;; esac;;
        ciphers) verdict 암호화 "$v"; add "$r:$ln" "암호화(SSH)" "$v" "$TH" "$PR" "$RP" "$dn";;
        macs) verdict 해시 "$v"; add "$r:$ln" "무결성(SSH MAC)" "$v" "$TH" "$PR" "$RP" "$dn";;
        *) verdict 서명 "$v"; case ",$lv," in *,ssh-rsa,*) WN=$(note "$WN" "ssh-rsa = SHA-1 서명(OpenSSH 8.8부터 기본 비활성)");; esac
           add "$r:$ln" "서명(SSH $d)" "$v" "$TH" "$PR" "$SSHRP" "$(note "$dn" "$WN")";;
      esac
    done
    if [ "${f##*/}" = sshd_config ] && ! grep -q -i -E '^[[:space:]]*kexalgorithms' "$f" && ! { [ -d "${f%/*}/sshd_config.d" ] && grep -r -q -i -E '^[[:space:]]*kexalgorithms' "${f%/*}/sshd_config.d"; }; then
      add "$r" "키교환(SSH)" "KexAlgorithms 미지정 → OpenSSH 기본값" "미확인(서버 버전 의존)" P1 "OpenSSH 10.0+ 기본 mlkem768x25519-sha256 · 9.0+ 기본 sntrup761x25519-sha512@openssh.com: ssh -V·sshd -T로 확인" ""
    fi
  done
}

# ---------- 키·인증서·키스토어 ----------
pkname() { case "$1" in
  rsaEncryption|RSA|rsassaPss) echo RSA;; id-ecPublicKey) echo EC;; dsaEncryption|DSA) echo DSA;; dhKeyAgreement|X9.42\ DH) echo DH;;
  2.16.840.1.101.3.4.3.17) echo ML-DSA-44;; 2.16.840.1.101.3.4.3.18) echo ML-DSA-65;; 2.16.840.1.101.3.4.3.19) echo ML-DSA-87;;
  2.16.840.1.101.3.4.4.1) echo ML-KEM-512;; 2.16.840.1.101.3.4.4.2) echo ML-KEM-768;; 2.16.840.1.101.3.4.4.3) echo ML-KEM-1024;;
  2.16.840.1.101.3.4.3.2[0-9]|2.16.840.1.101.3.4.3.3[01]) echo SLH-DSA;;
  1.3.101.112|Ed25519|ED25519) echo ED25519;; 1.3.101.113|Ed448|ED448) echo ED448;; 1.3.101.110|X25519) echo X25519;; 1.3.101.111|X448) echo X448;;
  *) echo "$1";; esac; }
keytext_alg() { # openssl -text 출력 → "RSA-2048" / "EC-256 prime256v1" / "ML-DSA-65"
  awk 'NR==1 && /^[A-Za-z0-9-]+ (Private|Public)-Key/ {a=$1}
       /(Private|Public)-Key: \(/ {s=$0; sub(/.*Key: \(/,"",s); sub(/ bit.*/,"",s); b=s}
       /^ *[Mm]odulus:/ {k="RSA"} /ASN1 OID:/ {s=$0; sub(/.*ASN1 OID: */,"",s); c=s; k="EC"}
       /^ *(P|prime):/ {if(k=="") k="DSA"} /Field Type:/ {k="EC"}
       END {if(a=="") a=k; if(a=="") exit; printf "%s%s%s\n", a, (b!="" && a !~ /[0-9]/ ? "-" b : ""), (c!="" ? " " c : "")}'
}
spki() { # stdin=PEM 공개키 → "공개키 DER(SubjectPublicKeyInfo) SHA-256 <TAB> 위치$1". 못 읽으면 아무것도 안 낸다(빈 입력의 해시 e3b0…를 지문으로 쓰지 않게)
  "$O" pkey -pubin -outform DER -out "$TMP/spki" 2>/dev/null && [ -s "$TMP/spki" ] && printf '%s\t%s\n' "$("$O" dgst -sha256 "$TMP/spki" | awk '{print $NF}')" "$1"; rm -f "$TMP/spki"; }
# 같은 공개키 인증서가 있는 고전 개인키 → 인증서 서명키(TLS 1.3에서는 CertificateVerify 서명에만 씀) P2 · 비고에 짝 위치
pair_keys() {
  [ -s "$TMP/keypub" ] && [ -s "$TMP/certpub" ] || return 0
  awk -F'\t' -v OFS='\t' -v kp="$TMP/keypub" -v cp="$TMP/certpub" -v rp="ML-DSA-65(FIPS 204): 인증서와 같이 재발급" \
    -v rsa="TLS 1.2 정적 RSA 키 전송(ECDHE 없는 TLS_RSA_* 스위트)을 허용하면 이 키가 세션 키를 푼다 → P1" '
    BEGIN { while ((getline l < cp) > 0) { split(l, a, "\t"); if (!(a[1] in c)) c[a[1]] = a[2]; else x[a[1]]++ }
            while ((getline l < kp) > 0) { split(l, a, "\t"); if (a[1] in c) m[a[2]] = c[a[1]] (x[a[1]] ? " 외 " x[a[1]] "곳" : "") } }
    ($2 in m) && index($3, "개인키(") == 1 && $5 == "쇼어로 깨짐" { $1 = ($1 >= 10 ? 12 : 2); $3 = "개인키(인증서 짝)"; $6 = "P2"; $7 = rp
      n = "인증서 짝: " m[$2]; if (index($4, "RSA") == 1) n = n " · " rsa
      # 주석·시험 표시(flag_of)는 비고 맨 앞에 남긴다: pqlite/rules.py cbom_flags 가 맨 앞만 읽는다(시험 폴더의 키·인증서 짝이 막는 위치가 됐다)
      f = ""; r = $8; sep = " · "
      while (1) { k = index(r, sep); p = (k ? substr(r, 1, k - 1) : r); if (p != "주석" && p != "테스트·예제") break
        f = f p sep; r = (k ? substr(r, k + length(sep)) : "") }
      $8 = f n (r == "" ? "" : sep r) }
    { print }' "$ROWS" > "$TMP/rows2" && mv "$TMP/rows2" "$ROWS"
}
key_row() { # 블록 형식(PEM|DER) 위치 pub|priv 비고
  local t a o
  if [ "$4" = pub ]; then t=$("$O" pkey -pubin -inform "$2" -in "$1" -noout -text 2>/dev/null); else t=$("$O" pkey -inform "$2" -in "$1" -noout -text -passin pass: 2>/dev/null </dev/null)
    "$O" pkey -inform "$2" -in "$1" -pubout -passin pass: 2>/dev/null </dev/null | spki "$3" >> "$TMP/keypub"; fi
  a=$(printf '%s\n' "$t" | keytext_alg)
  if [ -z "$a" ]; then o=$("$O" asn1parse -inform "$2" -in "$1" 2>/dev/null | sed -n -E 's/.*OBJECT *:(.*)$/\1/p' | head -1); [ -n "$o" ] && a="$(pkname "$o")"; fi
  [ -z "$a" ] && return 1
  case "$a" in ED25519|ED448|X25519|X448|ML-*|SLH-*) ;; *) a="$(pkname "${a%%[- ]*}")${a#"${a%%[- ]*}"}";; esac
  local u; [ "$4" = pub ] && u="공개키($(autouse "$a"))" || u="개인키($(autouse "$a"))"
  verdict "$u" "$a"; add "$3" "$u" "$a" "$TH" "$PR" "$RP" "$5"
}
cert_row() { # 블록 형식 위치 비고 [x509|req]
  local c=${5:-x509} t sig pk kb yr sub="" ca="" ex="" life="" a th pr rp wn
  t=$("$O" "$c" -inform "$2" -in "$1" -noout -text 2>/dev/null) || return 1
  sig=$(pkname "$(printf '%s\n' "$t" | sed -n -E 's/^ *Signature Algorithm: *(.*)$/\1/p' | head -1)")
  pk=$(pkname "$(printf '%s\n' "$t" | sed -n -E 's/^ *Public Key Algorithm: *(.*)$/\1/p' | head -1)")
  kb=$(printf '%s\n' "$t" | sed -n -E '/Subject Public Key Info/,/X509v3|Attributes|Signature Algorithm/p' | keytext_alg)
  case "$kb" in ""|EC*|RSA*|DSA*) a="${kb:-$pk}";; *) a=$pk;; esac
  if [ "$c" = x509 ]; then
    yr=$("$O" x509 -inform "$2" -in "$1" -noout -enddate 2>/dev/null | grep -o -E '[0-9]{4}' | tail -1)
    sub=$("$O" x509 -inform "$2" -in "$1" -noout -subject 2>/dev/null); sub=$(trim "${sub#subject=}")
    "$O" x509 -inform "$2" -in "$1" -noout -checkend 0 >/dev/null 2>&1 || ex="만료됨"
    "$O" x509 -inform "$2" -in "$1" -noout -pubkey 2>/dev/null | spki "$3" >> "$TMP/certpub"
  fi
  printf '%s' "$t" | grep -q 'CA:TRUE' && ca="CA:TRUE: 이 키로 서명한 하위 인증서도 재발급"
  verdict 인증서 "$sig"; th=$TH pr=$PR rp=$RP wn=$WN
  case "$th" in 안전*|미확인*) verdict 인증서 "$a"; th=$TH pr=$PR rp=$RP wn=$(note "$wn" "$WN");; esac
  if [ "$th" = "쇼어로 깨짐" ] && [ -n "$yr" ]; then
    if [ "$yr" -gt 2035 ]; then life="만료 $yr: 2035 이후 금지 구간까지 유효($NISTRP)"
    elif [ "$yr" -gt 2030 ]; then life="만료 $yr: 2030 이후 비권장 구간($NISTRP)"; fi
  fi
  add "$3" "인증서${ca:+(CA)}" "$a / 서명 $sig" "$th" "$pr" "$rp" "$(note "$4" "$ex" "${life:-${yr:+만료 $yr}}" "$ca" "$wn" "$sub")"
}
ssh_rows() { # 파일 위치접두 용도 비고 → ssh-keygen -l 줄마다 한 행
  local o="" i=0 a
  [ -n "$SK" ] && o=$("$SK" -l -f "$1" 2>/dev/null </dev/null | awk '{t=$NF; gsub(/[()]/,"",t); print t"-"$1}')
  # ssh-keygen이 없거나 모르는 형식(PQ 키 등)이면 형식 이름만: 공개키 줄의 AAAA 앞 필드, 개인키는 base64를 풀어 형식 문자열
  [ -z "$o" ] && o=$(awk '{for (i=1;i<NF;i++) if ($(i+1) ~ /^AAAA/) {print $i; break}}' "$1")
  [ -z "$o" ] && o=$(grep -v -e '-----' "$1" | tr -d '\r\n' | base64 -d 2>/dev/null | grep -a -o -E '(ssh|sk)-[a-z0-9@.-]+|ecdsa-sha2-[a-z0-9]+' | grep -v '^ssh-key-v1' | head -1)
  [ -z "$o" ] && return 1
  printf '%s\n' "$o" | while IFS= read -r a; do i=$((i+1)); verdict 서명 "$a"
    add "$2$( [ $i -gt 1 ] && echo "#$i")" "$3" "$a" "$TH" "$PR" "$SSHRP" "$4"; done
}
pem_blocks() { # 파일 표시경로 비고 [위치 고정]
  local p="$TMP/b$RANDOM" n=0 ln ty
  awk -v p="$p" '{sub(/^[ \t]+/,"")} /^-----BEGIN /{n++; f=p "." n; printf "%d\t%s\n", NR, $0 > (p ".idx"); inb=1} inb{print > f} /^-----END /{if(inb) close(f); inb=0}' "$1"   # YAML 블록 등 들여쓴 PEM도
  [ -f "$p.idx" ] || return
  local nc; nc=$(grep -c 'CERTIFICATE-----' "$p.idx")
  if [ "$nc" -gt 10 ]; then   # 공용 CA 묶음(ca-certificates.crt·tls-ca-bundle.pem)은 한 행: 수백 행이 서비스 자산을 묻지 않게
    n=$(wc -l < "$p.idx" | tr -d ' ')
    add "$2" "인증서(신뢰 저장소 묶음)" "인증서 ${nc}개" "미확인(묶음: 개별 파싱 생략)" 참고 "공용 CA 묶음이면 서비스 자산 아님: 사설 PQC CA를 쓰면 그 루트만 추가" "$(note "$3" "인증서 10개 넘는 파일은 요약")"
    : > "$p.idx"
  fi
  while IFS="$TAB" read -r ln ty <&3; do n=$((n+1)); ty=${ty#-----BEGIN }; ty=${ty%%-----*}; local L=${4:-$2:$ln}
    case "$ty" in
      CERTIFICATE|"TRUSTED CERTIFICATE"|"X509 CERTIFICATE") cert_row "$p.$n" PEM "$L" "$3" || add "$L" 인증서 "파싱 실패" 미확인 확인 "openssl 버전 확인" "$3";;
      *"CERTIFICATE REQUEST") cert_row "$p.$n" PEM "$L" "$(note "$3" CSR)" req || add "$L" 인증서 "CSR 파싱 실패" 미확인 확인 "수동 확인" "$3";;
      "ENCRYPTED PRIVATE KEY") add "$L" 개인키 "암호화된 PKCS#8(알고리즘 미확인)" 미확인 확인 "비밀번호로 열어 확인" "$3";;
      "OPENSSH PRIVATE KEY") ssh_rows "$p.$n" "$L" "개인키(SSH)" "$3" || add "$L" "개인키(SSH)" "OpenSSH 키(파싱 실패)" 미확인 확인 "수동 확인" "$3";;
      *"PRIVATE KEY") key_row "$p.$n" PEM "$L" priv "$3" || { local g=${ty% PRIVATE KEY}; verdict 개인키 "$g"; add "$L" 개인키 "$g(파싱 실패: 암호화·형식 확인)" "$TH" "$PR" "$RP" "$3"; };;
      "PUBLIC KEY"|"RSA PUBLIC KEY") key_row "$p.$n" PEM "$L" pub "$3" || add "$L" 공개키 "파싱 실패" 미확인 확인 "수동 확인" "$3";;
      *"DH PARAMETERS") add "$L" 키교환 "DH 파라미터" "쇼어로 깨짐" P1 "DHE 제거 → X25519MLKEM768" "$3";;
      "EC PARAMETERS") add "$L" 키교환·서명 "EC 파라미터" "쇼어로 깨짐" P1 "ML-KEM-768 · ML-DSA-65" "$3";;
      *) add "$L" 기타 "PEM $ty" 미확인 확인 "수동 확인" "$3";;
    esac
  done 3< "$p.idx"
  rm -f "$p.idx"; while [ $n -gt 0 ]; do rm -f "$p.$n"; n=$((n-1)); done
}
scan_file() { # 파일 표시경로 [비고]
  [ -r "$1" ] || { add "$2" 기타 "키·인증서 파일(읽기 권한 없음)" 미확인 확인 "sudo로 다시 스캔" "${3:-}"; return; }
  if grep -q -e '-----BEGIN ' "$1" 2>/dev/null; then pem_blocks "$1" "$2" "${3:-}"
  elif head -c 2000 "$1" 2>/dev/null | grep -q -E '(^|[[:space:]])((ssh|sk)-[a-z0-9@.-]+|ecdsa-sha2-[a-z0-9]+) AAAA'; then
    local su="공개키(SSH)"; case "${1##*/}" in *known_hosts*) su="서명(SSH 호스트 키 고정, known_hosts)";; esac   # 교차 리뷰 X59
    ssh_rows "$1" "$2" "$su" "${3:-}" || add "$2" "$su" "SSH 공개키(형식 미확인)" 미확인 확인 "수동 확인" "${3:-}"
  else cert_row "$1" DER "$2" "${3:-}" || key_row "$1" DER "$2" priv "${3:-}" || key_row "$1" DER "$2" pub "${3:-}" ||
    add "$2" 기타 "키·인증서 파일(형식 미확인)" 미확인 확인 "수동 확인" "${3:-}"; fi
}
scan_keys() {
  { find "$ROOT" $PRUNE -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.cer' -o -name '*.der' -o -name '*.key' -o -name '*.p8' -o -name '*.pk8' \
      -o -name '*.csr' -o -name '*.pub' -o -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'id_dsa' -o -name 'authorized_keys' -o -name 'ssh_host_*' \
      -o -name 'known_hosts' -o -name 'known_hosts2' -o -name 'ssh_known_hosts' \) -print 2>/dev/null | skip_out "$SKIPL"
    G -l -e '^[[:space:]]*-----BEGIN '; } | sort -u | while IFS= read -r f; do flag_of "${f#"$ROOT"/}" ""; scan_file "$f" "${f#"$ROOT"/}" "$FL"; done
  find "$ROOT" $PRUNE -type f \( -name '*.jks' -o -name '*.keystore' -o -name '*.truststore' -o -name '*.p12' -o -name '*.pfx' -o -name '*.jceks' -o -name '*.bks' \) -print 2>/dev/null | skip_out "$SKIPL" |
  while IFS= read -r f; do flag_of "${f#"$ROOT"/}" ""; scan_store "$f" "${f#"$ROOT"/}" "$FL"; done   # 시험 폴더 키스토어도 표시(교차 리뷰 X24)
}
passhint() { # 키스토어 폴더의 비밀번호 후보: 파일 이름과 설정 키 이름만 적고 값은 출력하지 않는다
  local h; h=$( { find "${1%/*}" -maxdepth 1 -type f \( -name '*.pass' -o -name '*.passfile' -o -name '*.password' -o -name '*.pwd' -o -name '*pass*.txt' \) 2>/dev/null
    find "${1%/*}" -maxdepth 1 -type f \( -name '*.properties' -o -name '*.conf' -o -name '*.yml' -o -name '*.yaml' -o -name '*.env' -o -name '*.ini' -o -name '*.cfg' \) \
      -exec grep -n -i -H -E "^[[:space:]]*[\"']?[A-Za-z0-9_.-]*pass[A-Za-z0-9_.-]*[\"']?[[:space:]]*[:=]" {} + 2>/dev/null |
      sed -n -E "s/^([^:]*:[0-9]+):[[:space:]]*[\"']?([A-Za-z0-9_.-]+).*/\\1 \\2/p"; } |
    awk -v r="$ROOT/" 'index($0, r) == 1 {$0 = substr($0, length(r) + 1)} {printf "%s%s", (NR > 1 ? " · " : ""), $0}')
  [ -n "$h" ] && printf '%s' "비밀번호 후보(값은 출력 안 함): $h → STOREPASS=\"\$(cat 파일)\"로 다시 스캔"
}
scan_store() { # 파일 표시경로 [주석·시험 표시]. 비밀번호 후보는 명령줄 대신 환경 변수로 넘긴다(ps 에 안 보이게, 교차 리뷰 X33)
  local f=$1 r=$2 fl=${3:-} out="" p how="" al
  if [ -n "$KT" ]; then
    for p in ${STOREPASS:-changeit changeme password secret}; do
      out=$(PQP_STOREPASS=$p "$KT" -J-Duser.language=en -J-Duser.country=US -list -v -keystore "$f" -storepass:env PQP_STOREPASS 2>/dev/null </dev/null) && { how=비밀번호; break; }; out=""; done
    [ -z "$out" ] && out=$(printf '\n' | "$KT" -J-Duser.language=en -J-Duser.country=US -list -v -keystore "$f" 2>/dev/null) && how="비밀번호 없이 목록만(무결성 미검증)"
  fi
  # PKCS12를 비밀번호 없이 열면 별칭만 나오고 인증서는 안 나온다(시험에서 .p12가 0행이었다) → 인증서 줄이 있을 때만 여기서 끝낸다
  if printf '%s' "$out" | grep -q '^Subject Public Key Algorithm:'; then
    printf '%s\n' "$out" | awk -F': ' '/^Alias name:/{al=$2; n=0} /^Entry type:/{et=$2} /^Certificate\[[0-9]+\]:/{n++}
      /until: /{u=$0; sub(/.*until: /,"",u)} /^Signature algorithm name:/{sg=$2}
      /^Subject Public Key Algorithm:/{print al"\t"et"\t"n"\t"$2"\t"sg"\t"u}' |
    while IFS="$TAB" read -r al et n pk sg u; do
      pk=$(printf '%s' "$pk" | sed -E 's/^([0-9]+)-bit ([A-Za-z0-9-]+)( \(([^)]*)\))? key$/\2-\1 \4/; s/ key$//'); pk=$(trim "$pk")
      verdict 인증서 "$sg"; case "$TH" in 안전*|미확인*) verdict 인증서 "$pk";; esac
      add "$r#$al$( [ "${n:-0}" -gt 1 ] && echo "[$n]")" "인증서(키스토어 $et)" "$pk / 서명 $sg" "$TH" "$PR" "$RP" "$(note "$fl" "$how" "${u:+만료 ${u##* }}")"
    done; return
  fi
  al=$(printf '%s\n' "$out" | awk -F': ' '/^Alias name:/{a=$2} /^Entry type:/{printf "%s%s(%s)", (n++ ? ", " : ""), a, $2}')
  case "$f" in *.p12|*.pfx)
    for p in ${STOREPASS:-changeit changeme password secret}; do
      for lg in "" -legacy; do out=$(PQP_STOREPASS=$p "$O" pkcs12 $lg -in "$f" -nokeys -passin env:PQP_STOREPASS 2>/dev/null </dev/null) && [ -n "$out" ] && break 2; out=""; done; done
    if [ -n "$out" ]; then printf '%s\n' "$out" > "$TMP/p12.pem"; pem_blocks "$TMP/p12.pem" "$r#pem" "$(note "$fl" "PKCS#12(openssl)")"; rm -f "$TMP/p12.pem"; return; fi;; esac
  if [ "$how" = 비밀번호 ]; then   # 열렸는데 공개키 알고리즘 줄이 없다: 그 줄을 안 찍는 옛 keytool(Owner: 줄은 있음) → -rfc PEM으로, 아니면 대칭키(SecretKeyEntry)만
    if printf '%s' "$out" | grep -q '^Owner:'; then
      PQP_STOREPASS=$p "$KT" -J-Duser.language=en -J-Duser.country=US -list -rfc -keystore "$f" -storepass:env PQP_STOREPASS 2>/dev/null </dev/null > "$TMP/ks.pem"
      pem_blocks "$TMP/ks.pem" "$r#rfc" "$(note "$fl" "키스토어(keytool -rfc)")"; rm -f "$TMP/ks.pem"; return; fi
    add "$r" "인증서(키스토어)" "키스토어(열림: 인증서 항목 없음)" 미확인 확인 "항목 확인: SecretKeyEntry는 대칭키(AES-256인지)" "$(note "$fl" "${al:+항목: $al}")"; return; fi
  add "$r" "인증서(키스토어)" "키스토어(열지 못함: STOREPASS 지정)" 미확인 확인 "STOREPASS로 비밀번호를 주고 다시 스캔(keytool -list -v)" \
    "$(note "$fl" "${al:+keytool 목록만: $al}" "$(passhint "$f")" "$( [ -n "$KT" ] || echo "keytool 없음")")"
}

# 문자열 속 PEM(.env·JSON·코드의 "-----BEGIN ...\n..."): \n 이스케이프를 풀어 같은 파서에 넣는다
scan_embedded() {
  G $CODE $CFG $NOLOCK -e '[^[:space:]].*-----BEGIN [A-Z0-9 ]+-----' | while IFS= read -r h; do
    local f=${h%%:*} rest=${h#*:} ln r; ln=${rest%%:*}; r=${f#"$ROOT"/}; seen "$r:$ln" && continue
    printf '%s\n' "$r:$ln" >> "$SEEN"; flag_of "$r" "${rest#*:}"
    printf '%s\n' "${rest#*:}" | awk '{gsub(/\\r/,""); gsub(/\\n/,"\n"); gsub(/-----BEGIN /,"\n-----BEGIN "); gsub(/-----END [A-Z0-9 ]+-----/,"&\n"); print}' > "$TMP/emb.pem"
    pem_blocks "$TMP/emb.pem" "$r" "$(note "$FL" "문자열 속 PEM")" "$r:$ln"; rm -f "$TMP/emb.pem"
  done
}

# ---------- 일반 패턴(놓치지 않기) ----------
scan_generic() {
  local CORE='rsa|ecdsa|ecdhe?|dsa|ed25519|x25519|secp256r1|secp384r1|secp521r1|secp256k1|prime256v1|[rpe]s(256|384|512)|eddsa|md5|sha-?1|3?des|desede|tripledes|rc4|arc4|arcfour|ecb|sslv3|ml-?kem-?[0-9]*|ml-?dsa-?[0-9]*|slh-?dsa(-(sha2|shake)-?[0-9]+[sf]?)?|x25519mlkem768|sha[0-9]*with(rsa|ecdsa|dsa)[a-z]*' RE
  # TLSv1·1.0·1.1만. 뒤가 '.'·숫자면(TLSv1.2·1.3) 안 맞게 경계를 따로 둔다(시험에서 proxy_ssl_protocols TLSv1.3 등 4행 오탐)
  RE="(^|[^A-Za-z0-9_])($CORE)([^A-Za-z0-9_]|\$)|(^|[^A-Za-z0-9_])(tlsv1(\\.[01])?)([^.0-9A-Za-z_]|\$)"
  G -i $CODE $CFG $NOLOCK -e "$RE" | while IFS= read -r h; do
    local f=${h%%:*} rest=${h#*:} ln txt r tk; ln=${rest%%:*}; txt=${rest#*:}; r=${f#"$ROOT"/}
    seen "$r:$ln" && continue
    tk=$(printf '%s\n' "$txt" | grep -o -i -E "$RE" | sed -E 's/^[^A-Za-z0-9]+//; s/[^A-Za-z0-9]+$//' | awk '!s[tolower($0)]++' | tr '\n' ',' | sed 's/,$//')
    [ -z "$tk" ] && continue
    local u t k b=9 bu bt bp br pq="" w; verdict "$(autouse "${tk%%,*}")" "$tk"; w=$WN
    for t in $(printf '%s' "$tk" | tr ',' ' '); do   # 한 줄에 이름이 여럿이면 가장 급한 것: PQC 이름이 고전 이름을 가리지 않게
      u=$(autouse "$t"); verdict "$u" "$t"; [ "$TH" = "안전(PQC)" ] && pq=1
      case "$PR" in P1) k=1;; P2) k=2;; P3) k=3;; 확인) k=4;; *) k=5;; esac
      [ $k -lt $b ] && { b=$k; bu=$u; bt=$TH; bp=$PR; br=$RP; }
    done
    [ -n "$pq" ] && [ $b -lt 5 ] && pq="PQC 이름도 함께 있음(전환·하이브리드 코드일 수 있음)" || pq=""
    local lt; lt=$(lc "$txt")
    if [[ $lt =~ $COMPRE ]] && ! [[ $lt =~ $WEAKPQ ]]; then bu=서명; bt=$COMPTH; bp=P2; br=$COMPRP; pq=""; fi   # 복합 서명 줄(X26)
    flag_of "$r" "$txt"
    add "$r:$ln" "$bu" "$tk" "$bt" "$bp" "$br" "$(note "$FL" "일반 패턴: 문맥 확인" "$pq" "$w" "$(snip "$txt")")"
  done
}

# ---------- 살아 있는 엔드포인트 ----------
to() { local s=$1; shift; if [ -n "$TO" ]; then "$TO" "$s" "$@"; return; fi
  "$@" & local p=$!; ( sleep "$s"; kill "$p" 2>/dev/null ) >/dev/null 2>&1 & local w=$!; wait "$p"; local rc=$?; kill "$w" 2>/dev/null; return $rc; }
handshake_ok() { printf '%s\n' "$1" | grep -q -E 'Cipher is [A-Z0-9_-]+' && ! printf '%s\n' "$1" | grep -q 'Cipher is (NONE)'; }
probe() {
  local hp=$1 host=${1%:*} sni="" g="" out grp proto cs n="" e
  case "$host" in *[!0-9.]*) sni="-servername $host";; esac
  [ $MLKEM = 1 ] && g="-groups X25519MLKEM768:X25519:P-256:P-384"
  out=$(to 10 "$O" s_client -connect "$hp" $sni $g -showcerts </dev/null 2>&1)
  if ! handshake_ok "$out"; then e=$(printf '%s\n' "$out" | grep -i -E 'error|refused|alert|timed|unknown' | head -1)
    n="접속·포트 확인"; [ $MLKEM = 1 ] || n="ML-KEM 있는 클라이언트(OpenSSL 3.5+ 또는 tls_probe)로 다시: 이 OpenSSL은 PQC 그룹을 못 보내 PQC 전용 서버에 alert 40"
    add "$hp" "TLS 엔드포인트" "핸드셰이크 실패" 미확인 확인 "$n" "$(snip "${e:-응답 없음}")"; return; fi
  grp=$(printf '%s\n' "$out" | sed -n -E 's/^Negotiated TLS1\.3 group: *(.*)$/\1/p' | head -1)
  [ -z "$grp" ] && grp=$(printf '%s\n' "$out" | sed -n -E 's/^(Server|Peer) Temp Key: *(ECDH, *)?([^,]*).*/\3/p' | head -1)
  proto=$(printf '%s\n' "$out" | sed -n -E 's/^[[:space:]]*Protocol *: *(.*)$/\1/p' | head -1)
  cs=$(printf '%s\n' "$out" | sed -n -E 's/.*Cipher is *([^[:space:]]+).*/\1/p' | head -1)
  verdict 키교환 "${grp:-미확인}"
  if [ $MLKEM = 0 ]; then n="클라이언트 OpenSSL에 ML-KEM 없음 → 서버 PQC 지원 여부 미확인"
  elif [ "${TH#안전}" != "$TH" ]; then
    handshake_ok "$(to 10 "$O" s_client -connect "$hp" $sni -groups X25519:P-256:P-384:P-521 </dev/null 2>&1)" \
      && n="고전 전용 클라이언트도 허용(폴백: 구형 클라이언트 경로 HNDL)" || n="고전 전용 요청 거부(강등 차단)"; fi
  [ "$TH" = "쇼어로 깨짐" ] && RP=$TLSRP
  add "$hp" "키교환(TLS 협상)" "${grp:-미확인} (${proto:-?})" "$TH" "$PR" "$RP" "$(note "$n" "${g:+탐침이 보낸 그룹 ${g#-groups }(권장값 아님)}")"
  verdict 암호화 "$cs"; add "$hp" "암호화(협상 스위트)" "$cs" "$TH" "$PR" "$RP" ""
  printf '%s\n' "$out" | awk '/-----BEGIN CERTIFICATE-----/{f=1} f{print} /-----END CERTIFICATE-----/{exit}' > "$TMP/ep.pem"
  [ -s "$TMP/ep.pem" ] && cert_row "$TMP/ep.pem" PEM "$hp" "서버 인증서(리프)"; rm -f "$TMP/ep.pem"
}

# ---------- 출력 ----------
render() { # md csv 명령줄
  local s="$TMP/sorted"
  sort -t "$TAB" -k1,1n -k2,2 "$ROWS" | awk '!s[$0]++' > "$s"
  utf() { if command -v iconv >/dev/null; then iconv -c -f UTF-8 -t UTF-8; else cat; fi; }
  {
    echo "# 암호 자산 목록(CBOM): ${ROOT}"
    echo
    echo "- 생성: $(date '+%Y-%m-%d %H:%M:%S %Z') · 명령: \`$3\`"
    echo "- 스캔 환경: $(uname -sr) · $("$O" version 2>/dev/null) (ML-KEM $( [ $MLKEM = 1 ] && echo 지원 || echo 미지원)) · $(ssh -V 2>&1 | head -1) · keytool $( [ -n "$KT" ] && echo 있음 || echo 없음)"
    awk -F'\t' '{n++; p[$6]++} END {printf "- 합계 %d건 · 우선순위: P1 %d · P2 %d · P3 %d · 확인 %d · 참고 %d\n", n, p["P1"], p["P2"], p["P3"], p["확인"], p["참고"]}' "$s"
    printf -- '- 양자 위협:'; cut -f5 "$s" | sort | uniq -c | sort -rn | awk '{c=$1; $1=""; printf "%s%s %d", (NR>1?" ·":""), $0, c} END {print ""}'
    echo "- 우선순위: P1 = 키교환·공개키 암호화(지금 수집·나중 복호 HNDL에 직접 노출) · P2 = 서명·인증서(위조 위험, 소급 없음)·고전 취약 · P3 = 그로버 약화(대칭 키 길이 상향) · 확인 = 버전·설정 확인 필요 · 참고 = 이미 PQC·안전"
    echo "- 비고에 '주석'·'테스트·예제'가 붙은 행은 실제 운영 경로가 아닐 수 있어 표 아래로 내렸다. '일반 패턴' 행은 문자열만 맞은 것이라 문맥 확인이 필요하다."
    echo
    echo "| # | 위치 | 용도 | 알고리즘·키 길이 | 양자 위협 | 우선순위 | 권장 대체 | 근거·비고 |"
    echo "|---|---|---|---|---|---|---|---|"
    awk -F'\t' '{for (i=2;i<=8;i++) gsub(/\|/,"\\|",$i); printf "| %d | %s | %s | %s | %s | %s | %s | %s |\n", NR, $2,$3,$4,$5,$6,$7,$8}' "$s"
  } | utf > "$1"
  { printf '\357\273\277'; echo "번호,위치,용도,알고리즘·키 길이,양자 위협,우선순위,권장 대체,근거·비고"
    awk -F'\t' '{printf "%d", NR; for (i=2;i<=8;i++) {v=$i; gsub(/"/,"\"\"",v); printf ",\"%s\"", v}; print ""}' "$s"; } | utf > "$2"
}

scan() { # DIR [host:port|파일 ...]
  ROOT=$(cd "$1" 2>/dev/null && pwd) || { echo "디렉터리 없음: $1" >&2; exit 2; }; shift
  SKIPL=$TMP/skip; skip_dirs "$ROOT" > "$SKIPL" || exit 2   # 건너뛸 폴더(G 와 find 결과를 skip_out 으로 거른다)
  skip_names "$ROOT"; PRUNE="-mindepth 1 ( -type d ( $SK_PRUNEX ) ) -prune -o"
  GX=""; for x in $SK_PRUNEL; do GX="$GX --exclude-dir=$x"; done
  scan_keys; scan_embedded; scan_ssh; scan_tls; scan_code; scan_generic
  local a l; for a in "$@"; do
    if [ -f "$a" ]; then while IFS= read -r l; do l=$(trim "${l%%#*}"); [ -n "$l" ] && probe "$l"; done < "$a"; else probe "$a"; fi; done
  pair_keys
}

# ---------- 자가 시험 ----------
gen_fixtures() {
  local g=$FIX/gen pw; [ -f "$g/.done" ] || { mkdir -p "$g"
  "$O" req -x509 -newkey rsa:2048 -nodes -keyout "$g/rsa2048.key" -out "$g/rsa-server.crt" -subj /CN=localhost -days 3650 -sha256 2>/dev/null
  "$O" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$g/ec-ca.key" -out "$g/ec-ca.crt" -subj "/CN=Demo EC CA" -days 7300 -addext basicConstraints=critical,CA:TRUE 2>/dev/null
  cat "$g/ec-ca.crt" "$g/rsa-server.crt" > "$g/chain.pem"
  "$O" x509 -in "$g/rsa-server.crt" -outform DER -out "$g/rsa-server.der"
  "$O" genpkey -algorithm ED25519 -out "$g/ed25519.key" 2>/dev/null
  "$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc -pass pass:fixture -out "$g/enc.key" 2>/dev/null
  "$O" pkcs12 -export -in "$g/rsa-server.crt" -inkey "$g/rsa2048.key" -name server -out "$g/server.p12" -passout pass:changeit 2>/dev/null
  if "$O" list -signature-algorithms 2>/dev/null | grep -qi ml-dsa; then
    "$O" req -x509 -newkey ML-DSA-65 -nodes -keyout "$g/mldsa65.key" -out "$g/mldsa65.crt" -subj /CN=localhost -days 30 2>/dev/null
    "$O" genpkey -algorithm ML-KEM-768 -out "$g/mlkem768.key" 2>/dev/null; fi
  [ -n "$SK" ] && { "$SK" -q -t rsa -b 2048 -N '' -C fixture -f "$g/id_rsa"; "$SK" -q -t ed25519 -N '' -C fixture -f "$g/id_ed25519"; }
  [ -n "$KT" ] && "$KT" -genkeypair -alias legacy -keyalg EC -keysize 256 -sigalg SHA256withECDSA -dname CN=legacy -validity 365 \
    -storetype JKS -keystore "$g/legacy.jks" -storepass changeit -keypass changeit >/dev/null 2>&1
  touch "$g/.done"; }
  # 추가분(이미 있는 gen/ 에도 생기게 따로): 짝 인증서 없는 RSA 개인키 · 비밀번호를 모르는 .p12(같은 폴더 비밀번호 파일·설정 키)
  [ -f "$g/solo.key" ] || "$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$g/solo.key" 2>/dev/null
  [ -f "$g/locked/locked.p12" ] || { mkdir -p "$g/locked"; pw=$("$O" rand -hex 12); printf '%s\n' "$pw" > "$g/locked/ks.pass"
    printf 'keystore.path=locked.p12\nkeystore.passfile=ks.pass\n' > "$g/locked/app.properties"
    "$O" pkcs12 -export -in "$g/rsa-server.crt" -inkey "$g/rsa2048.key" -name locked -out "$g/locked/locked.p12" -passout "pass:$pw" 2>/dev/null; }
  # 시험 폴더의 키스토어(주석·시험 표시가 붙어야 한다, 교차 리뷰 X24)
  [ -f "$g/test/ks.p12" ] || { mkdir -p "$g/test"; "$O" pkcs12 -export -in "$g/rsa-server.crt" -inkey "$g/rsa2048.key" -name t -out "$g/test/ks.p12" -passout pass:changeit 2>/dev/null; }
  # 시험 폴더의 키·인증서 짝(인증서 짝 비고가 시험 표시 뒤에 붙어야 한다)
  [ -f "$g/test/pair.crt" ] || "$O" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$g/test/pair.key" -out "$g/test/pair.crt" -subj /CN=test -days 3650 2>/dev/null
  # 비밀번호로 열리지만 인증서가 없는 키스토어(대칭키만)
  [ -n "$KT" ] && [ ! -f "$g/secret.jceks" ] && "$KT" -genseckey -alias aes -keyalg AES -keysize 256 -storetype JCEKS -keystore "$g/secret.jceks" \
    -storepass changeit -keypass changeit >/dev/null 2>&1
  return 0
}
PASS=0; FAIL=0; SKIP=0
skip() { SKIP=$((SKIP + ${1:-1})); }   # 도구가 없어 못 돈 단언(통과로 세지 않는다). 요약 줄에 전체 단언 수와 함께 찍는다
ck() { # 위치 알고리즘 위협 우선순위 [비고]: 모두 부분 문자열(알고리즘만 대소문자 무시: 리눅스에서 fixtures 의 /etc/ssh 호스트키를 root 는 'RSA-3072'·'ED25519-256', 일반 사용자는 .pub 로 'ssh-rsa'로 읽는다: 우분투 컨테이너에서 확인)
  if awk -F'\t' -v l="$1" -v a="$2" -v t="$3" -v p="$4" -v n="${5:-}" 'index($2,l)&&(a==""||index(tolower($4),tolower(a)))&&(t==""||index($5,t))&&(p==""||index($6,p))&&(n==""||index($7" "$8,n)){f=1} END{exit !f}' "$ROWS"
  then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "  FAIL: $*"; fi; }
none() { if awk -F'\t' -v l="$1" 'index($2,l){f=1} END{exit !f}' "$ROWS"; then FAIL=$((FAIL+1)); echo "  FAIL(오탐): $1"; else PASS=$((PASS+1)); fi; }
nck() { # 위치 문자열: 그 위치의 어느 행이든 용도~비고에 문자열이 있으면 실패(잘못된 판정)
  if awk -F'\t' -v l="$1" -v s="$2" 'index($2,l) && index($3" "$4" "$5" "$6" "$7" "$8, s){f=1} END{exit !f}' "$ROWS"; then FAIL=$((FAIL+1)); echo "  FAIL(오판): $1 에 '$2'"; else PASS=$((PASS+1)); fi; }
selftest() {
  FIX=$HERE/fixtures; gen_fixtures; local g=$FIX/gen s1 s2="" lo=127.0.0.1: i=0 P1=$((10000 + $$ % 10000 * 2)); local P2=$((P1 + 1)) eps="127.0.0.1:$P1"   # PID별 포트 쌍(리눅스 임시 포트 범위 아래): 동시 실행해도 안 겹친다
  [ -s "$g/ca-bundle.pem" ] || while [ $i -lt 12 ]; do cat "$g/rsa-server.crt" >> "$g/ca-bundle.pem"; i=$((i+1)); done   # 신뢰 저장소 묶음 흉내
  "$O" s_server -help 2>&1 | grep -q -i 'accept.*host' || lo=""   # LibreSSL은 -accept에 포트만 받는다
  # LibreSSL s_server는 stdin이 EOF(</dev/null)면 핸드셰이크에 응답하지 않는다: 열린 stdin을 물린다(sleep은 호출자 파이프를 잡지 않게 2>/dev/null)
  "$O" s_server -accept ${lo}$P1 -cert "$g/rsa-server.crt" -key "$g/rsa2048.key" -groups X25519:P-256 -quiet < <(exec sleep 120 2>/dev/null) >/dev/null 2>&1 & s1=$!
  if [ $MLKEM = 1 ] && [ -f "$g/mldsa65.crt" ]; then
    "$O" s_server -accept ${lo}$P2 -cert "$g/mldsa65.crt" -key "$g/mldsa65.key" -groups X25519MLKEM768 -quiet < <(exec sleep 120 2>/dev/null) >/dev/null 2>&1 & s2=$!; eps="$eps 127.0.0.1:$P2"; fi
  sleep 1
  scan "$FIX" $eps
  { kill $s1 $s2; wait $s1 $s2; } 2>/dev/null
  # TLS 설정
  ck nginx/nginx.conf:9 TLSv1 "고전 취약" P2;  ck nginx/nginx.conf:10 ECDHE-RSA "쇼어로 깨짐" P1 "rc4-sha · AES-128"
  ck nginx/nginx.conf:11 prime256v1 "쇼어로 깨짐" P1; ck nginx/nginx.conf:12 DH "쇼어로 깨짐" P1
  ck nginx/sites-available/pqc:5 TLSv1.3 "해당 없음" 참고; ck nginx/sites-available/pqc:6 X25519MLKEM768 "안전" 참고 "고전 폴백 허용(X25519)"
  ck nginx/sites-available/pqc:7 X25519MLKEM768 "안전" 참고; ck nginx/conf.d/default-groups.conf:2 "그룹 미지정" "미확인" P1
  ck apache/ssl.conf:4 all "고전 취약" P2; ck apache/ssl.conf:5 RC4 "쇼어로 깨짐" P1 rc4-sha; ck apache/ssl.conf:6 secp384r1 "쇼어로 깨짐" P1
  ck haproxy/haproxy.cfg:2 P-256 "쇼어로 깨짐" P1; ck haproxy/haproxy.cfg:3 TLS_AES_128 "그로버로 약화" P3; ck haproxy/haproxy.cfg:5 X25519MLKEM768 "안전" 참고
  ck openssl/openssl.cnf:7 TLSv1.2 "해당 없음" 참고; ck openssl/openssl.cnf:8 X25519:P-256 "쇼어로 깨짐" P1; ck openssl/openssl.cnf:9 SECLEVEL "쇼어로 깨짐" P1
  # SSH
  ck ssh/sshd_config:2 RSA "쇼어로 깨짐" P2; ck ssh/sshd_config:3 Ed25519 "쇼어로 깨짐" P2; ck ssh/sshd_config:4 curve25519-sha256 "쇼어로 깨짐" P1
  ck ssh/sshd_config:5 3des-cbc "그로버로 약화" P1; ck ssh/sshd_config:6 hmac-sha1 "그로버로 약화" P2; ck ssh/sshd_config:7 ssh-rsa "쇼어로 깨짐" P2 "SHA-1 서명"
  ck ssh/sshd_config.d/pq.conf:1 mlkem768x25519 "안전" 참고 "드롭인"; ck ssh-default/sshd_config "KexAlgorithms 미지정" "미확인" P1
  # Java
  local J=java/src/main/java/com/demo/CryptoService.java
  ck $J:9 RSA-2048 "쇼어로 깨짐" P1; ck $J:14 "EC secp256r1" "쇼어로 깨짐" P1; ck $J:19 RSA/ECB/OAEP "쇼어로 깨짐" P1
  ck $J:24 SHA256withECDSA "쇼어로 깨짐" P2; ck $J:28 ECDH "쇼어로 깨짐" P1; ck $J:32 MD5 "그로버로 약화" P2
  ck $J:35 "SunJCE 기본 ECB" "고전 취약" P2; ck $J:38 DESede "그로버로 약화" P1; ck $J:41 AES-128 "그로버로 약화" P3
  ck $J:45 RC4 "" "" 주석; ck CryptoServiceTest.java:7 DSA-1024 "쇼어로 깨짐" P2 테스트; ck java/pom.xml "bcprov-jdk18on 1.70" "간접" P2 "1.79+"
  # Python
  ck python/app.py:7 RSA-2048 "쇼어로 깨짐" P1; ck python/app.py:8 SECP384R1 "쇼어로 깨짐" P1; ck python/app.py:9 X25519 "쇼어로 깨짐" P1
  ck python/app.py:10 RSA-OAEP "쇼어로 깨짐" P1; ck python/app.py:11 sha1 "그로버로 약화" P2; ck python/app.py:12 "JWT RS256" "쇼어로 깨짐" P2
  ck python/app.py:13 "JWT ES256" "쇼어로 깨짐" P2; ck python/app.py:14 ECB "고전 취약" P2; ck python/app.py:15 DES "그로버로 약화" P1
  ck python/requirements.txt "cryptography 41.0.7" "간접" P2 "48.0.0+"
  # Node
  ck node/server.js:4 rsa-3072 "쇼어로 깨짐" P1; ck node/server.js:5 prime256v1 "쇼어로 깨짐" P1; ck node/server.js:6 "ECDH secp256k1" "쇼어로 깨짐" P1
  ck node/server.js:7 md5 "그로버로 약화" P2; ck node/server.js:8 aes-128-ecb "고전 취약" P2; ck node/server.js:9 des-ede3-cbc "그로버로 약화" P1
  ck node/server.js:10 publicEncrypt "쇼어로 깨짐" P1; ck node/server.js:11 "JWT RS256" "쇼어로 깨짐" P2; ck node/server.js:12 ml-dsa-65 "안전" 참고
  ck node/package.json "jsonwebtoken ^8.5.1" "간접" P2; none node_modules; ck node/test.mjs:2 sha1 "그로버로 약화" P2 테스트
  # Go
  ck go/main.go:4 crypto/ecdsa "쇼어로 깨짐" P2; ck go/main.go:6 crypto/md5 "그로버로 약화" P2; ck go/main.go:7 crypto/mlkem "안전" 참고
  ck go/main.go:9 crypto/rsa "쇼어로 깨짐" P1; ck go/main.go:12 x/crypto/ssh "미확인" 확인; ck go/main.go:16 RSA-2048 "쇼어로 깨짐" P1
  ck go/main.go:17 "ECDSA P256" "쇼어로 깨짐" P2; ck go/main.go:21 VersionTLS10 "고전 취약" P2; ck go/main.go:22 CurveP256:X25519 "쇼어로 깨짐" P1
  ck go/go.mod:3 "go 1.21" "쇼어로 깨짐" P1 ""; ck go/go.mod:5 "x/crypto v0.17.0" "간접" P2 "v0.38.0+"
  # 설정·스크립트(일반 패턴·키 생성 명령), 문서는 제외
  ck config/application.yml:3 SHA256withRSA "쇼어로 깨짐" P2 "일반 패턴"; ck config/application.yml:4 md5 "그로버로 약화" P2; ck config/application.yml:7 TLSv1.1 "고전 취약" P2
  ck config/application.yml:9 ML-KEM-768 "안전" 참고; ck config/application.yml:10 "RSA,ML-KEM-768" "쇼어로 깨짐" P1 "PQC 이름도 함께"   # 고전·PQC 혼재 줄은 고전 쪽으로
  ck scripts/provision.sh:2 RSA-2048 "쇼어로 깨짐" P2; ck scripts/provision.sh:3 "EC prime256v1" "쇼어로 깨짐" P1
  ck scripts/provision.sh:4 rsa-3072 "쇼어로 깨짐" P2; ck scripts/provision.sh:5 RSA-2048 "쇼어로 깨짐" P1; none docs/README.md
  # 키·인증서·키스토어(gen/은 selftest가 만든다)
  ck gen/rsa-server.crt:1 RSA-2048 "쇼어로 깨짐" P2 "2035 이후"; ck gen/chain.pem:1 EC-256 "쇼어로 깨짐" P2 "CA:TRUE"; ck gen/chain.pem: RSA-2048 "쇼어로 깨짐" P2
  ck gen/enc.key:1 "암호화된 PKCS#8" "미확인" 확인
  if [ -f "$g/ed25519.key" ]; then ck gen/ed25519.key:1 ED25519 "쇼어로 깨짐" P2; else skip; fi   # LibreSSL은 Ed25519 genpkey 불가
  ck gen/ca-bundle.pem "인증서 12개" "미확인" 참고; none gen/ca-bundle.pem:
  ck gen/rsa-server.der RSA-2048 "쇼어로 깨짐" P2; ck gen/server.p12 RSA-2048 "쇼어로 깨짐" P2
  if [ -n "$SK" ]; then ck gen/id_rsa:1 RSA-2048 "쇼어로 깨짐" P2; ck gen/id_ed25519.pub ED25519 "쇼어로 깨짐" P2; else skip 2; fi
  if [ -n "$KT" ] && [ -f "$g/legacy.jks" ]; then ck "gen/legacy.jks#" EC "쇼어로 깨짐" P2; else skip; fi   # '#legacy'(별칭) 또는 옛 keytool이면 '#rfc:N'
  if [ -f "$g/mldsa65.crt" ]; then ck gen/mldsa65.crt:1 ML-DSA-65 "안전" 참고; ck gen/mlkem768.key:1 ML-KEM-768 "안전" 참고; else skip 2; fi
  # 엔드포인트
  ck 127.0.0.1:$P1 X25519 "쇼어로 깨짐" P1; ck 127.0.0.1:$P1 RSA-2048 "쇼어로 깨짐" P2 "서버 인증서"
  if [ -n "$s2" ]; then ck 127.0.0.1:$P2 X25519MLKEM768 "안전" 참고 "강등 차단"; ck 127.0.0.1:$P2 ML-DSA-65 "안전" 참고; else skip 2; fi
  # 보강: ①못 여는 키스토어도 행(비밀번호 후보는 이름만) ②TLSv1.2·1.3 오탐 없음 ③PG≤17 설정 불가·'/' 호환 제안 ④짝 인증서 있는 개인키 P2 ⑤업스트림 proxy_ssl_*
  local pw; ck gen/locked/locked.p12 "열지 못함" "미확인" 확인 "gen/locked/ks.pass"; ck gen/locked/locked.p12 "열지 못함" "" "" "app.properties:2 keystore.passfile"
  if [ -n "$KT" ]; then ck gen/locked/locked.p12 "" "" "" "locked(PrivateKeyEntry)"; else skip; fi
  pw=$(cat "$g/locked/ks.pass" 2>/dev/null); if [ -n "$pw" ] && ! grep -F -q -- "$pw" "$ROWS"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "  FAIL: gen/locked/ks.pass 값이 CBOM에 있음(또는 픽스처 없음)"; fi
  none node/tls.js:2; ck node/tls.js:3 TLSv1 "고전 취약" P2
  # 코드 속 TLS 그룹: 따옴표 인자는 값으로 판정, 변수 인자는 '확인' 행(교차 리뷰에서 변수 인자 줄이 0행이었다)
  ck python/app.py:16 prime256v1 "쇼어로 깨짐" P1; ck python/app.py:17 "변수 curve_name" "미확인" 확인
  ck node/tls.js:4 X25519MLKEM768 "안전" 참고 "고전 폴백 허용(X25519)"; ck node/tls.js:5 "변수 process.env.TLS_CURVE" "미확인" 확인
  ck config/tls.properties:1 "TLSv1.3,TLSv1.2" "해당 없음" 참고; nck config/tls.properties:1 "고전 취약"; ck config/tls.properties:2 TLSv1.2 "쇼어로 깨짐" P1 "TLS 1.3 없음"
  ck postgres/16/main/postgresql.conf:3 TLSv1.2 "해당 없음" 참고; nck postgres/16/main/postgresql.conf:3 "고전 취약"
  ck postgres/16/main/postgresql.conf:4 TLSv1.2 "쇼어로 깨짐" P1 "TLS 1.3 없음"
  ck postgres/16/main/postgresql.conf:5 prime256v1 "쇼어로 깨짐" P1 "설정 불가: PG18 ssl_groups 또는 구간 보호"
  ck postgresql/15/main/postgresql.conf:2 X25519MLKEM768 "미확인" 확인 "설정 불가"; nck postgresql/15/main/postgresql.conf:2 "안전"
  ck postgres/18/data/postgresql.conf:2 prime256v1 "쇼어로 깨짐" P1 "X25519MLKEM768/X25519:P-256"; nck postgres/18/data/postgresql.conf:2 "설정 불가"
  ck nginx/nginx.conf:11 prime256v1 "쇼어로 깨짐" P1 "X25519MLKEM768/X25519:P-256"; ck 127.0.0.1:$P1 X25519 "쇼어로 깨짐" P1 "X25519MLKEM768/X25519:P-256"
  ck gen/rsa2048.key:1 RSA-2048 "쇼어로 깨짐" P2 "인증서 짝: gen/"; ck gen/rsa2048.key:1 RSA-2048 "" "" "정적 RSA"; ck gen/ec-ca.key:1 EC-256 "쇼어로 깨짐" P2 "인증서 짝: gen/"
  ck gen/solo.key:1 RSA-2048 "쇼어로 깨짐" P1; nck gen/solo.key:1 "인증서 짝"
  ck nginx/conf.d/upstream.conf:3 "TLSv1.2 TLSv1.3" "해당 없음" 참고 "업스트림"; nck nginx/conf.d/upstream.conf:3 "고전 취약"
  ck nginx/conf.d/upstream.conf:4 ECDHE-ECDSA "쇼어로 깨짐" P1 "업스트림"; ck nginx/conf.d/upstream.conf:5 X25519MLKEM768 "안전" 참고 "업스트림"
  # 3차 검토: grpc·Apache 업스트림, 제외 목록은 허용 목록이 아님, 경로에 postgresql만 든 비PG 설정, 열렸지만 인증서 없는 키스토어
  ck nginx/conf.d/upstream.conf:9 TLSv1.2 "쇼어로 깨짐" P1 "업스트림"
  ck apache/ssl.conf:7 TLSv1.2 "쇼어로 깨짐" P1 "업스트림"; ck apache/ssl.conf:8 TLS_AES_128 "그로버로 약화" P3 "업스트림"
  ck config/tls.properties:3 TLSv1 "해당 없음" 참고 "제외 목록"; nck config/tls.properties:3 "고전 취약"; ck config/tls.properties:4 TLSv1.3 "쇼어로 깨짐" P1 "TLS 1.3 꺼짐"
  ck postgresql-proxy/nginx.conf:1 prime256v1 "쇼어로 깨짐" P1 "X25519MLKEM768/X25519:P-256"; nck postgresql-proxy/nginx.conf:1 "PG"
  if [ -n "$KT" ] && [ -f "$g/secret.jceks" ]; then ck gen/secret.jceks "인증서 항목 없음" "미확인" 확인 "aes(SecretKeyEntry)"; nck gen/secret.jceks "열지 못함"; else skip 2; fi
  # 규칙 묶음 2(교차 리뷰 X18·X20·X22·X24·X25·X26·X33·X59)
  ck r2/node/sign.js:2 ml-dsa-65 "안전" 참고; ck r2/node/sign.js:3 "crypto.sign" "미확인" 확인; nck r2/node/sign.js:3 "쇼어로 깨짐"
  ck r2/node/sign.js:4 "Node TLS 상한" "쇼어로 깨짐" P1 "TLS 1.3 꺼짐"; ck r2/node/sign.js:5 "X25519(tweetnacl" "쇼어로 깨짐" P1
  ck r2/go/cap.go:3 "X25519(Go x/crypto/nacl/box" "쇼어로 깨짐" P1; ck r2/go/cap.go:5 "MaxVersion TLS12" "쇼어로 깨짐" P1 "TLS 1.3 꺼짐"
  ck r2/python/tls.py:1 "Python TLS 상한" "쇼어로 깨짐" P1; ck r2/python/tls.py:2 "Ed25519(PyNaCl" "쇼어로 깨짐" P2; ck r2/python/tls.py:3 "Python TLS 상한" "쇼어로 깨짐" P1
  ck r2/java/Composite.java:1 MLDSA65-ECDSA "복합 서명" P2; nck r2/java/Composite.java:1 "안전(PQC)"
  ck r2/java/Composite.java:2 "Nimbus" "쇼어로 깨짐" ""
  # FIPS 205: 일반 패턴이 SLH-DSA 의 DSA 를 고전 DSA 로 읽지 않는다. 128 은 보안레벨 1(규칙 묶음 4)
  ck r2/java/Slh.java:1 SLH-DSA-SHA2-192s "안전" ""; nck r2/java/Slh.java:1 "쇼어로 깨짐"
  ck r2/java/Slh.java:2 SLH-DSA-SHA2-128s "보안레벨 3 미만" P2; nck r2/java/Slh.java:2 "쇼어로 깨짐"
  ck r2/c/rsa.c:1 rsa "쇼어로 깨짐" ""; nck r2/c/rsa.c:1 "주석"
  ck r2/ssh/.ssh/config:2 ssh-rsa "쇼어로 깨짐" P2
  ck r2/ssh/known_hosts 25519 "쇼어로 깨짐" P2   # ssh-keygen 이 없어도 공개키 줄의 형식 이름으로 읽는다
  ck gen/test/ks.p12 RSA "쇼어로 깨짐" "" "테스트·예제"
  ck gen/test/pair.crt:1 EC-256 "쇼어로 깨짐" "" "테스트·예제"; ck gen/test/pair.key:1 EC-256 "쇼어로 깨짐" P2 "테스트·예제 · 인증서 짝: gen/test/pair.crt"
  ck r2/scripts/ks.sh:1 RSA "" "" "-storepass ***"; nck r2/scripts/ks.sh:1 "s3cretPW"
  echo "selftest: PASS $PASS · FAIL $FAIL · SKIP $SKIP of $((PASS + FAIL + SKIP)) (OpenSSL: $("$O" version), ML-KEM $MLKEM, keytool ${KT:-없음}, ssh-keygen ${SK:-없음})"
}

# ---------- main ----------
CMD="$0 $*"; TS=$(date +%Y%m%d-%H%M%S); OUT=${OUT:-$HERE/evidence}; mkdir -p "$OUT"
case "${1:-}" in
  --selftest) selftest; render "$OUT/cbom-selftest.md" "$OUT/cbom-selftest.csv" "$CMD"; echo "→ $OUT/cbom-selftest.md"; [ $FAIL = 0 ];;
  ""|-h|--help) sed -n '2,10p' "$0"; exit 2;;
  *) scan "$@"; render "$OUT/cbom-$TS.md" "$OUT/cbom-$TS.csv" "$CMD"
     echo "CBOM $(wc -l < "$ROWS" | tr -d ' ')건 → $OUT/cbom-$TS.md, $OUT/cbom-$TS.csv"
     cut -f5 "$ROWS" | sort | uniq -c | sort -rn;;
esac
