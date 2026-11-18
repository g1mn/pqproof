#!/bin/bash
# residue.sh <폴더>: 고전 공개키 '잔재' 집계(일반판). 읽기만 한다. prove.sh 의 (c) 단계가 원본과 고친 판에 한 번씩 돌린다.
#   [1] SITE   : 서비스별 '전환 대상 자리'(파일, 고전 흔적 정규식) 쌍. 일반판에는 없다. 서비스에 맞춘 판을 RESIDUE= 로 줄 때만 쓴다.
#   [2] GEN    : 일반 고전 패턴(RSA·EC·곡선·OAEP/PKCS1·고전 서명·JWT RS/ES/PS·EdDSA·X25519 단독·DH/DSA·AES-128·NIST 보안레벨 3 미만 PQC)
#                폴더 안 모든 텍스트 파일. 앞의 아홉 줄(G-RSA ~ G-DH-DSA)이 prove.sh 가 세는 '공개키 9계열'이다.
#   [3] LWRITE : 이름 규칙 레거시 파일(Legacy*.java) 안 쓰기 경로(암호화·서명·키 생성·파일 쓰기). 있으면 LEFT.
#   [4] EXPECT : 코드 줄(시험 폴더 밖)의 ML-KEM-768·ML-DSA-65 사용 흔적. 없으면 MISSING.
# 분류: code=코드 줄 LEFT / allow=이름 규칙 허용 / comment=주석·문서 줄(따로 센다, LEFT 아님).
# 이름 규칙 허용(ALLOW, LEFT 로 세지 않음. 상세 줄은 사람이 다시 본다):
#   - Legacy*.java 파일 안(옛 데이터 읽기·검증 전용으로 떼어 낸 파일)
#   - 같은 줄에 'legacy'(대소문자 무관, 식별자·주석 모두)가 있는 줄
#   - G-X25519 의 같은 줄 ML-KEM = 하이브리드
#   단, 쓰기 연산(ENCRYPT_MODE·WRAP_MODE·initSign·KeyPairGenerator·generateKeyPair)이 있는 줄은 허용하지 않는다.
#   허용 목록(ALLOW=)과 같은 함수 안 하이브리드 결합은 prove.sh 가 이 출력의 LEFT 줄을 다시 읽어 따로 뺀다.
# 시험 폴더(src/test·test·tests) 줄은 주석처럼 센다. vendor/(받아 둔 남의 라이브러리)는 건너뛴다.
# 건너뜀: .git·<폴더>/data·<폴더>/target·node_modules·vendor·build, 키·DB·비밀 모양 파일(.pem .key .p12 .jks .der .crt .sqlite3 .env)
#   내용은 읽지 않고 이름 개수만.
# 종료 코드: 0=CLEAN(잔재 0·PQC 흔적 모두 있음) 1=RESIDUE 2=사용법 오류. bash 3.2·BWK awk 호환.
ROOT=${1:?사용법: bash residue.sh <폴더>}
ROOT=${ROOT%/}
[ -d "$ROOT" ] || { echo "폴더 없음: $ROOT" >&2; exit 2; }

IFS= read -r -d '' RES_RULES <<'RULES'
# KIND@@ID@@자산@@파일(SITE=파일 이름, 나머지 *)@@정규식(ERE)@@설명@@규칙별 허용 정규식(선택)
GEN@@G-RSA@@-@@*@@(^|[^A-Za-z])[Rr][Ss][Aa]@@RSA 전반(Cipher·KeyFactory·라벨·변수)
GEN@@G-EC@@-@@*@@(^|[^A-Za-z])EC(DSA|DH|IES|PrivateKey|PublicKey|Point|GenParameterSpec|NamedCurve|ParameterSpec|Curve|[^A-Za-z]|$)@@EC/ECDSA/ECDH 전반
GEN@@G-CURVE@@-@@*@@secp[0-9]+[rk]1|prime[0-9]+v1|P-?(256|384|521)([^0-9]|$)|brainpool|1\.2\.840\.10045|1\.3\.132\.0@@고전 곡선 이름·OID
GEN@@G-OAEP-PKCS1@@-@@*@@OAEP|MGF1|PKCS#?1([^0-9]|$)|PSource@@RSA 패딩
GEN@@G-CLASSIC-SIG@@-@@*@@with(RSA|ECDSA|DSA|PLAIN-ECDSA)|NONEwith|RSASSA|RSA-?PSS@@고전 서명 알고리즘 이름(SHA256withRSA·SHA256withECDSA 등)
GEN@@G-JWT-ALG@@-@@*@@(^|[^A-Za-z0-9])(RS|ES|PS)(256|384|512)([^0-9]|$)@@JWT/JOSE 고전 alg(RS256·ES256·PS256)
GEN@@G-EDDSA@@-@@*@@Ed25519|Ed448|EdDSA|Curve25519@@EdDSA 서명
GEN@@G-X25519@@-@@*@@X25519|X448|XDH|ECDH|KeyAgreement@@X25519/ECDH 단독(같은 줄 ML-KEM 이면 하이브리드 허용)@@ML-?KEM|MLKEM
GEN@@G-DH-DSA@@-@@*@@DiffieHellman|"DH"|"DHE"|"DSA"|ElGamal|ECIES@@DH·DSA·ElGamal
GEN@@G-AES128@@-@@*@@AES-?128|AES_128|[Aa]es-?128|\.init\(128\)@@AES-128(보안레벨 1)
GEN@@G-WEAK-PQC@@-@@*@@ML-KEM-512|MLKEM512|ml_kem_512|ML_KEM_512|ML-DSA-44|MLDSA44|ml_dsa_44|ML_DSA_44|Kyber512|Dilithium2@@보안레벨 3 미만 PQC
LWRITE@@LW-legacy-write@@-@@*@@ENCRYPT_MODE|WRAP_MODE|initSign|KeyPairGenerator|generateKeyPair|Files\.(write|writeString|move|copy)@@Legacy*.java 는 읽기·검증 전용이어야 함
EXPECT@@E-MLKEM768@@-@@*@@ML-KEM-768|MLKEM768|ml_kem_768|ML_KEM_768@@ML-KEM-768 사용
EXPECT@@E-MLDSA65@@-@@*@@ML-DSA-65|MLDSA65|ml_dsa_65|ML_DSA_65@@ML-DSA-65 사용
RULES
export RES_RULES RES_ROOT="$ROOT"
export RES_ALLOWLINE='[Ll][Ee][Gg][Aa][Cc][Yy]'
export RES_WRITEOPS='ENCRYPT_MODE|WRAP_MODE|initSign|KeyPairGenerator|generateKeyPair'

FILES=(); SKIP=0; SKIPN=""
while IFS= read -r f; do
  b=${f##*/}
  case "$b" in
    *.pem|*.key|*.p12|*.pfx|*.jks|*.der|*.crt|*.cer|*.sqlite3|*.sqlite3-*|*.db|.env|*.class|*.jar|*.zip)
      SKIP=$((SKIP+1)); SKIPN="$SKIPN ${f#$ROOT/}"; continue ;;
  esac
  grep -Iq . "$f" 2>/dev/null || continue   # 바이너리·빈 파일 제외
  FILES+=("$f")
done < <(find "$ROOT" \( -name .git -o -path "$ROOT/data" -o -path "$ROOT/target" -o -name node_modules -o -name vendor -o -path "$ROOT/build" -o -name __pycache__ \) -prune -o -type f -print | LC_ALL=C sort)

echo "== residue $ROOT  ($(date '+%F %T %Z'))"
echo "INFO 검사 파일 ${#FILES[@]}개 · 건너뛴 키·DB·비밀 모양 파일 ${SKIP}개(내용 미열람)${SKIPN:+:$SKIPN}"
LC=$(grep -rnE '[Ll]egacy[A-Z][A-Za-z]*\(' "$ROOT/src" 2>/dev/null | grep -v '^Binary' | sed "s#^$ROOT/##" | head -20)
if [ -n "$LC" ]; then echo "INFO 레거시 호출처(쓰기 경로에서 부르면 안 됨, 사람이 확인):"; echo "$LC" | sed 's/^/      /'; else echo "INFO 레거시 호출처 없음"; fi
[ ${#FILES[@]} -gt 0 ] || { echo "검사할 파일 없음"; exit 2; }

LC_ALL=C awk '
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function short(s) { s = trim(s); if (length(s) > 150) s = substr(s, 1, 147) "..."; return s }
function ftype(b) {
  if (b ~ /\.(java|js|mjs|cjs|ts|kt|kts|go|c|h|cc|cpp|css|scss|gradle|jsonc|rs|swift)$/) return "c"
  if (b ~ /\.(sh|bash|zsh|ya?ml|properties|py|toml|conf|cfg|ini|env|example|r|rb)$/ || b ~ /^(Dockerfile|Makefile|\.dockerignore|\.gitignore|\.env)/) return "hash"
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
function add(r, t, ln, txt) {
  CNT[r, t]++
  if (CNT[r, t] <= MAXD) DET[r, t] = DET[r, t] "      " t " " REL ":" ln ": " short(txt) "\n"
  if (CNT[r, t] <= 14) LOC[r, t] = LOC[r, t] (LOC[r, t] == "" ? "" : ",") ln
}
BEGIN {
  ROOT = ENVIRON["RES_ROOT"]; ALLOWLINE = ENVIRON["RES_ALLOWLINE"]; WRITEOPS = ENVIRON["RES_WRITEOPS"]; MAXD = 100000
  n = split(ENVIRON["RES_RULES"], LN, "\n"); NRULE = 0
  for (i = 1; i <= n; i++) {
    if (LN[i] == "" || substr(LN[i], 1, 1) == "#") continue
    m = split(LN[i], F, "@@"); NRULE++
    KIND[NRULE] = F[1]; ID[NRULE] = F[2]; AS[NRULE] = F[3]; FG[NRULE] = F[4]; RE[NRULE] = F[5]; NOTE[NRULE] = F[6]; ALW[NRULE] = (m >= 7 ? F[7] : "")
  }
}
FNR == 1 {
  INBLOCK = 0; REL = FILENAME; if (index(REL, ROOT "/") == 1) REL = substr(REL, length(ROOT) + 2)
  BASE = FILENAME; sub(/.*\//, "", BASE); TYP = ftype(BASE); if (REL ~ /(^|\/)(src\/test|test|tests)\//) TYP = "doc"
  ISLEG = (BASE ~ /^Legacy[A-Za-z0-9_]*\.java$/); INSRC = (REL !~ /(^|\/)(src\/test|test|tests)\//); SEEN[BASE] = 1; NFILES++
}
{
  s = $0
  if (TYP == "c") splitc(s)
  else if (TYP == "xml") splitx(s)
  else if (TYP == "hash") { if (substr(trim(s), 1, 1) == "#") { CODE = ""; COM = s } else { CODE = s; COM = "" } }
  else if (TYP == "sql") { if (substr(trim(s), 1, 2) == "--") { CODE = ""; COM = s } else { CODE = s; COM = "" } }
  else if (TYP == "doc") { CODE = ""; COM = s }
  else { CODE = s; COM = "" }
  for (r = 1; r <= NRULE; r++) {
    k = KIND[r]
    if (k == "SITE" && BASE != FG[r]) continue
    if (k == "LWRITE" && !ISLEG) continue
    if (k == "EXPECT") { if (INSRC && CODE ~ RE[r]) add(r, "P", FNR, s); continue }
    if (CODE ~ RE[r]) {
      if (k == "LWRITE") { add(r, "LEFT", FNR, s); continue }
      wr = (CODE ~ WRITEOPS)
      if (!wr && (ISLEG || s ~ ALLOWLINE)) add(r, "ALLOW", FNR, s)
      else if (!wr && ALW[r] != "" && s ~ ALW[r]) add(r, "ALLOW", FNR, s)
      else add(r, "LEFT", FNR, s)
    } else if (COM != "" && COM ~ RE[r]) add(r, "COMMENT", FNR, s)
  }
}
END {
  sL = sA = sG = 0; gL = gN = gc = ga = gm = 0; lw = 0; eM = eN = 0
  print ""
  print "[1] 서비스별 전환 대상 자리(SITE 규칙이 있을 때만). 전환 뒤 전부 GONE 또는 ALLOW 여야 한다"
  for (r = 1; r <= NRULE; r++) if (KIND[r] == "SITE") {
    L = CNT[r, "LEFT"] + 0; A = CNT[r, "ALLOW"] + 0; C = CNT[r, "COMMENT"] + 0
    if (!(FG[r] in SEEN)) st = "GONE(파일 없음)"; else if (L > 0) st = "LEFT"; else if (A > 0) st = "ALLOW"; else st = (C > 0 ? "GONE(주석 " C ")" : "GONE")
    if (L > 0) sL++; else if (A > 0) sA++; else sG++
    printf "SITE %-18s %-10s %-24s %-6s code=%d allow=%d comment=%d  L%s  - %s\n", ID[r], AS[r], FG[r], st, L, A, C, (L > 0 ? LOC[r, "LEFT"] : (A > 0 ? LOC[r, "ALLOW"] : "-")), NOTE[r]
    printf "%s%s", DET[r, "LEFT"], DET[r, "ALLOW"]
  }
  print ""
  print "[2] 일반 고전 패턴: 폴더 전체(주석·문서 줄은 comment 로 따로)"
  for (r = 1; r <= NRULE; r++) if (KIND[r] == "GEN") {
    L = CNT[r, "LEFT"] + 0; A = CNT[r, "ALLOW"] + 0; C = CNT[r, "COMMENT"] + 0; gN++
    st = (L > 0 ? "LEFT" : (A > 0 ? "ALLOW" : "GONE")); if (L > 0) gL++
    gc += L; ga += A; gm += C
    printf "GEN  %-18s %-6s code=%d allow=%d comment=%d  - %s\n", ID[r], st, L, A, C, NOTE[r]
    printf "%s%s", DET[r, "LEFT"], DET[r, "ALLOW"]
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
  print "[4] PQC 실사용 흔적(시험 폴더 밖 코드 줄)"
  for (r = 1; r <= NRULE; r++) if (KIND[r] == "EXPECT") {
    P = CNT[r, "P"] + 0; eN++; if (P == 0) eM++
    printf "EXPECT %-16s %-8s n=%d  L%s  - %s\n", ID[r], (P > 0 ? "PRESENT" : "MISSING"), P, (P > 0 ? LOC[r, "P"] : "-"), NOTE[r]
  }
  verdict = (sL == 0 && gL == 0 && lw == 0 && eM == 0) ? "CLEAN" : "RESIDUE"
  print ""
  printf "SUMMARY files=%d sites=%d LEFT=%d ALLOW=%d GONE=%d | gen_rules=%d LEFT=%d (code=%d allow=%d comment=%d) | legacy_write=%d | pqc_expect MISSING=%d/%d | VERDICT=%s\n", NFILES, sL + sA + sG, sL, sA, sG, gN, gL, gc, ga, gm, lw, eM, eN, verdict
  exit (verdict == "CLEAN" ? 0 : 1)
}' "${FILES[@]}"
