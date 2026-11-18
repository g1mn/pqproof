#!/usr/bin/env python3
# prove.py: prove.sh의 본체. 설계는 DESIGN.md. 표준 라이브러리만 쓰고 인터넷을 쓰지 않는다.
# 흐름과 판정식은 g1mn/pq-proof 7b7803f (MIT) e2e/orders_edge.py에서 가져왔다(CBOM 전 → 탐침 → CBOM 후 → 검사 → 검증 증적 →
# 다시 확인). git clone 스냅숏 대신 zip·폴더 트리 해시를 쓰고, 모델·microVM·Vultr 부분은 없다.
"""원본과 고친 판을 받아 네 가지를 낸다.

(a) CBOM: scan/cbom-scan.sh(주력)와 pqlite/scan.py(Go 툴체인·GODEBUG·런타임 이미지·Java BC/JCA)를 두 판에 돌려 위치 기준으로
    합친다. 고친 판에 막는 위치(양자 컴퓨터로 깨지는 공개키, 허용·주석·테스트 제외)가 0이어야 한다.
(b) TLS: 바뀐 파일의 TLS 약화 수정(verify.weakening)은 늘 본다. TLS_TARGETS가 있으면 tls_probe로 양성·음성 대조 뒤
    대상마다 하이브리드 전용·옛 클라이언트 접속을 재고, 맥 모드면 OpenSSL 3.5 s_client로 교차 확인한다.
(c) 공개키 집계: residue.sh(RESIDUE로 준 것, 없으면 scan/residue.sh 일반판)를 두 판에 돌려 공개키 9계열 code 줄,
    ML-KEM-768·ML-DSA-65 사용, NIST 보안레벨 3 미만 PQC, 레거시 쓰기를 읽는다.
(d) 검증 증적: receipt.json(RFC 8785 + SHA-256), receipt.html, tables/*.csv, tables/fragment.html, evidence-fragment.json.
받은 소스는 믿지 않는 입력이다. 그 안의 코드는 실행하지 않는다(cbom-scan·residue는 grep·awk, scan.py는 읽기만).
종료 코드: 0 통과 · 1 실패 · 2 사용법·입력 오류 · 3 미판정.
"""
import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)  # python3 -I는 스크립트 폴더를 넣지 않는다

from pqlite import allowlist as al  # noqa: E402
from pqlite import receipt as rc  # noqa: E402
from pqlite import scan as scanmod  # noqa: E402
from pqlite import tlsprobe, verify  # noqa: E402
from pqlite import version as ver  # noqa: E402

CBOM_SCAN = os.path.join(HERE, "scan", "cbom-scan.sh")
GENERIC_RESIDUE = os.path.join(HERE, "scan", "residue.sh")
FAMILIES = ["G-RSA", "G-EC", "G-CURVE", "G-OAEP-PKCS1", "G-CLASSIC-SIG", "G-JWT-ALG", "G-EDDSA", "G-X25519", "G-DH-DSA"]
EXPECT_IDS = {"kem": "E-MLKEM768", "sig": "E-MLDSA65"}
EXPECT_OK = {"kem", "sig", "tls", "cert"}
# SCOPE: all(기본) = 모든 고전 공개키가 막는 위치. kex = 키 교환만(PQ-Proof 범위: TLS 그룹·툴체인·런타임 이미지).
# kex에서 서명·암호화 행은 '범위 밖'으로 표에 남기고 막는 위치로 세지 않는다. c-classic(공개키 9계열)은 해당 없음이 된다.
SCOPES = ("all", "kex")
KEX_USE = re.compile(r"키교환|TLS 설정|TLS 엔드포인트")  # cbom-scan 용도 칸('서명·키교환'처럼 섞인 것도 범위 안으로 본다)
KEX_KINDS = {"key-exchange", "toolchain", "base-image"}  # scan.py kind
MAX_TEXT = 1 << 20
MAX_ZIP_TOTAL = 1 << 30
MIN_COMMON = 0.5  # a-input: 원본 파일 중 고친 판에도 같은 경로로 있어야 하는 몫
STATUS_KO = rc.STATUS_KO


class UsageError(Exception):
    pass


def now():
    return time.time()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def slurp(path, binary=False):
    with open(path, "rb") as f:
        data = f.read()
    return data if binary else data.decode("utf-8")


def spit(path, data):
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


# OPENSSL 을 안 줬을 때 찾는 곳(이 순서, 그다음 PATH). src/pqproof/deps.py 의 OPENSSL_CANDIDATES 와 같아야 한다(tests/test_rule_sync.py)
OPENSSL_CANDIDATES = ("/opt/homebrew/opt/openssl@3.5/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl", "/opt/homebrew/bin/openssl",
                      "/usr/local/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl")


def default_openssl():
    """OPENSSL 을 주면 그것(3.5 미만이어도, Params 와 같은 규칙). 아니면 3.5 이상을 먼저 고른다(교차 확인·ML-DSA 인증서 읽기).
    없으면 처음 찾은 것(cbom-scan은 옛 OpenSSL로도 돈다)."""
    given = os.environ.get("OPENSSL")
    if given and os.path.isfile(given) and os.access(given, os.X_OK):
        return given
    found = []
    for c in OPENSSL_CANDIDATES + (shutil.which("openssl"),):
        if c and c not in found and os.path.isfile(c) and os.access(c, os.X_OK):
            found.append(c)
    return next((c for c in found if openssl_35(c)), found[0] if found else None)


# ---------------------------------------------------------------------------------------------
# 매개변수
class Params:
    def __init__(self, env=None):
        env = os.environ if env is None else env
        self.out = env.get("OUT") or None
        self.tls_targets = env.get("TLS_TARGETS", "").split()
        self.tls_targets_orig = env.get("TLS_TARGETS_ORIG", "").split()
        self.tls_via = env.get("TLS_VIA", "host") or "host"
        self.classic = env.get("CLASSIC", "allow") or "allow"
        raw = env.get("EXPECT", "kem,sig")
        self.expect = [] if raw.strip().lower() in ("", "none") else [x.strip() for x in raw.split(",") if x.strip()]
        self.residue = env.get("RESIDUE") or None
        self.extra = env.get("EXTRA_EV", "").split()
        self.openssl = env.get("OPENSSL") or default_openssl()
        self.cbom_scan = env.get("CBOM_SCAN") or CBOM_SCAN
        self.scope = (env.get("SCOPE", "all") or "all").strip().lower()
        # 허용 규칙: ALLOW=<unconverted.json>|none, EXCLUDE="글롭 …"|none, RECON=<recon.json>|none. 비우면 원본이 <W>/orig일 때
        # <W>/notes/unconverted.json·recon.json을 스스로 찾는다. EV_NAME은 deck.json·evidence-fragment.json의 ev 파일 이름.
        self.allow = (env.get("ALLOW") or "").strip() or None
        raw_ex = (env.get("EXCLUDE") or "").strip()
        self.exclude_off = raw_ex.lower() == "none"
        self.exclude = [] if self.exclude_off else [x for x in re.split(r"[\s,]+", raw_ex) if x]
        self.recon = (env.get("RECON") or "").strip() or None
        self.ev = (env.get("EV_NAME") or "").strip() or None
        # REQUIRE_REVIEW=1: 허용 항목에 받아들인 사람 확인 칸(reviewed_by·reviewed_at)이 없으면 r-allow 실패(기본은 검토 필요, 판정 그대로)
        rr = (env.get("REQUIRE_REVIEW") or "").strip().lower()
        if rr not in ("", "0", "1", "no", "yes", "false", "true"):
            raise UsageError(f"REQUIRE_REVIEW는 1 또는 0: {rr!r}")
        self.require_review = rr in ("1", "yes", "true")
        if self.ev and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", self.ev):
            raise UsageError(f"EV_NAME은 evidence/ 안 파일 이름: {self.ev!r}")
        if self.scope not in SCOPES:
            raise UsageError(f"SCOPE는 all 또는 kex: {self.scope!r}")
        if self.classic not in ("allow", "deny"):
            raise UsageError(f"CLASSIC은 allow 또는 deny: {self.classic!r}")
        if not (self.tls_via == "host" or re.fullmatch(r"container:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.tls_via)):
            raise UsageError(f"TLS_VIA는 host 또는 container:<컨테이너 이름>: {self.tls_via!r}")
        bad = [x for x in self.expect if x not in EXPECT_OK]
        if bad:
            raise UsageError(f"EXPECT에 모르는 값 {bad} (쓸 수 있는 값: kem, sig, tls, cert, none)")
        for t in self.tls_targets + self.tls_targets_orig:
            parse_target(t)


TARGET = re.compile(r"(?P<addr>[A-Za-z0-9_.\[\]:-]+:[0-9]{1,5})(?:@(?P<name>[A-Za-z0-9_.-]{1,253}))?(?:#(?P<ca>/.+))?")


def parse_target(spec):
    """'127.0.0.1:8443@localhost#/path/ca.pem' → (주소, 서버 이름, CA 경로 또는 None)."""
    m = TARGET.fullmatch(spec)
    if not m:
        raise UsageError(f"TLS 대상 꼴이 틀림: {spec!r} (host:port[@서버이름][#/CA.pem 절대 경로])")
    if m["ca"] and not os.path.isfile(m["ca"]):
        raise UsageError(f"CA 파일 없음: {m['ca']}")
    return m["addr"], m["name"] or "localhost", m["ca"]


# ---------------------------------------------------------------------------------------------
# 입력
MAX_ZIP_ENTRIES = 500_000
ZIP_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def zip_names_problem(names):
    """zip 항목 이름 목록에서 풀면 기계마다 트리가 달라지는 꼴을 찾는다(없으면 None): 같은 이름 두 번, 대소문자·유니코드 정규화만
    다른 이름(macOS·Windows 에서 한 파일로 겹친다), 제어 문자, 항목 수 상한."""
    if len(names) > MAX_ZIP_ENTRIES:
        return f"zip 항목이 {len(names)}개로 상한 {MAX_ZIP_ENTRIES}개를 넘는다"
    seen, folded = set(), {}
    for name in names:
        if ZIP_CONTROL.search(name):
            return f"zip 안 이름에 제어 문자가 있다: {name!r}"
        key = name.rstrip("/")
        if key in seen:
            return f"zip 안에 같은 이름이 두 번 있다: {name!r}(어느 쪽을 풀지 도구마다 다르다)"
        seen.add(key)
        fold = unicodedata.normalize("NFC", key).casefold()
        if fold in folded:
            return (f"zip 안 두 이름이 대소문자나 유니코드 정규화만 다르다: {folded[fold]!r}, {name!r}"
                    "(macOS·Windows 에서는 한 파일로 겹쳐 기계마다 트리가 달라진다)")
        folded[fold] = name
    return None


def unzip_safe(path, dest):
    """zip을 dest에 푼다. 절대 경로·..·역슬래시 이름은 거부, 심볼릭 링크는 풀지 않고 이름만 남긴다. 같은 이름·대소문자만 다른 이름·
    제어 문자·항목 수 상한과 풀 수 없는 꼴(파일 아래 파일)은 입력 오류(종료 2)다."""
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            problem = zip_names_problem([i.filename for i in infos])
            if problem:
                raise UsageError(problem)
            return _unzip_entries(z, infos, dest)
    except zipfile.BadZipFile as e:
        raise UsageError(f"zip 을 읽을 수 없다({e}): {path}") from e


def _unzip_entries(z, infos, dest):
    links = []
    total = 0
    for info in infos:
        name = info.filename
        parts = name.rstrip("/").split("/")
        if name.startswith("/") or "\\" in name or ".." in parts or re.match(r"^[A-Za-z]:", name):
            raise UsageError(f"zip 안 위험한 경로: {name!r}")
        if stat.S_ISLNK(info.external_attr >> 16):
            links.append(name)
            continue
        target = os.path.join(dest, *[p for p in parts if p])
        try:
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            total += info.file_size
            if total > MAX_ZIP_TOTAL:
                raise UsageError("zip이 1 GiB보다 크다")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, "xb") as dst:
                shutil.copyfileobj(src, dst)
        except (FileExistsError, NotADirectoryError, IsADirectoryError) as e:
            raise UsageError(f"zip 안 이름끼리 겹쳐 풀 수 없다(파일과 폴더가 같은 이름 등): {name!r} ({type(e).__name__})") from e
    return links


def unwrap(dest):
    """최상위에 폴더 하나뿐이면 그 안을 루트로 본다(zip을 폴더째 묶은 흔한 꼴)."""
    names = [n for n in os.listdir(dest) if n not in ("__MACOSX", ".DS_Store")]
    if len(names) == 1 and os.path.isdir(os.path.join(dest, names[0])) and not os.path.islink(os.path.join(dest, names[0])):
        return os.path.join(dest, names[0])
    return dest


def skipped_dirs(root):
    found = set()
    for dirpath, dirnames, _ in os.walk(root, followlinks=False):
        for d in list(dirnames):
            if d in rc.TREE_SKIP_DIRS:
                found.add(d)
        dirnames[:] = [d for d in dirnames if d not in rc.TREE_SKIP_DIRS]
    return sorted(found)


def prepare_input(path, out, side):
    """(receipt 입력 칸, 트리 루트 경로, 파일 목록, 풀지 않은 링크)"""
    path = os.path.abspath(path)
    links = []
    if os.path.isfile(path) and zipfile.is_zipfile(path):
        dest = os.path.join(out, "in", side)
        os.makedirs(dest)
        links = unzip_safe(path, dest)
        root = unwrap(dest)
        rel = os.path.relpath(root, out).replace(os.sep, "/")
        kind, zsha = "zip", sha256_file(path)
    elif os.path.isdir(path):
        root, rel, kind, zsha = path, path, "dir", None
    else:
        raise UsageError(f"폴더나 zip이 아님: {path}")
    files = rc.tree_files(root)
    info = {"path": path, "kind": kind, "zip_sha256": zsha, "root": rel, "files": len(files),
            "tree_sha256": rc.tree_sha256(files), "skipped": skipped_dirs(root) + [f"zip 링크 {n}" for n in links]}
    return info, root, files


def read_text(root, rel):
    full = os.path.join(root, *rel.split("/"))
    try:
        st = os.lstat(full)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_TEXT:
        return None
    with open(full, "rb") as f:
        data = f.read(MAX_TEXT)
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def changed_files(o_files, f_files):
    o = {rel: d for rel, d, _ in o_files}
    f = {rel: d for rel, d, _ in f_files}
    return (sorted(set(f) - set(o)), sorted(set(o) - set(f)), sorted(k for k in set(o) & set(f) if o[k] != f[k]))


# ---------------------------------------------------------------------------------------------
# 정적 TLS 신호
DOC = re.compile(r"\.(?:md|txt|adoc|rst|html?|svg|csv|json|lock)$", re.I)
COMMENT_LINE = re.compile(r"^\s*(?://|#|/\*|\*|--|<!--)")
SERVER_SIGNALS = [
    ("go", re.compile(r"\.go$"), re.compile(r"\bListenAndServeTLS\b|\bServeTLS\b|\btls\.Listen\b|\btls\.NewListener\b")),
    # 반박 검증에서 찾은 구멍: Netty·Jetty·Undertow·gRPC·Vert.x 서버 TLS와 Flask·aiohttp ssl_context=를 못 봐서 TLS 서비스가 '해당 없음'으로 통과했다
    ("java", re.compile(r"\.(?:java|kt)$"), re.compile(r"\bSSLServerSocket(?:Factory)?\b|\bHttpsServer\b|\bsetUseClientMode\s*\(\s*false|"
                                                        r"\bSslContextBuilder\s*\.\s*forServer\b|\bSslContextFactory\s*\.\s*Server\b|"
                                                        r"\baddHttpsListener\b|\buseTransportSecurity\s*\(|\.setSsl\s*\(\s*true")),
    ("node", re.compile(r"\.(?:js|mjs|cjs|ts)$"), re.compile(r"\bhttps\.createServer\b|\btls\.createServer\b|\bhttp2\.createSecureServer\b")),
    ("python", re.compile(r"\.py$"), re.compile(r"PROTOCOL_TLS_SERVER|server_side\s*=\s*True|\bssl_certfile\b|\bssl_keyfile\b|"
                                                r"(?:\.run|\brun_app|\brun_simple)\s*\([^)\n]*\bssl_context\s*=")),
    ("nginx", re.compile(r"(?:\.conf|\.conf\.template)$"), re.compile(r"^\s*listen\s+[^;#\n]*\bssl\b|^\s*ssl_certificate\s")),
    ("haproxy-apache", re.compile(r"\.(?:cfg|conf)$"), re.compile(r"\bbind\s+[^\n#]*\bssl\b[^\n#]*\bcrt\b|\bSSLEngine\s+on\b")),
    ("startup", re.compile(r"(?:\.sh|Dockerfile[^/]*|compose\.ya?ml|docker-compose\.ya?ml|Procfile)$"),
     re.compile(r"--ssl-certfile|--certfile\b|--tls-cert")),
    # 반박 검증에서 찾은 구멍: Tomcat server.xml 커넥터 TLS를 못 봐서 b-tls가 '해당 없음'이었다
    ("tomcat", re.compile(r"\.xml$"), re.compile(r"\bSSLEnabled\s*=\s*[\"']true[\"']|<SSLHostConfig\b")),
]
# Spring server.ssl.* 를 읽는 파일. 예전에는 Dockerfile ENV JAVA_OPTS="-Dserver.ssl.enabled=true"와 .env를 못 봤다
SPRING_PROPS = re.compile(r"(?:\.properties|\.ya?ml|\.env|\.sh|^Dockerfile[^/]*|^\.env[^/]*)$")
CLIENT_SIGNALS = [
    ("java", re.compile(r"\.(?:java|kt)$"), re.compile(r"\bSSLContext\b|\bHttpsURLConnection\b")),
    ("go", re.compile(r"\.go$"), re.compile(r"\btls\.Config\s*\{|\btls\.Dial\b")),
    ("node", re.compile(r"\.(?:js|mjs|cjs|ts)$"), re.compile(r"\bhttps\.request\b|\btls\.connect\b")),
    ("python", re.compile(r"\.py$"), re.compile(r"\bssl\.create_default_context\b|\bssl\.SSLContext\b")),
]
TERMINATORS = {"nginx", "haproxy-apache", "python"}  # 시스템 OpenSSL로 TLS를 받는 것(런타임 이미지의 OpenSSL이 중요)


def tls_signals(root, scan_rows):
    server, client, terminator = [], [], False
    for path, text in scanmod._files(root):
        if DOC.search(path) or scanmod.is_test(path):  # 시험·예제 경로는 scan/test-paths.ere 한 곳(두 스캐너와 같은 목록)
            continue
        name = path.rsplit("/", 1)[-1]
        lines = text.split("\n")
        for kind, fname, rx in SERVER_SIGNALS:
            if not fname.search(name):
                continue
            for no, line in enumerate(lines, 1):
                if rx.search(line) and not COMMENT_LINE.match(line):
                    server.append(f"{path}:{no} {kind}")
                    terminator = terminator or kind in TERMINATORS
                    break
        if SPRING_PROPS.search(name):
            ptext = re.sub(r"(?m)^[ \t]*(?:ENV|ARG|export)[ \t]+", "", text)  # Dockerfile ENV K=V, 셸 export K=V
            for no, key, value in sorted(verify._props(ptext)):
                if key.startswith("server.ssl.") and not (key == "server.ssl.enabled" and value.lower() == "false"):
                    server.append(f"{path}:{no} spring")
                    break
        for kind, fname, rx in CLIENT_SIGNALS:
            if fname.search(name):
                for no, line in enumerate(lines, 1):
                    if rx.search(line) and not COMMENT_LINE.match(line):
                        client.append(f"{path}:{no} {kind}")
                        break
    for r in scan_rows:
        # TLS 그룹 설정 행만(nginx·Go CurvePreferences·setNamedGroups·jdk.tls.namedGroups). 앱 안 KeyAgreement(ECDH·X25519)
        # 행도 key-exchange라 TLS 없는 서비스가 'TLS 서버 신호'로 미판정이 됐다(하이브리드 키 래핑 X25519+ML-KEM이 그 꼴)
        if r.kind == "key-exchange" and "pins the TLS groups" in r.detail:
            server.append(f"{r.path}:{r.line} {r.component} 그룹 설정")
            terminator = terminator or r.component == "nginx"
    return sorted(set(server)), sorted(set(client)), terminator


# ---------------------------------------------------------------------------------------------
# (a) CBOM
LEGACY_FILE = re.compile(r"(?:^|/)Legacy[A-Za-z0-9_]*\.java$")
ALLOWLINE = re.compile(r"legacy", re.I)
WRITEOPS = re.compile(r"ENCRYPT_MODE|WRAP_MODE|initSign|KeyPairGenerator|generateKeyPair")
# 허용 목록 줄의 쓰기 경로(허용 규칙): Java 규칙(WRITEOPS)에 Python·Go·Node의 새 서명·새 암호화·새 키 생성을 보탠다.
# 그 줄과 아래 3줄(다음 함수 머리 전까지)을 본다. getInstance("RSA…") 줄 다음 줄에서 ENCRYPT_MODE로 여는 꼴을 놓치지 않으려고.
ALLOW_WRITEOPS = re.compile(WRITEOPS.pattern + r"|\.sign\s*\(|\bSign(?:PKCS1v15|PSS|ASN1)?\s*\(|\.encrypt\s*\(|"
                            r"\bEncrypt(?:OAEP|PKCS1v15)\s*\(|generate_private_key|\bGenerateKey\s*\(|\.generate\s*\(|"
                            r"createSign\s*\(|publicEncrypt\s*\(|generateKeyPair(?:Sync)?\s*\(")
HYBRID_LINE = re.compile(r"ML[-_]?KEM", re.I)  # MLKEM768·ML-KEM-768·ml_kem_768
HYBRID_PART = re.compile(r"(?i)x25519|ecdh|x448|secp\d|p-?256|p-?384")
# 하이브리드 결합(허용 규칙): 같은 함수 안 몇 줄 위아래에 주석이 아닌 ML-KEM 코드가 있으면 키 교환 고전 성분은 '하이브리드 허용'.
# 곡선 이름(secp256r1·P-256)만 있는 줄은 서명 곡선일 수 있어 창 안에 키 교환 흔적(ECDH·X25519·exchange 등)이 같이 있어야 한다.
HYB_KEX = re.compile(r"(?i)x25519|x448|\bxdh\b|ecdh|keyagreement|diffie|\.exchange\s*\(|derive_?key\s*\(|\bdh\s*\(")
HYB_CURVE = re.compile(r"(?i)secp\d+[rk]1|\bp-?(?:256|384|521)\b|prime256v1|\bnistp\d+")
HYB_NOT = re.compile(r"(?i)ecdsa|signature|initsign|initverify|\bsign\s*\(|\bverify\s*\(|\brsa|ed25519|ed448|eddsa|oaep|pkcs1")
# 접근 제한자 없는 자바 메서드 머리('byte[] wrap(PublicKey k) throws Exception {')도 함수 머리로 본다. 'else if (…) {' 같은 줄도 걸리지만
# 창이 좁아질 뿐이라(하이브리드 허용이 줄어드는 쪽) 둔다.
FUNC_START = re.compile(r"^\s*(?:async\s+def|def|func|fn|fun|function)\b|^\s*(?:export\s+)?(?:async\s+)?function\b|"
                        r"^\s*(?:public|private|protected|internal|static|final|override|suspend|synchronized)\b[^;=]*\(|^\s*(?:class|struct)\b|"
                        r"^\s*(?:[\w$<>\[\],.?]+\s+)+[\w$]+\s*\([^;=]*\)\s*(?:throws\s+[\w$.,\s]+)?\{")
HYB_WINDOW = 12
HYBRID_REASON = "같은 함수 안 ML-KEM 결합(하이브리드 고전 성분)"
RANK = {"block": 7, "review": 6, "allow": 5, "comment": 4, "check": 3, "scope": 2, "info": 1}
STATUS_LABEL = {"block": "막음", "review": "검토 필요", "allow": "허용", "comment": "주석·테스트", "check": "확인", "scope": "범위 밖",
                "info": "참고"}
SCOPE_REASON = "범위 밖(SCOPE=kex, 키 교환만 본다)"


def in_scope(scope, tool, use):
    if scope == "all":
        return True
    return bool(KEX_USE.search(use or "")) if tool == "cbom-scan" else use in KEX_KINDS


class Lines:
    """트리 파일의 줄(허용 규칙용). 파일마다 한 번만 읽는다."""

    def __init__(self, root):
        self.root, self.cache = root, {}

    def all(self, path):
        if path not in self.cache:
            text = read_text(self.root, path)
            self.cache[path] = text.split("\n") if text is not None else None
        return self.cache[path]

    def get(self, path, line):
        lines = self.all(path)
        if lines is None or not (1 <= line <= len(lines)):
            return None
        return lines[line - 1]


# 줄 끝 주석(// · # · <!-- · /* */). https:// 같은 URL은 앞이 공백·;·줄머리일 때만 주석으로 본다.
TAIL_COMMENT = re.compile(r"/\*.*?(?:\*/|$)|(?:^|(?<=[\s;]))(?://|#|<!--).*$")


def code_part(text):
    return TAIL_COMMENT.sub(" ", text)


LEGACY_REASONS = ("Legacy*.java(옛 데이터 읽기·검증 전용)", "같은 줄 legacy(옛 데이터 읽기·검증)")


def allow_reason(path, text, alg):
    if text is None or WRITEOPS.search(text):
        return None
    if LEGACY_FILE.search(path):
        return LEGACY_REASONS[0]
    if ALLOWLINE.search(text):
        return LEGACY_REASONS[1]
    # 하이브리드는 코드 부분에 ML-KEM이 있어야 한다. 반박 검증에서 'ECDH ... // ML-KEM-768 전환 전 임시',
    # 'ssl_ecdh_curve X25519:prime256v1; # X25519MLKEM768은 3.5부터'처럼 주석에만 있는 줄이 '하이브리드' 허용으로 빠졌다
    code = code_part(text)
    if HYBRID_LINE.search(code) and HYBRID_PART.search(f"{alg} {code}"):
        return "같은 줄 ML-KEM(하이브리드)"
    return None


def write_near(lines, path, line, text):
    """허용 목록 줄이 쓰기 경로인지: 그 줄과 아래 3줄(주석 뺀 코드, 다음 함수 머리 전까지)에 새 키·서명·암호화가 있는지."""
    if text is not None and ALLOW_WRITEOPS.search(code_part(text)):
        return True
    for k in range(line + 1, line + 4) if line else ():
        t = lines.get(path, k)
        if t is None or FUNC_START.search(t):
            break
        if not COMMENT_LINE.match(t) and ALLOW_WRITEOPS.search(code_part(t)):
            return True
    return False


def hybrid_ok(lines, path, line, text, alg=""):
    """키 교환 고전 성분이 같은 함수 안에서 ML-KEM과 묶였는지(창: 위로 함수 머리까지, 아래로 다음 함수 머리 전까지, 각 12줄 안).
    쓰기 연산(임시 키 생성)은 하이브리드에 꼭 필요해서 막지 않는다. 주석·주석 줄의 ML-KEM은 세지 않는다."""
    if not line or text is None:
        return False
    code = code_part(text)
    if COMMENT_LINE.match(text) or HYB_NOT.search(code) or imported_names(path, text, lines, line):
        return False  # import 줄은 이웃 import 의 MLKEM 이름에 끌려 하이브리드가 되지 않게 import_cover 로 본다
    kex, curve = HYB_KEX.search(f"{alg} {code}"), HYB_CURVE.search(f"{alg} {code}")
    if not (kex or curve):
        return False
    lo = hi = line
    for k in range(line - 1, max(0, line - HYB_WINDOW - 1), -1):
        t = lines.get(path, k)
        if t is None:
            break
        lo = k
        if FUNC_START.search(t):
            break
    for k in range(line + 1, line + HYB_WINDOW + 1):
        t = lines.get(path, k)
        if t is None or FUNC_START.search(t):
            break
        hi = k
    window = [lines.get(path, k) or "" for k in range(lo, hi + 1)]
    window = [code_part(t) for t in window if not COMMENT_LINE.match(t)]
    if not any(HYBRID_LINE.search(t) for t in window):
        return False
    return bool(kex) or any(HYB_KEX.search(t) for t in window)


# 허용 줄이 쓰는 import(DESIGN.md 'Allow rules'). 예: 'import java.security.spec.MGF1ParameterSpec;'이 허용 목록의 옛 데이터 복호 줄에서만
# 쓰이는데 G-OAEP-PKCS1 로 남아 c-classic 이 실패하던 꼴. import 줄은 들여온 이름을 쓰는 코드 줄이 모두 허용 목록
# 범위 안이거나 하이브리드 결합 줄일 때만 같은 몫으로 센다. 한 곳이라도 밖에서 쓰거나, 아무 데서도 안 쓰거나, 와일드카드면 그대로 남는다.
IMP_JAVA = re.compile(r"^\s*import\s+(?:static\s+)?([\w.$]+?)(\.\*)?\s*;?\s*$")
IMP_PY_FROM = re.compile(r"^\s*from\s+[\w.]+\s+import\s+\(?\s*([\w\s,*]+?)\s*\)?\s*$")
IMP_PY = re.compile(r"^\s*import\s+([\w.]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*)\s*$")
IMP_JS = re.compile(r"^\s*import\s+(.+?)\s+from\s+['\"][^'\"]+['\"]\s*;?\s*$")
REQ_JS = re.compile(r"^\s*(?:const|let|var)\s+(.+?)\s*=\s*require\s*\(\s*['\"][^'\"]+['\"]\s*\)\s*;?\s*$")
IMP_GO = re.compile(r'^\s*(?:import\s+)?(?:([\w.]+)\s+)?"([\w./-]+)"\s*$')
JAVA_LIKE = re.compile(r"\.(?:java|kt|kts|scala|groovy)$")
JS_LIKE = re.compile(r"\.(?:js|mjs|cjs|jsx|ts|tsx)$")


def _js_names(clause):
    names = []
    for part in re.split(r"[{},]", clause):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(?:\*\s+as\s+)?([\w$]+)(?:\s+as\s+([\w$]+))?|([\w$]+)\s*:\s*([\w$]+)", part)
        if not m:
            return None
        names.append(m[2] or m[1] or m[4])
    return names or None


def _go_import_block(lines, path, line):
    for k in range(line - 1, 0, -1):
        t = (lines.get(path, k) or "").strip()
        if t.startswith("import ("):
            return True
        if t == ")" or t.startswith("func ") or t.startswith("package "):
            return False
    return False


def imported_names(path, text, lines=None, line=None):
    """import 한 줄 → 들여온 이름 목록. import 줄이 아니거나 못 읽거나 와일드카드면 None."""
    if text is None:
        return None
    t = code_part(text).strip()
    if JAVA_LIKE.search(path):
        m = IMP_JAVA.match(t)
        return None if not m or m[2] else [m[1].rsplit(".", 1)[-1]]
    if path.endswith(".py"):
        m = IMP_PY_FROM.match(t)
        if m:
            out = []
            for part in m[1].split(","):
                w = part.split()
                if not w or w[0] == "*":
                    return None
                out.append(w[-1])  # 'a as b' → b
            return out
        m = IMP_PY.match(t)
        return [(x.split()[-1] if " as " in x else x.strip().split(".")[0]) for x in m[1].split(",")] if m else None
    if JS_LIKE.search(path):
        m = IMP_JS.match(t) or REQ_JS.match(t)
        return _js_names(m[1]) if m else None
    if path.endswith(".go"):
        m = IMP_GO.match(t)
        if not m or m[1] in ("_", "."):
            return None
        if not t.startswith("import") and not (lines is not None and line and _go_import_block(lines, path, line)):
            return None
        return [m[1] or m[2].rsplit("/", 1)[-1]]
    return None


def import_cover(lines, path, line, text, allow):
    """허용 줄만 쓰는 import 인가 → (몫 'allowed'|'review'|'hybrid', 허용 항목 또는 None). 아니면 None."""
    names = imported_names(path, text, lines, line)
    if not names:
        return None
    pats = [re.compile(r"(?<![\w$])" + re.escape(n) + r"(?![\w$])") for n in names]
    kinds, entry, used = set(), None, False
    for k, t in enumerate(lines.all(path) or [], 1):
        if k == line or COMMENT_LINE.match(t):
            continue
        c = code_part(t)
        if not any(p.search(c) for p in pats) or imported_names(path, t, lines, k):
            continue
        used = True
        e = allow.match(path, k) if allow is not None else None
        if e is not None:
            kinds.add("review" if write_near(lines, path, k, t) else "allowed")
            entry = entry or e
        elif hybrid_ok(lines, path, k, t):
            kinds.add("hybrid")
        else:
            return None
    if not used:
        return None
    return ("review" if "review" in kinds else "allowed" if "allowed" in kinds else "hybrid"), entry


def split_loc(loc):
    m = re.fullmatch(r"(.+):([0-9]+)", loc)
    return (m[1], int(m[2])) if m else (loc, None)


def run_cbom_scan(script, root, outdir, openssl, cache=None, tree=None, test_paths=None):
    """cbom-scan.sh를 돌려 (ok, csv 경로, 행 목록). cache는 셀프 시험에서 같은 트리를 두 번 안 재려고 쓴다.
    test_paths: 시험 경로 목록 파일(증적에 남긴 사본). residue.sh 와 같은 파일을 준다."""
    os.makedirs(outdir)
    if cache is not None and tree in cache:
        for name in os.listdir(cache[tree]):
            shutil.copy2(os.path.join(cache[tree], name), os.path.join(outdir, name))
    else:
        env = dict(os.environ, OUT=outdir)
        if test_paths:
            env["TEST_PATHS"] = test_paths
        if openssl:
            env["OPENSSL"] = openssl
        try:
            r = subprocess.run(["bash", script, root], env=env, capture_output=True, text=True, errors="replace", timeout=900,
                               stdin=subprocess.DEVNULL)
            log = f"$ bash {script} {root}\n# exit={r.returncode}\n{r.stdout}\n{r.stderr}"
        except subprocess.TimeoutExpired:
            log = "timeout after 900s"
        with open(os.path.join(outdir, "run.log"), "x", encoding="utf-8") as f:
            f.write(log)
        if cache is not None:
            cache[tree] = outdir
    csvs = sorted(n for n in os.listdir(outdir) if re.fullmatch(r"cbom-[0-9-]+\.csv", n))
    log = slurp(os.path.join(outdir, "run.log"))
    if len(csvs) != 1 or "# exit=0" not in log:
        return False, None, []
    with open(os.path.join(outdir, csvs[0]), encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    return True, os.path.join(outdir, csvs[0]), rows


def merge_cbom(cbom_rows, scan_rows, lines, terminator, scope="all", allow=None):
    """두 도구의 행을 같은 꼴로 합치고 행마다 판정(block·review·allow·comment·check·scope·info)을 단다.
    scope가 kex면 키 교환이 아닌 행의 block·allow·check를 scope(범위 밖)로 내린다. 남은 block 중 하이브리드 결합이면 allow,
    허용 목록(allow, 고친 판만)이 덮는 줄이면 allow, 그 줄에 쓰기 연산이 있으면 review(검토 필요, 허용 규칙)."""
    items = []
    for r in cbom_rows:
        loc = r.get("위치", "")
        path, line = split_loc(loc)
        threat, note, alg = r.get("양자 위협", ""), r.get("근거·비고", ""), r.get("알고리즘·키 길이", "")
        reason = None
        if threat == "쇼어로 깨짐":
            if "주석" in note or "테스트" in note:
                status = "comment"
            else:
                reason = allow_reason(path, lines.get(path, line) if line else None, alg)
                status = "allow" if reason else "block"
        elif threat == "미확인":
            status = "check"
        else:
            status = "info"
        items.append({"loc": loc, "tool": "cbom-scan", "use": r.get("용도", ""), "alg": alg, "threat": threat,
                      "status": status, "reason": reason or "", "note": note})
    for r in scan_rows:
        loc = f"{r.path}:{r.line}"
        reason = None
        if r.kind == "base-image" and r.threat in (scanmod.SHOR, scanmod.UNKNOWN):
            status = "block" if terminator else "check"
            reason = "" if terminator else "시스템 OpenSSL로 TLS를 받는 곳(nginx 등)이 없어 참고만"
        elif r.threat == scanmod.SHOR:
            reason = allow_reason(r.path, lines.get(r.path, r.line), r.algorithm)
            status = "allow" if reason else "block"
        elif r.threat == scanmod.WEAK_PQC:
            status = "block"
        elif r.threat == scanmod.UNKNOWN:
            status = "check"
        else:
            status = "info"
        items.append({"loc": loc, "tool": "scan.py", "use": r.kind, "alg": r.algorithm, "threat": r.threat,
                      "status": status, "reason": reason or "", "note": r.detail})
    for it in items:
        if it["status"] in ("block", "allow", "check") and not in_scope(scope, it["tool"], it["use"]):
            it["status"], it["reason"] = "scope", SCOPE_REASON + (f" · {it['reason']}" if it["reason"] else "")
    for it in items:
        # 이름 규칙(legacy)으로 이미 허용된 줄도 허용 목록이 덮으면 그 항목의 사유로 센다(LEGACY_ 로 시작하는 상수 이름 때문에 먼저
        # 허용된 줄이 있으면 그 줄을 가리킨 허용 목록 항목이 '고전 줄 없음'으로 보였다). 쓰기 경로면 검토 필요로 올린다
        legacy = it["status"] == "allow" and it["reason"] in LEGACY_REASONS
        if not legacy and (it["status"] != "block" or it["threat"] == scanmod.WEAK_PQC):  # 보안레벨 3 미만 PQC는 허용하지 않는다
            continue
        path, line = split_loc(it["loc"])
        text = lines.get(path, line) if line else None
        if legacy:
            e = allow.match(path, line) if allow is not None else None
            if e is not None:
                head = f"허용 목록 #{e['n']}({e['kind'] or '종류 없음'})"
                if write_near(lines, path, line, text):
                    it["status"], it["reason"] = "review", f"{head}에 있으나 쓰기 경로(새 키·서명·암호화)라 사람이 확인: {e['why'][:100]}"
                    e["review"].append(it["loc"])
                else:
                    it["reason"] = f"{head}: {e['why'][:140]}"
                    e["allowed"].append(it["loc"])
            continue
        if it["use"] != "base-image" and hybrid_ok(lines, path, line, text, it["alg"]):
            it["status"], it["reason"] = "allow", HYBRID_REASON
            continue
        e = allow.match(path, line) if allow is not None else None
        if e is None:
            imp = import_cover(lines, path, line, text, allow) if it["use"] != "base-image" else None
            if imp is None:
                continue
            kind, e = imp
            if kind == "hybrid":
                it["status"], it["reason"] = "allow", HYBRID_REASON + "에서만 쓰는 import"
                continue
            head = f"허용 목록 #{e['n']}({e['kind'] or '종류 없음'})이 쓰는 import"
            it["status"] = "review" if kind == "review" else "allow"
            it["reason"] = f"{head}: {e['why'][:120]}"
            e[kind].append(it["loc"])
            continue
        head = f"허용 목록 #{e['n']}({e['kind'] or '종류 없음'})"
        if write_near(lines, path, line, text):
            it["status"], it["reason"] = "review", f"{head}에 있으나 쓰기 경로(새 키·서명·암호화)라 사람이 확인: {e['why'][:100]}"
            e["review"].append(it["loc"])
        else:
            it["status"], it["reason"] = "allow", f"{head}: {e['why'][:140]}"
            e["allowed"].append(it["loc"])
    by_loc = {}
    for it in items:
        by_loc.setdefault(it["loc"], set()).add(it["tool"])
    for it in items:
        it["source"] = "둘 다(같은 위치)" if len(by_loc[it["loc"]]) == 2 else it["tool"]
    # cbom-scan이 변수라 '미확인'으로 둔 자리에 scan.py가 대입 추적으로 읽은 이름이 있으면 사유 칸에 적는다(판정은 그대로 '확인')
    traced = {}
    for r in scan_rows:
        if r.threat in (scanmod.PQC, scanmod.WEAK_PQC, scanmod.SHOR) and ("(상수)" in r.detail or "(변수 추적)" in r.detail):
            traced.setdefault(f"{r.path}:{r.line}", []).append(r.algorithm)
    for it in items:
        if it["tool"] == "cbom-scan" and it["status"] == "check" and not it["reason"] and it["loc"] in traced:
            it["reason"] = "scan.py 대입 추적 값: " + ", ".join(dict.fromkeys(traced[it["loc"]])) + "(사람이 확인)"
    worst = {}
    for it in items:
        if RANK[it["status"]] > RANK.get(worst.get(it["loc"]), 0):
            worst[it["loc"]] = it["status"]
    counts = {k: sum(1 for v in worst.values() if v == k) for k in RANK}
    # 주석·테스트 중 시험·예제 경로(scan/test-paths.ere) 위치: 판정에 안 넣지만 따로 세어 보인다
    counts["tests"] = len({it["loc"] for it in items if it["status"] == "comment" and "테스트" in it["note"] and worst[it["loc"]] == "comment"})
    return items, counts, len(worst)


def csv_text(head, rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(head)
    w.writerows(rows)
    return "﻿" + buf.getvalue()


def cbom_csv(items):
    return csv_text(["위치", "출처", "용도·종류", "알고리즘", "양자 위협", "판정", "허용·참고 사유", "비고"],
                    [[i["loc"], i["source"], i["use"], i["alg"], i["threat"], STATUS_LABEL[i["status"]], i["reason"], i["note"]]
                     for i in sorted(items, key=lambda x: (-RANK[x["status"]], x["loc"], x["tool"]))])


# ---------------------------------------------------------------------------------------------
# (c) residue
RES_RULE = re.compile(r"^(GEN|SITE|LWRITE|EXPECT)\s+(\S+)\s+(.*)$")
RES_DETAIL = re.compile(r"^      (LEFT|ALLOW|COMMENT|TEST|P) (.+?):([0-9]+): (.*)$")


def parse_residue(text):
    rules, cur = {}, None
    verdict = None
    for line in text.split("\n"):
        m = RES_RULE.match(line)
        if m:
            kind, rid, rest = m[1], m[2], m[3]
            nums = {k: int(v) for k, v in re.findall(r"\b(code|allow|comment|test|n)=([0-9]+)", rest)}
            cur = rules[rid] = {"kind": kind, "code": nums.get("code", 0), "allow": nums.get("allow", 0),
                                "comment": nums.get("comment", 0), "test": nums.get("test", 0), "n": nums.get("n", 0), "lines": []}
            continue
        d = RES_DETAIL.match(line)
        if d and cur is not None:
            cur["lines"].append({"type": d[1], "path": d[2], "line": int(d[3]), "text": d[4]})
            continue
        s = re.search(r"^SUMMARY .*VERDICT=(\w+)", line)
        if s:
            verdict = s[1]
    if verdict is None:
        return None
    sites = [r for r in rules.values() if r["kind"] == "SITE"]
    # 시험 경로(scan/test-paths.ere)의 고전 코드 줄: 판정에 안 넣고 따로 센다(공개키 9계열·SITE). 옛 RESIDUE 판은 test 칸이 없어 0
    tests = [f"{x['path']}:{x['line']}" for rid, r in rules.items() if r["kind"] == "SITE" or rid in FAMILIES
             for x in r["lines"] if x["type"] == "TEST"]
    return {"rules": rules, "verdict": verdict,
            "tests": {"count": sum(r["test"] for rid, r in rules.items() if r["kind"] == "SITE" or rid in FAMILIES),
                      "lines": sorted(set(tests), key=al._loc_key)[:60]},
            "families": {f: {k: rules.get(f, {}).get(k, 0) for k in ("code", "allow", "comment", "test")} for f in FAMILIES},
            "expect": {rid: r["n"] for rid, r in rules.items() if r["kind"] == "EXPECT"},
            "weak_pqc": rules.get("G-WEAK-PQC", {}).get("code", 0),
            "legacy_write": sum(r["code"] for r in rules.values() if r["kind"] == "LWRITE"),
            "sites_left": sum(1 for r in sites if r["code"] > 0) if sites else None}


def reclass_residue(parsed, lines, allow):
    """고친 판 residue의 LEFT 줄 중 하이브리드 결합·허용 목록 줄을 다시 센다(허용 규칙). residue가 낸 code 수는 그대로 두고 뺄 몫만 낸다.
    공개키 9계열(GEN)과 서비스별 SITE(RESIDUE로 준 판에 있을 때)만 본다. 줄 목록이 MAXD로 잘린 residue면 목록에 나온 줄만 뺀다(나머지는 남은 것으로 센다)."""
    if not parsed:
        return None
    by = {"allowed": {}, "hybrid": {}, "review": {}}
    rows, left = [], []
    sites = [r for r in parsed["rules"].values() if r["kind"] == "SITE"]
    sites_left = 0 if sites else None
    for rid, rule in sorted(parsed["rules"].items()):
        if not (rule["kind"] == "SITE" or (rule["kind"] == "GEN" and rid in FAMILIES)):
            continue
        moved = 0
        for ln in rule["lines"]:
            if ln["type"] != "LEFT":
                continue
            loc = f"{ln['path']}:{ln['line']}"
            text = lines.get(ln["path"], ln["line"])
            text = ln["text"] if text is None else text
            kind, entry, via = None, None, "line"
            if hybrid_ok(lines, ln["path"], ln["line"], text):
                kind = "hybrid"
            elif allow is not None:
                entry = allow.match(ln["path"], ln["line"])
                if entry is not None:
                    kind = "review" if write_near(lines, ln["path"], ln["line"], text) else "allowed"
                    entry[kind].append(loc)
            if kind is None:
                imp = import_cover(lines, ln["path"], ln["line"], text, allow)
                if imp is not None:
                    (kind, entry), via = imp, "import"
                    if entry is not None and kind != "hybrid":
                        entry[kind].append(loc)
            if kind is None:
                left.append(f"{rid} {loc}")
                continue
            moved += 1
            if rule["kind"] == "GEN":
                by[kind][rid] = by[kind].get(rid, 0) + 1
            rows.append({"rule": rid, "loc": loc, "as": kind, "entry": entry["n"] if entry else None, "via": via})
        if rule["kind"] == "SITE" and rule["code"] - moved > 0:
            sites_left += 1
    tot = {k: sum(v.values()) for k, v in by.items()}
    return {"allowed": tot["allowed"], "hybrid": tot["hybrid"], "review": tot["review"], "by_family": by,
            "sites_left": sites_left, "lines": rows[:400], "left": left[:60]}


def java_left(j):
    """공개키 9계열 code 합에서 허용 목록·하이브리드·검토 필요 몫을 뺀 남은 줄(None이면 None)."""
    if not j:
        return None
    raw = sum(v["code"] for v in j["families"].values())
    lst = j.get("listed") or {}
    return raw - lst.get("allowed", 0) - lst.get("hybrid", 0) - lst.get("review", 0)


def run_residue(script, root, test_paths=None):
    try:
        env = dict(os.environ, TEST_PATHS=test_paths) if test_paths else None  # cbom-scan.sh 와 같은 시험 경로 목록
        r = subprocess.run(["bash", script, root], capture_output=True, text=True, errors="replace", timeout=600, stdin=subprocess.DEVNULL,
                           env=env)
        return r.returncode, f"$ bash {script} {root}\n{r.stdout}{r.stderr}\n# exit={r.returncode}\n"
    except subprocess.TimeoutExpired:
        return None, "timeout after 600s\n"


# ---------------------------------------------------------------------------------------------
# (b) TLS 대상
def tls_runs(params, tls_dir, art_log, targets, baseline, expect):
    """(controls, control_problem, targets 결과, baseline 결과)"""
    os.makedirs(tls_dir, exist_ok=True)
    cert_runner = tlsprobe.HostRunner(tls_dir, log=art_log)
    if params.tls_via == "host":
        runner = cert_runner
    else:
        try:
            runner = tlsprobe.ContainerRunner(tls_dir, params.tls_via.split(":", 1)[1], log=art_log)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:  # Docker가 꺼졌거나 컨테이너 이름이 틀림
            return None, f"컨테이너 모드 준비 실패: {str(e).strip()[:300]}", [], []
    results_t, results_b = [], []
    controls, problem = None, None
    # 교차 확인은 X25519MLKEM768을 아는 OpenSSL 3.5 이상만. 맥 기본 LibreSSL 3.3·리눅스 OpenSSL 3.0이면 맞는 서버도
    # '교차 확인이 다름'으로 미판정이 됐다(현장 PC에 openssl@3.5가 없을 수 있다)
    xcheck = params.openssl if params.tls_via == "host" and openssl_35(params.openssl) else None
    try:
        results, problem, addrs = tlsprobe.references(runner, cert_runner)
        if results:
            controls = {k: dict(h.to_json(), addr=addrs["positive"] if k == "positive" else addrs["negative"])
                        for k, (h, raw) in results.items()}
        for label, specs, out in (("t", targets, results_t), ("b", baseline, results_b)):
            for i, spec in enumerate(specs, 1):
                addr, name, ca = parse_target(spec)
                tag = f"{label}{i}"
                ca_in = None
                if ca:
                    shutil.copyfile(ca, os.path.join(tls_dir, f"{tag}-ca.pem"))
                    ca_in = runner.path(f"{tag}-ca.pem")
                res = tlsprobe.probe_target(runner, addr, servername=name, ca=ca_in, label=tag)
                hyb, cls = res["hybrid"][0], res["classical"][0]
                ok, why = tlsprobe.target_verdict(hyb, cls, params.classic)
                if "cert" in expect and not (hyb.cert_key or "").startswith("ML-DSA-65"):
                    ok, why = False, why + [f"인증서 공개키가 ML-DSA-65가 아님({hyb.cert_key})"]
                # openssl·openssl_agrees 칸은 늘 둔다. 교차 확인을 못 하면 둘 다 null 이고 openssl_note 에 '교차 확인 불가'와 까닭을 적는다
                # (OpenSSL 3.5 미만 러너에서 칸이 없어 읽는 쪽이 KeyError 로 죽던 것을 원인 쪽에서 막는다)
                item = {"target": spec, "addr": addr, "servername": name, "trust": "ca-file" if ca else "tofu",
                        "hybrid": hyb.to_json(), "classical": cls.to_json(), "ok": ok, "why": why, "openssl": None,
                        "openssl_agrees": None}
                if not xcheck:
                    item["openssl_note"] = (f"교차 확인 불가: OpenSSL 3.5 이상 아님({openssl_version(params.openssl) or '없음'})"
                                            if params.tls_via == "host" else f"교차 확인 불가: TLS_VIA={params.tls_via}(컨테이너 안에서 잼)")
                if xcheck:
                    ca_path = os.path.join(tls_dir, f"{tag}-ca.pem" if ca else f"{tag}-hybrid-tofu-ca.pem")
                    oh, argv, raw = tlsprobe.openssl_cross_check(xcheck, addr, name,
                                                                 ca_path if os.path.isfile(ca_path) else None)
                    art_log.append({"argv": argv, "exit_code": None, "stdout": raw, "stderr": "", "t": now()})
                    item["openssl"] = oh.to_json()
                    item["openssl_agrees"] = (oh.group == hyb.group) if hyb.ok else (not oh.ok)
                out.append(item)
    finally:
        runner.stop()
    return controls, problem, results_t, results_b


# ---------------------------------------------------------------------------------------------
def tool(name, path, version=""):
    sha = sha256_file(path) if path and os.path.isfile(path) else None
    return {"name": name, "path": str(path or ""), "sha256": sha, "version": version or ""}


def probe_tool():
    """증적 tools[] 의 tls_probe 칸. 이 기계에 바이너리가 없으면 None(없는 바이너리를 버전과 함께 적어 쓴 것처럼 보이지 않게).
    소스 해시 칸('tls_probe source')은 늘 따로 남는다."""
    try:
        path = tlsprobe.host_binary()
    except RuntimeError:
        return None
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        return None
    return tool("tls_probe", str(path), tlsprobe.PROBE_VERSION)


def openssl_version(openssl):
    if not openssl:
        return ""
    try:
        return subprocess.run([openssl, "version"], capture_output=True, text=True, errors="replace", timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def openssl_35(openssl):
    m = re.match(r"OpenSSL (\d+)\.(\d+)", openssl_version(openssl))
    return bool(m) and (int(m[1]), int(m[2])) >= (3, 5)


def default_out(orig):
    """원본이 <작업 폴더>/orig 이고 <작업 폴더>/evidence 가 있으면 그 아래 proof-HHMMSS, 아니면 ./proof-out-HHMMSS."""
    stamp = time.strftime("%H%M%S")
    o = os.path.abspath(orig)
    if os.path.basename(o) == "orig" and os.path.isdir(os.path.join(os.path.dirname(o), "evidence")):
        return os.path.join(os.path.dirname(o), "evidence", f"proof-{stamp}")
    return os.path.abspath(f"proof-out-{stamp}")


def pqc_names(rows, family):
    out = set()
    for r in rows:
        if r.threat != scanmod.PQC:
            continue
        m = re.search(r"ML-(KEM|DSA)-(\d+)", f"{r.algorithm} {r.detail}".replace("_", "-").upper().replace("MLKEM", "ML-KEM-")
                      .replace("MLDSA", "ML-DSA-").replace("--", "-"))
        if m and m[1] == family:
            out.add(f"ML-{m[1]}-{m[2]}")
    return sorted(out)


# ---------------------------------------------------------------------------------------------
# 사람이 읽는 마크다운 표(tables/report.md). 글꼴·색 없이 표만 내서 다른 문서(md)에 그대로 붙인다.
# 글꼴·색이 있는 조각은 tables/fragment.html 이다.
STEP = {"a-input": "입력 트리 해시·대조", "a-cbom": "(a) cbom-scan.sh + scan.py", "b-weakening": "(b) verify.weakening",
        "b-tls": "(b) tls_probe connect + openssl s_client", "c-classic": "(c) residue.sh 공개키 9계열",
        "c-expect": "(c) residue.sh EXPECT", "r-review": "(b) verify.review", "r-allow": "허용 목록 reviewed_by·reviewed_at·reviewed_digest"}


def md_cell(x):
    return str("" if x is None else x).replace("\r", " ").replace("\n", " ").replace("|", "\\|").strip()


def md_table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    return "\n".join(out + ["| " + " | ".join(md_cell(c) for c in row) + " |" for row in rows])


def report_md(r, fixed_items, ev):
    """검사 결과, 전환 뒤 남은 항목, (주소를 줬을 때) TLS 대상별 실측을 마크다운 표로 낸다."""
    p = r["params"]
    kex = p.get("scope") == "kex"
    env = ([f"SCOPE={p['scope']}"] if kex else []) + ["EXPECT=" + (",".join(p["expect"]) or "none")] \
        + ([f"CLASSIC={p['classic']}"] if p["classic"] != "allow" else []) + (["TLS_TARGETS=…"] if p["tls_targets"] else []) \
        + (["REQUIRE_REVIEW=1"] if p.get("require_review") else [])
    cmd = " ".join(env) + f" bash prove.sh {os.path.basename(r['inputs']['orig']['path'])} " \
        f"{os.path.basename(r['inputs']['fixed']['path'])}"
    fx = r["inputs"]["fixed"]
    out = [f"<!-- prove.sh가 만든 표. 고친 판 트리 sha256 {fx['tree_sha256']}"
           + (f", zip sha256 {fx['zip_sha256']}" if fx["zip_sha256"] else "") + ". receipt_id는 같은 폴더 receipt.json. -->", "",
           f"명령: `{md_cell(cmd)}` · 판정 **{rc.verdict_text(r)}** · 실행 기록 {ev}", ""]
    if r.get("format_version"):
        out += [f"판정 근거: pqproof {r['tool_version']} · 규칙 묶음 {r['ruleset_version']} "
                f"(sha256 `{r['ruleset_sha256'][:16]}`) · 증적 형식 {r['format_version']}", ""]
    rows = []
    for i, c in enumerate(r["checks"], 1):
        rows.append([f"V{i}", c["title"], f"`{STEP.get(c['id'], c['id'])}`", c["expected"], f"{STATUS_KO[c['status']]}: {c['actual']}"])
    out += ["검사 결과", "", md_table(["#", "검사", "도구", "기대", "실제"], rows), ""]
    left = {}
    for it in fixed_items:
        if it["status"] in ("review", "allow", "check") and RANK[it["status"]] > RANK.get(left.get(it["loc"], {}).get("status"), 0):
            left[it["loc"]] = it
    # 변수로 넘긴 getInstance 중 값 추적이 PQC로만 읽힌 곳은 '남은 고전'이 아니라 표에서 빼고 개수만 적는다
    traced = [k for k, it in left.items() if it["status"] == "check" and it["reason"].startswith("scan.py 대입 추적 값:")
              and all(re.match(r"\s*(?:ML-KEM|ML-DSA|SLH-DSA)", n)
                      for n in it["reason"].split(":", 1)[1].split("(")[0].split(","))]
    for k in traced:
        del left[k]
    rows = []
    for loc in sorted(left, key=lambda k: (-RANK[left[k]["status"]], k))[:12]:
        it = left[loc]
        why = it["reason"] or it["note"][:90]
        todo = {"allow": "폐기 조건·시점을 정한다", "review": "쓰기 경로: 고치거나 사유를 사람이 확인"}.get(it["status"],
                                                                                          "사람이 확인: 고전이면 고친다")
        rows.append([f"{it['alg'] or it['use']} ({STATUS_LABEL[it['status']]})", f"`{loc}`", why, todo])
    if not rows:
        rows = [["없음(허용·확인 행 0)", "", "", ""]]
    more = len(left) - 12
    out += ["전환 뒤 남은 항목(허용·검토 필요·확인)", "", md_table(["남은 고전 항목", "위치", "남은 이유", "할 일"], rows)]
    notes = ([f"외 {more}곳은 tables/cbom-fixed.csv."] if more > 0 else []) \
        + ([f"변수로 넘긴 알고리즘 이름 {len(traced)}곳은 값을 따라가 PQC로 읽혀 표에서 뺐다({', '.join(sorted(traced)[:4])})."]
           if traced else [])
    out += (["", " ".join(notes)] if notes else []) + [""]
    if r["tls"]["targets"]:
        rows = []
        for i, t in enumerate(r["tls"]["targets"], 1):
            h, c, o = t["hybrid"], t["classical"], t.get("openssl") or {}
            seen = f"`group: {h.get('group') or h.get('error')}` `protocol: {h.get('protocol') or ''}`"
            if h.get("cert_key"):
                seen += f" `cert_key: {h['cert_key']}`"
            if o.get("ok"):
                seen += f", OpenSSL 3.5 `Negotiated TLS1.3 group: {o.get('group')}`"
            seen += f"; 옛 클라이언트(X25519,P-256) `{c.get('group') or c.get('error')}`"
            rows.append([str(i), f"`{t['addr']}` ({t['servername']})",
                         f"X25519MLKEM768(TLS 1.3), 옛 클라이언트 {'고전 그룹 허용' if p['classic'] == 'allow' else '거부'}", seen])
        out += ["TLS 대상별 실측", "", md_table(["#", "대상", "기대", "실제 협상(출력 원문)"], rows), ""]
    out += ["이 도구는 기능·성능을 재지 않는다. 앱 기능 시험과 성능 측정은 따로 한다. "
            "다시 확인: `bash prove.sh --verify <출력 폴더>`(트리·zip sha256과 receipt_id를 다시 계산).", ""]
    return "\n".join(out)


def make_view(root, files, excluded, dest):
    """검사용 사본: 제외 파일과 링크를 뺀 일반 파일만 dest에 복사한다(in/ 아래라 증적 목록 검사에서 빠진다). 원본 트리는 건드리지 않는다."""
    keep = [x for x in files if x[0] not in excluded and not x[1].startswith("symlink:")]
    for rel, _, _ in keep:
        dst = os.path.join(dest, *rel.split("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(root, *rel.split("/")), dst)
    os.makedirs(dest, exist_ok=True)
    return dest, rc.tree_sha256(keep), len(keep)


def pick_note(value, work, name):
    """ALLOW·RECON 값 → (경로 또는 None, 자동으로 찾았나). 'none'이면 끈다. 비우면 <W>/notes/<name>이 있을 때만."""
    if value and value.lower() == "none":
        return None, False
    if value:
        return os.path.abspath(value), False
    auto = os.path.join(work, "notes", name) if work else None
    return (auto, True) if auto and os.path.isfile(auto) else (None, False)


def text_lines(root, rel):
    t = read_text(root, rel)
    return None if t is None else len(t.split("\n")) - (1 if t.endswith("\n") else 0)


def run(orig, fixed, params, out=None, cache=None, quiet=False):
    """한 번 돌린다. 반환: (receipt dict, 종료 코드, 출력 줄 목록)."""
    out = os.path.abspath(out or params.out or default_out(orig))
    if os.path.exists(out):
        raise UsageError(f"출력 폴더가 이미 있다(덮어쓰지 않음): {out}")
    os.makedirs(out)
    art = rc.Artifacts(out)
    started = now()
    timeline = []

    def phase(name, t0):
        timeline.append({"name": name, "started_at": rc.iso(t0), "ended_at": rc.iso(now())})

    # 준비
    t0 = now()
    in_o, root_o, files_o = prepare_input(orig, out, "orig")
    in_f, root_f, files_f = prepare_input(fixed, out, "fixed")
    for side, files in (("원본", files_o), ("고친 판", files_f)):
        if not files:  # 빈 폴더·빈 zip이면 도구가 아무것도 못 찾고 0으로 끝난다(반박 검증에서 찾음)
            raise UsageError(f"{side}에 읽을 파일이 0개다(빈 폴더·빈 zip이거나 build·target 같은 건너뛰는 폴더뿐): "
                             f"{(in_o if side == '원본' else in_f)['path']}")
    added, removed, modified = changed_files(files_o, files_f)
    ch_path, ch_sha = art.add_json("artifacts/changed-files.json", {"added": added, "removed": removed, "modified": modified})

    # 허용 규칙: 실행 데이터 제외(EXCLUDE·recon.json DATA_DIR)와 허용 목록(ALLOW = 전환 에이전트의 notes/unconverted.json)
    o_abs = os.path.abspath(orig).rstrip("/")
    work = os.path.dirname(o_abs) if os.path.basename(o_abs) == "orig" else None
    recon_path, recon_auto = pick_note(params.recon, work, "recon.json")
    allow_path, allow_auto = pick_note(params.allow, work, "unconverted.json")
    excl, app_roots, ex_notes, recon_digest = al.Exclusions(), [], [], None
    if recon_path:
        try:
            recon = json.loads(slurp(recon_path))
            recon_digest = sha256_file(recon_path)
        except (OSError, ValueError) as e:
            recon = None
            ex_notes.append(f"recon.json을 못 읽음({type(e).__name__}): {recon_path}")
        if recon is not None and not params.exclude_off:
            app_roots, notes = al.from_recon(excl, recon, "notes/recon.json" + (" (자동)" if recon_auto else ""))
            ex_notes += notes
        elif recon is not None:
            app_roots = al.recon_paths(recon)[0]
    for pat in params.exclude:
        if pat.startswith("/"):
            hit = [x for x in sorted(app_roots, key=len, reverse=True) if pat.startswith(x.rstrip("/") + "/")]
            if not hit:
                ex_notes.append(f"EXCLUDE {pat}: 앱 폴더 밖이거나 앱 루트를 몰라 뺄 것 없음(상대 글롭으로 준다)")
                continue
            pat = pat[len(hit[0].rstrip("/")) + 1:]
        before = excl.patterns
        if not excl.add(pat, "EXCLUDE"):
            ex_notes.append(f"EXCLUDE {pat}: " + ("recon.json 에서 이미 뺀 글롭" if al.Exclusions.norm(pat) in before
                                                  else "전부 빼는 글롭이라 무시(빈 트리로 통과하는 꼴을 막는다)"))
    # 코드·설정·빌드 파일은 글롭에 걸려도 빼지 않는다(EXCLUDE='src/**' 같은 글롭으로 고전 코드를 감추면 거짓 통과)
    def excluded(rel):
        return excl.match(rel) and not al.KEEP_FILE.search(rel)

    kept = sorted({x[0] for x in files_o + files_f if excl.match(x[0]) and al.KEEP_FILE.search(x[0])})
    if kept:
        ex_notes.append(f"코드·설정 파일 {len(kept)}개는 제외 글롭에 걸려도 검사한다: " + ", ".join(kept[:6]) + (" 외" if len(kept) > 6 else ""))
    ex_o = sorted(x[0] for x in files_o if excluded(x[0]))
    ex_f = sorted(x[0] for x in files_f if excluded(x[0]))
    tree_so, tree_sf = in_o["tree_sha256"], in_f["tree_sha256"]
    root_so, root_sf = root_o, root_f
    if ex_o:
        root_so, tree_so, n = make_view(root_o, files_o, set(ex_o), os.path.join(out, "in", "view-orig"))
        if not n:
            raise UsageError(f"EXCLUDE·recon 데이터 폴더를 빼니 원본에 남는 파일이 0개다: {excl.patterns}")
    if ex_f:
        root_sf, tree_sf, n = make_view(root_f, files_f, set(ex_f), os.path.join(out, "in", "view-fixed"))
        if not n:
            raise UsageError(f"EXCLUDE·recon 데이터 폴더를 빼니 고친 판에 남는 파일이 0개다: {excl.patterns}")
    fixed_all = [x[0] for x in files_f if not x[1].startswith("symlink:")]
    allow = al.AllowList.load(allow_path, fixed_all, lambda rel: text_lines(root_f, rel), app_roots, frozenset(ex_f))
    # 같은 목록을 원본 트리로도 푼다(판정에는 안 쓴다). 고친 판에서 안 쓰인 항목이 원본 고전 줄을 덮는지 보려고(결함 D1, note_other)
    orig_all = [x[0] for x in files_o if not x[1].startswith("symlink:")]
    allow_o = (al.AllowList.load(allow_path, orig_all, lambda rel: text_lines(root_o, rel), app_roots, frozenset(ex_o))
               if allow_path and allow.entries else None)
    allow_art = allow_sha = None
    if allow_path and os.path.isfile(allow_path):
        allow_art, allow_sha = art.add("artifacts/allow-list.json", slurp(allow_path, True))
    lines_o, lines_f = Lines(root_so), Lines(root_sf)
    phase("준비(입력·트리 해시·제외·허용 목록)", t0)

    # (a) CBOM
    t0 = now()
    # 시험·예제 경로 목록(scan/test-paths.ere) 사본을 증적에 두고 cbom-scan.sh·residue.sh 에 같은 파일을 준다(scan.py 는 같은 원본을 읽는다)
    tp_art, tp_sha = art.add("artifacts/test-paths.ere", slurp(scanmod.TEST_PATHS_FILE))
    tp_file = os.path.join(out, *tp_art.split("/"))
    scan_o, scan_f = scanmod.scan(root_so), scanmod.scan(root_sf)
    art.add_json("artifacts/scan-orig.json", [r.to_json() for r in scan_o])
    art.add_json("artifacts/scan-fixed.json", [r.to_json() for r in scan_f])
    sig_o = tls_signals(root_so, scan_o)
    sig_f = tls_signals(root_sf, scan_f)
    cbom = {}
    cbom_items = {}
    for side, root, rows, sig, lns, tree in (("orig", root_so, scan_o, sig_o, lines_o, tree_so),
                                             ("fixed", root_sf, scan_f, sig_f, lines_f, tree_sf)):
        d = os.path.join(out, "artifacts", f"cbom-{side}")
        ok, _, crow = run_cbom_scan(params.cbom_scan, root, d, params.openssl, cache, tree, tp_file)
        art.register_dir(f"artifacts/cbom-{side}")
        items, counts, nloc = merge_cbom(crow, rows, lns, sig[2], params.scope, allow if side == "fixed" else None)
        cbom_items[side] = items
        p, s = art.add(f"tables/cbom-{side}.csv", cbom_csv(items))
        cbom[side] = {"rows": len(items), "locations": nloc, "blocking": counts["block"], "allowed": counts["allow"],
                      "review": counts["review"],
                      "comment_or_test": counts["comment"], "tests": counts["tests"], "check": counts["check"], "info": counts["info"],
                      "out_of_scope": counts["scope"], "cbom_scan_ok": ok, "csv": p, "csv_sha256": s}
    phase("(a) CBOM(cbom-scan + scan.py)", t0)

    # (c) residue
    t0 = now()
    res_ref, res_ref_sha = None, None
    if params.residue:
        res_kind, res_script = "custom", os.path.abspath(params.residue)
    elif os.path.isfile(GENERIC_RESIDUE):
        # 일반판은 출력 폴더에 사본을 두고 그 사본을 돌린다(증적의 해시가 실제로 돈 스크립트를 가리킨다)
        res_kind = "generic"
        p, _ = art.add("artifacts/residue-generic.sh", slurp(GENERIC_RESIDUE))
        res_script = os.path.join(out, *p.split("/"))
    else:
        res_kind, res_script = "none", None
    if res_kind == "custom" and not os.path.isfile(res_script):
        raise UsageError(f"RESIDUE 파일 없음: {res_script}")
    if res_kind == "custom":
        p, _ = art.add("artifacts/residue-custom.sh", slurp(res_script))
        res_art = p
    elif res_kind == "generic":
        res_art = "artifacts/residue-generic.sh"
    else:
        res_art = None
    java = {}
    res_parsed = {}
    for side, root in (("orig", root_so), ("fixed", root_sf)):
        if not res_script:
            java[side] = None
            continue
        rcode, text = run_residue(res_script, root, tp_file)
        p, s = art.add(f"artifacts/residue-{side}.txt", text)
        parsed = parse_residue(text)
        res_parsed[side] = parsed
        java[side] = None if parsed is None else {
            "families": parsed["families"], "expect": parsed["expect"], "weak_pqc": parsed["weak_pqc"],
            "legacy_write": parsed["legacy_write"], "sites_left": parsed["sites_left"], "verdict": parsed["verdict"],
            "tests": parsed["tests"], "output": p, "output_sha256": s}
        if side == "fixed" and parsed is not None:
            java[side]["listed"] = reclass_residue(parsed, lines_f, allow)
    allow.finish()
    # 원본 고전 줄(고친 판에서 허용 목록과 맞춰 보는 것과 같은 몫: 막는 위치·이름 규칙 허용 줄, residue LEFT 중 하이브리드가 아닌 줄)
    orig_locs = {it["loc"] for it in cbom_items["orig"]
                 if it["status"] == "block" or (it["status"] == "allow" and it["reason"] in LEGACY_REASONS)}
    for rid, rule in ((res_parsed.get("orig") or {}).get("rules") or {}).items():
        if rule["kind"] == "SITE" or (rule["kind"] == "GEN" and rid in FAMILIES):
            orig_locs |= {f"{x['path']}:{x['line']}" for x in rule["lines"] if x["type"] == "LEFT"
                          and not hybrid_ok(lines_o, x["path"], x["line"], lines_o.get(x["path"], x["line"]) or x["text"])}
    allow.note_other(allow_o, sorted(orig_locs, key=al._loc_key))
    usage_rows = [[side, f"{r.path}:{r.line}", r.kind, r.algorithm, r.threat, r.detail]
                  for side, rows in (("원본", scan_o), ("고친 판", scan_f)) for r in rows if r.component == "java"]
    up, us = art.add("tables/java-usage.csv", csv_text(["판", "위치", "종류", "알고리즘", "threat", "비고"], usage_rows))
    jrows = []
    rules_all = sorted(set().union(*[set(v["rules"]) for v in res_parsed.values() if v] or [set()]))
    for rid in rules_all:
        o = (res_parsed.get("orig") or {}).get("rules", {}).get(rid, {})
        f = (res_parsed.get("fixed") or {}).get("rules", {}).get(rid, {})
        where = "; ".join(f"{x['type']} {x['path']}:{x['line']}" for x in f.get("lines", []) if x["type"] in ("LEFT", "ALLOW", "P"))
        jrows.append([rid, (o or f).get("kind", ""), "예" if rid in FAMILIES else "", o.get("code", ""), o.get("allow", ""),
                      o.get("comment", ""), o.get("n", ""), f.get("code", ""), f.get("allow", ""), f.get("comment", ""),
                      f.get("n", ""), where])
    art.add("tables/java.csv", csv_text(["규칙", "종류", "공개키 9계열", "원본 code", "원본 allow", "원본 comment", "원본 n",
                                         "고친 판 code", "고친 판 allow", "고친 판 comment", "고친 판 n", "고친 판 줄(LEFT·ALLOW·P)"],
                                        jrows))
    java_rec = {"residue_kind": res_kind, "script": res_art,
                "script_sha256": art.items[res_art]["sha256"] if res_art else None,
                "ref": res_ref, "ref_digest": res_ref_sha, "orig": java.get("orig"), "fixed": java.get("fixed"),
                "usage": up, "usage_sha256": us}
    phase("(c) 공개키 집계(residue)", t0)

    # (b) 약화 수정
    t0 = now()
    changed = {}
    for rel in added + removed + modified:
        if excluded(rel):  # 실행 데이터(키·DB·로그)는 약화 수정 검사에서도 뺀다
            continue
        before = "" if rel in added else read_text(root_o, rel)
        after = "" if rel in removed else read_text(root_f, rel)
        if before is None or after is None:
            continue
        changed[rel] = (before, after)
    deny = verify.weakening(changed)
    review = [dict(x, reason="") for x in verify.review(changed)]
    wp, ws = art.add_json("artifacts/weakening.json", {"deny": deny, "review": review, "files": sorted(changed)})
    phase("(b) TLS 약화 수정 검사", t0)

    # (b) TLS 대상
    t0 = now()
    tls_log = []
    controls = problem = None
    t_results, b_results = [], []
    if params.tls_targets or params.tls_targets_orig:
        controls, problem, t_results, b_results = tls_runs(params, os.path.join(out, "artifacts", "tls"), tls_log,
                                                           params.tls_targets, params.tls_targets_orig, params.expect)
    tl_path = tl_sha = None
    if tls_log:
        tl_path, tl_sha = art.add_json("artifacts/tls-log.json", [dict(x, t=rc.iso(x["t"])) for x in tls_log])
    if os.path.isdir(os.path.join(out, "artifacts", "tls")):
        art.register_dir("artifacts/tls")
    tls = {"signals": sig_f[0], "client_signals": sig_f[1], "applicable": bool(sig_f[0] or params.tls_targets),
           "via": params.tls_via, "controls": controls, "control_problem": problem, "targets": t_results,
           "baseline": b_results, "log": tl_path, "log_sha256": tl_sha}
    phase("(b) TLS 탐침", t0)

    # 검사
    checks = []

    def check(cid, title, status, expected, actual):
        checks.append({"id": cid, "title": title, "status": status, "expected": expected, "actual": actual})

    cf, co = cbom["fixed"], cbom["orig"]
    # review(검토 필요): 막는 위치는 0인데 허용 목록에 쓰기 경로 줄이 있다(허용 규칙). 판정은 바꾸지 않고 줄·사유를 남긴다
    a_status = "fail" if cf["blocking"] else ("undecided" if not cf["cbom_scan_ok"] else ("review" if cf["review"] else "pass"))
    kex = params.scope == "kex"
    # a-input: 두 입력이 같은 서비스의 전·후인지, 판정 근거가 있는지. 도구가 원본에서 아무것도 못 찾으면 고친 판 0은
    # 증거가 아니다(못 보는 언어·프레임워크, 잘못 준 폴더). 반박 검증에서 Netty·Flask TLS 서비스가 그대로 통과했다.
    o_paths, f_paths = {x[0] for x in files_o}, {x[0] for x in files_f}
    common = len(o_paths & f_paths)
    orig_code = (sum(v["code"] for v in java_rec["orig"]["families"].values())
                 if java_rec["orig"] and not kex else 0)
    basis = co["blocking"] + orig_code + len(t_results)
    vanished = sorted({split_loc(it["loc"])[0] for it in cbom_items["orig"] if it["status"] == "block"} & (o_paths - f_paths))
    in_act = (f"공통 파일 {common}/{len(o_paths)} · 원본 막는 위치 {co['blocking']}"
              + ("" if kex else f" · 원본 공개키 code {orig_code}") + f" · TLS 실측 대상 {len(t_results)}")
    if common < MIN_COMMON * len(o_paths):
        in_st = "undecided"
        in_act += " · 공통 파일이 절반 미만: 다른 서비스이거나 폴더 깊이가 다르다(zip 최상위 한 겹, repo 안 하위 폴더 등)"
    elif basis == 0:
        in_st = "undecided"
        in_act += (" · 원본에서 고전 " + ("키 교환을" if kex else "공개키를") + " 하나도 못 찾았고 TLS 실측도 없다: 도구가 이 언어·"
                   "프레임워크를 못 보는 것일 수 있다(crypto-grep.sh로 사람이 확인하거나 SCOPE·TLS_TARGETS를 맞춘다)")
    elif vanished:
        in_st = "review"
        in_act += (f" · 원본 막는 위치가 있던 파일 중 고친 판에서 사라진 것 {len(vanished)}개: " + ", ".join(vanished[:4])
                   + (" 외" if len(vanished) > 4 else "") + "(기능을 지워서 0이 된 것이 아닌지 확인)")
    else:
        in_st = "pass"
    check("a-input", "입력 확인(같은 서비스의 전·후, 원본에서 전환 대상을 찾음)", in_st,
          f"공통 파일 {int(MIN_COMMON * 100)}% 이상, 원본 막는 위치·공개키 code·TLS 실측 중 하나 이상", in_act)
    block_locs = sorted({it["loc"] for it in cbom_items["fixed"] if it["status"] == "block"})
    what = "남은 고전 키 교환" if kex else "막는 위치"
    check("a-cbom", "고친 판에 남은 고전 키 교환 0(SCOPE=kex)" if kex else "고친 판 CBOM에 막는 위치 0", a_status,
          f"{what} 0, cbom-scan 정상 종료",
          f"{what} {cf['blocking']}곳(원본 {co['blocking']})"
          + (": " + ", ".join(block_locs[:6]) + (" 외" if len(block_locs) > 6 else "") if block_locs else "")
          + f" · 허용 {cf['allowed']} · 주석·테스트 {cf['comment_or_test']}" + (f"(시험 {cf['tests']})" if cf.get("tests") else "")
          + f" · 확인 {cf['check']}"
          + (f" · 검토 필요 {cf['review']}(허용 목록의 쓰기 경로: "
             + ", ".join(sorted({it['loc'] for it in cbom_items['fixed'] if it['status'] == 'review'})[:4]) + ")" if cf["review"] else "")
          + (f" · 범위 밖 {cf['out_of_scope']}" if kex else "") + ("" if cf["cbom_scan_ok"] else " · cbom-scan 실패"))
    check("b-weakening", "TLS 약화 수정 없음", "fail" if deny else "pass", "deny 0",
          f"deny {len(deny)}" + (": " + "; ".join(deny[:3]) if deny else "") + f" · 본 파일 {len(changed)}")
    if not tls["applicable"] and sig_o[0]:  # TLS를 걷어 내고 평문으로 바꾼 판이 '해당 없음'으로 통과하지 않게(반박 검증에서 찾음)
        check("b-tls", "TLS 하이브리드 협상·옛 클라이언트", "undecided", "TLS 서버 신호 없음",
              f"원본 TLS 서버 신호 {len(sig_o[0])}곳({', '.join(sig_o[0][:3])})이 고친 판에서 0: TLS를 걷어 냈는지 사람이 확인"
              "(TLS 제거는 약화다. 일부러 앞단으로 옮겼으면 그 앞단 주소를 TLS_TARGETS로)")
    elif not tls["applicable"] and sig_f[1]:  # 클라이언트 TLS만 있는 서비스가 말없이 '해당 없음'이었다
        check("b-tls", "TLS 하이브리드 협상·옛 클라이언트", "review", "TLS 서버 신호 없음",
              f"TLS 서버 신호 0, 클라이언트 TLS 신호 {len(sig_f[1])}곳({', '.join(sig_f[1][:3])}): tls_probe는 서버만 잰다. "
              "이 클라이언트가 X25519MLKEM768을 제시하는지(jdk.tls.namedGroups·BCJSSE·Go CurvePreferences 등) 사람이 확인")
    elif not tls["applicable"]:
        check("b-tls", "TLS 하이브리드 협상·옛 클라이언트", "na", "TLS 서버 신호 없음", "TLS 서버·클라이언트 신호 0")
    elif not params.tls_targets:
        check("b-tls", "TLS 하이브리드 협상·옛 클라이언트", "undecided", "TLS_TARGETS로 실측",
              f"TLS 서버 신호 {len(sig_f[0])}곳인데 TLS_TARGETS 없음")
    else:
        disagree = [f"{t['addr']}@{t['servername']}" for t in t_results if t.get("openssl") is not None and not t.get("openssl_agrees")]
        if problem:
            st, act = "undecided", f"대조 실패: {problem.splitlines()[0]}"
        elif not all(t["ok"] for t in t_results):
            st = "fail"
            act = "; ".join(f"{t['addr']}@{t['servername']}: {', '.join(t['why'])}" for t in t_results if not t["ok"])
        elif disagree:
            st, act = "undecided", f"OpenSSL 3.5 교차 확인이 다름: {', '.join(disagree)}"
        else:
            st = "pass"
            act = "; ".join(f"{t['addr']}@{t['servername']} {t['hybrid']['group']} / 옛 클라이언트 "
                            f"{t['classical']['group'] or '거부'}" for t in t_results)
            act += f" · 잰 대상 {len(t_results)}개, 고친 판 TLS 서버 신호 {len(sig_f[0])}곳(신호마다 대상이 있는지 사람이 확인)"
            if sig_f[1]:
                act += f" · 클라이언트 TLS 신호 {len(sig_f[1])}곳은 재지 않음"
            if any(t.get("openssl_note") for t in t_results):
                act += " · OpenSSL 교차 확인 불가(3.5 미만이거나 컨테이너 모드, tls_probe 결과만)"
        check("b-tls", "TLS 하이브리드 협상·옛 클라이언트", st,
              f"대조 성립, 하이브리드 전용 제시 → X25519MLKEM768(TLS 1.3), 옛 클라이언트 {'접속' if params.classic == 'allow' else '거부'}",
              act)
    jf = java_rec["fixed"]
    if kex:
        left = sum(v["code"] for v in jf["families"].values()) if jf else None
        orig_left = sum(v["code"] for v in java_rec["orig"]["families"].values()) if java_rec["orig"] else None
        check("c-classic", "고전 공개키 9계열 code 0, 보안레벨 3 미만 PQC 0, 레거시 쓰기 0", "na",
              "SCOPE=kex라 판정에 안 씀(서명·암호화까지 보려면 SCOPE=all)",
              f"범위 밖 · 참고로 공개키 code {left}(원본 {orig_left})")
    elif jf is None:
        check("c-classic", "고전 공개키 9계열 code 0", "undecided", "residue 출력", "residue를 못 돌림")
    else:
        lst = jf.get("listed") or {}
        raw = sum(v["code"] for v in jf["families"].values())
        left = java_left(jf)
        sites = lst.get("sites_left", jf["sites_left"])
        orig_left = sum(v["code"] for v in java_rec["orig"]["families"].values()) if java_rec["orig"] else None
        ok = left == 0 and jf["weak_pqc"] == 0 and jf["legacy_write"] == 0 and not sites
        moved = lst.get("allowed", 0) + lst.get("hybrid", 0) + lst.get("review", 0)
        check("c-classic", "고전 공개키 9계열 code 0, 보안레벨 3 미만 PQC 0, 레거시 쓰기 0",
              ("review" if lst.get("review") else "pass") if ok else "fail",
              "모두 0(허용 목록·하이브리드 결합 줄은 사유와 함께 뺀다)",
              f"공개키 code {left}(원본 {orig_left}) · 보안레벨 3 미만 {jf['weak_pqc']} · 레거시 쓰기 {jf['legacy_write']}"
              + (f" · SITE LEFT {sites}" if sites is not None else "")
              + (f" · residue code {raw}에서 허용 목록 {lst.get('allowed', 0)}·하이브리드 {lst.get('hybrid', 0)}"
                 f"·검토 필요 {lst.get('review', 0)}줄 뺌" if moved else "")
              + (": 남은 LEFT " + ", ".join(lst.get("left", [])[:6]) + (" 외" if left > 6 else "") if left and lst.get("left") else "")
              + (f" · 시험 경로 코드 {jf['tests']['count']}줄(판정에 안 넣고 따로 셈: "
                 + ", ".join(jf["tests"]["lines"][:3]) + (" 외" if jf["tests"]["count"] > 3 else "") + ")"
                 if (jf.get("tests") or {}).get("count") else ""))
    if not params.expect:
        check("c-expect", "EXPECT PQC 사용", "na", "EXPECT 없음", "해당 없음")
    else:
        parts, st = [], "pass"
        for e in params.expect:
            if e in EXPECT_IDS:
                n = jf["expect"].get(EXPECT_IDS[e]) if jf else None
                parts.append(f"{EXPECT_IDS[e]} {n}")
                if n is None:
                    st = "undecided" if st == "pass" else st
                elif n < 1:
                    st = "fail"
            else:  # tls, cert: b-tls 판정을 따른다
                b = next(c for c in checks if c["id"] == "b-tls")["status"]
                parts.append(f"{e} → b-tls {STATUS_KO[b]}")
                if b == "fail" or (b == "na" and e in ("tls", "cert")):
                    st = "fail"
                elif b in ("undecided", "review") and st == "pass":  # review = 클라이언트 TLS만, 잰 것이 없다
                    st = "undecided"
        check("c-expect", "EXPECT PQC 사용", st, "EXPECT=" + ",".join(params.expect) + " 마다 1줄 이상(tls·cert는 b-tls 통과)",
              " · ".join(parts))
    check("r-review", "검증 생략 흔적(검토 등급, 실패 아님)", "review" if review else "pass", "0 또는 줄마다 사유",
          f"{len(review)}건" + (": " + "; ".join(f"{x['path']} {x['rule']}" for x in review[:3]) if review else ""))
    # r-allow: 허용 목록이 판정에서 뺀 줄을 사람이 확인했다는 기록(reviewed_by·reviewed_at)이 있는가. 도구는 사유가 맞는지
    # 모르므로 확인 전 허용은 검토 등급으로 남기고(판정 그대로), REQUIRE_REVIEW=1 이면 실패로 막는다. 목록 맨 위 칸은
    # reviewed_digest 가 지금 목록과 맞을 때만 센다(확인 뒤 더하거나 고친 항목이 예전 확인을 물려받지 않게, allowlist.resolve_reviews)
    # 고친 판에서 안 쓰인 항목(unused)도 여기서 본다: 목록은 어느 트리에 대든 걸리므로 그 항목은 원본 같은 다른 트리의 고전 줄을 가린다
    # (결함 D1). 판정은 그대로 두고 검토 필요로, REQUIRE_REVIEW=1 이면 실패로 막는다. 고친 판에서 지운 파일처럼
    # 고친 판에서는 무효·제외·트리 밖인데 원본 고전 줄을 덮는 항목도 안 쓰인 항목으로 센다(allowlist.counts_unused, 독립 검토에서 찾음)
    live = [e for e in allow.entries if e["status"] in al.IN_EFFECT]
    pending = allow.unreviewed()
    unused = allow.unused()
    need = "허용 항목마다 reviewed_by·reviewed_at(목록 맨 위 칸은 reviewed_digest 도), 고친 판에서 안 쓰인 항목 0" + (
        "(REQUIRE_REVIEW=1: 아니면 실패)" if params.require_review else "(아니면 검토 필요, 실패 아님)")
    title = "허용 항목 사람 확인(검토 등급, REQUIRE_REVIEW=1이면 실패)"
    dead_ko = {"invalid": " (고친 판에서 무효)", "excluded": " (고친 판에서 제외 파일)", "outside": " (고친 판에서 트리 밖)"}
    unused_txt = (f"고친 판에서 안 쓰인 항목 {len(unused)}건(원본 고전 {sum(len(e['orig']) for e in unused)}줄을 덮음, 사람 확인 전): "
                  + ", ".join(f"#{e['n']} {al.CONTROL.sub(' ', e['where'])[:48]}{dead_ko.get(e['status'], '')}" for e in unused[:4])
                  + (" 외" if len(unused) > 4 else "") if unused else "")
    if not live and not unused:
        check("r-allow", title, "na", need, "줄을 허용한 항목 0" if allow_path else "허용 목록 없음")
    elif not pending and not unused:
        check("r-allow", title, "pass", need, f"허용 항목 {len(live)}건 모두 사람 확인")
    else:
        head = (f"허용 항목 {len(live)}건 중 사람 확인 전 {len(pending)}건: "
                + ", ".join(f"#{e['n']} {al.CONTROL.sub(' ', e['where'])[:48]}" for e in pending[:4]) + (" 외" if len(pending) > 4 else "")
                if pending else (f"허용 항목 {len(live)}건 모두 사람 확인" if live else ""))
        check("r-allow", title, "fail" if params.require_review else "review", need, " · ".join(x for x in (head, unused_txt) if x))
    verdict = rc.derive_verdict(checks)

    # 표·조각
    extra = []
    for i, src in enumerate(params.extra, 1):
        if not os.path.isfile(src):
            raise UsageError(f"EXTRA_EV 파일 없음: {src}")
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(src))[:100] or f"extra-{i}"
        p, s = art.add(f"artifacts/extra/{i:02d}-{name}", slurp(src, True))
        extra.append({"source": os.path.abspath(src), "path": p, "path_sha256": s})
    tls_rows = []
    for t in t_results:
        for k, offered, want in (("hybrid", tlsprobe.OFFER_HYBRID, tlsprobe.OFFER_HYBRID),
                                 ("classical", tlsprobe.OFFER_CLASSICAL, "고전 그룹" if params.classic == "allow" else "거부")):
            h = t[k]
            tls_rows.append([t["target"], params.tls_via, offered, want, h.get("group") or h.get("error") or "",
                             h.get("protocol") or "", h.get("cert_sig") or "", h.get("cert_key") or "", t["trust"],
                             "예" if t["ok"] else "아니오"])
    art.add("tables/tls.csv", csv_text(["대상", "이름공간", "제시 그룹", "기대", "협상 그룹(또는 오류)", "프로토콜", "cert_sig",
                                        "cert_key", "신뢰 방식", "통과"], tls_rows))
    art.add("tables/summary.csv", csv_text(["검사", "제목", "판정", "기준", "실제"],
                                           [[c["id"], c["title"], STATUS_KO[c["status"]], c["expected"], c["actual"]]
                                            for c in checks]))
    # ev: 이 실행의 화면 출력을 따로 남긴 파일 이름. EV_NAME, 없으면 <출력 폴더 이름>.txt
    out_name, out_parent = os.path.basename(out), os.path.dirname(out)
    ev_name = params.ev or out_name + ".txt"
    in_ev = os.path.basename(out_parent) == "evidence"
    deck_meta = {"receipt_file": f"evidence/{out_name}/receipt.json" if in_ev else os.path.join(out, "receipt.json"),
                 "verify_cmd": f"bash prove.sh --verify {f'evidence/{out_name}' if in_ev else out}", "ev": ev_name}
    fam_sum = {k: sum(v[k] for v in jf["families"].values()) for k in ("code", "allow", "comment")} if jf else None
    if fam_sum:
        lst = jf.get("listed") or {}
        fam_sum["allow"] += lst.get("allowed", 0) + lst.get("hybrid", 0)
        fam_sum["code"] = java_left(jf) + lst.get("review", 0)
    c_classic = next(c for c in checks if c["id"] == "c-classic")["status"]
    hyb_groups = [t["hybrid"]["group"] for t in t_results if t["hybrid"].get("group")]
    art.add_json("evidence-fragment.json", {
        "note": ("다른 증거 묶음에 옮겨 적기 쉬운 값 요약. ev는 이 실행의 화면 출력을 남긴 파일 이름(<출력 폴더 이름>.txt)이다. "
                 "classic_lines는 공개키 9계열 code 줄 합계다. 앱 기능 시험 결과는 이 도구가 내지 않는다."),
        "classic_lines": ({"count": fam_sum["code"], "allow": fam_sum["allow"], "comment": fam_sum["comment"],
                           "tool": f"residue.sh({ {'generic': '일반판', 'custom': '지정본'}.get(res_kind, res_kind) }, 공개키 9계열) via prove.sh",
                           "verdict": {"pass": "CLEAN", "review": "CLEAN", "na": "SCOPE=kex(판정 안 함)"}.get(c_classic, "RESIDUE"),
                           "ev": [ev_name]}
                          if fam_sum else {"count": None, "verdict": "미실행"}),
        "pqc_partial": {"kem": pqc_names(scan_f, "KEM"), "sig": pqc_names(scan_f, "DSA"),
                              "tls_group": hyb_groups[0] if hyb_groups else None, "ev": [ev_name]},
        "proof": {"verdict": verdict, "verdict_text": rc.verdict_text({
                      "verdict": verdict, "format_version": ver.FORMAT_VERSION, "weakening": {"review": review}, "allowlist": {
                      "unreviewed": len(pending), "unused": len(unused), "write_review": len(allow.write_review())}}),
                  "allow_unreviewed": len(pending), "checks": {c["id"]: c["status"] for c in checks}},
    })

    tools = [tool("cbom-scan.sh", params.cbom_scan), tool("residue", res_script, res_kind),
             tool("test-paths.ere", scanmod.TEST_PATHS_FILE)]
    pyfiles = ["prove.py", "prove.sh", "pqlite/scan.py", "pqlite/verify.py", "pqlite/tlsprobe.py", "pqlite/receipt.py",
               "pqlite/allowlist.py", "pqlite/version.py"]
    tools += [tool(p, os.path.join(HERE, p)) for p in pyfiles]
    probe = probe_tool()
    if probe:
        tools.append(probe)
    tools.append({"name": "tls_probe source", "path": str(tlsprobe.PROBE_SRC), "sha256": tlsprobe.source_sha256(),
                  "version": tlsprobe.PROBE_VERSION})
    tools.append({"name": "python", "path": sys.executable, "sha256": None, "version": sys.version.split()[0]})
    tools.append(tool("openssl", params.openssl, openssl_version(params.openssl)))

    # 판정 근거 버전(증적 형식 2부터): 도구 버전, 실제로 돈 규칙 파일 여섯의 묶음 해시와 그 이름(scan/ruleset.json), 증적 형식.
    # 몇 년 뒤에도 어느 규칙으로 판정했는지 알 수 있게 한다. --verify 는 묶음 해시를 tools[] 의 해시로 다시 계산해 맞춘다
    rs_sha = ver.ruleset_from_tools(tools)
    r = {"format": rc.FORMAT, "format_version": ver.FORMAT_VERSION, "tool_version": ver.tool_version(),
         "ruleset_version": ver.ruleset_label(rs_sha), "ruleset_sha256": rs_sha,
         "note": rc.NOTE, "verdict": verdict, "started_at": rc.iso(started), "finished_at": None,
         "inputs": {"orig": in_o, "fixed": in_f}, "tools": tools,
         "params": {"classic": params.classic, "expect": params.expect, "scope": params.scope, "tls_via": params.tls_via,
                    "tls_targets": params.tls_targets, "tls_targets_orig": params.tls_targets_orig,
                    "residue": res_script or "", "allow": allow_path or "", "exclude": excl.patterns,
                    "recon": recon_path or "", "require_review": params.require_review},
         "changed": {"added": added, "removed": removed, "modified": modified, "file": ch_path, "file_sha256": ch_sha},
         "cbom": cbom, "java": java_rec, "tls": tls,
         "weakening": {"deny": deny, "review": review, "file": wp, "file_sha256": ws},
         "checks": checks, "timeline": timeline, "extra": extra}
    hyb_locs = sorted({it["loc"] for it in cbom_items["fixed"] if it["status"] == "allow" and it["reason"] == HYBRID_REASON}
                      | {x["loc"] for x in ((jf or {}).get("listed") or {}).get("lines", []) if x["as"] == "hybrid"},
                      key=al._loc_key)
    # 이름 규칙(Legacy*.java·같은 줄 legacy, 쓰기 연산 없음)으로만 허용된 위치. 허용 목록에 없어도 판정에서 빠지므로 증적·덱에 따로 남긴다
    legacy_locs = sorted({it["loc"] for it in cbom_items["fixed"] if it["status"] == "allow" and it["reason"] in LEGACY_REASONS},
                         key=al._loc_key)
    r["allowlist"] = {"source": allow_path, "auto": allow_auto, "file": allow_art, "file_sha256": allow_sha,
                      "entries": allow.record(), "warnings": allow.warnings, "unreviewed": len(pending),
                      "top_digest": allow.top_digest,
                      # 결함 D1 뒤에 보탬: 안 쓰인 항목 수, 그 항목들이 원본에서 덮는 고전 줄 수(사람 확인 전), 허용 범위 쓰기 경로 위치 수
                      "unused": len(unused), "unused_orig_lines": sum(len(e["orig"]) for e in unused),
                      "write_review": len(allow.write_review()),
                      "hybrid": hyb_locs, "legacy": legacy_locs,
                      "imports": sorted({x["loc"] for x in ((jf or {}).get("listed") or {}).get("lines", []) if x.get("via") == "import"}
                                        | {it["loc"] for it in cbom_items["fixed"] if it["status"] in ("allow", "review")
                                           and "쓰는 import" in it["reason"]}, key=al._loc_key)}
    r["test_paths"] = {"file": tp_art, "file_sha256": tp_sha}
    r["excluded"] = {"items": excl.items, "notes": ex_notes, "app_roots": app_roots, "recon_file": recon_path,
                     "recon_digest": recon_digest, "count_orig": len(ex_o), "count_fixed": len(ex_f),
                     "files_orig": ex_o[:200], "files_fixed": ex_f[:200]}
    r["deck_meta"] = deck_meta
    t0 = now()
    art.add("tables/fragment.html", rc.render_fragment(r))  # 다른 HTML에 붙일 조각(md 문서에는 report.md)
    art.add("tables/report.md", report_md(r, cbom_items["fixed"], ev_name))
    r["artifacts"] = art.manifest()
    phase("(d) 표·검증 증적", t0)
    r["finished_at"] = rc.iso(now())
    r["receipt_id"] = rc.compute_id(r)
    with open(os.path.join(out, "receipt.json"), "x", encoding="utf-8") as f:
        f.write(rc.dumps(r))  # verify 가 이 바이트 그대로인지 본다
    with open(os.path.join(out, "receipt.html"), "x", encoding="utf-8") as f:
        f.write(rc.render_html(r))
    with open(os.path.join(out, "deck.json"), "x", encoding="utf-8") as f:
        f.write(rc.render_deck(r))  # 발표 자료·대시보드용 요약. receipt.json에서 결정적으로 나와 verify가 다시 만들어 본다
    vres = rc.verify(out)
    bad = [w for ok, w in vres if not ok]

    lines = [f"== pqc-proof prove.sh  ({time.strftime('%Y-%m-%d %H:%M:%S %Z')})  [{platform.machine()}]",
             f"원본   : {in_o['path']} ({in_o['kind']}, 파일 {in_o['files']}, 트리 {in_o['tree_sha256'][:16]}"
             + (f", zip {in_o['zip_sha256'][:16]}" if in_o["zip_sha256"] else "") + ")",
             f"고친 판: {in_f['path']} ({in_f['kind']}, 파일 {in_f['files']}, 트리 {in_f['tree_sha256'][:16]}"
             + (f", zip {in_f['zip_sha256']}" if in_f["zip_sha256"] else "") + ")",
             f"바뀐 파일: 추가 {len(added)} · 삭제 {len(removed)} · 수정 {len(modified)}"]
    if excl.items or ex_notes:
        lines.append(f"실행 데이터 제외: {' '.join(excl.patterns) or '없음'} (원본 {len(ex_o)}·고친 판 {len(ex_f)}개 파일)"
                     + ("".join(f"\n  제외 메모 {n}" for n in ex_notes)))
    if allow_path or allow.warnings:
        st = {}
        for e in allow.entries:
            st[e["status"]] = st.get(e["status"], 0) + 1
        lines.append(f"허용 목록: {allow_path or '없음'}{' (자동)' if allow_auto else ''} · 항목 {len(allow.entries)}"
                     f" (허용 {st.get('allowed', 0)} · 검토 필요 {st.get('review', 0)} · 고전 줄 없음 {st.get('unused', 0)}"
                     f" · 무효 {st.get('invalid', 0)} · 제외 파일 {st.get('excluded', 0)} · 트리 밖 {st.get('outside', 0)})"
                     + (f" · 사람 확인 전 {len(pending)}{'(REQUIRE_REVIEW=1)' if params.require_review else ''}" if live else "")
                     + (f" · 허용 범위 쓰기 경로 {len(allow.write_review())}곳 검토 필요" if allow.write_review() else ""))
        for w in allow.warnings:
            lines.append(f"  경고  {w}")
        top_pending = [e for e in pending if e["n"] in allow.inherit]
        if top_pending and allow.top_state == "none":  # 맨 위 칸이 아직 없다: 사람이 읽은 뒤 옮겨 적을 값을 알려 준다
            lines.append(f"  사람 확인: 자기 칸이 없는 항목 {len(allow.inherit)}건을 읽었으면 목록을 {{\"unconverted\": [...]}} 꼴로 두고 맨 위에 "
                         f"reviewed_by·reviewed_at 과 reviewed_digest=\"{allow.top_digest}\" 를 적는다")
    if hyb_locs:
        lines.append(f"하이브리드 결합 허용 {len(hyb_locs)}줄: {', '.join(hyb_locs[:4])}{' 외' if len(hyb_locs) > 4 else ''}")
    if legacy_locs:
        lines.append(f"이름 규칙(legacy) 허용 {len(legacy_locs)}곳(허용 목록 밖, 쓰기 연산 없음): {', '.join(legacy_locs[:4])}"
                     f"{' 외' if len(legacy_locs) > 4 else ''}")
    for c in checks:
        lines.append(f"[{c['id']}] {STATUS_KO[c['status']]}  {c['actual']}")
    for d in deny:
        lines.append(f"  deny  {d}")
    for x in review:
        lines.append(f"  review {x['path']}: {x['rule']} ({x['before']}->{x['after']}) {x['detail']}")
    code = {"pass": 0, "fail": 1, "undecided": 3}[verdict]
    # 통과인데 사람이 볼 것(검증 호출 제거 흔적, 사람 확인 전 허용 항목, 허용 범위 쓰기 경로, 안 쓰인 항목)이 남았으면 판정 옆에 적는다
    note = rc.pending_note(r, en=True)
    lines.append(f"VERDICT={verdict.upper()}{f' ({note})' if note else ''}  receipt_id={r['receipt_id']}")
    # 건너뛴 검사는 통과가 아니다: 상태별 개수를 따로 찍는다(통과로 세는 것은 '통과'뿐)
    tally = {s: sum(1 for c in checks if c["status"] == s) for s in ("pass", "review", "na", "undecided", "fail", "check")}
    lines.append(f"검사 {len(checks)}개: 통과 {tally['pass']}"
                 + "".join(f" · {STATUS_KO[s]} {tally[s]}" for s in ("review", "na", "undecided", "fail", "check") if tally[s])
                 + " (통과로 세는 것은 '통과'뿐)"
                 + f" · 도구 {r['tool_version']} · 규칙 묶음 {r['ruleset_version']} · 증적 형식 {r['format_version']}")
    lines.append(f"검증 증적 다시 확인: {'ok' if not bad else 'FAIL'} ({len(vres)}개 검사)" + ("" if not bad else ": " + "; ".join(bad[:3])))
    lines.append(f"출력: {out}  (receipt.html, deck.json(요약), tables/report.md(문서에 붙일 표), tables/fragment.html, "
                 "evidence-fragment.json)")
    if bad:
        code = 3
    if not quiet:
        print("\n".join(lines))
    return r, code, lines


# ---------------------------------------------------------------------------------------------
# 셀프 시험(오프라인). DESIGN.md 'Self-test' S1~S10.
# S1~S3은 examples/(직접 쓴 작은 예제: 고전 RSA·ECDSA 원본 ↔ ML-KEM·ML-DSA 전환본), S4·S5는 orders-edge 사본(ORDERS_EDGE,
# 비우면 tests/fixtures/orders-edge 스냅숏), S6은 tls_probe 참조 서버, S7은 S1 검증 증적 변조,
# S8은 허용 목록 가림(결함 D1, S8f 는 고친 판에서 지운 파일), S9는 시험 경로 기준 하나(결함 D2),
# S10은 본 소스 패키지 이름의 example(src/main/java/com/example). S8~S10 은 examples/ 만 쓴다.
EXAMPLES = os.path.join(HERE, "examples")
FIXTURES = os.path.join(HERE, "tests", "fixtures")
ORDERS_EDGE = os.environ.get("ORDERS_EDGE") or os.path.join(FIXTURES, "orders-edge")


def zip_tree(src, dest):
    """src 폴더를 최상위 폴더 하나(sealer/)로 묶은 zip을 만든다(zip 입력 경로도 같이 시험하려고)."""
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(src):
            dirnames.sort()
            for n in sorted(filenames):
                full = os.path.join(dirpath, n)
                z.write(full, "sealer/" + os.path.relpath(full, src).replace(os.sep, "/"))
    return dest


def copy_tree(src, dst):
    shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    for dirpath, dirnames, filenames in os.walk(dst):
        for n in dirnames + filenames:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)


def apply_edits(root, edits):
    for e in edits:
        p = os.path.join(root, *e["path"].split("/"))
        text = slurp(p)
        if text.count(e["old"]) != 1:
            raise AssertionError(f"편집이 안 맞음: {e['path']}")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text.replace(e["old"], e["new"]))


def replace_method_body(text, signature, body):
    i = text.index(signature)
    j = text.index("{", i)
    depth = 0
    for k in range(j, len(text)):
        depth += {"{": 1, "}": -1}.get(text[k], 0)
        if depth == 0:
            return text[:j] + body + text[k + 1:]
    raise AssertionError("메서드 끝을 못 찾음")


def selftest(base=None, keep=False):
    results = []
    tmp = base or tempfile.mkdtemp(prefix="pqcproof-selftest-")
    cache = {}

    def ok(name, cond, why=""):
        results.append((name, "pass" if cond else "fail", why))
        print(f"{'ok  ' if cond else 'FAIL'} {name}{(': ' + why) if why and not cond else ''}", flush=True)

    def skip(name, why):
        """돌리지 못한 경우. 통과로 세지 않고 따로 센다(STRICT=1 이면 실패로 끝난다)."""
        results.append((name, "skip", why))
        print(f"SKIP {name}: {why}", flush=True)

    def P(**kw):
        env = {"EXPECT": "kem,sig"}
        env.update(kw)
        return Params(env)

    def st_of(r):
        return {c["id"]: c["status"] for c in r["checks"]}

    classic, pqc = os.path.join(EXAMPLES, "classic"), os.path.join(EXAMPLES, "pqc")
    java_rel = ("src", "main", "java", "demo", "sealer", "Sealer.java")
    zip_o = zip_tree(classic, os.path.join(tmp, "classic.zip"))
    t = time.time()
    # S1 고전 원본(zip) → 전환본(폴더)
    r, code, _ = run(zip_o, pqc, P(), os.path.join(tmp, "s1"), cache, quiet=True)
    jo, jf = r["java"]["orig"], r["java"]["fixed"]
    ok("S1 고전 예제 → 전환 예제 verdict pass", r["verdict"] == "pass" and code == 0, f"{r['verdict']} {[c for c in r['checks'] if c['status'] not in ('pass', 'na')]}")
    ok("S1 CBOM 원본 막는 위치 > 0, 고친 판 0", r["cbom"]["orig"]["blocking"] > 0 and r["cbom"]["fixed"]["blocking"] == 0,
       f"{r['cbom']['orig']['blocking']} / {r['cbom']['fixed']['blocking']}")
    o_code, f_code = sum(v["code"] for v in jo["families"].values()), sum(v["code"] for v in jf["families"].values())
    ok("S1 residue 공개키 code 원본 > 0 → 0", o_code > 0 and f_code == 0, f"{o_code} → {f_code}")
    ok("S1 E-MLKEM768·E-MLDSA65 원본 0, 고친 판 ≥ 1", jo["expect"].get("E-MLKEM768") == 0 and jo["expect"].get("E-MLDSA65") == 0
       and jf["expect"].get("E-MLKEM768", 0) >= 1 and jf["expect"].get("E-MLDSA65", 0) >= 1, json.dumps(jf["expect"]))
    ok("S1 TLS 해당 없음, 약화 수정 0, 검증 호출 유지", r["tls"]["applicable"] is False and r["weakening"]["deny"] == []
       and r["weakening"]["review"] == [], json.dumps(r["weakening"], ensure_ascii=False)[:300])
    s1 = os.path.join(tmp, "s1")
    # S2 Java 약화: 모두 믿는 TrustManager를 전환본에 끼운다
    s2f = os.path.join(tmp, "s2-fixed")
    copy_tree(pqc, s2f)
    dp = os.path.join(s2f, *java_rel)
    text = slurp(dp)
    inject = ("\n    static javax.net.ssl.TrustManager[] trustAll() {\n        return new javax.net.ssl.TrustManager[]{ new javax.net.ssl.X509TrustManager() {\n"
              "            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}\n"
              "            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}\n"
              "            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; } } };\n    }\n")
    k = text.rindex("}")
    spit(dp, text[:k] + inject + text[k:])
    r, code, _ = run(pqc, s2f, P(), os.path.join(tmp, "s2"), cache, quiet=True)
    ok("S2 TrustManager 주입 → deny ≥ 1, verdict fail", len(r["weakening"]["deny"]) >= 1 and r["verdict"] == "fail" and code == 1,
       json.dumps(r["weakening"]["deny"], ensure_ascii=False))
    # S3 검증 생략: verify 몸통을 return true 로
    s3f = os.path.join(tmp, "s3-fixed")
    copy_tree(pqc, s3f)
    dp = os.path.join(s3f, *java_rel)
    text = slurp(dp)
    spit(dp, replace_method_body(text, "public boolean verify(PublicKey key, byte[] message, byte[] signature)", "{ return true; }"))
    r, code, _ = run(pqc, s3f, P(), os.path.join(tmp, "s3"), cache, quiet=True)
    rv = next(c for c in r["checks"] if c["id"] == "r-review")
    ok("S3 verify 몸통 return true → review ≥ 1, 사유 빈칸은 '검토 필요'",
       len(r["weakening"]["review"]) >= 1 and rv["status"] == "review" and all(x["reason"] == "" for x in r["weakening"]["review"]),
       json.dumps(r["weakening"]["review"], ensure_ascii=False))
    # 같은 고친 판을 고전 원본에 대면 판정은 통과다(원본이 전환본이면 a-input 이 미판정). 그 통과가 말없이 지나가지 않아야 한다
    r, code, lines = run(classic, s3f, P(), os.path.join(tmp, "s3b"), cache, quiet=True)
    n_rv = len(r["weakening"]["review"])
    ok("S3b 고전 원본 → verify 몸통 return true: 통과는 그대로, 판정 줄에 검증 호출 제거 수",
       r["verdict"] == "pass" and f"검증 호출 제거 {n_rv}건 검토 필요" in rc.verdict_text(r)
       and any(x.startswith("VERDICT=PASS (") and "removed verification" in x for x in lines),
       rc.verdict_text(r) + " | " + next((x for x in lines if x.startswith("VERDICT=")), ""))
    # S4·S5 Go·nginx(orders-edge 사본. 스냅숏에도 수정 대상 파일 넷이 다 있다)
    if os.path.isdir(ORDERS_EDGE):
        model = json.loads(slurp(os.path.join(FIXTURES, "orders-edge-scripted-model.json")))
        inj = json.loads(slurp(os.path.join(FIXTURES, "orders-edge-injected-model.json")))
        s4o, s4f, s5f = (os.path.join(tmp, n) for n in ("s4-orig", "s4-fixed", "s5-fixed"))
        copy_tree(ORDERS_EDGE, s4o)
        copy_tree(ORDERS_EDGE, s4f)
        apply_edits(s4f, model["attempts"][-1])
        r, code, _ = run(s4o, s4f, P(EXPECT="none"), os.path.join(tmp, "s4"), cache, quiet=True)
        bo = [x for x in scanmod.scan(s4o) if x.blocks_hybrid]
        bf = [x for x in scanmod.scan(s4f) if x.blocks_hybrid]
        ok("S4 scan.py 원본 blocks_hybrid 행 있음, 고친 판 0", len(bo) > 0 and len(bf) == 0, f"{len(bo)} / {[x.path for x in bf]}")
        ok("S4 약화 수정 0, TLS 신호 있음(TLS_TARGETS 없으면 미판정)", r["weakening"]["deny"] == [] and r["tls"]["applicable"]
           and next(c for c in r["checks"] if c["id"] == "b-tls")["status"] == "undecided",
           json.dumps(r["weakening"]["deny"], ensure_ascii=False))
        copy_tree(ORDERS_EDGE, s5f)
        apply_edits(s5f, inj["attempts"][0])
        r, code, _ = run(s4o, s5f, P(EXPECT="none"), os.path.join(tmp, "s5"), cache, quiet=True)
        ok("S5 InsecureSkipVerify 주입 → deny, verdict fail",
           any("InsecureSkipVerify" in d for d in r["weakening"]["deny"]) and r["verdict"] == "fail",
           json.dumps(r["weakening"]["deny"]))
    else:
        skip("S4·S5 orders-edge(Go·nginx)", f"orders-edge 사본 없음({ORDERS_EDGE})")
    # S6 TLS: 참조 서버 셋을 대상으로(tls_probe 바이너리가 없으면 건너뛴다)
    try:
        has_probe = os.access(str(tlsprobe.host_binary()), os.X_OK)
    except RuntimeError:
        has_probe = False
    if not has_probe:
        skip("S6 TLS 참조 서버(S6a~S6e)", "tls_probe 바이너리 없음(build-probe.sh로 만든다, PROBE_BIN_DIR)")
    else:
        tiny_o, tiny_f = os.path.join(tmp, "s6-orig"), os.path.join(tmp, "s6-fixed")
        for d in (tiny_o, tiny_f):
            os.makedirs(d)
            spit(os.path.join(d, "README.md"), "tiny\n")
        tdir = os.path.join(tmp, "s6-servers")
        os.makedirs(tdir)
        host = tlsprobe.HostRunner(tdir)
        rc_, so, se = host.run(["cert", "-hosts=localhost,127.0.0.1", tdir])
        mdir = os.path.join(tdir, "mldsa")
        os.makedirs(mdir)
        host.run(["cert", "-alg=mldsa65", "-hosts=localhost,127.0.0.1", mdir])
        addrs = {}
        try:
            for name, groups, d in (("both", "X25519MLKEM768,X25519", tdir), ("classic", "X25519", tdir),
                                    ("pqonly", "X25519MLKEM768", tdir), ("mldsa", "X25519MLKEM768,X25519", mdir)):
                addr = host.ref_addr()
                while addr in addrs.values():
                    addr = host.ref_addr()
                addrs[name] = addr
                host.start(tlsprobe.serve_args(addrs[name], groups, os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")))
            ca = os.path.join(tdir, "ca.pem")
            r, code, _ = run(tiny_o, tiny_f, P(EXPECT="tls", TLS_TARGETS=f"{addrs['both']}@localhost#{ca}"), os.path.join(tmp, "s6a"),
                             cache, quiet=True)
            ok("S6a 하이브리드+X25519 서버, CLASSIC=allow → 통과(OpenSSL 3.5 이상이면 교차 확인 포함)", r["verdict"] == "pass",
               json.dumps(r["tls"]["targets"], ensure_ascii=False)[:600])
            r, code, _ = run(tiny_o, tiny_f, P(EXPECT="tls", TLS_TARGETS=f"{addrs['classic']}@localhost#{ca}"), os.path.join(tmp, "s6b"),
                             cache, quiet=True)
            ok("S6b X25519 전용 서버 → 실패", r["verdict"] == "fail", json.dumps(r["checks"], ensure_ascii=False)[:400])
            r, code, _ = run(tiny_o, tiny_f, P(EXPECT="tls", CLASSIC="deny", TLS_TARGETS=addrs["pqonly"]), os.path.join(tmp, "s6c"),
                             cache, quiet=True)
            ok("S6c 하이브리드 전용 서버, CLASSIC=deny, CA 없이 -tofu → 통과", r["verdict"] == "pass"
               and r["tls"]["targets"][0]["trust"] == "tofu", json.dumps(r["tls"]["targets"], ensure_ascii=False)[:600])
            r, code, _ = run(tiny_o, tiny_f, P(EXPECT="tls", CLASSIC="deny", TLS_TARGETS=f"{addrs['both']}@localhost#{ca}"),
                             os.path.join(tmp, "s6d"), cache, quiet=True)
            ok("S6d 하이브리드+X25519 서버, CLASSIC=deny → 실패", r["verdict"] == "fail")
            r, code, _ = run(tiny_o, tiny_f, P(EXPECT="tls,cert", TLS_TARGETS=f"{addrs['mldsa']}@localhost#{os.path.join(mdir, 'ca.pem')}"),
                             os.path.join(tmp, "s6e"), cache, quiet=True)
            ok("S6e ML-DSA-65 인증서 서버, EXPECT=cert → 통과, cert_key ML-DSA-65",
               r["verdict"] == "pass" and r["tls"]["targets"][0]["hybrid"]["cert_key"] == "ML-DSA-65",
               json.dumps(r["tls"]["targets"][0]["hybrid"], ensure_ascii=False))
        finally:
            host.stop()
    # S7 검증 증적 변조
    res = rc.verify(s1)
    ok("S7 S1 검증 증적 verify 전부 ok", all(o for o, _ in res), "; ".join(w for o, w in res if not o))
    s7 = os.path.join(tmp, "s7")
    shutil.copytree(s1, s7, symlinks=True)
    target = os.path.join(s7, "tables", "summary.csv")
    data = bytearray(slurp(target, True))
    data[-2] = data[-2] ^ 1
    spit(target, bytes(data))
    res = rc.verify(s7)
    ok("S7 산출물 1바이트 변경 → 해시 불일치", any((not o) and "summary.csv" in w for o, w in res))
    # S8 허용 목록 가림(결함 D1). 고친 판 기준 목록에 고친 판에서 안 쓰인 항목이 있으면 경고하고 원본에서 덮는 줄을 센다.
    # 같은 목록을 '원본 + PQC 이름 두 줄' 트리에 대면 막는 위치가 0이 된다(가림). 기본 판정은 그대로 두되 판정 옆에 쓰기 경로 수가 나오고,
    # REQUIRE_REVIEW=1 이면 실패다. 안 쓰인 항목을 지운 목록(여기서는 빈 목록)이면 막는 위치가 다시 나온다
    lst = os.path.join(tmp, "s8-allow.json")
    spit(lst, json.dumps([{"where": "src/main/java/demo/sealer/Sealer.java:1-52", "why": "전환 전 기록 열람", "kind": "fallback"},
                          {"where": "tools/sign_manifest.py:1-44", "why": "옛 서명 보관 내보내기", "kind": "kept"}], ensure_ascii=False))
    r, code, lines = run(classic, pqc, P(ALLOW=lst), os.path.join(tmp, "s8a"), cache, quiet=True)
    a, ra = r["allowlist"], next(c for c in r["checks"] if c["id"] == "r-allow")
    ok("S8a 고친 판에서 안 쓰인 항목 2 → 판정 통과 그대로, r-allow 검토 필요, 원본에서 덮는 줄 기록",
       (r["verdict"], code, ra["status"], a["unused"]) == ("pass", 0, "review", 2) and a["unused_orig_lines"] > 0
       and all(e["lines_fixed"] == 0 and e["lines_orig"] > 0 for e in a["entries"])
       and any(x.startswith("VERDICT=PASS (2 allowlist entries unused in the fixed tree)") for x in lines),
       json.dumps([ra, a["unused"], a.get("unused_orig_lines")], ensure_ascii=False)[:400])
    r, code, _ = run(classic, pqc, P(ALLOW=lst, REQUIRE_REVIEW="1"), os.path.join(tmp, "s8b"), cache, quiet=True)
    ok("S8b 같은 목록, REQUIRE_REVIEW=1 → r-allow 실패", (r["verdict"], code, st_of(r)["r-allow"]) == ("fail", 1, "fail"),
       json.dumps(st_of(r)))
    s8m = os.path.join(tmp, "s8-masked")
    copy_tree(classic, s8m)
    spit(os.path.join(s8m, *java_rel[:-1], "PqcNames.java"),
         'package demo.sealer;\n\nfinal class PqcNames {\n    static final String KEM = "ML-KEM-768";\n    static final String SIG = "ML-DSA-65";\n}\n')
    r, code, lines = run(classic, s8m, P(ALLOW=lst), os.path.join(tmp, "s8c"), cache, quiet=True)
    ok("S8c 원본 + PQC 이름 두 줄 + 같은 목록 → 막는 위치 0(가림), 판정 옆에 쓰기 경로 수",
       r["verdict"] == "pass" and r["cbom"]["fixed"]["blocking"] == 0 and r["allowlist"]["write_review"] > 0
       and "쓰기 경로" in rc.verdict_text(r) and any("write paths in allowed ranges need review" in x for x in lines),
       rc.verdict_text(r))
    r, code, _ = run(classic, s8m, P(ALLOW=lst, REQUIRE_REVIEW="1"), os.path.join(tmp, "s8d"), cache, quiet=True)
    ok("S8d 같은 가림, REQUIRE_REVIEW=1 → 실패", (r["verdict"], code) == ("fail", 1), json.dumps(st_of(r)))
    r, code, _ = run(classic, s8m, P(ALLOW="none"), os.path.join(tmp, "s8e"), cache, quiet=True)
    ok("S8e 안 쓰인 항목을 지운 목록 → 막는 위치가 다시 나와 실패", r["verdict"] == "fail" and r["cbom"]["fixed"]["blocking"] > 0,
       f"{r['verdict']} {r['cbom']['fixed']['blocking']}")
    # S9 시험 경로 기준 하나(결함 D2). 옛 P-256 키를 거부하는 Go 음성 시험(_test.go)은 a-cbom 과 c-classic 모두 시험으로 빼고 따로 센다
    s9f = os.path.join(tmp, "s9-fixed")
    copy_tree(pqc, s9f)
    os.makedirs(os.path.join(s9f, "internal", "seal"))
    spit(os.path.join(s9f, "internal", "seal", "seal_test.go"),
         'package seal\n\nimport (\n\t"crypto/ecdsa"\n\t"crypto/elliptic"\n\t"crypto/rand"\n\t"testing"\n)\n\n'
         "// 옛 P-256 키를 거부하는지 보는 음성 시험\nfunc TestRejectsP256(t *testing.T) {\n"
         "\tk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n\tif accept(k) {\n\t\tt.Fatal(\"P-256 key must be rejected\")\n\t}\n}\n")
    r, code, _ = run(classic, s9f, P(), os.path.join(tmp, "s9"), cache, quiet=True)
    cc = next(c for c in r["checks"] if c["id"] == "c-classic")
    ok("S9 _test.go 음성 시험 → a-cbom·c-classic 통과, 시험 줄은 따로 셈", (r["verdict"], st_of(r)["a-cbom"], cc["status"]) == ("pass", "pass", "pass")
       and r["java"]["fixed"]["tests"]["count"] >= 1 and "시험 경로 코드" in cc["actual"],
       json.dumps([st_of(r), cc["actual"]], ensure_ascii=False)[:400])
    # S8f 고친 판에서 지운 파일을 가리킨 항목(독립 검토에서 찾은 D1 빈틈). 고친 판에서는 무효지만 원본에서는 유효해 그 고전 줄을
    # 가린다. 사람 확인 칸을 채워도 안 쓰인 항목으로 세어 REQUIRE_REVIEW=1 이면 실패다
    s8o = os.path.join(tmp, "s8f-orig")
    copy_tree(classic, s8o)
    shutil.copyfile(os.path.join(classic, "tools", "sign_manifest.py"), os.path.join(s8o, "tools", "old_rsa.py"))
    lst_f = os.path.join(tmp, "s8f-allow.json")
    spit(lst_f, json.dumps({"unconverted": [{"where": "tools/old_rsa.py:1-44", "why": "전환 전 보관본 열람", "kind": "kept",
                                             "reviewed_by": "selftest", "reviewed_at": "2026-11-18"}]}, ensure_ascii=False))
    r, code, _ = run(s8o, pqc, P(ALLOW=lst_f, REQUIRE_REVIEW="1"), os.path.join(tmp, "s8f"), cache, quiet=True)
    a, e1 = r["allowlist"], r["allowlist"]["entries"][0]
    ok("S8f 고친 판에서 지운 파일을 가리킨 항목(확인 칸 있음) → 안 쓰인 항목, REQUIRE_REVIEW=1 이면 실패",
       (r["verdict"], code, st_of(r)["r-allow"], a["unused"], e1["status"]) == ("fail", 1, "fail", 1, "invalid")
       and e1["lines_orig"] > 0 and a["unused_orig_lines"] == e1["lines_orig"],
       json.dumps([st_of(r), a["unused"], e1["status"], e1.get("lines_orig")], ensure_ascii=False))
    # S10 본 소스 패키지 이름의 example(독립 검토에서 찾은 D2 고침의 회귀). src/main/java/com/example/… 는 시험이 아니다.
    # 두 방향: 고전 Java 를 남긴 전환본은 실패, 제대로 바꾼 Java 만 있는 트리는 통과
    def com_example(src, name, tools=True):
        d = os.path.join(tmp, name)
        copy_tree(src, d)
        os.makedirs(os.path.join(d, "src", "main", "java", "com"))
        os.rename(os.path.join(d, "src", "main", "java", "demo"), os.path.join(d, "src", "main", "java", "com", "example"))
        if not tools:
            shutil.rmtree(os.path.join(d, "tools"))
        return d
    s10o = com_example(classic, "s10-orig")
    s10f = com_example(classic, "s10-fixed")
    shutil.copyfile(os.path.join(pqc, "tools", "sign_manifest.py"), os.path.join(s10f, "tools", "sign_manifest.py"))
    r, code, _ = run(s10o, s10f, P(), os.path.join(tmp, "s10a"), cache, quiet=True)
    ok("S10a Python 만 전환, com/example 의 Java 는 고전 그대로 → a-cbom·c-classic 실패(시험으로 빼지 않음)",
       (r["verdict"], code, st_of(r)["a-cbom"], st_of(r)["c-classic"]) == ("fail", 1, "fail", "fail")
       and r["java"]["fixed"]["tests"]["count"] == 0 and r["cbom"]["fixed"]["tests"] == 0,
       json.dumps([st_of(r), r["java"]["fixed"]["tests"]["count"], r["cbom"]["fixed"]["tests"]], ensure_ascii=False))
    r, code, _ = run(com_example(classic, "s10j-orig", tools=False), com_example(pqc, "s10j-fixed", tools=False), P(),
                     os.path.join(tmp, "s10b"), cache, quiet=True)
    ok("S10b com/example 에 Java 만 있는 전환본 → 통과(a-input·c-expect 가 Java 를 본다)",
       (r["verdict"], code, st_of(r)["a-input"], st_of(r)["c-expect"]) == ("pass", 0, "pass", "pass"),
       json.dumps(st_of(r), ensure_ascii=False))
    bad = [n for n, s, _ in results if s == "fail"]
    skipped = [n for n, s, _ in results if s == "skip"]
    passed = sum(1 for _, s, _ in results if s == "pass")
    strict = os.environ.get("STRICT") == "1"
    print(f"selftest: {passed} 통과 · {len(skipped)} 건너뜀 · {len(bad)} 실패 (건너뛴 것은 통과로 세지 않는다), "
          f"{time.time() - t:.1f}초, 작업 폴더 {tmp}")
    if skipped:
        print("  건너뛴 것: " + ", ".join(skipped) + (" (STRICT=1 이라 실패로 끝낸다)" if strict else " (STRICT=1 이면 실패)"))
    if not keep and base is None:
        shutil.rmtree(tmp, ignore_errors=True)  # 이 셀프 시험이 mkdtemp로 만든 자기 폴더만 지운다
        print("(작업 폴더는 지웠다. 남기려면 KEEP=1)")
    return 0 if not bad and not (strict and skipped) else 1


def main(argv):
    if argv[:1] == ["--selftest"]:
        return selftest(base=os.environ.get("SELFTEST_DIR") or None, keep=os.environ.get("KEEP") == "1")
    if len(argv) != 2:
        print("사용: bash prove.sh <원본 폴더|zip> <고친 폴더|zip>   (환경 변수는 prove.sh 머리 주석)", file=sys.stderr)
        return 2
    try:
        params = Params()
        _, code, _ = run(argv[0], argv[1], params)
        return code
    except UsageError as e:
        print(f"prove.sh: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
