# rules.py: 판정 규칙(교차 리뷰 X10). prove.py 안에 있던 판정 상수와 판정 함수를 값 그대로 옮겼다.
# 판정식 derive_verdict(실패 > 미판정 > 통과)는 증적 형식의 정의라 pqlite/receipt.py 에 둔다(--verify 가 같은 식으로 맞춰 본다).
"""Verdict rules of PQ-Proof: classical families, allow rules, hybrid window, residue reading and the checks."""
import json
import os
import posixpath
import re
import stat

from . import allowlist as al
from . import impl
from . import scan as scanmod
from . import tlsprobe
from . import verify
from .receipt import STATUS_KO

# 공개키 9계열(residue.sh GEN 규칙 앞의 아홉 줄, c-classic 이 센다)과 EXPECT 규칙 이름
FAMILIES = ["G-RSA", "G-EC", "G-CURVE", "G-OAEP-PKCS1", "G-CLASSIC-SIG", "G-JWT-ALG", "G-EDDSA", "G-X25519", "G-DH-DSA"]
EXPECT_IDS = ("E-MLKEM768", "E-MLKEM1024", "E-MLDSA65", "E-MLDSA87", "E-SLHDSA", "E-KPQC-KEM", "E-KPQC-SIG")
# 알고리즘 프로필(교차 리뷰 X11·X28): c-expect 가 EXPECT=kem·sig 마다 세는 EXPECT 규칙, b-tls 가 홀로 제시하는 하이브리드 그룹,
# EXPECT=cert 가 받는 인증서 키. scan/profiles.json 한 곳에 두고 규칙 묶음 해시에 든다. PROFILE=<이름>, 기본 nist-cat3
PROFILES_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scan", "profiles.json")


def load_profiles(path=PROFILES_FILE):
    """scan/profiles.json → (기본 이름, {이름: {title, kem, sig, tls_group, cert_keys, impl_accept(선택)}}).
    impl_accept: 구현 검증(impl)이 받아 줄 KpqC 참조판('latest', '<파라미터>@<판>', '<알고리즘>@<판>' 목록, pqlite/impl.resolve_accept).
    목록이 가리키는 판이 실제로 있는지는 impl 이 KAT 목록과 맞춰 본다."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    profiles = doc["profiles"]
    for name, p in profiles.items():
        bad = [x for x in p["kem"] + p["sig"] if x not in EXPECT_IDS]
        if bad or not p["kem"] or not p["sig"] or not p.get("tls_group") or not p.get("cert_keys"):
            raise ValueError(f"scan/profiles.json: profile {name} is incomplete or names unknown EXPECT rules {bad}")
        acc = p.get("impl_accept")
        if acc is not None and (not isinstance(acc, list) or not acc or not all(isinstance(x, str) and x for x in acc)):
            raise ValueError(f"scan/profiles.json: profile {name} impl_accept must be a non-empty list of strings")
    if doc["default"] not in profiles:
        raise ValueError("scan/profiles.json: the default profile is not listed")
    return doc["default"], profiles


DEFAULT_PROFILE, PROFILES = load_profiles()
# SCOPE=kex 에서 범위 안으로 보는 행
KEX_USE = re.compile(r"키교환|TLS 설정|TLS 엔드포인트")  # cbom-scan 용도 칸('서명·키교환'처럼 섞인 것도 범위 안으로 본다)
KEX_KINDS = {"key-exchange", "toolchain", "base-image"}  # scan.py kind
MAX_TEXT = 1 << 20  # 허용 규칙·약화 검사가 읽는 파일 크기 상한(넘으면 줄을 못 읽어 허용 규칙이 안 걸린다)
MIN_COMMON = 0.5  # a-input: 원본 파일 중 고친 판에도 같은 경로로 있어야 하는 몫


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
# 토큰·인증서 서명 API(PyJWT jwt.encode, Go jwt SignedString, Java jjwt signWith, Go x509.CreateCertificate)도 쓰기다.
# 그 줄과 아래 3줄(다음 함수 머리 전까지)을 본다. getInstance("RSA…") 줄 다음 줄에서 ENCRYPT_MODE로 여는 꼴을 놓치지 않으려고.
ALLOW_WRITEOPS = re.compile(WRITEOPS.pattern + r"|\.sign\s*\(|\bSign(?:PKCS1v15|PSS|ASN1)?\s*\(|\.encrypt\s*\(|"
                            r"\bEncrypt(?:OAEP|PKCS1v15)\s*\(|generate_private_key|\bGenerateKey\s*\(|\.generate\s*\(|"
                            r"createSign\s*\(|publicEncrypt\s*\(|generateKeyPair(?:Sync)?\s*\(|"
                            r"\bjwt\.encode\s*\(|\.SignedString\s*\(|\.signWith\s*\(|\bCreateCertificate\s*\(")
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
# 열지 못한 키 자료와 알고리즘을 못 읽은 공개키 API(교차 리뷰 X27·X57): '확인' 수에 묻히지 않게 검토 필요로 올리고 따로 센다.
# REQUIRE_RESOLVED=1 이면 a-cbom 실패. 키·인증서 행(cbom-scan 용도 칸)의 이런 알고리즘 글, scan.py 의 unknown 행이 대상이다
UNRESOLVED_USE = re.compile(r"개인키|공개키|인증서|키스토어")
UNRESOLVED_ALG = re.compile(r"파싱 실패|열지 못함|암호화된 PKCS#8|형식 미확인|읽기 권한 없음|알고리즘 미확인")
UNRESOLVED_KEY = "열지 못한 키 자료(알고리즘을 모름, 사람이 확인)"
UNRESOLVED_API = "알고리즘 이름을 못 읽은 공개키 API(변수·잇기·설정 값, 사람이 확인)"
STATUS_LABEL = {"block": "막음", "review": "검토 필요", "allow": "허용", "comment": "주석·테스트", "check": "확인", "scope": "범위 밖",
                "info": "참고"}
SCOPE_REASON = "범위 밖(SCOPE=kex, 키 교환만 본다)"


def in_scope(scope, tool, use):
    if scope == "all":
        return True
    return bool(KEX_USE.search(use or "")) if tool == "cbom-scan" else use in KEX_KINDS


# 파이썬 문장 자리의 세 따옴표 글(독스트링). 코드 보기에서 지운다(교차 리뷰 X22)
DOCSTRING = re.compile(r"(?m)^([ \t]*)[rRuUbB]?(\"\"\"|\'\'\')[\s\S]*?(?:\2|\Z)")
CODE_KINDS = (verify.GO, verify.JS, verify.PY, verify.JAVA)  # 언어별 주석 판정을 하는 파일(verify.kind_of)
PQC_TOKEN = re.compile(r"(?i)ml-?kem|ml-?dsa|kyber|dilithium|slh-?dsa|sphincs|falcon")


class Lines:
    """트리 파일의 줄(허용 규칙용). 파일마다 한 번만 읽는다."""

    def __init__(self, root):
        self.root, self.cache, self.views = root, {}, {}

    def code(self, path, line):
        """그 줄의 코드 부분: 언어 토크나이저(pqlite/verify.py)로 주석을 지우고 파이썬 독스트링도 지운 글. Go·JS·TS·Python·Java·Kotlin
        파일만, 아니면 None(그 밖 언어는 cbom-scan.sh 의 줄머리 주석 표시를 믿는다)."""
        if path not in self.views:
            text, kind = read_text(self.root, path), verify.kind_of(path)
            if text is None or kind not in CODE_KINDS:
                self.views[path] = None
            else:
                v = verify.views(text, kind, keep_positions=True)[0]
                if kind == verify.PY:
                    v = DOCSTRING.sub(lambda m: m[1] + re.sub(r"[^\n]", " ", m[0][len(m[1]):]), v)
                self.views[path] = v.split("\n")
        v = self.views[path]
        return v[line - 1] if v is not None and line and 1 <= line <= len(v) else None

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
# 복합 서명(ML-DSA 와 고전 서명을 한 키로 묶은 IETF LAMPS·BouncyCastle 이름, 교차 리뷰 X26). 막지도 허용하지도 않고 '검토 필요'로 따로 센다. ML-DSA-44 를 묶은 것은 막는다
COMPOSITE = scanmod.COMPOSITE_NAME
COMPOSITE_REASON = "복합 서명(ML-DSA+고전 서명, 허용 여부는 사람이 확인)"
CBOM_COMPOSITE = "복합 서명(PQC+고전)"  # cbom-scan.sh verdict() 가 다는 위협
# cbom-scan.sh flag_of 가 비고 맨 앞에 붙이는 표시(note() 가 ' · ' 로 잇는다). 원본 줄 발췌나 뒤 문장의 낱말은 표시가 아니다(교차 리뷰 X06)
CBOM_FLAGS = ("주석", "테스트·예제")
# cbom-scan.sh verdict() 가 NIST 보안레벨 3 미만 PQC(ML-KEM-512·ML-DSA-44·Kyber512·Dilithium2)에 다는 위협(교차 리뷰 X07). 허용하지 않는다
CBOM_WEAK_PQC = "보안레벨 3 미만(PQC)"


def in_comment(lines, path, line, alg, note):
    """cbom-scan 행이 주석·독스트링 안인가(교차 리뷰 X22). 언어 토크나이저로 본 코드 부분이 비었거나, '일반 패턴' 행의 고전 이름이
    코드 부분에 하나도 없으면(줄 끝 주석에만 있다) 주석이다. 언어를 모르는 파일은 아니라고 본다."""
    cv = lines.code(path, line) if line else None
    if cv is None:
        return False
    if not re.search(r"\w", cv):
        return True
    if "일반 패턴" not in (note or ""):
        return False
    toks = [x.strip().lower() for x in (alg or "").split(",") if x.strip() and not PQC_TOKEN.search(x)]
    return bool(toks) and not any(x in cv.lower() for x in toks)


def cbom_flags(note):
    """cbom-scan 비고 맨 앞의 주석·시험 표시 집합({'주석', '테스트·예제'} 의 부분집합)."""
    out = set()
    for part in (note or "").split(" · "):
        if part not in CBOM_FLAGS:
            break
        out.add(part)
    return out


def name_rule(path, text):
    """이름 규칙이 걸리는 줄인가: Legacy*.java 파일이거나 주석을 뺀 코드에 legacy 가 있다. 주석의 legacy 는 세지 않는다(교차 리뷰 X01:
    '# legacy' 한 단어로 고전 키 생성이 허용됐다)."""
    return bool(LEGACY_FILE.search(path) or (text is not None and ALLOWLINE.search(code_part(text))))


def allow_reason(path, text, alg, lines=None, line=None):
    """허용 규칙(이름 규칙·같은 줄 ML-KEM)의 사유, 아니면 None. 이름 규칙은 쓰기 경로가 아닐 때만 쓴다: 그 줄(주석 뺀 코드)에 새 키·서명·
    암호화가 있으면 안 되고(ALLOW_WRITEOPS, 모든 언어), lines·line 을 주면 아래 3줄도 본다(write_near, 허용 목록과 같은 창)."""
    if text is None:
        return None
    c = COMPOSITE.search(code_part(text))
    if c and c[1] != "44":
        return COMPOSITE_REASON
    if name_rule(path, text) and not ALLOW_WRITEOPS.search(code_part(text)) \
            and not (lines is not None and line and write_near(lines, path, line, text)):
        return LEGACY_REASONS[0] if LEGACY_FILE.search(path) else LEGACY_REASONS[1]
    if WRITEOPS.search(text):
        return None
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
        comment = threat in ("쇼어로 깨짐", CBOM_WEAK_PQC, CBOM_COMPOSITE) and (cbom_flags(note) or in_comment(lines, path, line, alg, note))
        if threat == CBOM_COMPOSITE:  # 복합 서명: 막지 않고 검토 필요(교차 리뷰 X26)
            status, reason = ("comment", None) if comment else ("review", COMPOSITE_REASON)
        elif threat in ("쇼어로 깨짐", CBOM_WEAK_PQC):
            if comment:
                status = "comment"
            elif threat == CBOM_WEAK_PQC:  # 보안레벨 3 미만 PQC 는 허용 규칙을 쓰지 않는다
                status = "block"
            else:
                reason = allow_reason(path, lines.get(path, line) if line else None, alg, lines, line)
                status = "allow" if reason else "block"
        elif threat == "미확인" and UNRESOLVED_USE.search(r.get("용도", "")) and UNRESOLVED_ALG.search(alg) and not cbom_flags(note):
            status, reason = "review", UNRESOLVED_KEY
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
            reason = allow_reason(r.path, lines.get(r.path, r.line), r.algorithm, lines, r.line)
            status = "allow" if reason else "block"
        elif r.threat == scanmod.WEAK_PQC:
            status = "block"
        elif r.threat == scanmod.COMPOSITE:
            status, reason = "review", COMPOSITE_REASON
        elif r.threat == scanmod.UNKNOWN:
            status, reason = "review", UNRESOLVED_API
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
        if not legacy and (it["status"] != "block" or it["threat"] in (scanmod.WEAK_PQC, CBOM_WEAK_PQC)):  # 보안레벨 3 미만 PQC는 허용하지 않는다
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
        if r.threat in (scanmod.PQC, scanmod.WEAK_PQC, scanmod.SHOR, scanmod.COMPOSITE) and ("(상수)" in r.detail or "(변수 추적)" in r.detail):
            traced.setdefault(f"{r.path}:{r.line}", []).append(r.algorithm)
    pqc_only = {loc for loc in traced if not any(r.threat != scanmod.PQC for r in scan_rows if f"{r.path}:{r.line}" == loc
                                                    and ("(상수)" in r.detail or "(변수 추적)" in r.detail))}
    for it in items:
        if it["tool"] == "cbom-scan" and it["status"] == "check" and not it["reason"] and it["loc"] in traced:
            if it["loc"] in pqc_only:  # 끝까지 PQC 로 추적한 자리는 참고로 내린다(교차 리뷰 X27: '확인' 수에 늘 묻혀 있었다)
                it["status"] = "info"
                it["reason"] = "scan.py 대입 추적 값: " + ", ".join(dict.fromkeys(traced[it["loc"]])) + "(PQC)"
            else:
                it["reason"] = "scan.py 대입 추적 값: " + ", ".join(dict.fromkeys(traced[it["loc"]])) + "(사람이 확인)"
    worst = {}
    for it in items:
        if RANK[it["status"]] > RANK.get(worst.get(it["loc"]), 0):
            worst[it["loc"]] = it["status"]
    counts = {k: sum(1 for v in worst.values() if v == k) for k in RANK}
    # 주석·테스트 중 시험·예제 경로(scan/test-paths.ere) 위치: 판정에 안 넣지만 따로 세어 보인다
    counts["tests"] = len({it["loc"] for it in items if it["status"] == "comment" and "테스트·예제" in cbom_flags(it["note"])
                           and worst[it["loc"]] == "comment"})
    counts["unresolved"] = len({it["loc"] for it in items if it["status"] == "review" and it["reason"] in (UNRESOLVED_KEY, UNRESOLVED_API)
                                and worst[it["loc"]] == "review"})
    return items, counts, len(worst)


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
    공개키 9계열(GEN)과 서비스별 SITE(RESIDUE로 준 판에 있을 때)만 본다. 줄 목록이 MAXD로 잘린 residue면 목록에 나온 줄만 뺀다(나머지는 남은 것으로 센다).
    residue 가 ALLOW 로 둔 줄(이름 규칙·같은 줄 ML-KEM)도 CBOM 과 같은 allow_reason 으로 다시 본다(교차 리뷰 X01): 이 규칙으로 허용이
    아니면(쓰기 경로, 주석에만 legacy·ML-KEM) LEFT 처럼 다루고 relisted 로 센다. 이름 규칙으로만 남은 줄은 name_rule(위치)에 적는다."""
    if not parsed:
        return None
    by = {"allowed": {}, "hybrid": {}, "review": {}}
    rows, left, named, composite = [], [], [], []
    relisted = 0
    sites = [r for r in parsed["rules"].values() if r["kind"] == "SITE"]
    sites_left = 0 if sites else None
    for rid, rule in sorted(parsed["rules"].items()):
        if not (rule["kind"] == "SITE" or (rule["kind"] == "GEN" and rid in FAMILIES)):
            continue
        moved = again = 0
        for ln in rule["lines"]:
            if ln["type"] not in ("LEFT", "ALLOW"):
                continue
            loc = f"{ln['path']}:{ln['line']}"
            text = lines.get(ln["path"], ln["line"])
            text = ln["text"] if text is None else text
            if ln["type"] == "ALLOW":
                why = allow_reason(ln["path"], text, "", lines, ln["line"])
                if why is not None:
                    if why in LEGACY_REASONS and (allow is None or allow.match(ln["path"], ln["line"]) is None):
                        named.append(loc)
                    elif why == COMPOSITE_REASON:  # 복합 서명: 줄 수에는 안 넣고 검토 필요로 따로 센다(X26)
                        composite.append(loc)
                    continue
                again += 1
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
        if rule["kind"] == "GEN":
            relisted += again
        if rule["kind"] == "SITE" and rule["code"] + again - moved > 0:
            sites_left += 1
    tot = {k: sum(v.values()) for k, v in by.items()}
    return {"allowed": tot["allowed"], "hybrid": tot["hybrid"], "review": tot["review"], "relisted": relisted, "by_family": by,
            "sites_left": sites_left, "lines": rows[:400], "left": left[:60], "name_rule": sorted(set(named), key=al._loc_key)[:400],
            "composite": sorted(set(composite), key=al._loc_key)[:400]}


def java_left(j):
    """공개키 9계열 code 합에 residue ALLOW 에서 다시 센 줄(relisted)을 더하고 허용 목록·하이브리드·검토 필요 몫을 뺀 남은 줄(None이면 None)."""
    if not j:
        return None
    raw = sum(v["code"] for v in j["families"].values())
    lst = j.get("listed") or {}
    return raw + lst.get("relisted", 0) - lst.get("allowed", 0) - lst.get("hybrid", 0) - lst.get("review", 0)


# 심볼릭 링크(교차 리뷰 X04). 이 도구는 링크를 따라가지 않는다. 빌드 도구는 따라가므로, 검사 밖(트리 밖이거나 건너뛴 폴더)을 가리키는
# 링크는 a-input 에 적는다. 이름이나 대상이 코드·설정·빌드 파일이거나 확장자가 없으면(폴더일 수 있다) 미판정, 그 밖은 검토 필요.
# 대상 파일은 열지 않고 글만 본다(머신마다 같은 판정).
def link_info(rel, target, skipped=()):
    """트리 안 링크 rel → 대상 글 target 의 판단: {path, target, outside, why, code, zip}."""
    t = target.replace("\\", "/")
    if t.startswith("/") or re.match(r"^[A-Za-z]:", t):
        why = "트리 밖"
    else:
        norm = posixpath.normpath(posixpath.join(posixpath.dirname(rel), t))
        if norm == ".." or norm.startswith("../"):
            why = "트리 밖"
        elif any(norm == s or norm.startswith(s + "/") for s in skipped):
            why = "건너뛴 폴더"
        else:
            why = ""
    base = rel.rsplit("/", 1)[-1]
    code = bool(al.KEEP_FILE.search(rel) or al.KEEP_FILE.search(t) or "." not in base.lstrip("."))
    return {"path": rel, "target": target, "outside": bool(why), "why": why, "code": code, "zip": False}


def link_text(x):
    """inputs.*.skipped 에 적는 한 줄."""
    return (f"링크 {x['path']} -> {x['target'][:200]}" + (f" · {x['why']}" if x["why"] else "")
            + (" · zip 에서 풀지 않음" if x.get("zip") else ""))

def expect_count(jf, ids):
    """프로필이 고른 EXPECT 규칙 줄 수의 합과 보이는 글('E-MLKEM768 3 + E-MLKEM1024 0 = 3'). residue 출력에 그 규칙이 하나도
    없으면(옛 RESIDUE 판) 합은 None."""
    got = [(i, (jf or {}).get("expect", {}).get(i)) for i in ids]
    known = [v for _, v in got if v is not None]
    n = sum(known) if known else None
    shown = " + ".join(f"{i} {v}" for i, v in got)
    return n, shown + (f" = {n}" if len(got) > 1 else "")


# EXPECT 규칙 이름 → 파이썬 정규식(EXPECT_FROM=api 가 CBOM 행 알고리즘에 맞춘다)
EXPECT_RE = {"E-MLKEM768": r"(?i)ml[-_]?kem[-_]?768", "E-MLKEM1024": r"(?i)ml[-_]?kem[-_]?1024",
             "E-MLDSA65": r"(?i)ml[-_]?dsa[-_]?65", "E-MLDSA87": r"(?i)ml[-_]?dsa[-_]?87",
             "E-SLHDSA": r"(?i)slh[-_]?dsa[-_]?(sha2|shake)[-_]?(192|256)",
             "E-KPQC-KEM": r"(?i)smaug-?t|ntru\+|ntru_?plus", "E-KPQC-SIG": r"(?i)haetae|(?<![a-z])aimer(?![a-z])"}
API_KINDS = {"key-generation", "signature", "key-encapsulation", "key-exchange", "key-encryption"}  # scan.py 의 API 행(이름 상수 pqc-parameter 는 뺀다)


def expect_api(items, ids):
    """EXPECT_FROM=api(교차 리뷰 X30): 프로필 이름을 쓰는 PQC API 호출 위치 수. scan.py 의 JCA·BC 호출 행과 cbom-scan 의 API 규칙 행
    (Node generateKeyPair, Go crypto/mlkem 등, '일반 패턴' 행은 뺀다)만 센다. 상수만 남기고 호출을 지운 판은 0이다."""
    rx = [re.compile(EXPECT_RE[i]) for i in ids]
    locs = {it["loc"] for it in items if it["threat"] in (scanmod.PQC, "안전(PQC)")
            and ((it["tool"] == "scan.py" and it["use"] in API_KINDS) or (it["tool"] == "cbom-scan" and "일반 패턴" not in it["note"]))
            and any(x.search(it["alg"]) for x in rx)}
    return len(locs), f"API {'·'.join(ids)} {len(locs)}곳"


def review_kinds(items):
    """CBOM 검토 필요 위치를 까닭별로: 허용 목록의 쓰기 경로, 복합 서명, 열지 못한 키 자료·못 읽은 공개키 API."""
    rev = [it for it in items if it["status"] == "review"]
    comp = sorted({it["loc"] for it in rev if it["reason"] == COMPOSITE_REASON})
    unres = sorted({it["loc"] for it in rev if it["reason"] in (UNRESOLVED_KEY, UNRESOLVED_API)})
    wr = sorted({it["loc"] for it in rev if it["reason"] not in (COMPOSITE_REASON, UNRESOLVED_KEY, UNRESOLVED_API)})
    return " · ".join(x for x in (("허용 목록의 쓰기 경로: " + ", ".join(wr[:4]) if wr else ""),
                                  (f"복합 서명 {len(comp)}곳: " + ", ".join(comp[:4]) if comp else ""),
                                  (f"열지 못한 키 자료·못 읽은 공개키 API {len(unres)}곳: " + ", ".join(unres[:4]) if unres else "")) if x)


# ---------------------------------------------------------------------------------------------
# 검사 판정식: 단계마다 모은 결과로 검사 여덟 줄과 판정을 낸다. prove.run 이 부른다.
def judge(params, cbom, cbom_items, java_rec, files_o, files_f, t_results, sig_o, sig_f, tls, problem, deny, changed, review,
          allow, allow_path, derive_verdict, inputs_extra=None):
    """(checks, verdict, pending, unused, live, name_only). derive_verdict 는 pqlite/receipt.py 의 것(증적 형식의 판정식)을 받는다.
    inputs_extra: prove.prepare_input 의 입력 정보 {"orig"|"fixed": {links, skipped_output}}(고친 판만 본다).
    name_only: 이름 규칙(Legacy*.java·코드의 legacy)으로만 허용하고 허용 목록 항목이 없는 위치(CBOM, SCOPE=all 이면 residue 도)."""
    checks = []

    def check(cid, title, status, expected, actual):
        checks.append({"id": cid, "title": title, "status": status, "expected": expected, "actual": actual})

    cf, co = cbom["fixed"], cbom["orig"]
    prof = PROFILES[getattr(params, "profile", DEFAULT_PROFILE)]
    # review(검토 필요): 막는 위치는 0인데 허용 목록에 쓰기 경로 줄이 있다(허용 규칙). 판정은 바꾸지 않고 줄·사유를 남긴다
    a_status = "fail" if cf["blocking"] else ("undecided" if not cf["cbom_scan_ok"] else ("review" if cf["review"] else "pass"))
    if a_status == "review" and cf.get("unresolved") and getattr(params, "require_resolved", False):
        a_status = "fail"  # REQUIRE_RESOLVED=1: 열지 못한 키 자료·못 읽은 공개키 API 가 남으면 실패(교차 리뷰 X27)
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
    single = getattr(params, "mode", "pair") == "check"  # 한 트리 점검(--check, 교차 리뷰 X13): 두 트리 대조는 해당 없음
    if single:
        in_st = "na"
        in_act = "단일 트리 점검: 공통 파일·원본 근거·사라진 파일은 보지 않음"
    elif common < MIN_COMMON * len(o_paths):
        in_st = "undecided"
        in_act += " · 공통 파일이 절반 미만: 다른 서비스이거나 폴더 깊이가 다르다(zip 최상위 한 겹, repo 안 하위 폴더 등)"
    elif basis == 0:
        in_st = "undecided"
        in_act += (" · 원본에서 고전 " + ("키 교환을" if kex else "공개키를") + " 하나도 못 찾았고 TLS 실측도 없다: 도구가 이 언어·"
                   "프레임워크를 못 보는 것일 수 있다(tables/cbom-orig.csv 와 artifacts/cbom-orig/ 를 사람이 확인하거나 SCOPE·TLS_TARGETS를 맞춘다)")
    elif vanished:
        in_st = "review"
        in_act += (f" · 원본 막는 위치가 있던 파일 중 고친 판에서 사라진 것 {len(vanished)}개: " + ", ".join(vanished[:4])
                   + (" 외" if len(vanished) > 4 else "") + "(기능을 지워서 0이 된 것이 아닌지 확인)")
    else:
        in_st = "pass"
    # 고친 판의 링크와 건너뛴 폴더(교차 리뷰 X02·X03·X04·X09): 검사 밖을 가리키는 코드·폴더 링크는 미판정(REQUIRE_REVIEW=1 이면 실패),
    # 그 밖 검사 밖 링크와 코드 파일이 든 건너뛴 산출물 폴더는 검토 필요. 판정은 앞의 조건이 더 무겁다
    fx = (inputs_extra or {}).get("fixed") or {"links": [], "skipped_output": []}
    out_links = [x for x in fx["links"] if x["outside"]]
    code_links = [x for x in out_links if x["code"]]
    skip_code = [x for x in fx["skipped_output"] if x["code"]]
    oversize = fx.get("oversize") or []  # 크기 한도를 넘어 정밀 검사에서 빠진 코드·설정 파일(교차 리뷰 X56)
    if out_links:
        in_act += (f" · 검사 밖을 가리키는 링크 {len(out_links)}개(이 도구는 따라가지 않고 빌드 도구는 따라간다): "
                   + ", ".join(f"{x['path']} -> {x['target'][:60]}({x['why']})" for x in out_links[:4]) + (" 외" if len(out_links) > 4 else ""))
    if skip_code:
        in_act += (f" · 건너뛴 폴더 {len(skip_code)}곳에 코드 파일 {sum(x['code'] for x in skip_code)}개(빌드 산출물·받아 둔 의존성·가상 환경으로 "
                   "보고 검사하지 않음, scan/skip-dirs): " + ", ".join(f"{x['path']}/ {x['code']}개" for x in skip_code[:4])
                   + (" 외" if len(skip_code) > 4 else ""))
    if oversize:
        in_act += (f" · 크기 한도({MAX_TEXT:,}바이트)를 넘어 scan.py·약화·허용 검사가 건너뛴 코드·설정 파일 {len(oversize)}개"
                   "(cbom-scan.sh·residue.sh 는 읽음, MAX_FILE_MIB 로 한도를 올린다): " + ", ".join(oversize[:4]) + (" 외" if len(oversize) > 4 else ""))
    if code_links:
        in_act += " · 코드·폴더 링크는 내용을 보지 못해 판정할 수 없다(대상을 트리에 넣거나 링크를 지운다)"
        if params.require_review:
            in_st = "fail"
        elif in_st in ("pass", "review", "na"):  # 한 트리 점검(na)도 같다: 링크 너머 코드를 못 봤다
            in_st = "undecided"
    elif (out_links or skip_code or oversize) and in_st in ("pass", "na"):
        in_st = "review"
    check("a-input", "입력 확인(같은 서비스의 전·후, 원본에서 전환 대상을 찾음)", in_st,
          f"공통 파일 {int(MIN_COMMON * 100)}% 이상, 원본 막는 위치·공개키 code·TLS 실측 중 하나 이상, "
          "검사 밖을 가리키는 링크, 코드 파일이 든 건너뛴 폴더, 크기 한도를 넘은 코드 파일 없음", in_act)
    block_locs = sorted({it["loc"] for it in cbom_items["fixed"] if it["status"] == "block"})
    what = "남은 고전 키 교환" if kex else "막는 위치"
    check("a-cbom", "고친 판에 남은 고전 키 교환 0(SCOPE=kex)" if kex else "고친 판 CBOM에 막는 위치 0", a_status,
          f"{what} 0, cbom-scan 정상 종료",
          f"{what} {cf['blocking']}곳(원본 {co['blocking']})"
          + (": " + ", ".join(block_locs[:6]) + (" 외" if len(block_locs) > 6 else "") if block_locs else "")
          + f" · 허용 {cf['allowed']} · 주석·테스트 {cf['comment_or_test']}" + (f"(시험 {cf['tests']})" if cf.get("tests") else "")
          + f" · 확인 {cf['check']}"
          + (f" · 검토 필요 {cf['review']}(" + review_kinds(cbom_items["fixed"]) + ")" if cf["review"] else "")
          + (f" · 범위 밖 {cf['out_of_scope']}" if kex else "") + ("" if cf["cbom_scan_ok"] else " · cbom-scan 실패")
          + (" · REQUIRE_RESOLVED=1" if cf.get("unresolved") and getattr(params, "require_resolved", False) else ""))
    if single:
        check("b-weakening", "TLS 약화 수정 없음", "na", "deny 0", "단일 트리 점검: 바뀐 파일이 없어 보지 않음")
    else:
        check("b-weakening", "TLS 약화 수정 없음", "fail" if deny else "pass", "deny 0",
              f"deny {len(deny)}" + (": " + "; ".join(deny[:3]) if deny else "") + f" · 본 파일 {len(changed)}")
    if not tls["applicable"] and sig_o[0] and not single:  # TLS를 걷어 내고 평문으로 바꾼 판이 '해당 없음'으로 통과하지 않게(반박 검증에서 찾음)
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
        if tls.get("probe_build"):  # 탐침 바이너리 출처(교차 리뷰 X47)
            act += f" · tls_probe {tlsprobe.PROVENANCE_KO.get(tls['probe_build'], tls['probe_build'])}"
        check("b-tls", "TLS 하이브리드 협상·옛 클라이언트", st,
              f"대조 성립, 하이브리드 전용 제시 → {prof['tls_group']}(TLS 1.3), 옛 클라이언트 {'접속' if params.classic == 'allow' else '거부'}",
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
        comp = lst.get("composite") or []
        check("c-classic", "고전 공개키 9계열 code 0, 보안레벨 3 미만 PQC 0, 레거시 쓰기 0",
              ("review" if lst.get("review") or comp else "pass") if ok else "fail",
              "모두 0(허용 목록·하이브리드 결합 줄은 사유와 함께 뺀다)",
              f"공개키 code {left}(원본 {orig_left}) · 보안레벨 3 미만 {jf['weak_pqc']} · 레거시 쓰기 {jf['legacy_write']}"
              + (f" · SITE LEFT {sites}" if sites is not None else "")
              + (f" · residue code {raw}에서 허용 목록 {lst.get('allowed', 0)}·하이브리드 {lst.get('hybrid', 0)}"
                 f"·검토 필요 {lst.get('review', 0)}줄 뺌" if moved else "")
              + (f" · residue 가 허용했지만 이름 규칙·같은 줄 ML-KEM 에 안 맞는 {lst['relisted']}줄(주석에만 legacy·ML-KEM, 쓰기 경로)을 다시 셈"
                 if lst.get("relisted") else "")
              + (f" · 복합 서명 {len(comp)}줄 검토 필요(줄 수에는 안 넣음): " + ", ".join(comp[:4]) + (" 외" if len(comp) > 4 else "")
                 if comp else "")
              + (": 남은 LEFT " + ", ".join(lst.get("left", [])[:6]) + (" 외" if left > 6 else "") if left and lst.get("left") else "")
              + (f" · 시험 경로 코드 {jf['tests']['count']}줄(판정에 안 넣고 따로 셈: "
                 + ", ".join(jf["tests"]["lines"][:3]) + (" 외" if jf["tests"]["count"] > 3 else "") + ")"
                 if (jf.get("tests") or {}).get("count") else ""))
    if not params.expect:
        check("c-expect", "EXPECT PQC 사용", "na", "EXPECT 없음", "해당 없음")
    else:
        parts, st = [], "pass"
        for e in params.expect:
            if e in ("kem", "sig") and getattr(params, "expect_from", "names") == "api":
                n, shown = expect_api(cbom_items["fixed"], prof[e])
                parts.append(shown)
                if n < 1:
                    st = "fail"
            elif e in ("kem", "sig"):
                n, shown = expect_count(jf, prof[e])
                parts.append(shown)
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
        check("c-expect", "EXPECT PQC 사용", st, "EXPECT=" + ",".join(params.expect) + " 마다 1줄 이상(tls·cert는 b-tls 통과)"
              + f", 프로필 {getattr(params, 'profile', DEFAULT_PROFILE)}"
              + (", EXPECT_FROM=api(이름만 있는 상수는 세지 않음)" if getattr(params, "expect_from", "names") == "api" else ""),
              " · ".join(parts))
    if single:
        check("r-review", "검증 생략 흔적(검토 등급, 실패 아님)", "na", "0 또는 줄마다 사유", "단일 트리 점검: 바뀐 파일이 없어 보지 않음")
    else:
        check("r-review", "검증 생략 흔적(검토 등급, 실패 아님)", "review" if review else "pass", "0 또는 줄마다 사유",
              f"{len(review)}건" + (": " + "; ".join(f"{x['path']} {x['rule']}" for x in review[:3]) if review else ""))
    # r-allow: 허용 목록이 판정에서 뺀 줄을 사람이 확인했다는 기록(reviewed_by·reviewed_at)이 있는가. 도구는 사유가 맞는지
    # 모르므로 확인 전 허용은 검토 등급으로 남기고(판정 그대로), REQUIRE_REVIEW=1 이면 실패로 막는다. 목록 맨 위 칸은
    # reviewed_digest 가 지금 목록과 맞을 때만 센다(확인 뒤 더하거나 고친 항목이 예전 확인을 물려받지 않게, allowlist.resolve_reviews)
    # 고친 판에서 안 쓰인 항목(unused)도 여기서 본다: 목록은 어느 트리에 대든 걸리므로 그 항목은 원본 같은 다른 트리의 고전 줄을 가린다
    # (결함 D1). 판정은 그대로 두고 검토 필요로, REQUIRE_REVIEW=1 이면 실패로 막는다. 고친 판에서 지운 파일처럼
    # 고친 판에서는 무효·제외·트리 밖인데 원본 고전 줄을 덮는 항목도 안 쓰인 항목으로 센다(allowlist.counts_unused, 독립 검토에서 찾음)
    # 이름 규칙(Legacy*.java·코드의 legacy)으로만 허용한 줄도 여기서 본다(교차 리뷰 X01): 허용 목록 항목도 사람 확인도 없이 판정에서
    # 빠지므로 검토 필요, REQUIRE_REVIEW=1 이면 실패다. 꼭 남길 줄이면 허용 목록에 사유와 함께 적고 사람이 확인한다
    live = [e for e in allow.entries if e["status"] in al.IN_EFFECT]
    pending = allow.unreviewed()
    unused = allow.unused()
    expired = allow.expired() if hasattr(allow, "expired") else []  # expires_at 이 지난 허용 항목(교차 리뷰 X31)
    jfx = java_rec["fixed"] or {}
    name_only = sorted({it["loc"] for it in cbom_items["fixed"] if it["status"] == "allow" and it["reason"] in LEGACY_REASONS}
                       | (set((jfx.get("listed") or {}).get("name_rule") or []) if not kex else set()), key=al._loc_key)
    need = "허용 항목마다 reviewed_by·reviewed_at(목록 맨 위 칸은 reviewed_digest 도), 고친 판에서 안 쓰인 항목 0, 만료된 항목 0, 이름 규칙으로만 허용한 줄 0" + (
        "(REQUIRE_REVIEW=1: 아니면 실패)" if params.require_review else "(아니면 검토 필요, 실패 아님)")
    title = "허용 항목 사람 확인(검토 등급, REQUIRE_REVIEW=1이면 실패)"
    dead_ko = {"invalid": " (고친 판에서 무효)", "excluded": " (고친 판에서 제외 파일)", "outside": " (고친 판에서 트리 밖)"}
    unused_txt = (f"고친 판에서 안 쓰인 항목 {len(unused)}건(원본 고전 {sum(len(e['orig']) for e in unused)}줄을 덮음, 사람 확인 전): "
                  + ", ".join(f"#{e['n']} {al.CONTROL.sub(' ', e['where'])[:48]}{dead_ko.get(e['status'], '')}" for e in unused[:4])
                  + (" 외" if len(unused) > 4 else "") if unused else "")
    name_txt = (f"이름 규칙(legacy)으로만 허용한 곳 {len(name_only)}곳(허용 목록 항목·사람 확인 없음): " + ", ".join(name_only[:4])
                + (" 외" if len(name_only) > 4 else "") if name_only else "")
    exp_txt = (f"만료된 항목 {len(expired)}건: " + ", ".join(f"#{e['n']} {e['expires_at']}" for e in expired[:4])
               + (" 외" if len(expired) > 4 else "") if expired else "")
    if not live and not unused and not name_only:
        check("r-allow", title, "na", need, "줄을 허용한 항목 0" if allow_path else "허용 목록 없음")
    elif not pending and not unused and not name_only and not expired:
        check("r-allow", title, "pass", need, f"허용 항목 {len(live)}건 모두 사람 확인")
    else:
        head = (f"허용 항목 {len(live)}건 중 사람 확인 전 {len(pending)}건: "
                + ", ".join(f"#{e['n']} {al.CONTROL.sub(' ', e['where'])[:48]}" for e in pending[:4]) + (" 외" if len(pending) > 4 else "")
                if pending else (f"허용 항목 {len(live)}건 모두 사람 확인" if live else ""))
        check("r-allow", title, "fail" if params.require_review else "review", need,
              " · ".join(x for x in (head, unused_txt, exp_txt, name_txt) if x))
    verdict = derive_verdict(checks)
    return checks, verdict, pending, unused, live, name_only


# ---------------------------------------------------------------------------------------------
# 구현 검증(impl): 검사 두 줄 i-kpqc(KpqC KAT 대조)·i-nist(pq-verify 다리)와 판정. 파라미터별 판정(어느 참조판과 맞는가, 받아 줄 판인가)은
# pqlite/impl.py 의 match_versions·control_problem 이, pq-verify 보고서 판정은 pqverify_status 가 하고, 검사 행은 impl.check_row·
# impl.nist_check_row 가 만든다(--verify 가 같은 함수로 다시 만들어 맞춘다).
def judge_impl(results, control, problem, derive_verdict, nist=None, answered=True):
    """(checks, verdict). results: impl.match_versions 결과(파라미터마다), control: 자기 점검 까닭(None 이면 통과), problem: 답안 전체의
    문제(읽지 못함, 모르는 파라미터, 64 MiB 상한). 자기 점검 실패와 답안 문제는 미판정이다(건너뛴 대조는 통과가 아니다).
    nist: 증적 impl.nist(--pq-verify 를 안 줬으면 None, i-nist 해당 없음). answered: 답안을 줬는가(안 줬으면 i-kpqc 해당 없음).
    derive_verdict 는 pqlite/receipt.py 의 것(실패 > 미판정 > 통과, 검토 필요·해당 없음은 판정을 바꾸지 않는다)."""
    checks = [impl.check_row(results, control, problem, answered), impl.nist_check_row(nist)]
    return checks, derive_verdict(checks)
