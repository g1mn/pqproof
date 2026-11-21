# from g1mn/pq-proof 7b7803f (MIT)
# 이 위에 Java·JCA·BC 규칙, 대입 추적, KpqC·복합 서명 이름 등을 더했다(변경 이력은 CHANGELOG.md).
"""암호 사용처 목록(CBOM) 행을 만든다(PQ-Proof scan.py에 Java BC/JCA를 보탬).

오프라인판 추가분:
- java: KeyPairGenerator·Signature·Cipher(비대칭)·KeyAgreement·KeyFactory·KEM·KeyGenerator(PQC KEM)의
  getInstance 호출마다 한 행. 알고리즘 이름은 인자 속 문자열, 같은 파일의 `final String 이름 = "..."` 상수,
  삼항식의 두 문자열까지 읽는다. 공급자 이름("BC" 등)은 알고리즘이 아니라 비고로 간다.
- ML-KEM·ML-DSA·Kyber·Dilithium·SLH-DSA·Falcon 이름(식별자·문자열)은 'pqc-parameter' 행. NIST 보안레벨 3 미만
  (ML-KEM-512, ML-DSA-44, Kyber512, Dilithium2, SLH-DSA 128)은 threat 'weak-pqc'.
- BC 공급자 등록(Security.addProvider/insertProviderAt(new BouncyCastle...Provider()))은 'provider' 행(info).
- TLS 그룹: SSLParameters.setNamedGroups(...)와 jdk.tls.namedGroups 설정은 key-exchange 행.
- 보탬: getInstance 인자 속 식별자는 같은 파일 대입을 중괄호 범위로 따라간다(_JavaValues: 가장 가까운 선언과
  그 뒤 다시 대입, Map.of 표 값, 다른 파일 `static final String` 상수 Class.NAME). BC 경량 API(new RSAEngine·ECDSASigner·
  X25519Agreement·ECKeyPairGenerator 등), JCA 키 스펙(RSAKeyGenParameterSpec·ECGenParameterSpec·OAEPParameterSpec 등),
  곡선 표(ECNamedCurveTable·CustomNamedCurves), 고전 키 형(RSAPublicKey·ECPrivateKey 등, import 줄 제외),
  JWT/JOSE 상수(jjwt·nimbus·auth0·jose4j·Spring)와 "RS256" 문자열, BC OID 상수는 shor 행(kind key-type 포함).
  KeyPairGenerator·Signature·KeyAgreement·KeyFactory·KEM에서 가르지 못한 이름은 '확인'(unknown) 행.
threat 칸: shor(양자 컴퓨터로 깨짐) · pqc · weak-pqc · info · unknown. 통과 판정(허용 줄, 주석 줄)은 prove.py가 한다.
아래는 PQ-Proof 원문 설명이다.

Cryptography inventory (CBOM) of a repo snapshot: nginx configs, Go code, Dockerfiles, go.mod.

The scanner only reads files. It never runs the target repo's code, it does not follow symlinks
(a symlink in the snapshot could point anywhere on the host), and it reads at most MAX_FILE bytes
of a file. Vendored code, test files and .git are skipped: they do not set the service's TLS.

Each row is one place that matters for the migration:
- key-exchange: a TLS group list without X25519MLKEM768 (classical only), or with it (hybrid).
- base-image: a runtime image whose OpenSSL has no ML-KEM (OpenSSL 3.5 added it).
- toolchain: a go.mod `go` line below 1.24, which keeps Go's pre-1.24 default key exchanges
  (GODEBUG tlsmlkem=0) even after a curve pin is removed; or tlsmlkem=0 set outright (a go.mod
  godebug line or block, `godebug default=go1.N` with N < 24, `//go:debug`, a GODEBUG variable in
  a Dockerfile, shell, YAML or env file).
- signature: RSA or ECDSA signatures (JWT, certificates). Reported, never patched: signature
  migration is out of scope.
Rows are static findings. Whether a server really negotiates X25519MLKEM768 is decided by the
probe (prove.py), not by this module. Each file is read the way its parser reads it, with the same
readers as the TLS-weakening check (verify.py), so a commented-out pin is not a row and a comment
marker inside a word or a string hides nothing: nginx through nginx's own tokenizer (a `#` starts a
comment only where a word could start, quotes are resolved, a directive runs to its `;` across
lines, and text inside another directive's quoted value is not a directive); Go and go.mod with
comments removed outside string and rune literals (`//go:` directives stay), and Go code rules
matched outside literals; other files with lines that start with `#` as comments. Line numbers are
the file's own. Go group lists are read wherever a []tls.CurveID literal appears (field,
assignment or variable). A runtime
image whose tag names no known distribution gets blocks_hybrid None: unknown, not "does not block".
Row text goes into the model's context, so text taken from the repo is bounded: group names and
image references outside a narrow character set or length read "unrecognized".
"""
from __future__ import annotations  # 맥 기본 python3 3.9에서 bool | None 주석이 돌게
import os
import re
import stat
from dataclasses import asdict, dataclass, replace

from . import skipdirs, verify

MAX_FILE = 1 << 20
# 시험·예제 경로 목록 한 곳(scan/test-paths.ere). cbom-scan.sh(flag_of)·residue.sh(TEST 줄)·prove.py(TLS 신호)와 같은 줄을 쓴다.
TEST_PATHS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scan", "test-paths.ere")


def load_test_paths(path=TEST_PATHS_FILE):
    """test-paths.ere → (시험 경로 정규식, 본 소스 표시 정규식 또는 None). '#' 줄·빈 줄을 건너뛴 첫 줄과 둘째 줄을 쓴다.
    맞춰 보는 글은 '/' + 상대 경로다(is_test)."""
    with open(path, encoding="utf-8") as f:
        lines = [x.strip() for x in f if x.strip() and not x.lstrip().startswith("#")]
    if not lines:
        raise RuntimeError(f"시험 경로 목록이 비었다: {path}")
    return re.compile(lines[0]), (re.compile(lines[1]) if len(lines) > 1 else None)


TEST_PATH, MAIN_PATH = load_test_paths()


def is_test(path):
    """트리 안 상대 경로가 시험·예제 경로인가(scan/test-paths.ere). 본 소스 표시(/src/main/)가 있으면 그 앞부분만 본다:
    src/main/java/com/example/… 는 시험이 아니고, tests/it/src/main/… 는 시험이다(cbom-scan.sh·residue.sh 와 같은 식)."""
    p = "/" + path.lstrip("/")
    m = MAIN_PATH.search(p) if MAIN_PATH else None
    if m:
        p = p[:m.start() + 1]
    return bool(TEST_PATH.search(p))


PATH_SAFE = re.compile(r"[A-Za-z0-9._/-]{1,200}")
PATH_UNSAFE = re.compile(r"[^A-Za-z0-9._/-]")
SKIP_RULES = skipdirs.load()  # 건너뛰는 폴더: scan/skip-dirs 한 곳(교차 리뷰 X09)
HYBRID = "X25519MLKEM768"
NIST_KEX = "quantum-vulnerable: deprecated after 2030, disallowed after 2035 (NIST IR 8547, Table 4)"
NIST_SIG = "quantum-vulnerable: deprecated after 2030, disallowed after 2035 (NIST IR 8547, Table 2)"
NIST_PK = "quantum-vulnerable: deprecated after 2030, disallowed after 2035 (NIST IR 8547, Tables 2 and 4)"
NIST_PQ = "includes ML-KEM-768 (NIST IR 8547, Table 5)"
NIST_MLKEM = "ML-KEM (FIPS 203)"
NIST_MLDSA = "ML-DSA (FIPS 204)"
NIST_OTHER_PQ = "post-quantum (FIPS 205 SLH-DSA, FN-DSA draft, HQC)"
NIST_WEAK_PQ = "post-quantum but below NIST security category 3 (ML-KEM-512, ML-DSA-44, SLH-DSA 128)"
SHOR, PQC, WEAK_PQC, INFO, UNKNOWN = "shor", "pqc", "weak-pqc", "info", "unknown"
COMPOSITE = "composite"  # ML-DSA 와 고전 서명을 한 키로 묶은 복합 서명(교차 리뷰 X26): 막지 않고 검토 필요로 센다
NIST_KPQC = "post-quantum, Korean KpqC standard (not NIST-approved)"
NIST_COMPOSITE = "composite ML-DSA with a classical signature (IETF LAMPS draft)"
# 복합 서명 이름
COMPOSITE_NAME = re.compile(r"(?i)ml[-_]?dsa[-_]?(44|65|87)[-_](?:rsa|ecdsa|ed25519|ed448)")

# Go's names for TLS groups, and the names OpenSSL (nginx ssl_ecdh_curve) uses for the same groups.
GO_CURVES = {"CurveP256": "P-256", "CurveP384": "P-384", "CurveP521": "P-521", "X25519": "X25519",
             "X25519MLKEM768": HYBRID, "SecP256r1MLKEM768": "SecP256r1MLKEM768",
             "SecP384r1MLKEM1024": "SecP384r1MLKEM1024"}
OPENSSL_GROUPS = {"prime256v1": "P-256", "secp256r1": "P-256", "p-256": "P-256", "secp384r1": "P-384",
                  "p-384": "P-384", "secp521r1": "P-521", "p-521": "P-521", "x25519": "X25519",
                  "x448": "X448", "x25519mlkem768": HYBRID, "secp256r1mlkem768": "SecP256r1MLKEM768",
                  "secp384r1mlkem1024": "SecP384r1MLKEM1024"}
# Base image tag -> the OpenSSL its distribution ships. Static knowledge; the probe has the last word.
# 오프라인판 추가: Ubuntu jammy(22.04, OpenSSL 3.0.2)·noble(24.04, OpenSSL 3.0.13). eclipse-temurin:*-jammy 등.
DISTRO_OPENSSL = [
    (re.compile(r"(^|-)bullseye($|-)"), "Debian 11 (bullseye) ships OpenSSL 1.1.1, which has no ML-KEM", False),
    (re.compile(r"(^|-)bookworm($|-)"), "Debian 12 (bookworm) ships OpenSSL 3.0, which has no ML-KEM", False),
    (re.compile(r"(^|-)trixie($|-)"), "Debian 13 (trixie) ships OpenSSL 3.5, which has ML-KEM", True),
    (re.compile(r"(^|-)jammy($|-)"), "Ubuntu 22.04 (jammy) ships OpenSSL 3.0, which has no ML-KEM", False),
    (re.compile(r"(^|-)noble($|-)"), "Ubuntu 24.04 (noble) ships OpenSSL 3.0, which has no ML-KEM", False),
]

GO_CURVE_LIST = re.compile(r"\[\]tls\.CurveID\s*\{([^}]*)\}")
GO_MOD_GODEBUG = re.compile(r"^[ \t]*godebug[ \t]+(?:\(([^)]*)\)|(\S+))", re.M)
GO_DEBUG_DIRECTIVE = re.compile(r"^//go:debug[ \t]+(\S+)", re.M)
GODEBUG_VAR = re.compile(r"\bGODEBUG['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_.,=]+)")
GODEBUG_FILES = re.compile(r"(?:Dockerfile.*|.*\.Dockerfile|Makefile|.*\.(?:mk|sh|bash|env|ya?ml|service|toml|ini|conf)|\.env.*)")
GROUP_NAME = re.compile(r"[A-Za-z0-9-]{1,32}")  # what an OpenSSL or Go group name looks like
IMAGE_REF = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?")
GO_MOD_GO = re.compile(r"^go\s+1\.(\d+)(?:\.\d+)?\s*$", re.M)
FROM = re.compile(r"^[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(\S+)(?:[ \t]+AS[ \t]+(\S+))?[ \t]*$", re.I | re.M)
JWT_RSA = re.compile(r"SigningMethod(RS|PS)(256|384|512)\b|[\"'](RS|PS)(256|384|512)[\"']")
JWT_EC = re.compile(r"SigningMethodES(256|384|512)\b|[\"']ES(256|384|512)[\"']")


@dataclass(frozen=True)
class Row:
    path: str
    line: int
    component: str  # nginx | go | go.mod | dockerfile | config | java
    kind: str  # key-exchange | base-image | toolchain | signature | key-generation | key-encryption | key-encoding
    #            | key-encapsulation | pqc-parameter | provider | key-type
    algorithm: str
    detail: str
    nist: str
    blocks_hybrid: bool | None  # true when this row keeps the service off X25519MLKEM768; None: unknown
    auto_fix: bool  # false for what PQ-Proof reports but never patches (signatures)
    threat: str = UNKNOWN  # 오프라인판 추가: shor | pqc | weak-pqc | info | unknown

    def to_json(self):
        return asdict(self)


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _group(name, table):
    """A group's canonical name, the name itself if it looks like one, else "unrecognized"."""
    name = name.strip()
    return table.get(name if table is GO_CURVES else name.lower()) or (name if GROUP_NAME.fullmatch(name) else "unrecognized")


def _toolchain_row(path, line, component, setting):
    return Row(path=path, line=line, component=component, kind="toolchain", algorithm=setting,
               detail=f"{setting} turns off Go's {HYBRID} default (GODEBUG tlsmlkem=0)",
               nist=NIST_KEX, blocks_hybrid=True, auto_fix=True, threat=SHOR)


def _turns_off_mlkem(settings):
    """True for a godebug setting list that sets tlsmlkem=0 or defaults to Go before 1.24."""
    for item in re.split(r"[\s,]+", settings):
        key, _, value = item.partition("=")
        if key == "tlsmlkem" and value == "0":
            return True
        m = re.fullmatch(r"go1\.(\d+)(?:\.\d+)?", value) if key == "default" else None
        if m and int(m[1]) < 24:
            return True
    return False


def _files(root):
    """(relative path, text) of regular files under root, without following symlinks. Folders are skipped by scan/skip-dirs."""
    for rel, full, kind in skipdirs.walk(root, SKIP_RULES)[0]:
        if kind != "file":
            continue
        st = os.lstat(full)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
            continue
        with open(full, "rb") as f:
            data = f.read(MAX_FILE)
        yield rel, data.decode("utf-8", errors="replace")


def _groups_row(path, line, component, names, detail_prefix):
    hybrid = HYBRID in names
    return Row(path=path, line=line, component=component, kind="key-exchange",
               algorithm=", ".join(names) or "(empty)",
               detail=f"{detail_prefix}: {'offers' if hybrid else 'no'} {HYBRID}",
               nist=NIST_PQ if hybrid else NIST_KEX, blocks_hybrid=not hybrid, auto_fix=True,
               threat=PQC if hybrid else SHOR)


def scan_nginx(path, text):
    """ssl_ecdh_curve, and (proxy_)ssl_conf_command Groups or Curves, as nginx reads the file."""
    rows = []
    for line, st in verify.nginx_statements(text, with_lines=True):
        if st[-1] != ";" or len(st) < 3:
            continue
        name, args = st[0].lower(), st[1:-1]
        if name == "ssl_ecdh_curve":
            directive, value = st[0], " ".join(args)
        elif name in ("ssl_conf_command", "proxy_ssl_conf_command") and len(args) >= 2 and \
                args[0].lower() in ("groups", "curves"):
            directive, value = f"{st[0]} {args[0]}", " ".join(args[1:])
        else:
            continue
        names = [_group(g, OPENSSL_GROUPS) for g in value.strip().split(":") if g.strip()]
        rows.append(_groups_row(path, line, "nginx", names, f"{directive} pins the TLS groups"))
    return rows


def scan_go(path, text):
    # code: comments removed outside literals; bare: string and rune contents removed too (positions kept)
    code, bare = verify.views(text, verify.GO, keep_positions=True)
    rows = []
    for m in GO_DEBUG_DIRECTIVE.finditer(bare):
        if _turns_off_mlkem(m[1]):
            rows.append(_toolchain_row(path, _line_of(bare, m.start()), "go", f"//go:debug {m[1]}"))
    for m in GO_CURVE_LIST.finditer(bare):
        names = [_group(tok, GO_CURVES) for tok in re.findall(r"tls\.([A-Za-z0-9_]+)", m[1])]
        rows.append(_groups_row(path, _line_of(bare, m.start()), "go", names, "a []tls.CurveID list (CurvePreferences) pins the TLS groups"))
    for rx, alg in ((JWT_RSA, "RSA"), (JWT_EC, "ECDSA")):  # "RS256" is a string: read the code view
        for m in rx.finditer(code):
            name = m[0].strip("\"'").replace("SigningMethod", "")
            rows.append(Row(path=path, line=_line_of(code, m.start()), component="go", kind="signature",
                            algorithm=f"JWT {name} ({alg})", detail="token signature; out of scope for automatic fixes",
                            nist=NIST_SIG, blocks_hybrid=False, auto_fix=False, threat=SHOR))
    return rows


def scan_go_mod(path, text):
    text = verify.views(text, verify.GOMOD, keep_positions=True)[0]
    rows = []
    m = GO_MOD_GO.search(text)
    if m and int(m[1]) < 24:
        rows.append(Row(path=path, line=_line_of(text, m.start()), component="go.mod", kind="toolchain",
                        algorithm=f"go 1.{m[1]}",
                        detail=f"go 1.{m[1]} < 1.24 keeps Go's pre-1.24 default key exchanges (GODEBUG tlsmlkem=0), "
                               f"so {HYBRID} stays off once a curve pin is removed",
                        nist=NIST_KEX, blocks_hybrid=True, auto_fix=True, threat=SHOR))
    for m in GO_MOD_GODEBUG.finditer(text):
        body = m[1] if m[1] is not None else m[2]
        for off, line in enumerate(body.split("\n")):
            if line.strip() and _turns_off_mlkem(line):
                at = m.start(1 if m[1] is not None else 2) + sum(len(x) + 1 for x in body.split("\n")[:off])
                rows.append(_toolchain_row(path, _line_of(text, at), "go.mod", f"godebug {line.strip()}"))
    return rows


def scan_godebug_var(path, text):
    """GODEBUG=...tlsmlkem=0 in a Dockerfile, shell, YAML, env or config file (lines that start with
    `#` skipped, as verify.py reads such files)."""
    text = verify.views(text, verify.ANY, keep_positions=True)[0]
    return [_toolchain_row(path, _line_of(text, m.start()), "config", "GODEBUG " + m[1])
            for m in GODEBUG_VAR.finditer(text) if _turns_off_mlkem(m[1].replace(",", " "))]


def dockerfile_images(text):
    """[(line, image, stage name or None)] for each FROM, in order."""
    return [(_line_of(text, m.start()), m[1], m[2]) for m in FROM.finditer(text)]


def scan_dockerfile(path, text):
    images = dockerfile_images(text)
    if not images:
        return []
    line, image, _ = images[-1]  # the runtime stage; build stages do not serve TLS
    if not IMAGE_REF.fullmatch(image):
        image = "unrecognized image reference"
    tag = image.split("@", 1)[0].rsplit(":", 1)[1] if ":" in image.split("@", 1)[0] else ""
    for rx, why, has_mlkem in DISTRO_OPENSSL:
        if rx.search(tag):
            return [Row(path=path, line=line, component="dockerfile", kind="base-image", algorithm=image,
                        detail=f"runtime base image: {why}", nist=NIST_PQ if has_mlkem else NIST_KEX,
                        blocks_hybrid=not has_mlkem, auto_fix=True, threat=PQC if has_mlkem else SHOR)]
    return [Row(path=path, line=line, component="dockerfile", kind="base-image", algorithm=image,
                detail="runtime base image: OpenSSL version unknown from the tag; the probe decides",
                nist="unknown", blocks_hybrid=None, auto_fix=True, threat=UNKNOWN)]


# ---------------------------------------------------------------------------------------------
# 오프라인판 추가: Java BC/JCA.
JAVA_FILES = (".java", ".kt", ".kts", ".groovy", ".scala")
JCA_CALL = re.compile(r"\b(KeyPairGenerator|Signature|Cipher|KeyAgreement|KeyFactory|KEM|KeyGenerator)\s*\.\s*getInstance\s*\(")
JCA_KIND = {"KeyPairGenerator": "key-generation", "Signature": "signature", "Cipher": "key-encryption",
            "KeyAgreement": "key-exchange", "KeyFactory": "key-encoding", "KEM": "key-encapsulation",
            "KeyGenerator": "key-encapsulation"}
J_STR = re.compile(r"\"((?:\\.|[^\"\\\n])*)\"")
J_CONST = re.compile(r"\b(?:final\s+)?(?:static\s+)?(?:final\s+)?String\s+([A-Za-z_]\w*)\s*=\s*\"((?:\\.|[^\"\\\n])*)\"\s*;")
J_IDENT = re.compile(r"(?<![\w.\"])([A-Z_][A-Z0-9_]*|[a-z]\w*)(?![\w(\"])")
PROVIDERS = {"BC", "BCPQC", "BCFIPS", "BCJSSE", "SunJCE", "SunEC", "SunRsaSign", "SunJSSE", "SUN", "SunPKCS11", "SunMSCAPI",
             "XMLDSig", "SunJGSS", "SunSASL", "JdkLDAP", "JdkSASL", "SunPCSC", "Apple"}
PQ_NAME = re.compile(r"(?i)(?<![A-Za-z0-9])(?:ml[-_]?kem[-_]?(?:512|768|1024)|ml[-_]?dsa[-_]?(?:44|65|87)|kyber(?:512|768|1024)|"
                     r"dilithium[235]|slh[-_]?dsa[-_A-Za-z0-9]*|sphincs[-_+A-Za-z0-9]*|falcon[-_]?(?:512|1024)?|"
                     r"haetae[-_]?(?:2|3|5|120|180|260)?|aimer[-_]?(?:128|192|256)?[fs]?|smaug[-_]?t[-_]?(?:1|3|5)?|ntru[-_]?(?:\+|plus)(?:[-_]?\d+)?)"
                     r"(?![A-Za-z0-9])")
BC_PROVIDER = re.compile(r"\bSecurity\s*\.\s*(?:addProvider|insertProviderAt)\s*\(\s*new\s+(BouncyCastle(?:PQC|JSSE|Fips)?Provider)\s*\(")
NAMED_GROUPS_CALL = re.compile(r"\bsetNamedGroups\s*\(")
JDK_GROUPS = re.compile(r"jdk\.tls\.namedGroups[\"']?\s*(?:=|:|,)\s*[\"']?([A-Za-z0-9_, -]{1,200})")
JDK_GROUPS_FILES = re.compile(r"(?:.*\.(?:properties|ya?ml|sh|bash|env|conf|cfg)|java\.security|Dockerfile.*|\.env.*)")
SHOR_ALG = re.compile(r"(?i)rsa|ecdsa|ecdh|ecies|ecmqv|eddsa|ed25519|ed448|x25519|x448|\bxdh\b|diffie|elgamal|\bsm2\b|"
                      r"with(?:plain-)?(?:dsa|ecdsa|rsa)|^ec$|^dh$|^dsa$|^ecc$|^ecgost|^gost3410|\bdhkem\b")
# 변이 시험에서 보탬: 대입 추적, BC 경량 API·JCA 키 스펙·키 형·곡선 표·JWT/JOSE 상수·OID 상수.
J_ASSIGN = re.compile(r"(?<![\w.$])([A-Za-z_]\w*)\s*=(?!=)")  # bare(문자열 비운 판)에서 찾는다: 선언·다시 대입
J_QUAL = re.compile(r"(?<![\w.])([A-Z]\w*)\s*\.\s*([A-Z_][A-Z0-9_]*)\b(?!\s*\()")  # 다른 파일 상수 Class.NAME
J_KEYWORDS = {"return", "else", "case", "do", "throw", "new", "yield", "assert", "this", "super", "if", "while", "for", "break",
              "continue", "package", "import", "goto"}
J_DECL_ONLY = re.compile(r"(?<![\w.$])([A-Za-z_][\w.]*(?:\s*<[^;=(){}]*>)?(?:\s*\[\s*\])*)\s+([A-Za-z_]\w*)\s*;")  # String alg;
J_NEW = re.compile(r"\bnew\s+(?:[a-z_]\w*\s*\.\s*)*([A-Z]\w*)\s*(?:<[^<>()]*>\s*)?\(")
# new 클래스(...)만으로 고전 공개키가 정해지는 클래스. 종류 → 알고리즘 → 클래스 이름들
_CLASSIC_CLASSES = {
    "signature": {
        "RSA": "RSADigestSigner ISO9796d2Signer X931Signer", "RSA-PSS": "PSSSigner ISO9796d2PSSSigner PSSParameterSpec",
        "ECDSA": "ECDSASigner", "ECNR": "ECNRSigner", "DSA": "DSASigner DSADigestSigner", "SM2": "SM2Signer",
        "GOST3410": "GOST3410Signer ECGOST3410Signer ECGOST3410_2012Signer",
        "Ed25519": "Ed25519Signer Ed25519ctxSigner Ed25519phSigner", "Ed448": "Ed448Signer Ed448phSigner",
    },
    "key-encryption": {
        "RSA": "RSAEngine RSABlindedEngine RSACoreEngine ISO9796d1Encoding", "RSA-OAEP": "OAEPEncoding OAEPParameterSpec",
        "RSA-PKCS1": "PKCS1Encoding", "ElGamal": "ElGamalEngine ECElGamalEncryptor ECElGamalDecryptor", "SM2": "SM2Engine",
        "ECIES": "IESEngine EthereumIESEngine IESParameterSpec",
    },
    "key-encapsulation": {
        "RSA-KEM": "RSAKeyEncapsulation RSAKEMGenerator RSAKEMExtractor",
        "ECIES": "ECIESKeyEncapsulation ECIESKEMGenerator ECIESKEMExtractor",
    },
    "key-exchange": {
        "ECDH": "ECDHBasicAgreement ECDHCBasicAgreement ECDHCUnifiedAgreement ECMQVBasicAgreement",
        "DH": "DHBasicAgreement DHAgreement DHUnifiedAgreement MQVBasicAgreement", "X25519": "X25519Agreement",
        "X448": "X448Agreement", "XDH": "XDHBasicAgreement XDHUnifiedAgreement", "SM2": "SM2KeyExchange",
    },
    "key-generation": {
        "RSA": "RSAKeyPairGenerator RSAKeyGenerationParameters RSAKeyGenParameterSpec",
        "EC": "ECKeyPairGenerator ECKeyGenerationParameters",
        "DSA": "DSAKeyPairGenerator DSAParametersGenerator DSAKeyGenerationParameters DSAGenParameterSpec",
        "DH": "DHKeyPairGenerator DHBasicKeyPairGenerator DHParametersGenerator DHKeyGenerationParameters DHGenParameterSpec",
        "ElGamal": "ElGamalKeyPairGenerator", "Ed25519": "Ed25519KeyPairGenerator", "Ed448": "Ed448KeyPairGenerator",
        "X25519": "X25519KeyPairGenerator", "X448": "X448KeyPairGenerator",
        "EC(Nimbus)": "ECKeyGenerator", "RSA(Nimbus)": "RSAKeyGenerator", "EdDSA·XDH(Nimbus OKP)": "OctetKeyPairGenerator",
    },
    "key-encoding": {
        "RSA": "RSAKeyParameters RSAPrivateCrtKeyParameters RSAPublicKeySpec RSAPrivateKeySpec RSAPrivateCrtKeySpec "
               "RSAMultiPrimePrivateCrtKeySpec",
        "EC": "ECPublicKeyParameters ECPrivateKeyParameters ECDomainParameters ECNamedDomainParameters ECParameterSpec "
              "ECPublicKeySpec ECPrivateKeySpec ECNamedCurveSpec ECNamedCurveParameterSpec ECPoint",
        "DSA": "DSAParameters DSAPublicKeyParameters DSAPrivateKeyParameters DSAParameterSpec DSAPublicKeySpec DSAPrivateKeySpec",
        "DH": "DHParameters DHPublicKeyParameters DHPrivateKeyParameters DHParameterSpec DHPublicKeySpec DHPrivateKeySpec",
        "Ed25519": "Ed25519PublicKeyParameters Ed25519PrivateKeyParameters",
        "Ed448": "Ed448PublicKeyParameters Ed448PrivateKeyParameters",
        "X25519": "X25519PublicKeyParameters X25519PrivateKeyParameters", "X448": "X448PublicKeyParameters X448PrivateKeyParameters",
        "XDH": "XECPublicKeySpec XECPrivateKeySpec", "EdDSA": "EdECPublicKeySpec EdECPrivateKeySpec",
    },
}
CLASSIC_CLASS = {c: (alg, kind) for kind, algs in _CLASSIC_CLASSES.items() for alg, names in algs.items() for c in names.split()}
# 인자 속 이름으로 알고리즘이 정해지는 클래스(이름을 _classify로 가른다)
NAMED_CLASS = {"JcaContentSignerBuilder": "signature", "NamedParameterSpec": "key-generation"}
# 곡선 이름을 받는 것: 곡선은 모두 고전 EC
J_CURVE_CALL = re.compile(r"\b(?:CustomNamedCurves|ECNamedCurveTable|SECNamedCurves|NISTNamedCurves|X962NamedCurves|TeleTrusTNamedCurves|"
                          r"ANSSINamedCurves|GMNamedCurves|ECUtil)\s*\.\s*(?:getByName\w*|getParameterSpec|getNamedCurveByName|getByOID\w*)\s*\(")
# 정적 상수(JWT·JOSE 라이브러리, JCA 스펙 상수, BC OID). (정규식, 알고리즘 이름 틀, 종류)
J_STATIC = [
    (re.compile(r"\b(?:SignatureAlgorithm|JwsAlgorithms|JWSAlgorithm)\s*\.\s*((?:RS|PS|ES)(?:256|384|512)K?|EdDSA|Ed25519|Ed448)\b"),
     "JWT {1}", "signature"),
    (re.compile(r"\bJwts\s*\.\s*SIG\s*\.\s*((?:RS|PS|ES)(?:256|384|512)|EdDSA)\b"), "JWT {1}", "signature"),
    (re.compile(r"\bAlgorithm\s*\.\s*((?:RSA|ECDSA)(?:256|384|512)K?)\s*\("), "JWT {1}", "signature"),  # auth0 java-jwt
    (re.compile(r"\bAlgorithmIdentifiers\s*\.\s*((?:RSA|ECDSA)_\w+|EDDSA)\b"), "JWT {1}", "signature"),  # jose4j
    (re.compile(r"\b(?:JWEAlgorithm|KeyManagementAlgorithmIdentifiers)\s*\.\s*((?:RSA|ECDH)\w*)\b"), "JWE {1}", "key-encryption"),
    (re.compile(r"\bJwts\s*\.\s*KEY\s*\.\s*((?:RSA|ECDH)\w*)\b"), "JWE {1}", "key-encryption"),
    (re.compile(r"\bNamedParameterSpec\s*\.\s*(X25519|X448|ED25519|ED448)\b"), "{1}", "key-generation"),
    (re.compile(r"\bRSAKeyGenParameterSpec\s*\.\s*F[04]\b"), "RSA", "key-generation"),
    (re.compile(r"\b(?:MGF1ParameterSpec\s*\.\s*SHA\w*|PSource\s*\.\s*PSpecified)\b"), "RSA-OAEP", "key-encryption"),
    (re.compile(r"\bPKCSObjectIdentifiers\s*\.\s*(rsaEncryption|\w+WithRSAEncryption|id_RSAES_OAEP|id_RSASSA_PSS|id_rsa_KEM)\b"),
     "OID {1}", "key-encoding"),
    (re.compile(r"\bX9ObjectIdentifiers\s*\.\s*(id_ecPublicKey|ecdsa_with_\w+|prime\d+v\d|id_dsa\w*|dhpublicnumber)\b"),
     "OID {1}", "key-encoding"),
    (re.compile(r"\bSECObjectIdentifiers\s*\.\s*(sec[pt]\d+[rk]\d)\b"), "OID {1}", "key-encoding"),
    (re.compile(r"\bEdECObjectIdentifiers\s*\.\s*(id_Ed25519|id_Ed448|id_X25519|id_X448)\b"), "OID {1}", "key-encoding"),
    (re.compile(r"\bNISTObjectIdentifiers\s*\.\s*(\w*dsa_with_\w+|id_rsassa_\w+)\b"), "OID {1}", "key-encoding"),
    # Nimbus JOSE+JWT 곡선 상수(교차 리뷰 X20)
    (re.compile(r"\bCurve\s*\.\s*(P_256|P_384|P_521|SECP256K1|Ed25519|Ed448|X25519|X448)\b"), "Nimbus Curve {1}", "key-encoding"),
]
# 고전 키 형(캐스트·instanceof·선언). BC 구현 클래스(BCECPublicKey 등)도 같다
J_KEYTYPE = re.compile(r"\b((?:BC)?(?:RSA(?:Public|Private|PrivateCrt|MultiPrimePrivateCrt)?|EC(?:Public|Private)?|DSA(?:Public|Private)?|"
                       r"DH(?:Public|Private)?|XEC(?:Public|Private)?|EdEC(?:Public|Private)?|EdDSA(?:Public|Private)|"
                       r"XDH(?:Public|Private))Key)\b")
KEYTYPE_ALG = [("RSA", "RSA"), ("EdEC", "EdDSA"), ("EdDSA", "EdDSA"), ("XEC", "XDH"), ("XDH", "XDH"), ("EC", "EC"),
               ("DSA", "DSA"), ("DH", "DH")]


def _classify(name):
    """알고리즘 이름 → (보이는 이름, threat, nist, 비고). 비대칭이 아니면 None."""
    low = name.lower()
    c = COMPOSITE_NAME.search(low)
    if c:  # 복합 서명: ML-DSA-44 를 묶은 것은 보안레벨 3 미만이라 그대로 막는다
        if c[1] == "44":
            return name, WEAK_PQC, NIST_WEAK_PQ, "보안레벨 2(ML-DSA-44)를 묶은 복합 서명"
        return name, COMPOSITE, NIST_COMPOSITE, "복합 서명(ML-DSA+고전), 허용 여부는 사람이 확인"
    if re.search(r"haetae|aimer|smaug|ntru[-_]?(?:\+|plus)", low):
        return name, PQC, NIST_KPQC, "양자내성(국내 KpqC, NIST 비승인)"
    m = re.search(r"ml[-_]?kem(?:[-_]?(512|768|1024))?|kyber(512|768|1024)?", low)
    if m:
        size = m[1] or m[2]
        pre = " FIPS 203 이전 이름(Kyber), ML-KEM으로 바꾸길 권함" if "kyber" in low else ""
        hybrid = " 하이브리드" if re.search(r"x25519|secp|p256|p384", low) else ""
        if size == "512":
            return name, WEAK_PQC, NIST_WEAK_PQ, f"보안레벨 1(ML-KEM-512){pre}"
        return name, PQC, NIST_MLKEM, (f"ML-KEM-{size}" if size else "ML-KEM(매개변수는 다른 줄)") + hybrid + pre
    m = re.search(r"ml[-_]?dsa(?:[-_]?(44|65|87))?|dilithium([235])?", low)
    if m:
        size = m[1] or {"2": "44", "3": "65", "5": "87"}.get(m[2] or "")
        pre = " FIPS 204 이전 이름(Dilithium), ML-DSA로 바꾸길 권함" if "dilithium" in low else ""
        if size == "44":
            return name, WEAK_PQC, NIST_WEAK_PQ, f"보안레벨 2(ML-DSA-44){pre}"
        return name, PQC, NIST_MLDSA, (f"ML-DSA-{size}" if size else "ML-DSA(매개변수는 다른 줄)") + pre
    m = re.search(r"slh[-_]?dsa[-_]?(?:sha2|shake)[-_]?(128|192|256)", low)  # FIPS 205 이름(규칙 묶음 4)
    if m:
        if m[1] == "128":
            return name, WEAK_PQC, NIST_WEAK_PQ, "보안레벨 1(SLH-DSA-128)"
        return name, PQC, NIST_OTHER_PQ, f"SLH-DSA-{m[1]}(FIPS 205)"
    if re.search(r"slh[-_]?dsa|sphincs|falcon|fn[-_]?dsa|\bhqc|ntru|\blms\b|xmss", low):
        return name, PQC, NIST_OTHER_PQ, "양자내성"
    if SHOR_ALG.search(name.strip()):
        return name, SHOR, NIST_PK, "양자 컴퓨터로 깨지는 공개키 알고리즘"
    return None


J_CONCAT = re.compile(r"(?:\"(?:\\.|[^\"\\\n])*\"\s*\+\s*)+\"(?:\\.|[^\"\\\n])*\"")


def _concat(expr):
    """식 속 리터럴 조각 잇기("R" + "SA")를 한 이름으로(교차 리뷰 X57). 조각마다의 이름은 부르는 쪽이 따로 읽는다."""
    return ["".join(J_STR.findall(m[0])) for m in J_CONCAT.finditer(expr)]


def _call_span(bare, open_paren):
    """open_paren 위치의 '('에 짝이 맞는 ')' 위치(못 찾으면 줄 끝). bare는 문자열 내용을 비운 판이라 괄호를 믿을 수 있다."""
    depth, i = 0, open_paren
    while i < len(bare):
        c = bare[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        elif c == ";" and depth <= 1:
            return i
        i += 1
    return len(bare)


def _java_row(path, line, kind, name, provider, how):
    cls = _classify(name)
    if cls is None:
        return None
    alg, threat, nist, note = cls
    detail = f"{how}: {note}" + (f" · 공급자 {provider}" if provider else "")
    return Row(path=path, line=line, component="java", kind=kind, algorithm=alg[:80], detail=detail, nist=nist,
               blocks_hybrid=False, auto_fix=False, threat=threat)


def _norm(name):
    """같은 줄 중복을 가리는 이름 꼴: 소문자, 하이픈·밑줄 없음."""
    return re.sub(r"[-_]", "", name.lower())


def _safe_name(s):
    """저장소에서 읽은 이름을 행 글에 넣을 때: 좁은 문자 집합, 40자."""
    return re.sub(r"[^A-Za-z0-9._/+-]", "?", s)[:40] or "(빈 문자열)"


def _in_import(text, pos):
    start = text.rfind("\n", 0, pos) + 1
    return re.match(r"[ \t]*import[ \t]", text[start:pos]) is not None


def _expr_end(bare, i):
    """대입 오른쪽 식의 끝: 깊이 0의 ';'·','나 짝 없는 닫는 괄호(최대 4000자)."""
    depth, n = 0, min(len(bare), i + 4000)
    while i < n:
        c = bare[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif c in ";," and depth == 0:
            return i
        i += 1
    return i


class _JavaValues:
    """같은 파일 안 대입(선언·다시 대입)을 따라가, 식 속 식별자가 가질 수 있는 문자열 값을 모은다.
    범위는 중괄호 깊이로만 본다. 대입이 있던 블록이 호출 전에 닫혔으면 그 대입은 안 보인다(다른 메서드의 같은 이름 지역 변수).
    후보는 호출 앞의 가장 가까운 선언 하나와, 그 선언 뒤·호출 앞의 다시 대입(분기마다 다른 값)이다. 선언이 호출 뒤에만
    있으면(아래쪽 필드) 보이는 대입을 모두 쓴다. 메서드 반환값·설정값·매개변수는 못 읽는다(부르는 쪽이 '확인'으로 남긴다)."""

    def __init__(self, code, bare, xconsts):
        self.code, self.bare, self.x, self._dep = code, bare, xconsts, None
        self.assigns = {}
        for m in J_ASSIGN.finditer(bare):
            if m[1] in J_KEYWORDS:
                continue
            prev = re.search(r"(\w+|[>\]])\s*$", bare[max(0, m.start() - 120):m.start()])
            decl = bool(prev) and prev[1] not in J_KEYWORDS
            self.assigns.setdefault(m[1], []).append((m.start(), decl, code[m.end():_expr_end(bare, m.end())]))
        for m in J_DECL_ONLY.finditer(bare):  # 값 없는 선언(String alg;): 뒤 분기의 다시 대입을 모으는 기준점
            if m[1] not in J_KEYWORDS and m[2] not in J_KEYWORDS:
                self.assigns.setdefault(m[2], []).append((m.start(2), True, ""))
        for v in self.assigns.values():
            v.sort()

    def _visible(self, a, p):
        if self._dep is None:
            d, dep = 0, []
            for c in self.bare:
                dep.append(d)
                d += 1 if c == "{" else -1 if c == "}" else 0
            dep.append(d)
            self._dep = dep
        lo, hi = (a, p) if a < p else (p, a)
        return min(self._dep[lo:hi + 1]) >= self._dep[a]

    def _candidates(self, name, p):
        every = self.assigns.get(name, [])
        seen = [x for x in every if self._visible(x[0], p)]
        decls = [x for x in seen if x[1] and x[0] < p]
        if not decls:
            return seen
        d = decls[-1]
        return [d] + [x for x in every if not x[1] and d[0] < x[0] < p and self._visible(d[0], x[0])]

    def trace(self, expr, pos, depth=0, seen=None):
        """식 expr(code 판 조각, 시작 위치 pos) 속 식별자를 따라간 [(값, 순수)]. 순수 = 메서드 호출이 없는 식(문자열·잇기·
        삼항)에서만 왔다. expr 안의 문자열 리터럴 자체는 넣지 않는다(부르는 쪽이 따로 읽는다)."""
        seen = set() if seen is None else seen
        flat = J_STR.sub(" ", expr)
        out = [(v, True) for q in J_QUAL.finditer(flat) for v in self.x.get((q[1], q[2]), ())]
        if depth >= 3:
            return out
        for ident in dict.fromkeys(J_IDENT.findall(flat)):
            for a, _, rhs in self._candidates(ident, pos):
                if (ident, a) in seen:
                    continue
                seen.add((ident, a))
                pure = "(" not in J_STR.sub(" ", rhs)
                out += [(v, pure) for v in _concat(rhs) + J_STR.findall(rhs)]
                out += [(v, pure and p) for v, p in self.trace(rhs, a, depth + 1, seen)]
        return out


def _classic_row(path, line, kind, alg, how):
    nist = NIST_SIG if kind == "signature" else NIST_KEX if kind == "key-exchange" else NIST_PK
    return Row(path=path, line=line, component="java", kind=kind, algorithm=alg[:80],
               detail=f"{how}: 양자 컴퓨터로 깨지는 공개키 알고리즘", nist=nist, blocks_hybrid=False, auto_fix=False, threat=SHOR)


def _unknown_row(path, line, kind, how, provider, names):
    what = (f"알고리즘 이름({', '.join(_safe_name(n) for n in names[:3])})을 가르지 못함" if names
            else "알고리즘 이름이 변수라 정적으로 못 읽음")
    return Row(path=path, line=line, component="java", kind=kind,
               algorithm="unrecognized (name)" if names else "unrecognized (variable)",
               detail=f"{how}: {what}, 사람이 확인" + (f" · 공급자 {provider}" if provider else ""),
               nist="unknown", blocks_hybrid=False, auto_fix=False, threat=UNKNOWN)


def java_constants(files):
    """다른 파일이 Class.NAME으로 읽는 문자열 상수 {(파일 이름 = 클래스 이름, NAME): [값]}. 시험 폴더는 뺀다."""
    out = {}
    for path, text in files:
        if path.endswith(JAVA_FILES) and not is_test(path) and "String" in text:
            cls = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            for m in J_CONST.finditer(verify.views(text, verify.JAVA, keep_positions=True)[0]):
                out.setdefault((cls, m[1]), []).append(m[2])
    return out


def scan_java(path, text, xconsts=None):
    code, bare = verify.views(text, verify.JAVA, keep_positions=True)
    vals = _JavaValues(code, bare, xconsts or {})
    rows, covered = [], set()

    def add(row, key=None):
        k = (row.line, _norm(row.algorithm) if key is None else key)
        if k not in covered:
            covered.add(k)
            rows.append(row)

    def names_at(open_paren):
        """호출 인자 속 이름: (문자열 리터럴, 따라간 [(값, 순수)], 공급자)."""
        args = code[open_paren + 1:_call_span(bare, open_paren)]
        literals, traced = _concat(args) + J_STR.findall(args), vals.trace(args, open_paren + 1)
        provider = next((s for s in literals + [v for v, _ in traced] if s in PROVIDERS), None)
        if provider is None and re.search(r"\bBouncyCastle(?:PQC)?Provider\b", args):
            provider = "BC"
        return [s for s in literals if s not in PROVIDERS], [(v, p) for v, p in traced if v not in PROVIDERS], provider

    for m in JCA_CALL.finditer(bare):
        cls_name, line = m[1], _line_of(bare, m.start())
        lit, tr, provider = names_at(m.end() - 1)
        how = f"{cls_name}.getInstance"
        asym_lit = [n for n in dict.fromkeys(lit) if _classify(n)]
        asym_tr = [n for n in dict.fromkeys(v for v, _ in tr) if _classify(n) and n not in asym_lit]
        for n in asym_lit:
            add(_java_row(path, line, JCA_KIND[cls_name], n, provider, how))
        for n in asym_tr:  # 상수·지역 변수·Map.of 표를 따라가 읽은 이름
            add(_java_row(path, line, JCA_KIND[cls_name], n, provider,
                          how + ("(상수)" if all(p for _, p in tr) else "(변수 추적)")))
        if asym_lit or asym_tr or cls_name in ("Cipher", "KeyGenerator"):
            continue  # Cipher·KeyGenerator의 대칭 알고리즘(AES 등)이나 못 읽은 이름은 공개키가 아닐 때가 많아 행이 없다
        add(_unknown_row(path, line, JCA_KIND[cls_name], how, provider, list(dict.fromkeys(lit + [v for v, _ in tr]))), key="")
    for m in PQ_NAME.finditer(code):
        line = _line_of(code, m.start())
        row = _java_row(path, line, "pqc-parameter", m[0], None, "PQC 이름")
        if row:
            add(row)

    def curve_row(m, kind, how):
        lit, tr, _ = names_at(m.end() - 1)
        curve = next((n for n in lit + [v for v, _ in tr] if GROUP_NAME.fullmatch(n)), None)
        return _classic_row(path, _line_of(bare, m.start()), kind, f"EC {curve}" if curve else "EC", how)

    for m in J_NEW.finditer(bare):  # BC 경량 API·JCA 키 스펙·BC 키 매개변수
        cls, line = m[1], _line_of(bare, m.start())
        if cls in CLASSIC_CLASS:
            alg, kind = CLASSIC_CLASS[cls]
            add(_classic_row(path, line, kind, alg, f"new {cls}"))
        elif cls == "ECGenParameterSpec":
            add(curve_row(m, "key-generation", f"new {cls}"))
        elif cls in NAMED_CLASS:
            lit, tr, _ = names_at(m.end() - 1)
            names = list(dict.fromkeys(lit + [v for v, _ in tr]))
            asym = [n for n in names if _classify(n)]
            for n in asym:
                add(_java_row(path, line, NAMED_CLASS[cls], n, None, f"new {cls}"))
            if not asym:
                add(_unknown_row(path, line, NAMED_CLASS[cls], f"new {cls}", None, names), key="")
    for m in J_CURVE_CALL.finditer(bare):
        add(curve_row(m, "key-encoding", re.sub(r"\s+", "", m[0]).rstrip("(")))
    for rx, fmt, kind in J_STATIC:  # JWT·JOSE 상수, JCA 스펙 상수, BC OID
        for m in rx.finditer(bare):
            if not _in_import(bare, m.start()):
                alg = fmt.replace("{1}", m[1]) if m.lastindex else fmt
                add(_classic_row(path, _line_of(bare, m.start()), kind, alg.replace("ED25519", "Ed25519").replace("ED448", "Ed448"),
                                 re.sub(r"\s+", "", m[0]).rstrip("(")))
    for rx, fam in ((JWT_RSA, "RSA"), (JWT_EC, "ECDSA")):  # "RS256" 같은 JWT alg 문자열
        for m in rx.finditer(code):
            if not m[0].startswith("SigningMethod"):
                add(_classic_row(path, _line_of(code, m.start()), "signature", f"JWT {m[0].strip(chr(34) + chr(39))} ({fam})",
                                 "JWT alg 문자열"))
    for m in J_KEYTYPE.finditer(bare):  # 고전 키 형(캐스트·instanceof·선언)
        if not _in_import(bare, m.start()):
            t = m[1][2:] if m[1].startswith("BC") else m[1]
            add(_classic_row(path, _line_of(bare, m.start()), "key-type", next(a for p, a in KEYTYPE_ALG if t.startswith(p)),
                             f"{m[1]} 키 형"))
    for m in BC_PROVIDER.finditer(bare):
        rows.append(Row(path=path, line=_line_of(bare, m.start()), component="java", kind="provider", algorithm=m[1],
                        detail="BouncyCastle 공급자 등록", nist="n/a", blocks_hybrid=False, auto_fix=False, threat=INFO))
    for m in NAMED_GROUPS_CALL.finditer(bare):
        end = _call_span(bare, m.end() - 1)
        names = [_group(g, OPENSSL_GROUPS) for s in J_STR.findall(code[m.end():end]) for g in s.split(",") if g.strip()]
        if names:
            rows.append(replace(_groups_row(path, _line_of(bare, m.start()), "java", names,
                                            "SSLParameters.setNamedGroups pins the TLS groups"), auto_fix=False))
    return sorted(rows, key=lambda r: r.line)


def scan_jdk_groups(path, text, component):
    """jdk.tls.namedGroups 설정(-D, System.setProperty, .properties, YAML, 셸, Dockerfile)."""
    view = text if component == "java" else verify.views(text, verify.ANY, keep_positions=True)[0]
    rows = []
    for m in JDK_GROUPS.finditer(view):
        names = [_group(g, OPENSSL_GROUPS) for g in m[1].split(",") if g.strip()]
        if names:
            rows.append(replace(_groups_row(path, _line_of(view, m.start()), component, names,
                                            "jdk.tls.namedGroups pins the TLS groups"), auto_fix=False))
    return rows


def scan(root):
    """CBOM rows for a snapshot directory, in path order."""
    rows = []
    files = list(_files(root))
    xconsts = java_constants(files)  # 오프라인판 추가: 다른 Java 파일의 String 상수(Class.NAME)
    for path, text in files:
        name = path.rsplit("/", 1)[-1]
        if name.endswith(".conf") and "ssl_" in text:
            rows += scan_nginx(path, text)
        elif name.endswith(".go") and not is_test(path):
            rows += scan_go(path, text)
        elif name == "go.mod":
            rows += scan_go_mod(path, text)
        elif name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile."):
            rows += scan_dockerfile(path, text)
        elif name.endswith(JAVA_FILES) and not is_test(path):
            rows += scan_java(path, text, xconsts)
            if "jdk.tls.namedGroups" in text:
                code = verify.views(text, verify.JAVA, keep_positions=True)[0]
                rows += scan_jdk_groups(path, code, "java")
        if GODEBUG_FILES.fullmatch(name) and "GODEBUG" in text:
            rows += scan_godebug_var(path, text)
        if JDK_GROUPS_FILES.fullmatch(name) and "jdk.tls.namedGroups" in text:
            rows += scan_jdk_groups(path, text, "config")
    return [r if PATH_SAFE.fullmatch(r.path) else replace(r, path=PATH_UNSAFE.sub("?", r.path)[:200]) for r in rows]
