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
--impl(구현 검증, KpqC): 문제지를 내고(prompt), 사용자 하네스가 쓴 답안 JSON 이나 PQCgenKAT .rsp 를 참조판 KAT 와 대조한다(judge).
    검사 대상 구현은 빌드하거나 실행하지 않는다(pqlite/impl.py). 증적은 같은 꼴의 receipt.json(형식 4, params.mode impl).
    judge --pq-verify "<인자>" 를 주면 사용자가 켠 바깥 도구 pq-verify 로 NIST PQC 구현 감사도 하고 같은 증적에 담는다(검사 i-nist).
    대상 라이브러리를 불러 실행하는 것은 pq-verify 다. PQ-Proof 는 셸 없이 부르고 그 JSON 보고서·종료 코드·출력만 읽는다.
받은 소스는 믿지 않는 입력이다. 그 안의 코드는 실행하지 않는다(cbom-scan·residue는 grep·awk, scan.py는 읽기만).
종료 코드: 0 통과 · 1 실패 · 2 사용법·입력 오류 · 3 미판정 · 4 도구 오류(예상 못 한 예외) · 5 통과지만 검토 필요(FAIL_ON_REVIEW=1).
"""
import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import signal
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
from pqlite import impl  # noqa: E402
from pqlite import receipt as rc  # noqa: E402
from pqlite import rules  # noqa: E402
from pqlite import skipdirs  # noqa: E402
from pqlite import scan as scanmod  # noqa: E402
from pqlite import tlsprobe, verify  # noqa: E402
from pqlite import version as ver  # noqa: E402
# 판정 규칙(공개키 9계열, 허용 규칙, 하이브리드 창, residue 해석, 검사 판정식)은 pqlite/rules.py 한 곳에 있다(규칙 묶음 해시에 든다)
from pqlite.rules import (FAMILIES, HYBRID_REASON, LEGACY_REASONS, RANK, STATUS_LABEL, Lines, hybrid_ok,  # noqa: E402
                          java_left, merge_cbom, parse_residue, read_text, reclass_residue, tls_signals)

CBOM_SCAN = os.path.join(HERE, "scan", "cbom-scan.sh")
GENERIC_RESIDUE = os.path.join(HERE, "scan", "residue.sh")
EXPECT_OK = {"kem", "sig", "tls", "cert"}
# SCOPE: all(기본) = 모든 고전 공개키가 막는 위치. kex = 키 교환만(PQ-Proof 범위: TLS 그룹·툴체인·런타임 이미지).
# kex에서 서명·암호화 행은 '범위 밖'으로 표에 남기고 막는 위치로 세지 않는다. c-classic(공개키 9계열)은 해당 없음이 된다.
SCOPES = ("all", "kex")
MAX_ZIP_TOTAL = 1 << 30
STATUS_KO = rc.STATUS_KO


class UsageError(Exception):
    pass


# 설정 이름(환경 변수). 흔한 오타(REQUIRE_REVEIW 등)는 실행 머리에 경고한다(교차 리뷰 X50)
SETTINGS = ("OUT", "TLS_TARGETS", "TLS_TARGETS_ORIG", "TLS_VIA", "CLASSIC", "EXPECT", "SCOPE", "RESIDUE", "EXTRA_EV", "OPENSSL",
            "CBOM_SCAN", "ALLOW", "EXCLUDE", "RECON", "EV_NAME", "REQUIRE_REVIEW", "PROBE_BIN_DIR", "PROFILE", "FAIL_ON_REVIEW",
            "EXPECT_FROM", "REVIEW_MAX_AGE_DAYS", "MAX_FILE_MIB", "REQUIRE_RESOLVED", "PQ_VERIFY", "PQ_VERIFY_TIMEOUT")
EXIT_TOOL_ERROR = 4  # 예상 못 한 예외(도구 오류, 교차 리뷰 X62). 판정 실패(1)·입력 오류(2)와 가른다
EXIT_REVIEW = 5  # FAIL_ON_REVIEW=1 이고 판정은 통과인데 검토 필요인 검사가 있다(교차 리뷰 X30)
OTHER_ENV = ("PYTHON", "STRICT", "SELFTEST_DIR", "KEEP", "ORDERS_EDGE", "TEST_PATHS", "SARIF_SCHEMA", "PQPROOF_HOME",
             "PQPROOF_ENTRY", "PQPROOF_PQV_LIB", "PQPROOF_PQV_BAD_LIB")  # PQPROOF_PQV_*: tests/test_pqverify.py 실측 시험의 ML-KEM 라이브러리
DOCS = "https://github.com/g1mn/pqproof/blob/v{v}/{page}"


def _distance(a, b):
    """두 이름의 편집 거리(이웃 글자 바꿈도 1, optimal string alignment)."""
    d = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def env_warnings(env):
    """설정 이름과 거의 같은데 다른 환경 변수(오타)와 모르는 PQPROOF_ 이름마다 경고 한 줄. 오타면 그 설정은 기본값으로 돈다."""
    known = set(SETTINGS) | set(OTHER_ENV)
    out = []
    for name in sorted(env):
        if name in known:
            continue
        if name.startswith("PQPROOF_"):
            out.append(f"환경 변수 {name}: PQ-Proof 가 모르는 이름이다(설정 목록: pqproof --env)")
            continue
        if len(name) < 5:
            continue
        near = [k for k in SETTINGS if len(k) >= 5 and _distance(name, k) <= (2 if len(k) >= 10 else 1)]
        if near:
            k = near[0]
            what = " 엄격 모드(사람 확인 필수)가 꺼진 채로 돈다." if k == "REQUIRE_REVIEW" else f" {k} 는 기본값으로 돈다."
            out.append(f"환경 변수 {name}: 설정 이름이 아니다. {k} 를 뜻했나?{what}")
    return out


def entry_cmd():
    """사람에게 보일 진입점: pqproof 명령이 띄웠으면 'pqproof', 아니면 'bash prove.sh'."""
    return "pqproof" if os.environ.get("PQPROOF_ENTRY") == "pqproof" else "bash prove.sh"


def doc_url(page):
    return DOCS.format(v=ver.tool_version(), page=page)


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


# OPENSSL 을 안 줬을 때 찾는 곳(이 순서, 그다음 PATH)
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
    def __init__(self, env=None, mode="pair"):
        env = os.environ if env is None else env
        self.mode = mode  # pair: 원본과 고친 판, check: 한 트리의 지금 상태만(--check, 교차 리뷰 X13), impl: 구현 검증(--impl)
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
        self.require_review = flag(env, "REQUIRE_REVIEW")
        # FAIL_ON_REVIEW=1: 통과인데 검토 필요인 검사가 있으면 종료 코드 5(판정은 그대로). REQUIRE_RESOLVED=1: 열지 못한 키 자료·못 읽은
        # 공개키 API 가 남으면 a-cbom 실패. EXPECT_FROM=api: c-expect 를 PQC API 호출 위치로 센다(교차 리뷰 X27·X30)
        self.fail_on_review = flag(env, "FAIL_ON_REVIEW")
        self.require_resolved = flag(env, "REQUIRE_RESOLVED")
        self.expect_from = (env.get("EXPECT_FROM") or "names").strip().lower()
        if self.expect_from not in ("names", "api"):
            raise UsageError(f"EXPECT_FROM은 names 또는 api: {self.expect_from!r}")
        # REVIEW_MAX_AGE_DAYS=N: 그보다 오래된 reviewed_at 은 사람 확인 전(교차 리뷰 X31). MAX_FILE_MIB: scan.py·약화·허용 검사의 파일 크기
        # 한도(기본 1, 넘은 코드·설정 파일은 a-input 검토 필요로 적는다, 교차 리뷰 X56)
        self.review_max_age_days = number(env, "REVIEW_MAX_AGE_DAYS", None, 1, 36500)
        self.max_file_bytes = number(env, "MAX_FILE_MIB", 1, 1, 64) << 20
        # PQ_VERIFY: impl judge --pq-verify 가 부를 pq-verify 실행 파일(비우면 PATH 의 pq-verify). PQ_VERIFY_TIMEOUT: 감사 한 번의 시간 한도(초)
        self.pq_verify = (env.get("PQ_VERIFY") or "").strip() or None
        self.pq_verify_timeout = number(env, "PQ_VERIFY_TIMEOUT", 1800, 1, 86400)
        if self.ev and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", self.ev):
            raise UsageError(f"EV_NAME은 evidence/ 안 파일 이름: {self.ev!r}")
        if self.scope not in SCOPES:
            raise UsageError(f"SCOPE는 all 또는 kex: {self.scope!r}")
        if self.classic not in ("allow", "deny"):
            raise UsageError(f"CLASSIC은 allow 또는 deny: {self.classic!r}")
        if not (self.tls_via == "host" or re.fullmatch(r"container:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.tls_via)):
            raise UsageError(f"TLS_VIA는 host 또는 container:<컨테이너 이름>: {self.tls_via!r}")
        # PROFILE: 알고리즘 프로필(scan/profiles.json). c-expect 가 세는 이름, b-tls 가 홀로 제시하는 그룹, EXPECT=cert 의 인증서 키
        self.profile = (env.get("PROFILE") or ("kpqc" if mode == "impl" else rules.DEFAULT_PROFILE)).strip().lower()
        if self.profile not in rules.PROFILES:
            raise UsageError(f"PROFILE은 {', '.join(rules.PROFILES)} 중 하나: {self.profile!r}")
        bad = [x for x in self.expect if x not in EXPECT_OK]
        if bad:
            raise UsageError(f"EXPECT에 모르는 값 {bad} (쓸 수 있는 값: kem, sig, tls, cert, none)")
        for t in self.tls_targets + self.tls_targets_orig:
            parse_target(t)


def flag(env, name):
    v = (env.get(name) or "").strip().lower()
    if v not in ("", "0", "1", "no", "yes", "false", "true"):
        raise UsageError(f"{name}는 1 또는 0: {v!r}")
    return v in ("1", "yes", "true")


def number(env, name, default, lo, hi):
    v = (env.get(name) or "").strip()
    if not v:
        return default
    if not re.fullmatch(r"[0-9]{1,9}", v) or not lo <= int(v) <= hi:  # isdigit 은 '²'·'٣' 같은 유니코드 숫자도 받는다
        raise UsageError(f"{name}는 {lo}~{hi} 정수: {v!r}")
    return int(v)


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
    """zip을 dest에 푼다. 절대 경로·..·역슬래시 이름은 거부, 심볼릭 링크는 풀지 않고 [(이름, 대상)]으로 돌려준다. 같은 이름·대소문자만 다른 이름·
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
        if stat.S_ISLNK(info.external_attr >> 16):  # 링크는 풀지 않고 이름과 대상 글만 남긴다(대상은 zip 안 데이터)
            links.append((name.rstrip("/"), z.read(info)[:1024].decode("utf-8", errors="replace")))
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


def count_files(top):
    """폴더 안 일반 파일 수와 그중 코드 파일 수(링크는 따라가지 않는다)."""
    n = c = 0
    for dirpath, _, filenames in os.walk(top, followlinks=False):
        for name in filenames:
            if stat.S_ISREG(os.lstat(os.path.join(dirpath, name)).st_mode):
                n += 1
                c += bool(al.CODE_FILE.search(name))
    return n, c


MAX_SKIPPED = 100  # inputs.*.skipped 에 하나씩 적는 건너뛴 폴더·링크 수(넘으면 '외 n곳')


def prepare_input(path, out, side, skip_rules=None, max_bytes=rules.MAX_TEXT):
    """(receipt 입력 칸, 트리 루트 경로, 파일 목록, 입력 정보 {links, skipped_output}). 건너뛰는 폴더는 scan/skip-dirs(skip_rules).
    links: 트리의 심볼릭 링크와 zip 안 링크(풀지 않음)마다 rules.link_info. skipped_output: 세는 폴더(산출물 폴더와 제자리가 아닌
    any 이름 폴더, pqlite/skipdirs.Rules.kind)마다 파일·코드 파일 수. 코드 파일이 없는 any 이름 폴더는 이름만 skipped 에 적는다."""
    path = os.path.abspath(path)
    skip_rules = skip_rules or skipdirs.load()
    zlinks = []
    if os.path.isfile(path) and zipfile.is_zipfile(path):
        dest = os.path.join(out, "in", side)
        os.makedirs(dest)
        zlinks = unzip_safe(path, dest)
        root = unwrap(dest)
        rel = os.path.relpath(root, out).replace(os.sep, "/")
        kind, zsha = "zip", sha256_file(path)
        top = os.path.relpath(root, dest).replace(os.sep, "/")
        top = "" if top == "." else top + "/"
        zlinks = [(n[len(top):], tgt) for n, tgt in zlinks if n.startswith(top) and n != top.rstrip("/")]
    elif os.path.isdir(path):
        root, rel, kind, zsha = path, path, "dir", None
    else:
        raise UsageError(f"폴더나 zip이 아님: {path}")
    skips = []
    files = rc.tree_files(root, skip_rules, skips)
    odd = next((r for r, _, _ in files if ZIP_CONTROL.search(r)), None)
    if odd is not None:  # 줄바꿈·탭 같은 제어 문자가 든 이름은 줄 단위로 읽는 스캐너가 놓치거나 잘못 가른다(교차 리뷰 X21)
        raise UsageError(f"파일 이름에 제어 문자(줄바꿈·탭 등)가 있다: {odd!r}. 이름을 바꾼 뒤 다시 돌린다(스캐너가 줄 단위로 읽어 그 파일을 놓친다)")
    skipped_rel = [r for r, _ in skips]
    skip_out, quiet_any = [], set()
    for r, k in skips:
        if k == "output":
            n, c = count_files(os.path.join(root, *r.split("/")))
            name = r.rsplit("/", 1)[-1]
            if name in skip_rules.any and not c:  # 제자리가 아닌 any 폴더도 코드 파일이 없으면 이름만 적는다(__pycache__·.idea 등)
                quiet_any.add(name)
                continue
            skip_out.append({"path": r, "files": n, "code": c})
    links = [rules.link_info(r, d[len("symlink:"):], skipped_rel) for r, d, _ in files if d.startswith("symlink:")]
    for n, tgt in zlinks:
        parts = n.split("/")
        # 건너뛴 폴더 안 링크는 폴더 입력과 같이 보지 않는다. 링크만 든 폴더는 풀리지 않아 skipped_rel 에 없을 수 있어 any 이름으로도
        # 거른다(main 표시 아래 any 이름은 운영 소스일 수 있어 빼지 않는다)
        if any(x in skip_rules.any and not (skip_rules.main and skip_rules.main in "/" + "/".join(parts[:i + 1]) + "/")
               for i, x in enumerate(parts[:-1])) or any(n.startswith(s + "/") for s in skipped_rel):
            continue
        links.append(dict(rules.link_info(n, tgt, skipped_rel), zip=True))
    shown = [f"{x['path']}/ 파일 {x['files']} · 코드 {x['code']}" for x in skip_out] + [rules.link_text(x) for x in links]
    # 크기 한도를 넘어 scan.py·약화·허용 검사가 통째로 건너뛰는 코드·설정 파일(교차 리뷰 X56). 형식 3 inputs.*.oversize
    big = [f"{r} ({n:,}바이트)" for r, d, n in files if not d.startswith("symlink:") and n > max_bytes and al.KEEP_FILE.search(r)]
    info = {"path": path, "kind": kind, "zip_sha256": zsha, "root": rel, "files": len(files), "tree_sha256": rc.tree_sha256(files),
            "skipped": sorted({r.rsplit("/", 1)[-1] for r, k in skips if k == "any"} | quiet_any) + shown[:MAX_SKIPPED]
            + ([f"외 {len(shown) - MAX_SKIPPED}곳"] if len(shown) > MAX_SKIPPED else []),
            "oversize": big[:MAX_SKIPPED] + ([f"외 {len(big) - MAX_SKIPPED}개"] if len(big) > MAX_SKIPPED else [])}
    return info, root, files, {"links": links, "skipped_output": skip_out, "oversize": big}


def changed_files(o_files, f_files):
    o = {rel: d for rel, d, _ in o_files}
    f = {rel: d for rel, d, _ in f_files}
    return (sorted(set(f) - set(o)), sorted(set(o) - set(f)), sorted(k for k in set(o) & set(f) if o[k] != f[k]))


# ---------------------------------------------------------------------------------------------
# (a) CBOM: 스캐너 실행과 표(판정은 rules.merge_cbom)
def run_cbom_scan(script, root, outdir, openssl, cache=None, tree=None, test_paths=None, skip_dirs=None):
    """cbom-scan.sh를 돌려 (ok, csv 경로, 행 목록). cache는 셀프 시험에서 같은 트리를 두 번 안 재려고 쓴다.
    test_paths·skip_dirs: 시험 경로 목록·건너뛰는 폴더 목록 파일(증적에 남긴 사본). residue.sh 와 같은 파일을 준다.
    HOST_FILES(트리 밖 인증서·호스트 키를 읽는 단독 실행용 설정)는 넘기지 않는다: 판정은 머신과 상관없이 같아야 한다(교차 리뷰 X05)."""
    os.makedirs(outdir)
    if cache is not None and tree in cache:
        for name in os.listdir(cache[tree]):
            shutil.copy2(os.path.join(cache[tree], name), os.path.join(outdir, name))
    else:
        env = dict(os.environ, OUT=outdir)
        env.pop("HOST_FILES", None)
        if test_paths:
            env["TEST_PATHS"] = test_paths
        if skip_dirs:
            env["SKIP_DIRS"] = skip_dirs
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


def csv_text(head, rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(head)
    w.writerows(rows)
    return "﻿" + buf.getvalue()


# 발췌에 실린 비밀 값을 가린다(교차 리뷰 X33): keytool·jarsigner 의 -storepass·-keypass 값, OpenSSL pass:값, password=·token= 같은
# 대입 값, 알려진 토큰 접두사. 원문(artifacts/ 의 스캐너 출력, zip 입력을 푼 in/)은 그대로다
REDACT = (
    r"(?i)(-(?:src|dest)?(?:storepass|keypass)\s+)(\"[^\"]*\"|'[^']*'|[^\s\"'`]+)",
    r"(?i)(\bpass:)(\"[^\"]*\"|'[^']*'|[^\s\"'`]+)",
    r"(\b(?i:ssh-keygen)\b[^\n]*?\s-N\s+)(\"[^\"]*\"|'[^']*'|[^\s\"'`]+)",
    r"(?i)(\b(?:password|passwd|passphrase|pwd|secret|client_secret|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|token|"
    r"(?:access|refresh|auth|api|bearer)[_-]?token)\b[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s\"'`,;)]+)",
    r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=-]{8,})",
    r"()(\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|sk-|AKIA|ASIA|AIza)[A-Za-z0-9_-]{10,})",
)
_REDACT = [re.compile(p) for p in REDACT]
MASK = "***"


def redact(text):
    """text 의 비밀처럼 보이는 값을 *** 로 바꾼다. (바꾼 글, 가린 곳 수). 이미 *** 인 값은 세지 않는다."""
    n = 0

    def sub(m):
        nonlocal n
        if m.group(2) in (MASK, f'"{MASK}"', f"'{MASK}'"):
            return m.group(0)
        n += 1
        return m.group(1) + MASK

    for rx in _REDACT:
        text = rx.sub(sub, text)
    return text, n


def cbom_csv(items):
    """CBOM 표 CSV 와 비고 칸에서 가린 곳 수. 비고 칸의 발췌는 redact() 를 거친다. 규칙 묶음 2부터 cbom-scan.sh 가 발췌에서
    먼저 가린 값(***)도 가린 곳으로 센다(교차 리뷰 X33)."""
    rows, masked = [], 0
    for i in sorted(items, key=lambda x: (-RANK[x["status"]], x["loc"], x["tool"])):
        pre = redact(i["note"].replace(MASK, "x" * 8))[1] if MASK in i["note"] else 0
        note, n = redact(i["note"])
        masked += max(n, pre)
        rows.append([i["loc"], i["source"], i["use"], i["alg"], i["threat"], STATUS_LABEL[i["status"]], i["reason"], note])
    return csv_text(["위치", "출처", "용도·종류", "알고리즘", "양자 위협", "판정", "허용·참고 사유", "비고"], rows), masked


# ---------------------------------------------------------------------------------------------
# (c) residue 실행(해석은 rules.parse_residue·reclass_residue)
def run_residue(script, root, test_paths=None, skip_dirs=None):
    try:
        env = dict(os.environ)  # cbom-scan.sh 와 같은 시험 경로·건너뛰는 폴더 목록
        if test_paths:
            env["TEST_PATHS"] = test_paths
        if skip_dirs:
            env["SKIP_DIRS"] = skip_dirs
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
    prof = rules.PROFILES[params.profile]
    group, cert_keys = prof["tls_group"], prof["cert_keys"]
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
                res = tlsprobe.probe_target(runner, addr, servername=name, ca=ca_in, label=tag, hybrid_group=group)
                hyb, cls = res["hybrid"][0], res["classical"][0]
                ok, why = tlsprobe.target_verdict(hyb, cls, params.classic, group)
                if "cert" in expect and not any((hyb.cert_key or "").startswith(k) for k in cert_keys):
                    ok, why = False, why + [f"인증서 공개키가 {'·'.join(cert_keys)}가 아님({hyb.cert_key})"]
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
                                                                 ca_path if os.path.isfile(ca_path) else None, group=group)
                    art_log.append({"argv": argv, "exit_code": None, "stdout": raw, "stderr": "", "t": now()})
                    item["openssl"] = oh.to_json()
                    item["openssl_agrees"] = (oh.group == hyb.group) if hyb.ok else (not oh.ok)
                out.append(item)
    finally:
        runner.stop()
    return controls, problem, results_t, results_b


# ---------------------------------------------------------------------------------------------
def tool(name, path, version=""):
    """증적 tools[] 한 칸. 폴더(scan/kat 발췌)는 그 안 *.json 의 해시 묶음(pqlite/version.py path_sha256)."""
    sha = ver.path_sha256(path) if path else None
    return {"name": name, "path": str(path or ""), "sha256": sha, "version": version or ""}


def rule_tools():
    """규칙 묶음에 드는 파일 전부의 tools[] 칸(규칙 묶음 해시를 tools[] 로 다시 계산하려면 다 있어야 한다)."""
    return [tool(n, os.path.join(HERE, *p.split("/"))) for p, n in ver.RULESET_FILES]


def probe_tool():
    """증적 tools[] 의 tls_probe 칸. 이 기계에 바이너리가 없으면 None(없는 바이너리를 버전과 함께 적어 쓴 것처럼 보이지 않게).
    소스 해시 칸('tls_probe source')은 늘 따로 남는다."""
    try:
        path = tlsprobe.host_binary()
    except RuntimeError:
        return None
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        return None
    t = tool("tls_probe", str(path), tlsprobe.PROBE_VERSION)
    t["version"] += f" ({tlsprobe.provenance(path, t['sha256'])})"  # 릴리스 해시와 대조(교차 리뷰 X47): release · local · unchecked
    return t


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


def default_out(orig, prefix="proof"):
    """원본이 <작업 폴더>/orig 이고 <작업 폴더>/evidence 가 있으면 그 아래 proof-YYYYMMDD-HHMMSS, 아니면 ./proof-out-YYYYMMDD-HHMMSS.
    prefix 는 이름 앞머리만 바꾼다(--inventory 는 inventory). 같은 이름이 이미 있으면(같은 초에 두 번 돌린 경우) 뒤에 -2, -3 을
    붙인다. OUT 으로 준 이름은 그대로 쓰고 있으면 멈춘다."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    o = os.path.abspath(orig)
    if os.path.basename(o) == "orig" and os.path.isdir(os.path.join(os.path.dirname(o), "evidence")):
        base = os.path.join(os.path.dirname(o), "evidence", f"{prefix}-{stamp}")
    else:
        base = os.path.abspath(f"{prefix}-out-{stamp}")
    path, n = base, 1
    while os.path.lexists(path):
        n += 1
        path = f"{base}-{n}"
    return path


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


def md_cell(x, html=True):
    """마크다운 표 칸. 링크 대상·경로·답안의 파라미터 이름처럼 입력이 정하는 글이 들어오므로 &·<·> 를 엔티티로 바꾸고(원시 HTML 을
    받는 위키에 붙여도 태그가 되지 않게) '](' 를 ']\\(' 로 적는다([글](주소)·![글](주소) 꼴이 눌리는 링크나 그림이 되지 않게. 경로의
    [id] 같은 대괄호는 그대로 둔다). 코드 스팬(백틱) 안에서는 엔티티와 이스케이프가 풀리지 않으니 html=False 로 둔다."""
    s = str("" if x is None else x).replace("\r", " ").replace("\n", " ")
    if html:
        s = s.replace("](", "]\\(")
    s = s.replace("|", "\\|").strip()
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") if html else s


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
    cmd = " ".join(env) + f" {entry_cmd()} {os.path.basename(r['inputs']['orig']['path'])} " \
        f"{os.path.basename(r['inputs']['fixed']['path'])}"
    fx = r["inputs"]["fixed"]
    out = [f"<!-- prove.sh가 만든 표. 고친 판 트리 sha256 {fx['tree_sha256']}"
           + (f", zip sha256 {fx['zip_sha256']}" if fx["zip_sha256"] else "") + ". receipt_id는 같은 폴더 receipt.json. -->", "",
           f"명령: `{md_cell(cmd, html=False)}` · 판정 **{rc.verdict_text(r)}** · 실행 기록 {ev}", ""]
    if r.get("format_version"):
        out += [f"판정 근거: pqproof {r['tool_version']} · 규칙 묶음 {r['ruleset_version']} "
                f"(sha256 `{r['ruleset_sha256'][:16]}`) · 증적 형식 {r['format_version']}", ""]
    rows = []
    for i, c in enumerate(r["checks"], 1):
        rows.append([f"V{i}", c["title"], f"`{STEP.get(c['id'], c['id'])}`", c["expected"], f"{STATUS_KO[c['status']]}: {c['actual']}"])
    out += ["검사 결과", "", md_table(["#", "검사", "도구", "기대", "실제"], rows), ""]
    blocks = sorted({it["loc"]: it for it in fixed_items if it["status"] == "block"}.items(), key=lambda kv: al._loc_key(kv[0]))
    jf = (r.get("java") or {}).get("fixed") or {}
    res_left = ((jf.get("listed") or {}).get("left") or []) if (r.get("params") or {}).get("scope") != "kex" else []
    if blocks or res_left:
        rows = [[f"`{loc}`", it["alg"] or it["use"], "a-cbom", it["reason"] or redact(it["note"])[0][:90]] for loc, it in blocks[:20]]
        rows += [[f"`{x.split(' ', 1)[1]}`", x.split(" ", 1)[0], "c-classic", "사유 없이 남은 고전 공개키 코드 줄"] for x in res_left[:20]]
        out += ["막는 위치(실패 원인)", "", md_table(["위치", "알고리즘·규칙", "검사", "까닭"], rows), ""]
        more = []
        if len(blocks) > 20:
            more.append(f"a-cbom 외 {len(blocks) - 20}곳은 tables/cbom-fixed.csv('판정'이 막음인 행).")
        if len(res_left) > 20 or (jf.get("listed") and len(res_left) >= 60):
            more.append("c-classic 전체 줄은 artifacts/residue-fixed.txt 의 LEFT 줄.")
        more.append("꼭 남겨야 하는 줄은 허용 목록에 사유와 함께 적는다: " + doc_url("guide/allowlist.md"))
        out += [" ".join(more), ""]
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
        why = it["reason"] or redact(it["note"])[0][:90]
        todo = {"allow": "폐기 조건·시점을 정한다", "review": "쓰기 경로: 고치거나 사유를 사람이 확인"}.get(it["status"],
                                                                                          "사람이 확인: 고전이면 고친다")
        rows.append([f"{it['alg'] or it['use']} ({STATUS_LABEL[it['status']]})", f"`{loc}`", why, todo])
    if not rows:
        rows = [["없음(허용·검토 필요·확인 행 0)" + (". 실패 원인은 위 '막는 위치' 표" if blocks or res_left else ""), "", "", ""]]
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
            f"다시 확인: `{entry_cmd()} --verify <출력 폴더>`(트리·zip sha256과 receipt_id를 다시 계산).", ""]
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


def settings_line(params, out):
    """실행 머리에 찍는 적용 설정 한 줄(오타로 엄격 모드가 꺼졌는지 바로 보이게)."""
    allow = params.allow or "비움(<W>/notes/unconverted.json 자동)"
    return (f"설정: EXPECT={','.join(params.expect) or 'none'} · SCOPE={params.scope} · CLASSIC={params.classic} · "
            f"REQUIRE_REVIEW={1 if params.require_review else 0} · ALLOW={allow} · "
            f"EXCLUDE={' '.join(params.exclude) or ('none' if params.exclude_off else '없음')} · "
            f"TLS_TARGETS {len(params.tls_targets)}개 · 출력 {out}")


def run(orig, fixed, params, out=None, cache=None, quiet=False):
    """한 번 돌린다. 반환: (receipt dict, 종료 코드, 출력 줄 목록). quiet 가 아니면 단계마다 stderr 에 진행 줄을 찍는다."""
    out = os.path.abspath(out or params.out or default_out(orig))
    if os.path.exists(out):
        raise UsageError(f"출력 폴더가 이미 있다(덮어쓰지 않음): {out}")
    started = now()

    def say(msg):
        if not quiet:
            print(f"pqproof: {msg}", file=sys.stderr, flush=True)

    say(settings_line(params, out))
    os.makedirs(out)
    art = rc.Artifacts(out)
    timeline = []
    steps = ["준비", "(a) CBOM", "(c) 공개키 집계", "(b) 약화 수정", "(b) TLS 탐침", "(d) 표·증적"]

    def phase(name, t0):
        timeline.append({"name": name, "started_at": rc.iso(t0), "ended_at": rc.iso(now())})
        say(f"[{len(timeline)}/{len(steps)}] {steps[len(timeline) - 1]} 끝 {now() - t0:.1f}초 (누적 {now() - started:.1f}초)")

    # 준비
    t0 = now()
    say(f"[1/{len(steps)}] 준비: 입력 읽기·트리 해시")
    skip_rules = skipdirs.load()  # 건너뛰는 폴더(scan/skip-dirs): 트리 해시·세 스캐너·a-input 이 같은 규칙을 쓴다
    rules.MAX_TEXT = scanmod.MAX_FILE = params.max_file_bytes  # MAX_FILE_MIB(교차 리뷰 X56): scan.py·약화·허용 검사가 함께 쓴다
    as_of = rc.iso(started)[:10]  # 허용 항목 만료·REVIEW_MAX_AGE_DAYS 의 기준 날(UTC, --verify 가 started_at 으로 다시 본다)
    in_o, root_o, files_o, extra_o = prepare_input(orig, out, "orig", skip_rules, params.max_file_bytes)
    in_f, root_f, files_f, extra_f = prepare_input(fixed, out, "fixed", skip_rules, params.max_file_bytes)
    say(f"  원본 파일 {len(files_o):,} · 고친 판 파일 {len(files_f):,}")
    for side, files in (("원본", files_o), ("고친 판", files_f)):
        if not files:  # 빈 폴더·빈 zip이면 도구가 아무것도 못 찾고 0으로 끝난다(반박 검증에서 찾음)
            raise UsageError(f"{side}에 읽을 파일이 0개다(빈 폴더·빈 zip이거나 .git·node_modules 같은 건너뛰는 폴더뿐, scan/skip-dirs): "
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
    allow = al.AllowList.load(allow_path, fixed_all, lambda rel: text_lines(root_f, rel), app_roots, frozenset(ex_f), as_of,
                              params.review_max_age_days)
    # 같은 목록을 원본 트리로도 푼다(판정에는 안 쓴다). 고친 판에서 안 쓰인 항목이 원본 고전 줄을 덮는지 보려고(결함 D1, note_other)
    orig_all = [x[0] for x in files_o if not x[1].startswith("symlink:")]
    allow_o = (al.AllowList.load(allow_path, orig_all, lambda rel: text_lines(root_o, rel), app_roots, frozenset(ex_o), as_of,
                                 params.review_max_age_days)
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
    # 건너뛰는 폴더 목록(scan/skip-dirs) 사본도 같이 둔다. 두 셸 스캐너가 이 사본을 읽고, --verify 가 in/ 트리 해시를 이 사본으로 다시 잰다
    sd_art, sd_sha = art.add("artifacts/skip-dirs", slurp(skipdirs.SKIP_FILE))
    sd_file = os.path.join(out, *sd_art.split("/"))
    scan_o, scan_f = scanmod.scan(root_so), scanmod.scan(root_sf)
    art.add_json("artifacts/scan-orig.json", [r.to_json() for r in scan_o])
    art.add_json("artifacts/scan-fixed.json", [r.to_json() for r in scan_f])
    sig_o = tls_signals(root_so, scan_o)
    sig_f = tls_signals(root_sf, scan_f)
    cbom = {}
    cbom_items = {}
    masked = 0  # 표 발췌에서 가린 비밀 값 수(콘솔에만 적는다: 증적 형식 2에는 칸이 없다)
    for side, root, rows, sig, lns, tree in (("orig", root_so, scan_o, sig_o, lines_o, tree_so),
                                             ("fixed", root_sf, scan_f, sig_f, lines_f, tree_sf)):
        d = os.path.join(out, "artifacts", f"cbom-{side}")
        t1 = now()
        say(f"[2/{len(steps)}] (a) CBOM: cbom-scan.sh {'원본' if side == 'orig' else '고친 판'} (큰 저장소는 몇 분 걸린다)")
        ok, _, crow = run_cbom_scan(params.cbom_scan, root, d, params.openssl, cache, tree, tp_file, sd_file)
        say(f"  cbom-scan.sh {'원본' if side == 'orig' else '고친 판'} {now() - t1:.1f}초")
        art.register_dir(f"artifacts/cbom-{side}")
        items, counts, nloc = merge_cbom(crow, rows, lns, sig[2], params.scope, allow if side == "fixed" else None)
        cbom_items[side] = items
        table, n_masked = cbom_csv(items)
        masked += n_masked
        p, s = art.add(f"tables/cbom-{side}.csv", table)
        cbom[side] = {"rows": len(items), "locations": nloc, "blocking": counts["block"], "allowed": counts["allow"],
                      "review": counts["review"],
                      "comment_or_test": counts["comment"], "tests": counts["tests"], "check": counts["check"], "info": counts["info"],
                      "out_of_scope": counts["scope"], "unresolved": counts["unresolved"], "cbom_scan_ok": ok, "csv": p, "csv_sha256": s}
    phase("(a) CBOM(cbom-scan + scan.py)", t0)

    # (c) residue
    t0 = now()
    say(f"[3/{len(steps)}] (c) 공개키 집계: residue.sh 두 판")
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
        rcode, text = run_residue(res_script, root, tp_file, sd_file)
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
    say(f"[4/{len(steps)}] (b) 약화 수정: 바뀐 파일 {len(added) + len(removed) + len(modified):,}개")
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
    say(f"[5/{len(steps)}] (b) TLS 탐침: " + (f"대상 {len(params.tls_targets) + len(params.tls_targets_orig)}개"
                                             if params.tls_targets or params.tls_targets_orig else "TLS_TARGETS 없음, 건너뜀"))
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
    probe = probe_tool()
    tls = {"signals": sig_f[0], "client_signals": sig_f[1], "applicable": bool(sig_f[0] or params.tls_targets),
           "probe_build": (probe["version"].rsplit("(", 1)[-1].rstrip(")") if probe and t_results else None),
           "via": params.tls_via, "controls": controls, "control_problem": problem, "targets": t_results,
           "baseline": b_results, "log": tl_path, "log_sha256": tl_sha}
    phase("(b) TLS 탐침", t0)

    # 검사(판정식은 pqlite/rules.py)
    checks, verdict, pending, unused, live, name_only = rules.judge(
        params, cbom, cbom_items, java_rec, files_o, files_f, t_results, sig_o, sig_f, tls, problem, deny, changed, review, allow,
        allow_path, rc.derive_verdict, {"orig": extra_o, "fixed": extra_f})
    jf = java_rec["fixed"]
    # 복합 서명 위치(CBOM 검토 필요와 residue 가 따로 센 줄). 증적 allowlist.composite 와 판정 줄에 남긴다(형식 3, 교차 리뷰 X26)
    composite_locs = sorted({it["loc"] for it in cbom_items["fixed"] if it["status"] == "review" and it["reason"] == rules.COMPOSITE_REASON}
                            | set(((jf or {}).get("listed") or {}).get("composite") or []), key=al._loc_key)

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
        hg = rules.PROFILES[params.profile]["tls_group"]
        for k, offered, want in (("hybrid", hg, hg),
                                 ("classical", tlsprobe.OFFER_CLASSICAL, "고전 그룹" if params.classic == "allow" else "거부")):
            h = t[k]
            tls_rows.append([t["target"], params.tls_via, offered, want, h.get("group") or h.get("error") or "",
                             h.get("protocol") or "", h.get("cipher") or "", h.get("cert_sig") or "", h.get("cert_key") or "",
                             h.get("cert_not_after") or "", t["trust"], "예" if t["ok"] else "아니오"])
    art.add("tables/tls.csv", csv_text(["대상", "이름공간", "제시 그룹", "기대", "협상 그룹(또는 오류)", "프로토콜", "암호 스위트", "cert_sig",
                                        "cert_key", "인증서 만료(UTC)", "신뢰 방식", "통과"], tls_rows))
    art.add("tables/summary.csv", csv_text(["검사", "제목", "판정", "기준", "실제"],
                                           [[c["id"], c["title"], STATUS_KO[c["status"]], c["expected"], c["actual"]]
                                            for c in checks]))
    # ev: 이 실행의 화면 출력을 따로 남긴 파일 이름. EV_NAME, 없으면 <출력 폴더 이름>.txt
    out_name, out_parent = os.path.basename(out), os.path.dirname(out)
    ev_name = params.ev or out_name + ".txt"
    in_ev = os.path.basename(out_parent) == "evidence"
    deck_meta = {"receipt_file": f"evidence/{out_name}/receipt.json" if in_ev else os.path.join(out, "receipt.json"),
                 "verify_cmd": f"{entry_cmd()} --verify {f'evidence/{out_name}' if in_ev else out}", "ev": ev_name}
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
                      "verdict": verdict, "format_version": ver.FORMAT_VERSION, "weakening": {"review": review}, "checks": checks,
                      "allowlist": {"unreviewed": len(pending), "unused": len(unused), "write_review": len(allow.write_review()),
                                    "legacy": name_only, "composite": composite_locs, "expired": len(allow.expired())},
                      "cbom": {"fixed": {"unresolved": cbom["fixed"]["unresolved"]}}}),
                  "allow_unreviewed": len(pending), "checks": {c["id"]: c["status"] for c in checks}},
    })

    tools = [tool("cbom-scan.sh", params.cbom_scan), tool("residue", res_script, res_kind),
             tool("test-paths.ere", scanmod.TEST_PATHS_FILE), tool("skip-dirs", skipdirs.SKIP_FILE),
             tool("profiles", rules.PROFILES_FILE), tool("kat-kpqc", impl.KAT_FILE), tool("kat-excerpts", os.path.join(HERE, "scan", "kat"))]
    pyfiles = ["prove.py", "prove.sh", "pqlite/scan.py", "pqlite/verify.py", "pqlite/tlsprobe.py", "pqlite/receipt.py",
               "pqlite/allowlist.py", "pqlite/version.py", "pqlite/rules.py", "pqlite/skipdirs.py", "pqlite/impl.py"]
    tools += [tool(p, os.path.join(HERE, p)) for p in pyfiles]
    if probe:
        tools.append(probe)
    tools.append({"name": "tls_probe source", "path": str(tlsprobe.PROBE_SRC), "sha256": tlsprobe.source_sha256(),
                  "version": tlsprobe.PROBE_VERSION})
    tools.append({"name": "python", "path": sys.executable, "sha256": None, "version": sys.version.split()[0]})
    tools.append(tool("openssl", params.openssl, openssl_version(params.openssl)))

    # 판정 근거 버전(증적 형식 2부터): 도구 버전, 실제로 돈 규칙 파일(pqlite/version.py RULESET_FILES)의 묶음 해시와 그 이름
    # (scan/ruleset.json), 증적 형식.
    # 몇 년 뒤에도 어느 규칙으로 판정했는지 알 수 있게 한다. --verify 는 묶음 해시를 tools[] 의 해시로 다시 계산해 맞춘다
    rs_sha = ver.ruleset_from_tools(tools)
    r = {"format": rc.FORMAT, "format_version": ver.FORMAT_VERSION, "tool_version": ver.tool_version(),
         "ruleset_version": ver.ruleset_label(rs_sha), "ruleset_sha256": rs_sha,
         "note": rc.NOTE, "verdict": verdict, "started_at": rc.iso(started), "finished_at": None,
         "inputs": {"orig": in_o, "fixed": in_f}, "tools": tools,
         "params": {"classic": params.classic, "expect": params.expect, "scope": params.scope, "tls_via": params.tls_via,
                    "tls_targets": params.tls_targets, "tls_targets_orig": params.tls_targets_orig,
                    "residue": res_script or "", "allow": allow_path or "", "exclude": excl.patterns,
                    "recon": recon_path or "", "require_review": params.require_review, "profile": params.profile,
                    "fail_on_review": params.fail_on_review, "require_resolved": params.require_resolved, "expect_from": params.expect_from,
                    "review_max_age_days": params.review_max_age_days, "max_file_bytes": params.max_file_bytes, "mode": params.mode},
         "changed": {"added": added, "removed": removed, "modified": modified, "file": ch_path, "file_sha256": ch_sha},
         "cbom": cbom, "java": java_rec, "tls": tls,
         "weakening": {"deny": deny, "review": review, "file": wp, "file_sha256": ws},
         "checks": checks, "timeline": timeline, "extra": extra}
    hyb_locs = sorted({it["loc"] for it in cbom_items["fixed"] if it["status"] == "allow" and it["reason"] == HYBRID_REASON}
                      | {x["loc"] for x in ((jf or {}).get("listed") or {}).get("lines", []) if x["as"] == "hybrid"},
                      key=al._loc_key)
    # 이름 규칙(Legacy*.java·코드의 legacy, 쓰기 경로 아님)으로만 허용된 위치(CBOM, SCOPE=all 이면 residue 도). 허용 목록에 없어도
    # 판정에서 빠지므로 증적·덱에 따로 남기고 r-allow 가 검토 필요로 본다(형식 3, 교차 리뷰 X01)
    legacy_locs = name_only
    r["allowlist"] = {"source": allow_path, "auto": allow_auto, "file": allow_art, "file_sha256": allow_sha,
                      "entries": allow.record(), "warnings": allow.warnings, "unreviewed": len(pending),
                      "top_digest": allow.top_digest,
                      # 결함 D1 뒤에 보탬: 안 쓰인 항목 수, 그 항목들이 원본에서 덮는 고전 줄 수(사람 확인 전), 허용 범위 쓰기 경로 위치 수
                      "unused": len(unused), "unused_orig_lines": sum(len(e["orig"]) for e in unused), "expired": len(allow.expired()),
                      "write_review": len(allow.write_review()),
                      "hybrid": hyb_locs, "legacy": legacy_locs, "composite": composite_locs,
                      "imports": sorted({x["loc"] for x in ((jf or {}).get("listed") or {}).get("lines", []) if x.get("via") == "import"}
                                        | {it["loc"] for it in cbom_items["fixed"] if it["status"] in ("allow", "review")
                                           and "쓰는 import" in it["reason"]}, key=al._loc_key)}
    r["test_paths"] = {"file": tp_art, "file_sha256": tp_sha}
    r["skip_dirs"] = {"file": sd_art, "file_sha256": sd_sha}
    r["excluded"] = {"items": excl.items, "notes": ex_notes, "app_roots": app_roots, "recon_file": recon_path,
                     "recon_digest": recon_digest, "count_orig": len(ex_o), "count_fixed": len(ex_f),
                     "files_orig": ex_o[:200], "files_fixed": ex_f[:200]}
    r["deck_meta"] = deck_meta
    t0 = now()
    say(f"[6/{len(steps)}] (d) 표·검증 증적")
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
    with open(os.path.join(out, "README.txt"), "x", encoding="utf-8") as f:
        f.write(rc.render_readme(r))  # 결과 폴더 안내(형식 3). 먼저 볼 파일·다시 확인 명령. verify 가 다시 만들어 본다
    vres = rc.verify(out)
    bad = [w for ok, w in vres if not ok]

    lines = [f"== PQ-Proof {ver.tool_version()}  ({time.strftime('%Y-%m-%d %H:%M:%S %Z')})  [{platform.machine()}]",
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
        lines.append(f"이름 규칙(legacy)으로만 허용 {len(legacy_locs)}곳(허용 목록 밖, 쓰기 경로 아님, 사람 확인 전): {', '.join(legacy_locs[:4])}"
                     f"{' 외' if len(legacy_locs) > 4 else ''}")
    for c in checks:
        lines.append(f"[{c['id']}] {STATUS_KO[c['status']]}  {c['actual']}")
    for d in deny:
        lines.append(f"  deny  {d}")
    for x in review:
        lines.append(f"  review {x['path']}: {x['rule']} ({x['before']}->{x['after']}) {x['detail']}")
    code = {"pass": 0, "fail": 1, "undecided": 3}[verdict]
    if code == 0 and params.fail_on_review and any(c["status"] == "review" for c in checks):
        code = EXIT_REVIEW  # FAIL_ON_REVIEW=1: 판정은 통과 그대로, 종료 코드만 5
    # 통과인데 사람이 볼 것(검증 호출 제거 흔적, 사람 확인 전 허용 항목, 허용 범위 쓰기 경로, 안 쓰인 항목)이 남았으면 판정 옆에 적는다
    note = rc.pending_note(r, en=True)
    lines.append(f"VERDICT={verdict.upper()}{f' ({note})' if note else ''}  receipt_id={r['receipt_id']}")
    # 건너뛴 검사는 통과가 아니다: 상태별 개수를 따로 찍는다(통과로 세는 것은 '통과'뿐)
    tally = {s: sum(1 for c in checks if c["status"] == s) for s in ("pass", "review", "na", "undecided", "fail", "check")}
    lines.append(f"검사 {len(checks)}개: 통과 {tally['pass']}"
                 + "".join(f" · {STATUS_KO[s]} {tally[s]}" for s in ("review", "na", "undecided", "fail", "check") if tally[s])
                 + " (통과로 세는 것은 '통과'뿐)"
                 + f" · 도구 {r['tool_version']} · 규칙 묶음 {r['ruleset_version']} · 증적 형식 {r['format_version']}")
    if masked:
        lines.append(f"비밀번호·토큰처럼 보이는 값 {masked}곳을 발췌에서 *** 로 가렸다(표·SARIF·스캐너 출력. 원문은 입력 폴더와 "
                     "zip 입력을 푼 in/ 에만 있다. 폴더를 넘기기 전에 확인한다)")
    lines.append(f"검증 증적 다시 확인: {'ok' if not bad else 'FAIL'} ({len(vres)}개 검사)" + ("" if not bad else ": " + "; ".join(bad[:3])))
    lines += next_steps(r, cbom_items["fixed"], out)
    if bad:
        code = 3
    if not quiet:
        print("\n".join(lines))
    return r, code, lines


# ---------------------------------------------------------------------------------------------
# 한 트리 인벤토리(--inventory, 교차 리뷰 X13): 판정 없이 CBOM 과 계열별 고전 줄, PQC 이름 줄을 센다. 정기 감사·첫 현황 조사용
def inventory(tree, params, out=None, quiet=False):
    """한 트리를 두 스캐너와 residue.sh 로 훑어 out 에 inventory.json·tables/cbom.csv·artifacts/ 를 쓴다. 반환 (요약 dict, 종료 코드 0)."""
    out = os.path.abspath(out or params.out or default_out(tree, "inventory"))
    if os.path.exists(out):
        raise UsageError(f"출력 폴더가 이미 있다(덮어쓰지 않음): {out}")
    started = now()
    os.makedirs(out)
    art = rc.Artifacts(out)
    rules.MAX_TEXT = scanmod.MAX_FILE = params.max_file_bytes
    info, root, files, extra = prepare_input(tree, out, "tree", skipdirs.load(), params.max_file_bytes)
    if not files:
        raise UsageError(f"읽을 파일이 0개다: {info['path']}")
    tp_art, _ = art.add("artifacts/test-paths.ere", slurp(scanmod.TEST_PATHS_FILE))
    sd_art, _ = art.add("artifacts/skip-dirs", slurp(skipdirs.SKIP_FILE))
    tp_file, sd_file = os.path.join(out, *tp_art.split("/")), os.path.join(out, *sd_art.split("/"))
    rows = scanmod.scan(root)
    art.add_json("artifacts/scan.json", [x.to_json() for x in rows])
    sig = tls_signals(root, rows)
    ok, _, crow = run_cbom_scan(params.cbom_scan, root, os.path.join(out, "artifacts", "cbom"), params.openssl, None, None, tp_file, sd_file)
    art.register_dir("artifacts/cbom")
    items, counts, nloc = merge_cbom(crow, rows, Lines(root), sig[2], params.scope, None)
    table, _ = cbom_csv(items)
    art.add("tables/cbom.csv", table)
    code, text = run_residue(params.residue or GENERIC_RESIDUE, root, tp_file, sd_file)
    art.add("artifacts/residue.txt", text)
    parsed = parse_residue(text)
    fams = parsed["families"] if parsed else None
    rs_sha = ver.ruleset_from_tools(rule_tools())
    summary = {
        "format": "pqproof inventory 1", "tool_version": ver.tool_version(), "ruleset_version": ver.ruleset_label(rs_sha),
        "ruleset_sha256": rs_sha, "started_at": rc.iso(started), "input": info, "profile": params.profile, "scope": params.scope,
        "cbom": {"rows": len(items), "locations": nloc, "blocking": counts["block"], "review": counts["review"], "allowed": counts["allow"],
                 "comment_or_test": counts["comment"], "tests": counts["tests"], "check": counts["check"], "unresolved": counts["unresolved"],
                 "cbom_scan_ok": ok},
        "blocking": sorted({it["loc"] for it in items if it["status"] == "block"}, key=al._loc_key)[:400],
        "families": fams, "classic_code_lines": sum(v["code"] for v in fams.values()) if fams else None,
        "weak_pqc": parsed["weak_pqc"] if parsed else None, "expect": parsed["expect"] if parsed else None,
        "tls": {"server_signals": sig[0], "client_signals": sig[1]},
        "note": "판정이 아니다. 한 트리의 지금 상태(인벤토리)이고 같은 규칙 묶음으로 센 수다. 전환 판정은 두 트리를 넣어 돌린다.",
        "artifacts": None}
    summary["artifacts"] = art.manifest()
    with open(os.path.join(out, "inventory.json"), "x", encoding="utf-8") as f:
        f.write(json.dumps(summary, ensure_ascii=False, indent=1, sort_keys=True) + "\n")
    if not quiet:
        c = summary["cbom"]
        print(f"== PQ-Proof {ver.tool_version()} 인벤토리(판정 아님)  {info['path']} (파일 {info['files']}, 트리 {info['tree_sha256'][:16]})")
        print(f"CBOM 위치 {c['locations']} · 막는 위치 {c['blocking']} · 검토 필요 {c['review']} · 확인 {c['check']}"
              + ("" if ok else " · cbom-scan 실패"))
        if fams:
            print("공개키 9계열 code: " + " · ".join(f"{k} {v['code']}" for k, v in fams.items() if v["code"])
                  + f" (합 {summary['classic_code_lines']}) · 보안레벨 3 미만 PQC {summary['weak_pqc']}")
            print("PQC 이름 줄: " + " · ".join(f"{k} {v}" for k, v in (summary["expect"] or {}).items()))
        print(f"TLS 서버 신호 {len(sig[0])} · 클라이언트 신호 {len(sig[1])} · 규칙 묶음 {summary['ruleset_version']}")
        print(f"출력: {out} (inventory.json, tables/cbom.csv)")
    return summary, 0


# ---------------------------------------------------------------------------------------------
# 구현 검증(--impl, KpqC KAT 대조). 문제지를 내고(prompt), 사용자 하네스가 쓴 답안(JSON 또는 PQCgenKAT .rsp)을 참조판 KAT 와
# 대조한다(judge). 검사 대상 구현은 빌드하거나 실행하지 않는다. 대조 규칙은 pqlite/impl.py, 받아 줄 판은 scan/profiles.json 의
# impl_accept(PROFILE, 구현 검증의 기본은 kpqc). 판정은 검사 두 줄 i-kpqc·i-nist(pqlite/rules.py judge_impl)이고 증적은 형식 4다.
# judge --pq-verify "<인자>"(사용자가 켤 때만): 바깥 도구 pq-verify 를 셸 없이 하위 프로세스로 불러 NIST PQC 구현 감사를 하고(대상
# 라이브러리를 실행하는 것은 pq-verify), 보고서(artifacts/impl/pq-verify/report.json)와 실행 기록(log.json)을 증적에 담아 i-nist 를 정한다.
IMPL_USAGE = ("사용: bash prove.sh --impl prompt [--param 이름 ...] [-o 파일]      문제지(JSON)를 쓴다(파일을 안 주면 표준 출력)\n"
              "      bash prove.sh --impl judge <답안.json|kat.rsp> [--param 이름] [--pq-verify \"<pq-verify 인자>\"]\n"
              "                                답안을 참조판 KAT 와 대조해 증적 폴더를 쓴다. --pq-verify 를 주면 pq-verify 감사도 같은 증적에 담는다\n"
              "      bash prove.sh --impl judge --pq-verify \"--audit-kem <라이브러리> ML-KEM-768\"   답안 없이 pq-verify 감사만")
IMPL_SAYS = ("참조판 KAT 와 일치하는지 본 것이다. 표준 준수 시험이나 공인 시험(KCMVP)이 아니고, PQ-Proof 는 구현을 빌드하거나 "
             "실행하지 않았다(답안은 사용자 하네스가 만들었다).")
PQV_SAYS = ("NIST 구현 감사는 사용자가 켠 바깥 도구 pq-verify 가 대상 라이브러리를 불러 실행했고, PQ-Proof 는 그 보고서와 종료 코드만 "
            "읽었다. pq-verify 는 샌드박스가 아니다: 믿지 못할 라이브러리는 컨테이너나 VM 안에서 돌린다.")


class ToolDataError(Exception):
    """도구 자신의 데이터(KAT 목록, 프로필)가 깨졌다(종료 4)."""


def impl_cmd():
    """사람에게 보일 구현 검증 명령 앞머리: 'pqproof impl' 또는 'bash prove.sh --impl'."""
    return "pqproof impl" if entry_cmd() == "pqproof" else "bash prove.sh --impl"


def impl_args(argv):
    """--impl 뒤 인자 → (명령, 입력 파일 또는 None, [--param 이름], 출력 파일, --pq-verify 인자 글 또는 None). 틀리면 UsageError.
    judge 는 답안 파일과 --pq-verify 중 적어도 하나가 있어야 한다."""
    if not argv or argv[0] not in ("prompt", "judge"):
        raise UsageError(IMPL_USAGE)
    cmd, rest, names, out, pos, pqv = argv[0], argv[1:], [], None, [], None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--param", "-p", "-o", "--output", "--pq-verify"):
            if i + 1 >= len(rest):
                raise UsageError(f"{a} 뒤에 값이 없다\n{IMPL_USAGE}")
            if a in ("-o", "--output"):
                if cmd != "prompt":
                    raise UsageError(f"{a} 는 prompt 에만 쓴다(judge 는 OUT 으로 증적 폴더를 정한다)\n{IMPL_USAGE}")
                out = rest[i + 1]
            elif a == "--pq-verify":
                if cmd != "judge" or pqv is not None:
                    raise UsageError(f"--pq-verify 는 judge 에 한 번만 쓴다(인자는 따옴표로 묶어 한 덩어리로 준다)\n{IMPL_USAGE}")
                pqv = rest[i + 1]
            else:
                names.append(rest[i + 1])
            i += 2
        elif a.startswith("-"):
            raise UsageError(f"모르는 옵션 {a}\n{IMPL_USAGE}")
        else:
            pos.append(a)
            i += 1
    if (cmd == "prompt" and pos) or (cmd == "judge" and (len(pos) > 1 or (not pos and pqv is None))):
        raise UsageError(IMPL_USAGE)
    if cmd == "judge" and names and not pos:
        raise UsageError(f"--param 은 답안(.rsp)과 함께 준다\n{IMPL_USAGE}")
    return cmd, (pos[0] if pos else None), names, out, pqv


def impl_manifest():
    try:
        return impl.load_manifest()
    except impl.ManifestError as e:
        raise ToolDataError(f"KpqC KAT 목록이 깨졌다: {e}") from None


def impl_names(manifest, names):
    """--param 이름(정식 이름·별칭, 대소문자 무관) → 정식 이름 목록(목록 순서, 겹침 없음)."""
    got = []
    for n in names:
        pid = manifest["names"].get(n.strip().lower())
        if pid is None:
            raise UsageError(f"모르는 파라미터 {n!r}. 아는 이름: {', '.join(manifest['order'])}(별칭은 scan/kat-kpqc.json 의 aliases)")
        if pid not in got:
            got.append(pid)
    return [p for p in manifest["order"] if p in got]


def impl_prompt(names, out_path=None, quiet=False):
    """문제지를 out_path(이미 있으면 멈춘다) 또는 표준 출력에 쓴다. 반환 (문제지, 종료 코드 0)."""
    m = impl_manifest()
    pids = impl_names(m, names) if names else list(m["order"])
    prompt = impl.emit_prompt(impl.build_key(m, pids))
    text = impl.dumps(prompt)
    if out_path:
        if os.path.lexists(out_path):
            raise UsageError(f"문제지 파일이 이미 있다(덮어쓰지 않음): {out_path}")
        with open(out_path, "x", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    if not quiet:
        print(f"pqproof: 문제지 {len(prompt['items'])}문항(파라미터 {len(pids)}개) prompt_sha256 {prompt['prompt_sha256']}"
              + (f" -> {out_path}" if out_path else ""), file=sys.stderr)
    return prompt, 0


def pqverify_exe(params):
    """(실행 파일 절대 경로 또는 None, 없을 때 까닭). PQ_VERIFY 를 주면 그것, 아니면 PATH 의 pq-verify(src/pqproof/deps.py 와 같은 규칙)."""
    given = params.pq_verify
    if given:
        if os.path.isfile(given) and os.access(given, os.X_OK):
            return os.path.abspath(given), None
        return None, f"PQ_VERIFY={given} 가 실행 파일이 아니다(pq-verify 를 돌리지 못함)"
    found = shutil.which(impl.PQV_NAME)
    if found:
        return os.path.abspath(found), None
    return None, (f"{impl.PQV_NAME} 를 찾지 못했다(PATH 에 없고 PQ_VERIFY 도 주지 않았다). 따로 만든 가상 환경에 판과 휠 해시를 고정해 "
                  "설치하고(guide/impl.md, .github/requirements/pq-verify.txt) PQ_VERIFY 로 가리킨다")


def _kill_group(p):
    """시간 초과한 하위 프로세스를 그 세션 묶음째 멈춘다(pq-verify 가 띄운 감사 자식까지)."""
    try:
        if os.name != "nt":
            os.killpg(p.pid, signal.SIGKILL)
        else:
            p.kill()
    except OSError:
        try:
            p.kill()
        except OSError:
            pass


def _drain(stream, buf, keep=impl.PQV_MAX_TEXT):
    """파이프를 끝까지 읽어 비우되 앞 keep 바이트와 뒤 keep 바이트만 메모리에 둔다(감사 대상 라이브러리가 같은 stdout 에 많이 써도
    PQ-Proof 의 메모리가 커지지 않게). buf({"head", "tail", "total"})를 읽는 대로 고치므로 중간에 멈춰도 읽은 데까지 남는다."""
    try:
        while True:
            chunk = stream.read1(1 << 16)
            if not chunk:
                break
            buf["total"] += len(chunk)
            head = buf["head"]
            if len(head) < keep:
                n = keep - len(head)
                head += chunk[:n]
                chunk = chunk[n:]
            if chunk:
                tail = buf["tail"]
                tail += chunk
                if len(tail) > keep:
                    del tail[:len(tail) - keep]
    except (OSError, ValueError):
        pass


def run_logged(argv, log, role, timeout, env, cwd):
    """하위 프로세스 하나를 셸 없이 새 세션에서 돌린다(시간 초과면 묶음째 멈춤). tlsprobe.HostRunner.run 처럼 argv·종료 코드·stdout·
    stderr 를 log 에 남긴다(글은 impl.clip_stream 상한, 읽는 동안에도 앞·뒤만 메모리에 둔다). communicate 처럼 출력 파이프가 닫힐 때까지
    기다리고, 프로세스가 끝났어도 그 자식이 파이프를 쥐고 시간 한도를 넘기면 시간 초과로 적고 묶음째 멈춘다. 반환: 그 기록."""
    import threading
    t = time.time()
    rec = {"role": role, "argv": list(argv), "exit_code": None, "stdout": "", "stderr": "", "t": t, "seconds": 0.0, "timeout": timeout,
           "timed_out": False, "error": None}
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd,
                             start_new_session=os.name != "nt")
    except OSError as e:
        rec["error"] = str(e)
        log.append(rec)
        return rec
    bufs = [{"head": bytearray(), "tail": bytearray(), "total": 0} for _ in range(2)]
    readers = [threading.Thread(target=_drain, args=(s, b), daemon=True) for s, b in zip((p.stdout, p.stderr), bufs)]
    for th in readers:
        th.start()
    try:
        p.wait(timeout=timeout)
        for th in readers:
            th.join(max(0.0, t + timeout - time.time()))
        if any(th.is_alive() for th in readers):
            raise subprocess.TimeoutExpired(argv, timeout)
        rec["exit_code"] = p.returncode
    except subprocess.TimeoutExpired:
        rec["timed_out"] = True
        _kill_group(p)
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        for th in readers:
            th.join(timeout=10)
    for f in (p.stdout, p.stderr):
        try:
            f.close()
        except OSError:
            pass
    rec["stdout"], rec["stderr"] = (impl.clip_stream(bytes(b["head"]), bytes(b["tail"]), b["total"]) for b in bufs)
    rec["seconds"] = round(time.time() - t, 3)
    log.append(rec)
    return rec


PQV_DIR = "artifacts/impl/pq-verify"


def pqverify_run(spec, params, out, art):
    """pq-verify 감사를 한 번 돌리고 증적 impl.nist 기록과 tools[] 칸(실행 파일이 없으면 None)을 낸다. 셸 없음, 빈 임시 작업 폴더,
    PQV_*·LD_*·DYLD_*·PYTHONPATH 등을 뺀 환경, 시간 한도 PQ_VERIFY_TIMEOUT. pq-verify 는 보고서를 증적 폴더 안(PQV_DIR/report.json)에 쓰고,
    실행 기록(--version 과 감사 두 번의 argv·종료 코드·stdout·stderr)은 PQV_DIR/log.json 에 남는다."""
    exe, why = pqverify_exe(params)
    env, dropped = impl.pqverify_env(dict(os.environ))
    target = os.path.abspath(spec["target"])
    lib_sha = sha256_file(target) if os.path.isfile(target) else None
    rel_report = PQV_DIR + "/report.json"
    report_full = os.path.join(out, *rel_report.split("/"))
    os.makedirs(os.path.dirname(report_full), exist_ok=True)
    log, run, tool_rec = [], None, None
    nist = {"engine": impl.PQV_NAME, "args": spec["args"], "argv": None, "executable": exe, "env_removed": dropped,
            "timeout": params.pq_verify_timeout, "exit_code": None, "not_run": None, "library": {"path": target, "sha256": lib_sha},
            "report": None, "report_sha256": None, "log": None, "log_sha256": None}
    with tempfile.TemporaryDirectory(prefix="pqproof-pqv-") as cwd:
        if exe is None:
            nist["not_run"] = why
        else:
            v = run_logged([exe, "--version"], log, "version", 60, env, cwd)
            tool_rec = {"name": impl.PQV_NAME, "path": exe, "sha256": sha256_file(exe), "version": impl.pqverify_version(v["stdout"])}
            nist["argv"] = impl.pqverify_argv(exe, spec, target, report_full)
            run = run_logged(nist["argv"], log, "audit", params.pq_verify_timeout, env, cwd)
            nist["exit_code"] = run["exit_code"]
    report = None
    if os.path.lexists(report_full):
        try:
            nist["report"], nist["report_sha256"] = art.register(rel_report)
            report = rc._read_nofollow(out, rel_report)
        except (OSError, ValueError):  # 링크 같은 것: 목록에 올리지 않아 --verify 가 '목록에 없는 파일'로 잡는다
            report = None
    nist["log"], nist["log_sha256"] = art.add_json(PQV_DIR + "/log.json", log)
    summary = impl.pqverify_summary(spec["audit"], run, report, lib_sha, nist["not_run"])
    status, detail = impl.pqverify_status(summary)
    nist.update(summary=summary, status=status, detail=detail)
    return nist, tool_rec


def impl_report_md(r):
    """구현 검증의 tables/report.md."""
    x = r["impl"]
    inp, nist = x["input"], x.get("nist")
    cmd = f"{impl_cmd()} judge" + (f" {md_cell(os.path.basename(inp['path']), html=False)}" if inp else "") + (" --pq-verify ..." if nist else "")
    out = [f"<!-- prove.sh --impl 이 만든 표. 답안 sha256 {inp['sha256'] if inp else '없음'}. receipt_id는 같은 폴더 receipt.json. -->", "",
           f"명령: `{cmd}` · 판정 **{rc.verdict_text(r)}**", "",
           f"판정 근거: pqproof {r['tool_version']} · 규칙 묶음 {r['ruleset_version']} (sha256 `{r['ruleset_sha256'][:16]}`) · "
           f"증적 형식 {r['format_version']} · PROFILE={r['params']['profile']} · 받아 줄 판 {', '.join(x['accept']) or '없음'}", ""]
    out += ["검사 결과", "", md_table(["#", "검사", "기대", "실제"], [[f"V{i}", c["title"], c["expected"], f"{STATUS_KO[c['status']]}: {c['actual']}"]
                                                                  for i, c in enumerate(r["checks"], 1)]), ""]
    rows = [[f"`{a}`", b, c, d, e, f, STATUS_KO.get(g, ""), h] for a, b, c, d, e, f, g, h in rc.impl_rows(r)]
    if rows:
        out += ["파라미터별 참조판 대조", "", md_table(["파라미터", "판", "역할", "받아 줌", "대조", "첫 불일치", "결과", "요약"], rows), ""]
    if nist:
        out += ["NIST 구현 감사(pq-verify)", "", md_table(["항목", "값"], [[a, b] for a, b in rc.nist_rows(r)]), "", PQV_SAYS, ""]
    out += [IMPL_SAYS + f" 다시 확인: `{entry_cmd()} --verify <출력 폴더>`(답안·보고서 사본으로 다시 판정한다).", ""]
    return "\n".join(out)


def impl_review_sources(m, key, results, accept, profile):
    """검토 필요인 파라미터마다 일치한 판과 받아 줄 판이 어느 출처인지(scan/kat-kpqc.json sources 의 제목) 적는 콘솔 줄. 옛 참조판과
    일치했으면 프로필로 그 판도 받게 하는 법을 덧붙인다. 증적에는 넣지 않는다(판정 글은 정답 묶음 사본만으로 다시 만들 수 있어야 한다)."""
    out = []
    for res in results:
        if res["status"] != "review":
            continue
        P = next(P for P in key["params"] if P["id"] == res["param"])
        by = {V["version"]: V for V in P["versions"]}
        acc = accept.get(P["id"], [])

        def title(v, by=by):
            sid = by[v]["source"] if v in by else None
            return f"{v} = {m['sources'].get(sid) or sid or '출처 없음'}"
        out.append(f"  {res['param']} 판 출처(scan/kat-kpqc.json): 일치 " + " · ".join(title(v) for v in res["matched"])
                   + " / 받아 줄 판 " + (" · ".join(title(v) for v in acc) or "없음"))
        old = next((v for v in res["matched"] if v not in acc and by.get(v, {}).get("role") == "reference"), None)
        if old:
            out.append(f"    이 판도 받으려면 scan/profiles.json 의 {profile} 프로필 impl_accept 에 \"{res['param']}@{old}\" 을 더한다"
                       "(규칙 묶음이 '+modified' 로 적히고, --verify 도 같은 프로필로 한다. guide/impl.md)")
    return out


def impl_judge(path, names, params, out=None, quiet=False, pq_verify=None):
    """답안 하나(또는 None)를 판정하고 pq_verify(--pq-verify 인자 글, 또는 None)를 주면 pq-verify 감사도 돌려 증적 폴더를 쓴다.
    반환: (receipt dict, 종료 코드, 출력 줄 목록)."""
    if path is None and pq_verify is None:
        raise UsageError(IMPL_USAGE)
    if path is not None and not os.path.isfile(path):
        raise UsageError(f"답안 파일이 없다: {path}")
    spec = None
    if pq_verify is not None:
        try:
            spec = impl.pqverify_args(pq_verify)
        except ValueError as e:
            raise UsageError(f"--pq-verify: {e}") from None
    m = impl_manifest()
    hint = None
    if names:
        if path is None:
            raise UsageError("--param 은 답안(.rsp)과 함께 준다")
        pids = impl_names(m, names)
        if len(pids) != 1:
            raise UsageError("--param 은 .rsp 하나에 하나만 준다(답안 JSON 은 params 칸을 읽는다)")
        hint = pids[0]
    acc_spec = rules.PROFILES[params.profile].get("impl_accept")
    if path is not None and not acc_spec:
        raise UsageError(f"PROFILE={params.profile} 에는 받아 줄 판(impl_accept)이 없다. 구현 검증은 PROFILE=kpqc(기본)로 돈다")
    out = os.path.abspath(out or params.out or default_out(path if path is not None else spec["target"], "impl"))
    if os.path.exists(out):
        raise UsageError(f"출력 폴더가 이미 있다(덮어쓰지 않음): {out}")
    started = now()
    size = sha = data = None
    parsed, pids, problem, key, accept, control, results = {"kind": None, "problem": None}, [], None, None, {}, None, []
    if path is not None:
        size, sha = os.path.getsize(path), sha256_file(path)
        if size > impl.MAX_INPUT:
            parsed = {"kind": None, "problem": impl.oversize_problem(size)}
        else:
            data = slurp(path, binary=True)
            parsed = impl.parse_input(data)
        if parsed["kind"] == "response" and hint:
            raise UsageError("--param 은 .rsp 에만 쓴다(답안 JSON 은 params 칸을 읽는다)")
        pids, problem = impl.input_params(parsed, m["names"], hint)
        problem = parsed["problem"] or problem
        key = impl.build_key(m, pids)
        try:
            accept = impl.resolve_accept(m["params"], acc_spec, pids)
        except ValueError as e:
            raise ToolDataError(f"scan/profiles.json {params.profile}: {e}") from None
    t1 = now()
    if key is not None and not problem:
        control, results = impl.control_problem(key, accept, parsed["kind"]), impl.match_versions(key, parsed, accept)
    t2 = now()
    os.makedirs(out)
    art = rc.Artifacts(out)
    nist, pqv_tool = pqverify_run(spec, params, out, art) if spec else (None, None)
    t3 = now()
    checks, verdict = rules.judge_impl(results, control, problem, rc.derive_verdict, nist, answered=path is not None)
    timeline = [{"name": "준비", "started_at": rc.iso(started), "ended_at": rc.iso(t1)}]
    if path is not None:
        timeline.append({"name": "대조", "started_at": rc.iso(t1), "ended_at": rc.iso(t2)})
    if spec:
        timeline.append({"name": "pq-verify", "started_at": rc.iso(t2), "ended_at": rc.iso(t3)})
    in_file = in_sha = None
    if data is not None:
        in_file, in_sha = art.add("artifacts/impl/answer." + ("rsp" if parsed["kind"] == "rsp" else "json"), data)
    key_rec = None
    if key is not None:
        key_file, key_sha = art.add("artifacts/impl/key.json", impl.dumps(key))
        key_rec = {"file": key_file, "file_sha256": key_sha, "params": len(key["params"])}
    prompt_rec = None
    if parsed["kind"] == "response" and not problem:
        prompt = impl.emit_prompt(key)
        pf, ps = art.add("artifacts/impl/prompt.json", impl.dumps(prompt))
        prompt_rec = {"file": pf, "file_sha256": ps, "prompt_sha256": prompt["prompt_sha256"], "items": len(prompt["items"])}
    tools = rule_tools() + [tool(p, os.path.join(HERE, p)) for p in ("prove.py", "prove.sh", "pqlite/receipt.py", "pqlite/version.py")]
    tools.append({"name": "python", "path": sys.executable, "sha256": None, "version": sys.version.split()[0]})
    if pqv_tool:  # 실행 파일을 찾았을 때만(없는 도구를 쓴 것처럼 적지 않는다)
        tools.append(pqv_tool)
    rs_sha = ver.ruleset_from_tools(tools)
    out_name, out_parent = os.path.basename(out), os.path.dirname(out)
    in_ev = os.path.basename(out_parent) == "evidence"
    r = {"format": rc.FORMAT, "format_version": ver.FORMAT_VERSION, "tool_version": ver.tool_version(),
         "ruleset_version": ver.ruleset_label(rs_sha), "ruleset_sha256": rs_sha, "note": rc.NOTE, "verdict": verdict,
         "started_at": rc.iso(started), "finished_at": None, "tools": tools,
         "params": {"mode": "impl", "profile": params.profile, "params": [P["id"] for P in key["params"]] if key else [],
                    "input": parsed["kind"], "fail_on_review": params.fail_on_review},
         "impl": {"engine": impl.ENGINE, "kat_manifest_sha256": m["sha256"],
                  "input": None if path is None else {
                      "path": os.path.abspath(path), "kind": parsed["kind"], "bytes": size, "sha256": sha, "file": in_file,
                      "file_sha256": in_sha, "implementation": parsed.get("implementation"), "header": parsed.get("header")},
                  "prompt": prompt_rec, "key": key_rec, "accept": impl.accept_list(accept),
                  "control": {"ok": control is None, "problem": control}, "problem": problem, "results": results, "nist": nist},
         "checks": checks, "timeline": timeline,
         "deck_meta": {"receipt_file": f"evidence/{out_name}/receipt.json" if in_ev else os.path.join(out, "receipt.json"),
                       "verify_cmd": f"{entry_cmd()} --verify {f'evidence/{out_name}' if in_ev else out}",
                       "ev": params.ev or out_name + ".txt"}}
    t4 = now()
    art.add("tables/summary.csv", csv_text(["검사", "제목", "판정", "기준", "실제"],
                                           [[c["id"], c["title"], STATUS_KO[c["status"]], c["expected"], c["actual"]] for c in checks]))
    art.add("tables/impl.csv", csv_text(["파라미터", "판", "역할", "받아 줌", "대조", "첫 불일치", "결과", "요약"],
                                        [[a, b, c, d, e, f, STATUS_KO.get(g, ""), h] for a, b, c, d, e, f, g, h in rc.impl_rows(r)]))
    art.add("tables/report.md", impl_report_md(r))
    r["artifacts"] = art.manifest()
    timeline.append({"name": "표·증적", "started_at": rc.iso(t4), "ended_at": rc.iso(now())})
    r["finished_at"] = rc.iso(now())
    r["receipt_id"] = rc.compute_id(r)
    for name, text in (("receipt.json", rc.dumps(r)), ("receipt.html", rc.render_html(r)), ("deck.json", rc.render_deck(r)),
                       ("README.txt", rc.render_readme(r))):
        with open(os.path.join(out, name), "x", encoding="utf-8") as f:
            f.write(text)
    vres = rc.verify(out)
    bad = [w for ok, w in vres if not ok]
    inp = r["impl"]["input"]
    what = " · ".join(x for x, on in (("KpqC KAT 대조", inp), ("pq-verify 감사", nist)) if on)
    lines = [f"== PQ-Proof {ver.tool_version()} 구현 검증({what})  ({time.strftime('%Y-%m-%d %H:%M:%S %Z')})  [{platform.machine()}]"]
    if inp:
        lines += [f"답안: {inp['path']} ({ {'response': '답안 JSON', 'rsp': 'PQCgenKAT .rsp'}.get(inp['kind'], '읽지 않음') }, {size:,}바이트, "
                  f"sha256 {sha[:16]})" + (f" · 구현: {inp['implementation'][:80]}" if inp["implementation"] else "")
                  + (f" · 머리 줄 {inp['header']}" if inp["header"] else ""),
                  f"판정 기준: PROFILE={params.profile} · 받아 줄 판 {', '.join(r['impl']['accept']) or '없음'}"
                  + (f" · 문제지 {prompt_rec['items']}문항" if prompt_rec else "")]
    if nist:
        extra = rc.nist_extra_args(nist)
        lines.append(f"pq-verify: {nist['executable'] or '없음'}" + (f" ({pqv_tool['version'] or '판 모름'})" if pqv_tool else "")
                     + f" · {spec['audit']} {nist['library']['path']} {spec['param_set']}"
                     + (f" · 더 준 옵션 {' '.join(impl.shown(a, 200) for a in extra)}" if extra else "") + f" · 종료 {nist['exit_code']}"
                     + (f" · 보고서 {nist['report']}" if nist["report"] else " · 보고서 없음"))
    for c in checks:
        lines.append(f"[{c['id']}] {STATUS_KO[c['status']]}  {c['actual']}")
    for res in results:
        lines.append(f"  {res['param']}: " + " · ".join(
            f"{v['version']}{'(받아 줌)' if v['accepted'] else ''} "
            + (v["records"] if v["records"] is not None else (f"{v['ok']}/{v['checked']}" if v["checked"] else "발췌 없음"))
            + (f" 첫 불일치 {v['first_mismatch']}" if v["first_mismatch"] and not (v["checked"] and v["ok"] == v["checked"]) else "")
            for v in res["versions"]))
    lines += impl_review_sources(m, key, results, accept, params.profile)
    if inp:
        lines.append("자기 점검: " + ("통과(정답 답안 통과, 한 바이트 바꾼 답안 실패)" if control is None and not problem
                                     else (f"실패: {control}" if control else "안 돌림(답안을 판정하지 못함)")))
    code = {"pass": 0, "fail": 1, "undecided": 3}[verdict]
    if code == 0 and params.fail_on_review and any(c["status"] == "review" for c in checks):
        code = EXIT_REVIEW
    note = rc.pending_note(r, en=True)
    if code == 0 and any(c["id"] == impl.CHECK_ID and c["status"] == "review" for c in checks):
        lines.append("주의: i-kpqc 가 검토 필요다(받아 줄 판과만 일치한 것이 아니다: 옛 판·알려진 변형과 일치했거나 판을 가르지 못했다). "
                     "검토 필요는 판정을 바꾸지 않아 종료 코드가 0 이다. CI 에서 멈추려면 FAIL_ON_REVIEW=1 을 준다(종료 5).")
    lines.append(f"VERDICT={verdict.upper()}{f' ({note})' if note else ''}  receipt_id={r['receipt_id']}")
    lines.append(f"검사 {len(checks)}개: " + " · ".join(f"{c['id']} {STATUS_KO[c['status']]}" for c in checks)
                 + f" (통과로 세는 것은 '통과'뿐, 해당 없음은 판정을 바꾸지 않는다) · 도구 {r['tool_version']} · 규칙 묶음 "
                 f"{r['ruleset_version']} · 증적 형식 {r['format_version']}")
    if inp:
        lines.append(IMPL_SAYS)
    if nist:
        lines.append(PQV_SAYS)
    lines.append(f"검증 증적 다시 확인: {'ok' if not bad else 'FAIL'} ({len(vres)}개 검사)" + ("" if not bad else ": " + "; ".join(bad[:3])))
    lines += [f"출력: {out}", "  사람이 볼 것: receipt.html · 기계가 읽을 것: receipt.json · 문서에 붙일 표: tables/report.md",
              f"  다시 확인: {entry_cmd()} --verify {out} (폴더에 파일을 더하거나 고치면 실패한다)"]
    if bad:
        code = 3
    if not quiet:
        print("\n".join(lines))
    return r, code, lines


def impl_main(argv):
    """--impl prompt|judge. 종료: 0 통과(prompt 는 씀) · 1 실패 · 2 사용법 · 3 미판정 · 4 도구 데이터 오류 · 5 FAIL_ON_REVIEW."""
    cmd, path, names, out, pqv = impl_args(argv)
    try:
        if cmd == "prompt":
            return impl_prompt(names, out)[1]
        return impl_judge(path, names, Params(mode="impl"), pq_verify=pqv)[1]
    except ToolDataError as e:
        print(f"pqproof: {e} (도구 오류, 종료 {EXIT_TOOL_ERROR})", file=sys.stderr)
        return EXIT_TOOL_ERROR


def next_steps(r, fixed_items, out):
    """콘솔 끝: 먼저 볼 파일과 다시 확인 명령, 실패면 고칠 곳 전체 목록과 허용 목록 안내(교차 리뷰 X49·X67)."""
    lines = [f"출력: {out}",
             "  사람이 볼 것: receipt.html · 기계가 읽을 것: receipt.json · 문서에 붙일 표: tables/report.md",
             f"  다시 확인: {entry_cmd()} --verify {out} (폴더에 파일을 더하거나 고치면 실패한다)"]
    st = {c["id"]: c["status"] for c in r["checks"]}
    if r["verdict"] == "fail":
        lines.append("다음 할 일:")
        nblock = len({it["loc"] for it in fixed_items if it["status"] == "block"})
        if st.get("a-cbom") == "fail":
            lines.append(f"  막는 위치 전체 {nblock}곳: tables/cbom-fixed.csv ('판정'이 막음인 행), 요약은 tables/report.md")
        if st.get("c-classic") == "fail":
            lines.append("  남은 고전 줄 전체: artifacts/residue-fixed.txt 의 LEFT 줄(규칙마다)")
        if st.get("b-weakening") == "fail":
            lines.append("  약화 수정: artifacts/weakening.json 의 deny. 되돌리거나 같은 강도로 다시 쓴다")
        if st.get("c-expect") == "fail":
            prof = r["params"].get("profile") or rules.DEFAULT_PROFILE
            names = " · ".join(f"{k} {'/'.join(rules.PROFILES[prof][k])}" for k in ("kem", "sig") if k in r["params"]["expect"])
            lines.append(f"  c-expect: EXPECT 로 요구한 PQC 가 고친 판 코드에 없다(프로필 {prof}" + (f": {names}" if names else "")
                         + "). 다른 크기를 쓰면 PROFILE 을 맞춘다")
        if st.get("r-allow") == "fail":
            lines.append("  r-allow: 허용 항목마다 사람이 읽고 reviewed_by·reviewed_at 을 적거나, 안 쓰인 항목을 지운다")
        if st.get("a-cbom") == "fail" or st.get("c-classic") == "fail":
            lines.append("  꼭 남겨야 하는 줄이면 허용 목록에 사유와 함께 적는다: 예시 "
                         + os.path.join(HERE, "examples", "allowlist", "unconverted.json") + ", 설명 " + doc_url("guide/allowlist.md"))
    elif r["verdict"] == "undecided":
        lines.append("다음 할 일: 미판정 까닭은 위 [검사] 줄에 있다(예: TLS 서버 신호가 있으면 TLS_TARGETS 로 주소를 준다). "
                     "미판정은 통과로 세지 않는다")
    return lines


# ---------------------------------------------------------------------------------------------
# 셀프 시험(오프라인). DESIGN.md 'Self-test' S1~S10.
# S1~S3은 examples/(직접 쓴 작은 예제: 고전 RSA·ECDSA 원본 ↔ ML-KEM·ML-DSA 전환본), S4·S5는 orders-edge 사본(ORDERS_EDGE,
# 비우면 tests/fixtures/orders-edge 스냅숏), S6은 tls_probe 참조 서버, S7은 S1 검증 증적 변조,
# S8은 허용 목록 가림(결함 D1, S8f 는 고친 판에서 지운 파일), S9는 시험 경로 기준 하나(결함 D2),
# S10은 본 소스 패키지 이름의 example(src/main/java/com/example). S8~S10 은 examples/ 만 쓴다.
# S11은 구현 검증(--impl): 참조판 KAT 발췌로 만든 최신판 답안 통과, 한 바이트 바꾼 답안 실패, 옛 판 답안 검토 필요, 증적 다시 확인.
#   S11d 는 --pq-verify 를 줬는데 pq-verify 실행 파일이 없으면 i-nist 가 미판정이고 KpqC 결과와 한 증적에 담기는지 본다(pq-verify 는 돌리지 않음).
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
    # S11 구현 검증(KpqC KAT 대조, 구현은 실행하지 않음). 답안은 발췌로 만든다(어느 판 구현이라면 낼 답, pqlite/impl.example_answers)
    m = impl.load_manifest()
    key = impl.build_key(m, ["smaug-t/mode1", "aimer/128f"])
    for tag, pick, edit, want in (("a", {"smaug-t/mode1": "1.2.0", "aimer/128f": "3.0"}, None, ("pass", 0, "pass")),
                                  ("b", {"smaug-t/mode1": "1.2.0", "aimer/128f": "3.0"}, "smaug-t/mode1@1.2.0#0:decaps", ("fail", 1, "fail")),
                                  ("c", {"smaug-t/mode1": "1.1.1", "aimer/128f": "aim2-2026-01"}, None, ("pass", 0, "review"))):
        resp = impl.example_answers(key, pick)
        if edit:
            resp["answers"][edit]["ss"] = impl._flip_hex(resp["answers"][edit]["ss"])
        ans = os.path.join(tmp, f"s11{tag}.json")
        spit(ans, impl.dumps(resp))
        r, code, _ = impl_judge(ans, [], Params({}, mode="impl"), os.path.join(tmp, f"s11{tag}"), quiet=True)
        vbad = [w for o, w in rc.verify(os.path.join(tmp, f"s11{tag}")) if not o]
        ok(f"S11{tag} 구현 검증 {'최신판 답안' if tag == 'a' else '한 바이트 바꾼 답안' if tag == 'b' else '옛 판 답안'} → "
           f"{STATUS_KO[want[2]]}, 증적 다시 확인 통과", (r["verdict"], code, r["checks"][0]["status"]) == want and not vbad
           and r["impl"]["control"]["ok"], json.dumps([r["verdict"], code, r["checks"][0]["actual"][:200], vbad[:2]], ensure_ascii=False))
    r, code, _ = impl_judge(os.path.join(tmp, "s11a.json"), [], Params({"PQ_VERIFY": os.path.join(tmp, "no-pq-verify")}, mode="impl"),
                            os.path.join(tmp, "s11d"), quiet=True, pq_verify="--audit-kem libmlkem768.so ML-KEM-768")
    vbad = [w for o, w in rc.verify(os.path.join(tmp, "s11d")) if not o]
    ok("S11d --pq-verify 인데 pq-verify 가 없음 → i-nist 미판정(건너뜀은 통과가 아님), KpqC 통과와 한 증적, 다시 확인 통과",
       ([c["status"] for c in r["checks"]], r["verdict"], code) == (["pass", "undecided"], "undecided", 3) and not vbad
       and not any(t["name"] == impl.PQV_NAME for t in r["tools"]), json.dumps([r["checks"][1]["actual"][:200], vbad[:2]], ensure_ascii=False))
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
    if argv[:1] == ["--impl"]:  # 구현 검증(KpqC KAT 대조): 표준 라이브러리만, bash·openssl 없이 돈다
        for w in env_warnings(os.environ):
            print(f"pqproof: 경고: {w}", file=sys.stderr)
        try:
            return impl_main(argv[1:])
        except UsageError as e:
            print(f"prove.sh: {e}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            return 130
        except Exception as e:  # noqa: BLE001  도구 오류는 판정 실패(1)와 가른다
            import traceback
            traceback.print_exc()
            print(f"pqproof: 도구 오류({type(e).__name__}: {str(e)[:200]}). 판정이 아니다(종료 {EXIT_TOOL_ERROR})", file=sys.stderr)
            return EXIT_TOOL_ERROR
    if argv[:1] in (["--check"], ["--inventory"]):
        if len(argv) != 2:
            print(f"사용: bash prove.sh {argv[0]} <폴더|zip>", file=sys.stderr)
            return 2
        argv = [argv[0], argv[1], argv[1]] if argv[0] == "--check" else argv
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[0] != "--check"):
        print("사용: bash prove.sh <원본 폴더|zip> <고친 폴더|zip>   (환경 변수는 prove.sh 머리 주석)", file=sys.stderr)
        return 2
    for w in env_warnings(os.environ):
        print(f"pqproof: 경고: {w}", file=sys.stderr)
    try:
        if argv[0] == "--inventory":
            return inventory(argv[1], Params())[1]
        if argv[0] == "--check":
            _, code, _ = run(argv[1], argv[2], Params(mode="check"))
            return code
        params = Params()
        _, code, _ = run(argv[0], argv[1], params)
        return code
    except UsageError as e:
        print(f"prove.sh: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001  도구 오류는 판정 실패(1)와 가른다(교차 리뷰 X62)
        import traceback
        traceback.print_exc()
        print(f"pqproof: 도구 오류({type(e).__name__}: {str(e)[:200]}). 판정이 아니다(종료 {EXIT_TOOL_ERROR}). "
              "https://github.com/g1mn/pqproof/issues 에 위 내용과 함께 알려 주면 고친다", file=sys.stderr)
        return EXIT_TOOL_ERROR


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
