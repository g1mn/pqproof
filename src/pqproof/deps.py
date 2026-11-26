# deps.py: PQ-Proof 가 실행 중에 부르는 바깥 도구를 미리 점검해 알기 쉬운 오류로 바꾼다. 표준 라이브러리만 쓴다.
# 꼭 있어야 하는 것: bash, grep·awk·sed·find 같은 기본 명령, openssl(3.5 이상 권장).
# 있으면 쓰는 것: JDK keytool(키스토어 .jks·.p12 읽기), tls_probe(TLS_TARGETS 실측), go 1.27+(tls_probe 빌드),
#   pq-verify(pqproof impl judge --pq-verify 의 NIST PQC 구현 감사. PQ_VERIFY 또는 PATH, 사용자가 따로 설치한다).
"""Check the external programs PQ-Proof calls at run time and turn a missing one into a clear message."""
import os
import platform
import re
import shutil
import subprocess
import zipfile

SHELL_TOOLS = ("grep", "awk", "sed", "find", "sort", "head", "tail", "tr", "cut", "uniq", "wc", "mktemp", "date")
KEYSTORE = re.compile(r"\.(?:jks|jceks|p12|pfx|keystore|bks)$", re.I)
OPENSSL_CANDIDATES = ("/opt/homebrew/opt/openssl@3.5/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl", "/opt/homebrew/bin/openssl",
                      "/usr/local/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl")


# OpenSSL 3.5 미만·LibreSSL 의 실제 영향(교차 리뷰 X68: 예전 문구는 ML-DSA 인증서를 못 읽는다고 했지만 cbom-scan.sh 는 OID 표로 읽는다)
OLD_OPENSSL_EFFECT = ("the scan still runs and names ML-KEM and ML-DSA keys and certificates from their OIDs. Two things are lost: the "
                      "OpenSSL TLS cross-check (recorded as not possible) and some key details in the CBOM notes. Set OPENSSL to "
                      "3.5 or later only if you need those.")


class Report:
    def __init__(self):
        self.errors, self.warnings, self.info, self.optional = [], [], [], []

    def ok(self):
        return not self.errors


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def openssl_version(path):
    code, out = _run([path, "version"])
    if code != 0:
        return None, out
    m = re.search(r"OpenSSL\s+([0-9]+)\.([0-9]+)\.([0-9]+)", out)
    return ((int(m[1]), int(m[2]), int(m[3])) if m else None), out.splitlines()[0] if out else ""


def find_openssl(env):
    """prove.py 와 같은 규칙: OPENSSL 을 주면 그것(3.5 미만이어도). 아니면 Homebrew 경로, PATH 에서 3.5 이상을 먼저 고른다."""
    given = env.get("OPENSSL")
    if given and os.path.isfile(given) and os.access(given, os.X_OK):
        ver, line = openssl_version(given)
        return given, ver, line
    seen = []
    for c in OPENSSL_CANDIDATES + (shutil.which("openssl"),):
        if c and c not in seen and os.path.isfile(c) and os.access(c, os.X_OK):
            seen.append(c)
    best = None
    for c in seen:
        ver, line = openssl_version(c)
        if ver and ver >= (3, 5, 0):
            return c, ver, line
        if best is None:
            best = (c, ver, line)
    return best if best else (None, None, "")


# pqlite/tlsprobe.py PROBE_VERSION 과 같아야 한다(tests/test_pqproof_pkg.py). 이 패키지는 pqlite 를 들여오지 않는다
PROBE_VERSION = "0.6.0"


def probe_version(path):
    """바이너리가 'tls_probe version' 에 찍는 판, 못 읽으면 None."""
    _, out = _run([path, "version"])
    m = re.match(r"tls_probe (\S+)", out)
    return m[1] if m else None


def probe_binary(bin_dir):
    system = platform.system().lower()
    arch = platform.machine().lower()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    path = os.path.join(bin_dir, f"tls_probe-{system}-{arch}")
    return path if os.path.isfile(path) and os.access(path, os.X_OK) else None


PQV_NAME = "pq-verify"
# pq-verify 를 부를 때 뺄 환경 변수
PQV_ENV_DROP_PREFIX = ("PQV_", "LD_", "DYLD_")
PQV_ENV_DROP = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT")


def find_pqverify(env, run_version=True):
    """prove.py pqverify_exe 와 같은 규칙: PQ_VERIFY 를 주면 그것(실행 파일이 아니면 None), 아니면 PATH 의 pq-verify. 반환 (경로 또는 None, 판).
    run_version=False 면 --version 을 돌리지 않고 찾기만 한다(판은 '')."""
    given = (env.get("PQ_VERIFY") or "").strip()
    if given:
        path = given if os.path.isfile(given) and os.access(given, os.X_OK) else None
    else:
        path = shutil.which(PQV_NAME, path=env.get("PATH"))
    if not path or not run_version:
        return path or None, ""
    # prove.py 가 감사 때 넘기는 환경과 같은 규칙으로 뺀다(pqlite/impl.py pqverify_env): PQV_*·LD_*·DYLD_*·PYTHONPATH 등
    clean = {k: v for k, v in env.items() if not k.startswith(PQV_ENV_DROP_PREFIX) and k not in PQV_ENV_DROP}
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, errors="replace", timeout=60, stdin=subprocess.DEVNULL,
                           env=clean)
        code, out = r.returncode, r.stdout + r.stderr
    except (OSError, subprocess.TimeoutExpired):
        code, out = None, ""
    m = re.search(r"\bpq-verify\s+([0-9][0-9A-Za-z.+-]*)", out)
    return path, (m[1] if code == 0 and m else "")


def has_keystores(inputs, limit=20000):
    """입력 폴더·zip 안에 키스토어 파일이 있는지 이름만 본다(여는 일 없음)."""
    seen = 0
    for p in inputs:
        if os.path.isdir(p):
            for _, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "target", "build", ".venv", "venv")]
                for f in files:
                    seen += 1
                    if KEYSTORE.search(f):
                        return True
                    if seen > limit:
                        return False
        elif os.path.isfile(p) and zipfile.is_zipfile(p):
            try:
                with zipfile.ZipFile(p) as z:
                    if any(KEYSTORE.search(n) for n in z.namelist()[:limit]):
                        return True
            except zipfile.BadZipFile:
                pass
    return False


def check(env=None, inputs=(), bin_dir=None, need_tls=None, need_pqverify=None):
    """바깥 도구 점검(Report). need_pqverify: None 이면 pq-verify 를 보지 않는다(트리 판정은 쓰지 않는다), False 면 있는지·판만 적고(doctor),
    True 면 --pq-verify 를 준 실행이라 없을 때 경고한다(판정은 i-nist 미판정으로 남고 실행은 막지 않는다)."""
    env = os.environ if env is None else env
    rep = Report()
    if os.name == "nt":  # Git Bash·Cygwin 의 bash 가 PATH 에 있어도 경로·OpenSSL 이 달라 엉뚱하게 실패한다
        rep.errors.append("Windows: judge inside WSL (Ubuntu) or a Linux container. pqproof --verify and pqproof sarif work "
                          "here with Python alone.")
        return rep
    if not shutil.which("bash"):
        rep.errors.append("bash not found. PQ-Proof runs its scanners (cbom-scan.sh, residue.sh) with bash 3.2 or later.")
    missing = [t for t in SHELL_TOOLS if not shutil.which(t)]
    if missing:
        rep.errors.append(f"basic commands not found: {', '.join(missing)}. The scanners need them (grep, awk, sed, find ...).")
    path, ver, line = find_openssl(env)
    if not path:
        rep.errors.append("openssl not found. Install OpenSSL (3.5 or later recommended) or set OPENSSL=/path/to/openssl. "
                          "macOS: brew install openssl@3. Debian/Ubuntu: apt install openssl.")
    elif not ver:
        rep.warnings.append(f"{path} is not OpenSSL ({line}), which works like OpenSSL below 3.5: " + OLD_OPENSSL_EFFECT)
    elif ver < (3, 5, 0):
        rep.warnings.append(f"OpenSSL {'.'.join(map(str, ver))} at {path}: below 3.5. " + OLD_OPENSSL_EFFECT)
    else:
        rep.info.append(f"openssl: {path} ({line})")
    kt = shutil.which("keytool") or (os.path.join(env["JAVA_HOME"], "bin", "keytool") if env.get("JAVA_HOME") else None)
    if kt and os.path.isfile(kt):
        rep.info.append(f"keytool: {kt}")
    elif inputs and has_keystores(inputs):
        rep.warnings.append("keystore files (.jks, .p12 ...) are in the input but keytool (JDK) was not found: they will be listed as "
                            "'not checked' instead of read. Install a JDK or set JAVA_HOME.")
    else:
        rep.optional.append("keytool: not found (optional, only for .jks/.p12 keystores)")
    if need_tls is None:
        need_tls = bool((env.get("TLS_TARGETS") or "").strip() or (env.get("TLS_TARGETS_ORIG") or "").strip())
    probe = probe_binary(bin_dir) if bin_dir else None
    got = probe_version(probe) if probe else None
    if probe and got != PROBE_VERSION:
        # 캐시·PROBE_BIN_DIR 의 바이너리는 도구를 올려도 남는다. 0.5.0 은 CA 없는 대상(시스템 신뢰 저장소)을 사용법 오류로 끝낸다
        msg = (f"tls_probe at {probe} is version {got or 'unknown'}, but this PQ-Proof needs {PROBE_VERSION}. Rebuild it with "
               "`pqproof build-probe` (from a clone: bash build-probe.sh), or replace the binaries in PROBE_BIN_DIR with the "
               "release assets of this version.")
        (rep.errors if need_tls else rep.warnings).append(msg)
    elif probe:
        rep.info.append(f"tls_probe: {probe} ({got})")
    elif need_tls:
        rep.errors.append(f"TLS_TARGETS is set but no tls_probe binary for this machine in {bin_dir}. Either run `pqproof build-probe` "
                          "(needs Go 1.27 or later, no network), or download tls_probe-<os>-<arch> and SHA256SUMS from the GitHub release, "
                          "check them with `shasum -a 256 -c --ignore-missing SHA256SUMS`, and set PROBE_BIN_DIR to that folder.")
    else:
        rep.optional.append("tls_probe: not found (optional, only for TLS_TARGETS live checks; pqproof build-probe)")
    if need_pqverify is not None:
        pqv_line(rep, env, need_pqverify)
    return rep


def pqv_line(rep, env, need=False, run_version=True):
    """pq-verify 줄: 있으면 경로와 판(info), 없으면 선택 의존(optional) 또는 --pq-verify 를 줬을 때 경고. run_version=False 면 실행하지 않고
    찾기만 한다(pqproof impl judge 의 미리 알림: 인자 검사 전에 pq-verify 를 띄우지 않는다)."""
    path, ver = find_pqverify(env, run_version)
    if path:
        rep.info.append(f"pq-verify: {path} ({'pq-verify ' + ver if ver else 'version unknown'}; runs the library it audits, "
                        "use a container or VM for untrusted code)")
    elif need:
        rep.warnings.append("--pq-verify is given but pq-verify was not found (PQ_VERIFY or PATH): i-nist will be undecided. "
                            "Install it apart from PQ-Proof in its own virtual environment, pinned by version and wheel hash "
                            "(guide/impl.md, .github/requirements/pq-verify.txt), and set PQ_VERIFY.")
    else:
        rep.optional.append("pq-verify: not found (optional, only for pqproof impl judge --pq-verify; set PQ_VERIFY or put it on PATH)")
    return rep


def go_ok():
    go = shutil.which("go")
    if not go:
        return None, "go not found"
    code, out = _run([go, "version"])
    m = re.search(r"go([0-9]+)\.([0-9]+)", out)
    if code != 0 or not m:
        return None, out
    return (int(m[1]), int(m[2])) >= (1, 27), out
