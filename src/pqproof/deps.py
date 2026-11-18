# deps.py: PQ-Proof 가 실행 중에 부르는 바깥 도구를 미리 점검해 알기 쉬운 오류로 바꾼다. 표준 라이브러리만 쓴다.
# 꼭 있어야 하는 것: bash, grep·awk·sed·find 같은 기본 명령, openssl(3.5 이상 권장).
# 있으면 쓰는 것: JDK keytool(키스토어 .jks·.p12 읽기), tls_probe(TLS_TARGETS 실측), go 1.27+(tls_probe 빌드).
"""Check the external programs PQ-Proof calls at run time and turn a missing one into a clear message."""
import os
import platform
import re
import shutil
import subprocess
import zipfile

SHELL_TOOLS = ("grep", "awk", "sed", "find", "sort", "head", "tail", "tr", "cut", "uniq", "wc", "mktemp", "date")
KEYSTORE = re.compile(r"\.(?:jks|jceks|p12|pfx|keystore|bks)$", re.I)
# prove.py OPENSSL_CANDIDATES 와 같아야 한다(tests/test_rule_sync.py)
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


def probe_binary(bin_dir):
    system = platform.system().lower()
    arch = platform.machine().lower()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    path = os.path.join(bin_dir, f"tls_probe-{system}-{arch}")
    return path if os.path.isfile(path) and os.access(path, os.X_OK) else None


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


def check(env=None, inputs=(), bin_dir=None, need_tls=None):
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
    if probe:
        rep.info.append(f"tls_probe: {probe}")
    elif need_tls:
        rep.errors.append(f"TLS_TARGETS is set but no tls_probe binary for this machine in {bin_dir}. Either run `pqproof build-probe` "
                          "(needs Go 1.27 or later, no network), or download tls_probe-<os>-<arch> and SHA256SUMS from the GitHub release, "
                          "check them with `shasum -a 256 -c SHA256SUMS`, and set PROBE_BIN_DIR to that folder.")
    else:
        rep.optional.append("tls_probe: not found (optional, only for TLS_TARGETS live checks; pqproof build-probe)")
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
