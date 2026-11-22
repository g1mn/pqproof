# from g1mn/pq-proof 7b7803f (MIT)
# 수정: prove.py에서 순수 함수만(Handshake, parse, control_problem, 상수, connect·serve argv, source_sha256) 가져오고
#       microVM 세션 함수(build_probe·install_probe·verify_probe·listeners·controls·probe_target)는 버렸다.
#       대신 맥(host)과 컨테이너 이름공간(container:<이름>) 두 실행기를 새로 썼다. parse는 cert_sig·cert_key·trust 줄도 읽는다.
"""고정 버전 TLS 탐침(tls_probe)을 돌리고 출력을 읽는다. 양성·음성 대조가 성립할 때만 대상 판정이 유효하다.

- 양성 대조: 같은 자리(맥 또는 대상 컨테이너의 네트워크 이름공간)에 띄운 참조 서버(X25519MLKEM768,X25519)에
  X25519MLKEM768만 제시하면 X25519MLKEM768로 붙어야 한다.
- 음성 대조: X25519 전용 참조 서버에 X25519MLKEM768만 제시하면 실패하고, X25519,P-256을 제시하면 X25519로 붙어야 한다.
  늘 하이브리드라고 답하는 가짜 탐침은 여기서 걸린다.
판정은 탐침 출력의 `key: value` 줄로만 한다. parse()는 `openssl s_client` 출력도 읽어 OpenSSL 3.5로 교차 확인한다.
- 하이브리드: "Negotiated TLS1.3 group: X25519MLKEM768"
- 고전: "Negotiated TLS1.3 group" 줄 없이 "Peer Temp Key: X25519, 253 bits"
- 실패: 경고(alert)와 "Cipher is (NONE)". 그때의 "Negotiated TLS1.3 group NID: 0"은 그룹이 아니다.
"""
from __future__ import annotations  # 맥 기본 python3 3.9에서 str | None 주석이 돌게
import hashlib
import os
import pathlib
import platform
import re
import socket
import subprocess
import time
from dataclasses import asdict, dataclass

PROBE_NAME = "tls_probe"
PROBE_VERSION = "0.5.0"
HERE = pathlib.Path(__file__).resolve().parent.parent
PROBE_SRC = HERE / "probe"
BIN_DIR = pathlib.Path(os.environ.get("PROBE_BIN_DIR") or HERE / "bin")  # build-probe.sh 와 같은 PROBE_BIN_DIR
HYBRID_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
OFFER_HYBRID = "X25519MLKEM768"  # 하이브리드만 아는 클라이언트: 붙으면 ML-KEM으로 협상한 것
OFFER_CLASSICAL = "X25519,P-256"  # ML-KEM 이전 클라이언트
NEGATIVE_GROUPS = "X25519"
REFERENCE_POSITIVE = f"{OFFER_HYBRID},X25519"


@dataclass(frozen=True)
class Handshake:
    ok: bool
    group: str | None
    protocol: str | None
    error: str | None
    client: str  # tls_probe | openssl
    cert_sig: str | None = None
    cert_key: str | None = None
    trust: str | None = None
    cipher: str | None = None  # 0.5.0 탐침부터(옛 출력·openssl 은 None)
    cert_not_after: str | None = None  # 잎 인증서 만료 시각(RFC 3339 UTC), 국정원 가이드북 초안 G7

    @property
    def kind(self):
        """hybrid, classical 또는 failed."""
        if not self.ok:
            return "failed"
        return "hybrid" if self.group in HYBRID_GROUPS else "classical"

    def to_json(self):
        return dict(asdict(self), kind=self.kind)


def _field(text, name):
    m = re.search(rf"^{name}:[ \t]*(.*?)[ \t]*$", text, re.M)
    return m[1] if m else None


def parse(text):
    """tls_probe connect 출력이나 openssl s_client 출력에서 Handshake."""
    text = str(text)
    result = _field(text, "result")
    if result is not None:
        ok = result == "connected"
        return Handshake(ok=ok, group=_field(text, "group") if ok else None, protocol=_field(text, "protocol") if ok else None,
                         error=None if ok else (_field(text, "error") or "handshake failed"), client="tls_probe",
                         cert_sig=_field(text, "cert_sig") if ok else None, cert_key=_field(text, "cert_key") if ok else None,
                         trust=_field(text, "trust"), cipher=_field(text, "cipher") if ok else None,
                         cert_not_after=_field(text, "cert_not_after") if ok else None)
    cipher = re.search(r"^(?:New|Reused), (\S+), Cipher is (\S+)", text, re.M)
    alert = re.search(r"^.*alert.*$", text, re.M | re.I)
    if not cipher or cipher[2] == "(NONE)":
        err = alert[0].strip() if alert else "no cipher negotiated"
        return Handshake(ok=False, group=None, protocol=None, error=err, client="openssl")
    group = re.search(r"^Negotiated TLS1\.3 group: (\S+)[ \t]*$", text, re.M)
    if not group:  # classical groups are reported only as the peer's temporary key
        group = re.search(r"^(?:Peer|Server) Temp Key: ([^,\s]+)", text, re.M)
    proto = re.search(r"^\s*Protocol\s*:\s*(\S+)", text, re.M)
    sig = re.search(r"^Peer signature type: (\S+)", text, re.M)
    return Handshake(ok=True, group=group[1] if group else None, protocol=proto[1] if proto else cipher[1],
                     error=None, client="openssl", cert_sig=sig[1] if sig else None, cipher=cipher[2])


def control_problem(results):
    """대조가 성립하지 않는 이유, 성립하면 None. results: {'positive': (Handshake, 원문), 'negative_hybrid': ..., 'negative_classical': ...}"""
    (pos, pr), (neg, nr), (cls, cr) = results["positive"], results["negative_hybrid"], results["negative_classical"]
    if pos.kind != "hybrid" or pos.group != OFFER_HYBRID:
        return f"양성 대조 실패(참조 서버에서 {OFFER_HYBRID}가 나와야 한다):\n{pr}"
    if neg.kind != "failed":
        return f"음성 대조 실패(하이브리드 전용 클라이언트가 X25519 전용 참조 서버에 붙었다고 함, 이 자리의 탐침 출력은 믿을 수 없다):\n{nr}"
    if cls.kind != "classical" or cls.group != NEGATIVE_GROUPS:
        return f"음성 대조 실패(고전 X25519 핸드셰이크가 나와야 한다):\n{cr}"
    return None


def target_verdict(hybrid, classical, classic="allow", group=OFFER_HYBRID):
    """대상 하나의 판정: (통과 여부, 이유 목록). hybrid·classical은 Handshake. group: 홀로 제시한 하이브리드 그룹(PROFILE 이 정한다,
    기본 X25519MLKEM768, cnsa2 는 SecP384r1MLKEM1024. 교차 리뷰 X11)."""
    why = []
    if hybrid.group != group:
        why.append(f"하이브리드 전용 제시에 {group}가 아님({hybrid.group or hybrid.error})")
    elif (hybrid.protocol or "").replace(" ", "").replace("v", "") != "TLS1.3":  # "TLS 1.3"(Go), "TLSv1.3"(OpenSSL)
        why.append(f"프로토콜이 TLS 1.3이 아님({hybrid.protocol})")
    if classic == "allow" and classical.kind != "classical":
        why.append(f"옛 클라이언트(X25519,P-256) 접속이 고전 그룹이 아님({classical.group or classical.error})")
    if classic == "deny" and classical.kind != "failed":
        why.append(f"옛 클라이언트(X25519,P-256)가 붙었다({classical.group}), CLASSIC=deny")
    return not why, why


def source_sha256(src=PROBE_SRC):
    h = hashlib.sha256()
    for p in sorted(pathlib.Path(src).rglob("*")):
        if p.is_file() and not p.is_symlink():
            h.update(p.relative_to(src).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


# 릴리스 빌드의 tls_probe 해시(교차 리뷰 X47). 릴리스 작업이 같은 실행에서 만든 SHA256SUMS 를 휠·sdist 에 이 이름으로 넣는다. 소스 저장소에는
# 없다(그때 탐침은 '릴리스 해시 없음'). 실행할 때 바이너리 해시가 이 목록과 맞으면 '릴리스 빌드', 다르면 '릴리스 빌드 아님'으로 증적과 b-tls 에 적는다
RELEASE_SUMS = pathlib.Path(__file__).with_name("tls_probe-release.sha256")


def release_sums(path=RELEASE_SUMS):
    """{바이너리 이름: sha256}. 'sha256  이름' 줄(shasum 꼴). 파일이 없으면 {}."""
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError:
        return {}
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(\S+)", line.strip())
        if m:
            out[m[2].rsplit("/", 1)[-1]] = m[1]
    return out


def provenance(binary, sha, sums=None):
    """탐침 바이너리의 출처 표시: release(릴리스 해시와 같음) · local(다름, 직접 빌드했거나 바뀐 파일) · unchecked(릴리스 해시 목록 없음)."""
    sums = release_sums() if sums is None else sums
    if not sums:
        return "unchecked"
    return "release" if sums.get(pathlib.Path(binary).name) == sha else "local"


PROVENANCE_KO = {"release": "릴리스 빌드(해시 일치)", "local": "릴리스 빌드 아님(직접 빌드했거나 바뀐 바이너리, 사람이 확인)",
                 "unchecked": "릴리스 해시 목록 없음(소스에서 실행)"}


def host_binary():
    """이 맥(또는 리눅스)에서 돌 tls_probe 바이너리 경로."""
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}.get(platform.machine())
    if not system or not arch:
        raise RuntimeError(f"tls_probe 바이너리가 없는 플랫폼: {platform.system()} {platform.machine()}")
    return BIN_DIR / f"{PROBE_NAME}-{system}-{arch}"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def connect_args(target, groups, ca=None, tofu=None, servername="localhost", wait="10s"):
    trust = f"-ca={ca}" if ca else f"-tofu={tofu}"
    return ["connect", f"-groups={groups}", trust, f"-servername={servername}", f"-wait={wait}", target]


def serve_args(addr, groups, cert, key):
    return ["serve", f"-addr={addr}", f"-groups={groups}", f"-cert={cert}", f"-key={key}"]


class HostRunner:
    """맥에서 바로 돈다. TLS 폴더(tls_dir)는 그대로 경로를 쓴다."""
    via = "host"

    def __init__(self, tls_dir, binary=None, log=None):
        self.tls_dir, self.binary = str(tls_dir), str(binary or host_binary())
        self.log = log if log is not None else []
        self.servers = []

    def path(self, *parts):
        return os.path.join(self.tls_dir, *parts)

    def argv(self, args):
        return [self.binary, *args]

    def run(self, args, timeout=60):
        argv = self.argv(args)
        t = time.time()
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
            out = (r.returncode, r.stdout, r.stderr)
        except subprocess.TimeoutExpired as e:
            out = (None, e.stdout or "", f"timeout after {timeout}s")
        self.log.append({"argv": argv, "exit_code": out[0], "stdout": out[1], "stderr": out[2], "t": t})
        return out

    def ref_addr(self):
        return f"127.0.0.1:{free_port()}"

    def start(self, args):
        argv = self.argv(args)
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        self.servers.append(p)
        self.log.append({"argv": argv, "exit_code": None, "stdout": "", "stderr": "(background)", "t": time.time()})
        return p

    def stop(self):
        for p in self.servers:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        self.servers = []


class ContainerRunner(HostRunner):
    """대상 컨테이너의 네트워크 이름공간(--network container:<이름>)에서 분리 컨테이너로 돈다. 대상 컨테이너에는 파일을
    넣지 않는다. 이미지는 대상 컨테이너가 쓰는 이미지(이미 맥에 있다, 내려받기 없음)이고 진입점만 정적 바이너리로 바꾼다."""
    via = "container"

    def __init__(self, tls_dir, container, docker="docker", log=None, inspect=None):
        super().__init__(tls_dir, binary="/p/tls_probe", log=log)
        self.container, self.docker = container, docker
        info = inspect or self._inspect()
        self.image, self.arch = info["image"], info["arch"]
        self.names, self.n = [], 0

    def _inspect(self):
        image = subprocess.run([self.docker, "inspect", "-f", "{{.Image}}", self.container], capture_output=True, text=True,
                               timeout=30)
        if image.returncode != 0:
            raise RuntimeError(f"docker inspect {self.container} 실패: {image.stderr.strip()}")
        img = image.stdout.strip()
        arch = subprocess.run([self.docker, "image", "inspect", "-f", "{{.Architecture}}", img], capture_output=True,
                              text=True, timeout=30).stdout.strip()
        return {"image": img, "arch": {"aarch64": "arm64", "x86_64": "amd64"}.get(arch, arch)}

    def path(self, *parts):
        return "/t/" + "/".join(parts)

    def _docker(self, extra, args):
        # --pull=never: 이미지가 맥에 없으면 내려받지 말고 실패한다(오프라인 보장)
        return [self.docker, "run", *extra, "--network", f"container:{self.container}", "--user", "0:0", "--pull=never",
                "-v", f"{BIN_DIR}:/b:ro", "-v", f"{self.tls_dir}:/t",
                "--entrypoint", f"/b/{PROBE_NAME}-linux-{self.arch}", self.image, *args]

    def argv(self, args):
        return self._docker(["--rm"], args)

    def ref_addr(self):
        self.n += 1
        return f"127.0.0.1:{44300 + (os.getpid() % 500) * 2 + self.n}"

    def start(self, args):
        name = f"pqcproof-ref-{os.getpid()}-{len(self.names) + 1}"
        argv = self._docker(["-d", "--name", name], args)
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.names.append(name)
        self.log.append({"argv": argv, "exit_code": r.returncode, "stdout": r.stdout, "stderr": r.stderr, "t": time.time()})
        return name

    def stop(self):
        for name in self.names:  # 이 실행이 띄운 pqcproof-ref-* 컨테이너만 내린다
            argv = [self.docker, "rm", "-f", name]
            r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            self.log.append({"argv": argv, "exit_code": r.returncode, "stdout": r.stdout, "stderr": r.stderr, "t": time.time()})
        self.names = []


def references(runner, cert_runner):
    """참조 서버 두 개(양성: 하이브리드+X25519, 음성: X25519 전용)를 띄우고 대조 세 번을 돌린다.
    cert_runner는 맥에서 인증서를 만드는 HostRunner(컨테이너 모드여도 인증서는 맥에서 만든다).
    반환: (results, problem, addrs)"""
    os.makedirs(os.path.join(runner.tls_dir, "ref"), exist_ok=True)
    rc, out, err = cert_runner.run(["cert", "-hosts=localhost,127.0.0.1", os.path.join(runner.tls_dir, "ref")])
    if rc != 0:
        return None, f"참조 인증서를 못 만듦: {err.strip()}", {}
    ca, cert, key = runner.path("ref", "ca.pem"), runner.path("ref", "cert.pem"), runner.path("ref", "key.pem")
    pos, neg = runner.ref_addr(), runner.ref_addr()
    while neg == pos:
        neg = runner.ref_addr()
    runner.start(serve_args(pos, REFERENCE_POSITIVE, cert, key))
    runner.start(serve_args(neg, NEGATIVE_GROUPS, cert, key))
    results = {}
    for name, addr, groups in (("positive", pos, OFFER_HYBRID), ("negative_hybrid", neg, OFFER_HYBRID),
                               ("negative_classical", neg, OFFER_CLASSICAL)):
        rc, out, err = runner.run(connect_args(addr, groups, ca=ca))
        results[name] = (parse(out), out + err)
    return results, control_problem(results), {"positive": pos, "negative": neg}


def probe_target(runner, target, servername="localhost", ca=None, label="t", hybrid_group=OFFER_HYBRID):
    """대상 하나에 하이브리드 전용·옛 클라이언트 두 번 접속. ca가 없으면 -tofu(처음 받은 사슬의 마지막 인증서를 믿고 다시 검증)."""
    out = {}
    for name, groups in (("hybrid", hybrid_group), ("classical", OFFER_CLASSICAL)):
        tofu = None if ca else runner.path(f"{label}-{name}-tofu-ca.pem")
        rc, so, se = runner.run(connect_args(target, groups, ca=ca, tofu=tofu, servername=servername))
        out[name] = (parse(so), so + se, rc)
    return out


def openssl_cross_check(openssl, target, servername, ca, group=OFFER_HYBRID, timeout=20):
    """OpenSSL 3.5 s_client로 같은 대상에 하이브리드만 제시(맥 모드에서만). 반환: (Handshake, argv, 원문)"""
    argv = [openssl, "s_client", "-connect", target, "-servername", servername, "-groups", group, "-tls1_3"]
    if ca:
        argv += ["-CAfile", ca, "-verify_return_error"]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        raw = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        raw = "timeout"
    return parse(raw), argv, raw
