# cli.py: 콘솔 명령 pqproof. `bash prove.sh` 와 같은 동작을 하고, 하위 명령 sarif·doctor·build-probe·mutations 를 더한다.
#   pqproof <원본 폴더|zip> <고친 폴더|zip>     환경 변수(OUT, ALLOW, REQUIRE_REVIEW, TLS_TARGETS ...)는 prove.sh 와 같다
#   pqproof --verify <결과 폴더> · pqproof --unit [이름] · pqproof --selftest
#   pqproof sarif <결과 폴더> [-o 파일] [--uri-prefix P] [--anchor 파일]
#   pqproof doctor          바깥 도구 점검표(bash, openssl, keytool, tls_probe, go)
#   pqproof build-probe     tls_probe 를 사용자 캐시 폴더에 빌드(Go 1.27+, 인터넷 없음)
#   pqproof mutations [--strict]   심어 둔 결함 시험 묶음
# 도구 본체는 패키지 데이터 pqproof/_tool(설치본) 또는 저장소 루트(소스에서 실행)에서 찾는다. PQPROOF_HOME 으로 바꿀 수 있다.
# prove.sh 는 이 파이썬(sys.executable)으로 돌게 PYTHON 을 넘긴다. 판정 출력의 다시 확인 안내가 pqproof 로 나오게 PQPROOF_ENTRY 도 넘긴다.
# 재검증(--verify)·--version·sarif·--env 는 bash 없이 이 파이썬으로만 돈다(Windows 에서도). 스캔·시험은 bash·grep·awk·OpenSSL 이
# 있어야 해서 Windows 에서는 WSL 안내 뒤 2로 끝낸다.
"""Console entry point: `pqproof` behaves like `bash prove.sh`, plus sarif, doctor, build-probe and mutations."""
import os
import subprocess
import sys

from pqproof import __version__
from pqproof import deps

USAGE = """usage:
  pqproof <original dir|zip> <converted dir|zip>   judge both trees, write the evidence folder (env vars as in prove.sh)
  pqproof --verify <out dir>                       re-check an evidence folder (schema, receipt_id, file hashes, HTML)
  pqproof --unit [name]                            unit tests (standard library unittest)
  pqproof --selftest                               offline self-test on the bundled examples
  pqproof sarif <out dir> [-o file] [--uri-prefix path/] [--anchor file] [--lang en|ko]
  pqproof doctor                                   list the external programs PQ-Proof uses and what is missing
  pqproof build-probe                              build tls_probe into the user cache (Go 1.27+, offline)
  pqproof mutations [--strict] [--only ids]        planted-defect suite
  pqproof --version | --help | --env               (--env prints the environment variables prove.sh reads)
exit codes: 0 pass, 1 fail, 2 usage or input error, 3 undecided, 4 tool error, 5 pass with checks that need review
(only with FAIL_ON_REVIEW=1). A skipped check is never counted as passed.
--verify, sarif, --env and --version need only Python; judging needs bash, grep, awk and OpenSSL (on Windows, use WSL)."""

WINDOWS = ("pqproof: judging two trees runs bash, grep, awk and OpenSSL, so on Windows run it inside WSL: `wsl --install`, then "
           "`pip install pqproof` in the Ubuntu shell. Re-checking evidence works here without WSL: pqproof --verify <folder>, "
           "pqproof sarif <folder>.")


def is_windows():
    return os.name == "nt"


def env_help(root):
    """prove.sh 머리 주석(둘째 줄부터 첫 비주석 줄 앞까지). bash 없이 읽는다."""
    lines = []
    with open(os.path.join(root, "prove.sh"), encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i == 0:
                continue
            if not line.startswith("#"):
                break
            lines.append(line.rstrip("\n"))
    return "\n".join(lines)


def version_line():
    """'pqproof 0.1.0 (ruleset 1, evidence format 2)'. 규칙 묶음·증적 형식은 도구 파일의 pqlite/version.py 가 안다."""
    root = tool_root()
    path = os.path.join(root, "pqlite", "version.py") if root else None
    if path and os.path.isfile(path):
        import importlib.util
        spec = importlib.util.spec_from_file_location("pqproof_tool_version", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        current, _ = mod.ruleset_history()
        return f"pqproof {__version__} (ruleset {current or 'unknown'}, evidence format {mod.FORMAT_VERSION})"
    return f"pqproof {__version__}"


def tool_root():
    """prove.sh 가 있는 폴더: PQPROOF_HOME → 패키지 데이터 → 저장소 루트."""
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.environ.get("PQPROOF_HOME"), os.path.join(here, "_tool"), os.path.dirname(os.path.dirname(here))):
        if c and os.path.isfile(os.path.join(c, "prove.sh")):
            return c
    return None


def cache_bin():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "pqproof", "bin")


def probe_dir(root):
    """PROBE_BIN_DIR → <root>/bin(소스 실행) → 사용자 캐시. 바이너리가 있는 첫 곳, 없으면 캐시."""
    if os.environ.get("PROBE_BIN_DIR"):
        return os.environ["PROBE_BIN_DIR"]
    for c in (os.path.join(root, "bin"), cache_bin()):
        if deps.probe_binary(c):
            return c
    return cache_bin()


def child_env(root, entry=False):
    """prove.sh 에 넘길 환경. entry 면 PQPROOF_ENTRY=pqproof(판정 출력의 다시 확인 안내가 pqproof 로 나오게, 판정 실행에만)."""
    env = dict(os.environ)
    env.setdefault("PYTHON", sys.executable)
    env["PROBE_BIN_DIR"] = probe_dir(root)
    if entry:
        env["PQPROOF_ENTRY"] = "pqproof"
    else:
        env.pop("PQPROOF_ENTRY", None)
    return env


def run(cmd, env):
    try:
        return subprocess.call(cmd, env=env)
    except KeyboardInterrupt:
        return 130
    except OSError as e:
        print(f"pqproof: cannot start {cmd[0]}: {e}", file=sys.stderr)
        return 2


def preflight(root, inputs=(), quiet=False):
    rep = deps.check(inputs=inputs, bin_dir=probe_dir(root))
    for w in rep.warnings:
        if not quiet:
            print(f"pqproof: warning: {w}", file=sys.stderr)
    for e in rep.errors:
        print(f"pqproof: {e}", file=sys.stderr)
    return rep.ok()


def doctor(root):
    rep = deps.check(bin_dir=probe_dir(root), need_tls=False)
    print(f"PQ-Proof {__version__}")
    print(f"tool: {root}")
    print(f"python: {sys.executable} ({sys.version.split()[0]})")
    for line in rep.info:
        print(f"  ok    {line}")
    for line in rep.optional:
        print(f"  info  {line}")
    for line in rep.warnings:
        print(f"  warn  {line}")
    for line in rep.errors:
        print(f"  MISSING {line}")
    ok, line = deps.go_ok()
    print(f"  {'ok   ' if ok else 'info '} go: {line} {'(can build tls_probe)' if ok else '(only needed for pqproof build-probe)'}")
    return 0 if rep.ok() else 2


def build_probe(root):
    ok, line = deps.go_ok()
    if not ok:
        print(f"pqproof: build-probe needs Go 1.27 or later (crypto/mldsa). Found: {line}", file=sys.stderr)
        print("  Or download tls_probe-<os>-<arch> and SHA256SUMS from the GitHub release, run `shasum -a 256 -c --ignore-missing SHA256SUMS` in that folder, "
              "and set PROBE_BIN_DIR to that folder.", file=sys.stderr)
        return 2
    env = dict(os.environ)
    env["PROBE_BIN_DIR"] = os.environ.get("PROBE_BIN_DIR") or cache_bin()
    os.makedirs(env["PROBE_BIN_DIR"], exist_ok=True)
    return run(["bash", os.path.join(root, "build-probe.sh")], env)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    first = argv[0] if argv else ""
    if first in ("-h", "--help", ""):
        print(USAGE)
        return 0 if first else 2
    if first in ("-V", "--version"):
        print(version_line())
        return 0
    if first == "sarif":
        from pqproof import sarif
        return sarif.main(argv[1:])
    root = tool_root()
    if not root:
        print("pqproof: the tool files (prove.sh, prove.py, pqlite/, scan/) are missing from this install. "
              "Reinstall the package or set PQPROOF_HOME to a PQ-Proof checkout.", file=sys.stderr)
        return 2
    if first == "--env":
        print(env_help(root))
        return 0
    if first == "--verify":
        if len(argv) != 2:
            print("usage: pqproof --verify <out dir>", file=sys.stderr)
            return 2
        return run([sys.executable, "-I", "-B", os.path.join(root, "pqlite", "receipt.py"), "verify", argv[1]], dict(os.environ))
    if is_windows():
        print(WINDOWS, file=sys.stderr)
        return 2
    prove = ["bash", os.path.join(root, "prove.sh")]
    if first == "doctor":
        return doctor(root)
    if first == "build-probe":
        return build_probe(root)
    if first == "mutations":
        runner = os.path.join(root, "tests", "mutations", "run_mutations.py")
        if not os.path.isfile(runner):
            print("pqproof: tests/mutations is not in this install", file=sys.stderr)
            return 2
        if not preflight(root):
            return 2
        sarif_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sarif.py")
        cmd = f'bash "{os.path.join(root, "prove.sh")}"'
        return run([sys.executable, "-I", "-B", runner, "--root", root, "--sarif", sarif_py, "--cmd", cmd] + argv[1:], child_env(root))
    if first in ("--unit", "--selftest"):
        if not preflight(root):
            return 2
        return run(prove + argv, child_env(root))
    if first.startswith("-"):
        print(f"pqproof: unknown option {first}\n{USAGE}", file=sys.stderr)
        return 2
    if len(argv) != 2:
        print("usage: pqproof <original dir|zip> <converted dir|zip>   (pqproof --help)", file=sys.stderr)
        return 2
    if not preflight(root, inputs=argv):
        return 2
    return run(prove + argv, child_env(root, entry=True))


if __name__ == "__main__":
    sys.exit(main())
