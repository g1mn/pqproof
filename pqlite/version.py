# version.py: 버전 세 가지를 한곳에서 읽는다(표준 라이브러리만).
#   도구 버전(tool_version)   : src/pqproof/__init__.py 의 __version__ 한 곳(pyproject 는 동적으로 읽고, prove.sh --version 도 여기서 읽는다)
#   규칙 묶음(ruleset)        : 판정을 정하는 규칙 파일 여섯의 해시 묶음. 버전 이름과 해시의 짝은 scan/ruleset.json 에 적는다
#   증적 형식(format_version) : receipt.json 의 꼴. 이 칸이 없는 옛 증적은 형식 1로 읽는다(pqlite/receipt.py 가 계속 읽는다)
# 규칙 파일을 고치면 해시가 바뀐다. 그때는 scan/ruleset.json 에 새 버전 이름과 해시를 더하고 current 를 옮기며, CHANGELOG 의
# '판정 영향' 칸에 적는다(tests/test_versioning.py 가 짝이 안 맞으면 실패한다).
#   python3 -I -B pqlite/version.py            → "pqproof 0.1.0 (ruleset 1, evidence format 2)"
#   python3 -I -B pqlite/version.py --ruleset  → 지금 규칙 파일로 계산한 ruleset_sha256
"""Tool version, ruleset version and hash, and evidence format version for PQ-Proof."""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 저장소 루트, 또는 설치본의 pqproof/_tool
FORMAT_VERSION = 2   # 이 도구가 쓰는 증적 형식
FORMAT_READS = (1, 2)  # 이 도구가 --verify 로 읽는 형식(1 = format_version 칸이 없는 0.1.0 이전 공개본 증적)
# 규칙 묶음에 드는 파일: (저장소 경로, receipt.json tools[] 의 name). 탐지 패턴, 시험 경로, 허용 규칙, TLS 약화 규칙이 이 안에 있다
RULESET_FILES = (
    ("scan/cbom-scan.sh", "cbom-scan.sh"),
    ("scan/residue.sh", "residue"),
    ("scan/test-paths.ere", "test-paths.ere"),
    ("pqlite/scan.py", "pqlite/scan.py"),
    ("pqlite/verify.py", "pqlite/verify.py"),
    ("pqlite/allowlist.py", "pqlite/allowlist.py"),
)
RULESET_JSON = os.path.join(ROOT, "scan", "ruleset.json")
_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_version():
    """__version__ 를 소스 파일에서 읽는다: 저장소면 src/pqproof/__init__.py, 설치본이면 pqproof/_tool 바로 위 __init__.py."""
    for p in (os.path.join(ROOT, "src", "pqproof", "__init__.py"), os.path.join(os.path.dirname(ROOT), "__init__.py")):
        try:
            with open(p, encoding="utf-8") as f:
                m = _VERSION_RE.search(f.read())
        except OSError:
            continue
        if m:
            return m[1]
    return "0+unknown"


def ruleset_digest(digests):
    """{저장소 경로: sha256 또는 None} → 규칙 묶음 해시. 줄마다 '경로\\0sha256\\n'(없으면 none)을 경로 순으로 이어 SHA-256."""
    h = hashlib.sha256()
    for path, _ in sorted(RULESET_FILES):
        h.update(f"{path}\0{digests.get(path) or 'none'}\n".encode("utf-8"))
    return h.hexdigest()


def ruleset_from_tools(tools):
    """receipt.json 의 tools[] 에서 규칙 파일 해시를 골라 규칙 묶음 해시를 다시 계산한다(--verify 가 쓴다)."""
    by_name = {t.get("name"): t.get("sha256") for t in tools}
    return ruleset_digest({path: by_name.get(name) for path, name in RULESET_FILES})


def current_ruleset_sha256(root=ROOT):
    return ruleset_digest({p: (_sha256_file(os.path.join(root, *p.split("/"))) if os.path.isfile(os.path.join(root, *p.split("/")))
                              else None) for p, _ in RULESET_FILES})


def ruleset_history(path=RULESET_JSON):
    """scan/ruleset.json: {"current": 이름, "versions": {이름: sha256}}. 못 읽으면 빈 기록."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return str(data["current"]), {str(k): str(v) for k, v in data["versions"].items()}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None, {}


def ruleset_label(digest, path=RULESET_JSON):
    """실행에 쓴 규칙 묶음의 이름: 기록된 해시면 그 이름, 아니면 '<현재 이름>+modified'(RESIDUE·CBOM_SCAN 을 바꿨거나 파일을 고쳤다)."""
    current, versions = ruleset_history(path)
    for name, sha in versions.items():
        if sha == digest:
            return name
    return f"{current or '0'}+modified"


def describe():
    current, _ = ruleset_history()
    return f"pqproof {tool_version()} (ruleset {current or 'unknown'}, evidence format {FORMAT_VERSION})"


def main(argv):
    if argv[:1] == ["--ruleset"]:
        print(current_ruleset_sha256())
        return 0
    print(describe())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
