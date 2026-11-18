# version.py: 버전 세 가지를 한곳에서 읽는다(표준 라이브러리만).
#   도구 버전(tool_version)   : src/pqproof/__init__.py 의 __version__ 한 곳(pyproject 는 동적으로 읽고, prove.sh --version 도 여기서 읽는다)
#   규칙 묶음(ruleset)        : 판정을 정하는 규칙 파일(RULESET_FILES)의 해시 묶음. 버전 이름과 해시·파일 목록의 짝은 scan/ruleset.json 에 적는다.
#                              규칙 묶음마다 파일 목록이 다를 수 있다(1은 여섯, 2는 rules.py·tlsprobe.py·skipdirs.py·skip-dirs·profiles.json 을 더해 열하나).
#                              --verify 는 증적에 적힌 묶음 이름의 파일 목록으로 해시를 다시 계산한다
#   증적 형식(format_version) : receipt.json 의 꼴. 이 칸이 없는 옛 증적은 형식 1로 읽는다(pqlite/receipt.py 가 계속 읽는다)
# 규칙 파일을 고치면 해시가 바뀐다. 그때는 scan/ruleset.json 에 새 버전 이름과 기록(sha256·since·verdict_impact·files)을 더하고
# current 를 옮기며, CHANGELOG 의 '판정 영향' 칸에 적는다(tests/test_versioning.py 와 tests/version_policy.py 가 짝이 안 맞으면 실패한다).
# ruleset.json 의 옛 꼴({이름: sha256})도 읽는다.
#   python3 -I -B pqlite/version.py                 → "pqproof 0.1.0 (ruleset 1, evidence format 2)"
#   python3 -I -B pqlite/version.py --ruleset       → 지금 규칙 파일로 계산한 ruleset_sha256
#   python3 -I -B pqlite/version.py --ruleset-json  → 지금 규칙 파일의 sha256·files(ruleset.json 새 기록의 바탕, since·verdict_impact 는 사람이 적는다)
"""Tool version, ruleset version and hash, and evidence format version for PQ-Proof."""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 저장소 루트, 또는 설치본의 pqproof/_tool
FORMAT_VERSION = 3   # 이 도구가 쓰는 증적 형식(3: skip_dirs 사본, scan/skip-dirs 로 잰 트리 해시, 이름 규칙 허용이 r-allow 에 듦)
FORMAT_READS = (1, 2, 3)  # 이 도구가 --verify 로 읽는 형식(1 = format_version 칸이 없는 0.1.0 이전 공개본 증적)
# 규칙 파일 경로 → receipt.json tools[] 의 name. 옛 규칙 묶음에만 든 파일도 지우지 않는다(옛 증적의 묶음 해시를 다시 계산한다)
TOOL_NAMES = {
    "scan/cbom-scan.sh": "cbom-scan.sh",
    "scan/residue.sh": "residue",
    "scan/test-paths.ere": "test-paths.ere",
    "pqlite/scan.py": "pqlite/scan.py",
    "pqlite/verify.py": "pqlite/verify.py",
    "pqlite/allowlist.py": "pqlite/allowlist.py",
    "pqlite/rules.py": "pqlite/rules.py",
    "pqlite/tlsprobe.py": "pqlite/tlsprobe.py",
    "pqlite/skipdirs.py": "pqlite/skipdirs.py",
    "scan/skip-dirs": "skip-dirs",
    "scan/profiles.json": "profiles",
}
# 지금 규칙 묶음에 드는 파일: (저장소 경로, receipt.json tools[] 의 name). 탐지 패턴, 시험 경로, 허용 규칙, TLS 약화 규칙,
# 판정 상수와 검사 판정식(pqlite/rules.py), TLS 대상 판정(pqlite/tlsprobe.py), 건너뛰는 폴더 목록과 걷기(scan/skip-dirs,
# pqlite/skipdirs.py)가 이 안에 있다
RULESET_FILES = tuple((p, TOOL_NAMES[p]) for p in (
    "scan/cbom-scan.sh", "scan/residue.sh", "scan/test-paths.ere", "pqlite/scan.py", "pqlite/verify.py", "pqlite/allowlist.py",
    "pqlite/rules.py", "pqlite/tlsprobe.py", "pqlite/skipdirs.py", "scan/skip-dirs", "scan/profiles.json"))
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


def ruleset_digest(digests, paths=None):
    """{저장소 경로: sha256 또는 None} → 규칙 묶음 해시. 줄마다 '경로\0sha256\n'(없으면 none)을 경로 순으로 이어 SHA-256.
    paths: 묶음에 드는 경로(기본은 지금 RULESET_FILES). 옛 묶음은 그 묶음의 파일 목록으로 계산한다."""
    h = hashlib.sha256()
    for path in sorted(paths if paths is not None else (p for p, _ in RULESET_FILES)):
        h.update(f"{path}\0{digests.get(path) or 'none'}\n".encode("utf-8"))
    return h.hexdigest()


def ruleset_paths(name, path=RULESET_JSON):
    """규칙 묶음 이름('2', '1+modified')의 파일 경로 목록. '+modified' 는 앞 이름의 목록을 쓴다. 기록에 없거나 목록이 없으면
    지금 RULESET_FILES."""
    base = str(name or "").split("+", 1)[0]
    files = (ruleset_entries(path)[1].get(base) or {}).get("files")
    if isinstance(files, list) and files and all(isinstance(f, dict) and f.get("path") in TOOL_NAMES for f in files):
        return sorted(f["path"] for f in files)
    return sorted(p for p, _ in RULESET_FILES)


def ruleset_from_tools(tools, name=None, path=RULESET_JSON):
    """receipt.json 의 tools[] 에서 규칙 파일 해시를 골라 규칙 묶음 해시를 다시 계산한다(--verify 가 쓴다).
    name: 증적의 ruleset_version. 그 묶음의 파일 목록으로 계산한다(없으면 지금 목록)."""
    by_name = {t.get("name"): t.get("sha256") for t in tools}
    paths = ruleset_paths(name, path) if name is not None else sorted(p for p, _ in RULESET_FILES)
    return ruleset_digest({p: by_name.get(TOOL_NAMES[p]) for p in paths}, paths)


def current_ruleset_files(root=ROOT):
    """지금 규칙 파일의 [{"path", "sha256"}](경로 순, 없는 파일은 sha256 None)."""
    return [{"path": p, "sha256": (_sha256_file(os.path.join(root, *p.split("/"))) if os.path.isfile(os.path.join(root, *p.split("/")))
                                   else None)} for p, _ in sorted(RULESET_FILES)]


def current_ruleset_sha256(root=ROOT):
    return ruleset_digest({f["path"]: f["sha256"] for f in current_ruleset_files(root)})


def ruleset_entries(path=RULESET_JSON):
    """scan/ruleset.json 의 묶음 기록: (current, {이름: {"sha256", "since", "verdict_impact", "files"}}).
    새 꼴은 이름마다 객체({"sha256": …, "since": "0.1.0", "verdict_impact": "yes"|"no", "files": [{"path", "sha256"}]}),
    옛 꼴은 이름마다 sha256 문자열이다(그때 다른 칸은 None). 못 읽으면 (None, {})."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        out = {}
        for k, v in data["versions"].items():
            if isinstance(v, str):
                out[str(k)] = {"sha256": v, "since": None, "verdict_impact": None, "files": None}
            else:
                out[str(k)] = {"sha256": str(v["sha256"]), "since": v.get("since"), "verdict_impact": v.get("verdict_impact"),
                               "files": v.get("files")}
        return str(data["current"]), out
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None, {}


def ruleset_history(path=RULESET_JSON):
    """scan/ruleset.json 의 (current, {이름: sha256}). 못 읽으면 (None, {})."""
    current, entries = ruleset_entries(path)
    return current, {k: v["sha256"] for k, v in entries.items()}


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
    if argv[:1] == ["--ruleset-json"]:
        print(json.dumps({"sha256": current_ruleset_sha256(), "files": current_ruleset_files()}, indent=1))
        return 0
    print(describe())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
