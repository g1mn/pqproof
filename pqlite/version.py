# version.py: 버전 세 가지를 한곳에서 읽는다(표준 라이브러리만).
#   도구 버전(tool_version)   : src/pqproof/__init__.py 의 __version__ 한 곳(pyproject 는 동적으로 읽고, prove.sh --version 도 여기서 읽는다)
#   규칙 묶음(ruleset)        : 판정을 정하는 규칙 파일(RULESET_FILES)의 해시 묶음. 버전 이름과 해시·파일 목록의 짝은 scan/ruleset.json 에 적는다.
#                              묶음마다 파일 목록이 다를 수 있다(scan/ruleset.json). scan/kat 은 폴더라 그 안 *.json 의 해시 묶음을 쓴다(path_sha256)
#                              --verify 는 증적에 적힌 묶음 이름의 파일 목록으로 해시를 다시 계산한다
#   증적 형식(format_version) : receipt.json 의 꼴. 이 칸이 없는 옛 증적은 형식 1로 읽는다(pqlite/receipt.py 가 계속 읽는다)
# 규칙 파일을 고치면 해시가 바뀐다. 그때는 scan/ruleset.json 에 새 버전 이름과 기록(sha256·since·verdict_impact·files)을 더하고
# current 를 옮기며, CHANGELOG 의 '판정 영향' 칸에 적는다(tests/test_versioning.py 와 tests/version_policy.py 가 짝이 안 맞으면 실패한다).
# ruleset.json 의 옛 꼴({이름: sha256})도 읽는다.
#   python3 -I -B pqlite/version.py                 → "pqproof <판> (ruleset <묶음>, evidence format <형식>)"
#   python3 -I -B pqlite/version.py --ruleset       → 지금 규칙 파일로 계산한 ruleset_sha256
#   python3 -I -B pqlite/version.py --ruleset-json  → 지금 규칙 파일의 sha256·files·comment_free(ruleset.json 새 기록의 바탕, since·verdict_impact 는 사람이 적는다)
#   python3 -I -B pqlite/version.py --alias         → 주석만 고쳤으면 지금 해시를 현재 묶음의 별칭으로 적는다(아니면 종료 1)
"""Tool version, ruleset version and hash, and evidence format version for PQ-Proof."""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 저장소 루트, 또는 설치본의 pqproof/_tool
FORMAT_VERSION = 4   # 이 도구가 쓰는 증적 형식(4: 구현 검증 params.mode impl 과 최상위 impl 칸, 검사 i-kpqc. 두 트리·한 트리 증적은 3과 같은 꼴)
FORMAT_READS = (1, 2, 3, 4)  # 이 도구가 --verify 로 읽는 형식(1 = format_version 칸이 없는 0.1.0 이전 공개본 증적)
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
    "pqlite/impl.py": "pqlite/impl.py",
    "scan/kat-kpqc.json": "kat-kpqc",
    "scan/kat": "kat-excerpts",
}
# 지금 규칙 묶음에 드는 파일: (저장소 경로, receipt.json tools[] 의 name). 탐지 패턴, 시험 경로, 허용 규칙, TLS 약화 규칙,
# 판정 상수와 검사 판정식(pqlite/rules.py), TLS 대상 판정(pqlite/tlsprobe.py), 건너뛰는 폴더 목록과 걷기(scan/skip-dirs,
# pqlite/skipdirs.py), 구현 검증의 대조 규칙과 KpqC 참조판 KAT 목록·발췌(pqlite/impl.py, scan/kat-kpqc.json, scan/kat)가 이 안에 있다
RULESET_FILES = tuple((p, TOOL_NAMES[p]) for p in (
    "scan/cbom-scan.sh", "scan/residue.sh", "scan/test-paths.ere", "pqlite/scan.py", "pqlite/verify.py", "pqlite/allowlist.py",
    "pqlite/rules.py", "pqlite/tlsprobe.py", "pqlite/skipdirs.py", "scan/skip-dirs", "scan/profiles.json", "pqlite/impl.py",
    "scan/kat-kpqc.json", "scan/kat"))
RULESET_JSON = os.path.join(ROOT, "scan", "ruleset.json")
_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def path_sha256(path):
    """규칙 파일의 해시. 파일이면 SHA-256, 폴더(scan/kat)면 그 아래 *.json 마다 '상대 경로\0sha256\n' 을 경로 순으로 이은 SHA-256
    (NOTICE 같은 다른 파일은 판정에 쓰지 않아 넣지 않는다), 없으면 None."""
    if os.path.isfile(path):
        return _sha256_file(path)
    if not os.path.isdir(path):
        return None
    found = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        for n in filenames:
            if n.endswith(".json"):
                full = os.path.join(dirpath, n)
                found.append((os.path.relpath(full, path).replace(os.sep, "/"), full))
    h = hashlib.sha256()
    for rel, full in sorted(found):
        h.update(f"{rel}\0{_sha256_file(full)}\n".encode("utf-8"))
    return h.hexdigest()


# 주석을 뺀 해시(규칙 묶음 5부터). 주석만 고친 판은 그 묶음 기록의 aliases 에 새 해시를 더해 이름을 그대로 둔다(--alias).
# 파이썬은 주석 토큰을 모두, 셸은 맨 위 수준(따옴표·heredoc 밖)의 주석 줄과 빈 줄만 뺀다. 셸 줄 끝 주석은 해시에 남는다.
# test-paths.ere·skip-dirs 는 읽는 쪽이 건너뛰는 '#' 줄과 빈 줄을 뺀다. JSON 과 scan/kat 은 바이트 그대로다.
# 셸에서 뺀 줄이 정말 맨 위 수준 주석인지는 tests/test_versioning.py 가 bash -n 으로 확인한다.
_HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def _python_without_comments(text):
    import io
    import tokenize
    cut, inside = {}, set()
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type == tokenize.COMMENT:
            cut[tok.start[0]] = tok.start[1]
        elif tok.end[0] > tok.start[0] and tok.type not in (tokenize.NEWLINE, tokenize.NL):
            inside.update(range(tok.start[0] + 1, tok.end[0] + 1))  # 여러 줄 문자열의 둘째 줄부터(빈 줄도 문자열의 일부)
    out = []
    for row, line in enumerate(text.split("\n"), 1):
        if row in cut:
            line = line[:cut[row]].rstrip()
        if row in inside:
            out.append(line)
        elif line.strip():
            out.append(line.rstrip())
    return "\n".join(out)


def _shell_scan(line, quote, heredocs):
    """한 줄을 읽고 줄 끝의 따옴표 상태를 돌려준다. 따옴표 밖에서 만난 heredoc 시작(<<EOF)은 heredocs 에 더한다."""
    j, n = 0, len(line)
    while j < n:
        c = line[j]
        if quote == "'":
            quote = None if c == "'" else quote
        elif quote in ('"', "$'"):
            if c == "\\":
                j += 1
            elif c == quote[-1]:
                quote = None
        elif c == "\\":
            j += 1
        elif c == "#" and (j == 0 or line[j - 1] in " \t;|&()"):
            break  # 줄 끝 주석: 그 안의 따옴표는 세지 않는다
        elif c in "'\"":
            quote = c
        elif c == "$" and line[j + 1:j + 2] == "'":
            quote, j = "$'", j + 1
        elif line.startswith("<<", j) and not line.startswith("<<<", j):
            m = _HEREDOC.match(line, j)
            if m:
                heredocs.append((m[3], m[1] == "-"))
                j = m.end()
                continue
        j += 1
    return quote


def shell_comment_lines(text):
    """셸 글에서 빼는 줄 번호(1부터): 맨 위 수준의 '#' 줄(첫 줄 #! 은 남긴다)과 빈 줄."""
    drop, quote, pending, active = [], None, [], None
    for row, line in enumerate(text.split("\n"), 1):
        if active:
            if (line.lstrip("\t") if active[1] else line) == active[0]:
                active = pending.pop(0) if pending else None
            continue
        if quote is None and (not line.strip() or (line.lstrip().startswith("#") and not (row == 1 and line.startswith("#!")))):
            drop.append(row)
            continue
        quote = _shell_scan(line, quote, pending)
        if quote is None and pending:
            active = pending.pop(0)
    return drop


def comment_free_text(path):
    """규칙 파일에서 주석을 뺀 글(바이트). 주석이 없는 꼴(JSON 등)은 파일 바이트 그대로."""
    with open(path, "rb") as f:
        raw = f.read()
    name = os.path.basename(path)
    if not (name.endswith((".py", ".sh", ".ere")) or name == "skip-dirs"):
        return raw
    text = raw.decode("utf-8")
    if name.endswith(".py"):
        return _python_without_comments(text).encode("utf-8")
    if name.endswith(".sh"):
        drop = set(shell_comment_lines(text))
        return "\n".join(line for row, line in enumerate(text.split("\n"), 1) if row not in drop).encode("utf-8")
    return "\n".join(line for line in text.split("\n") if line.strip() and not line.startswith("#")).encode("utf-8")


def comment_free_sha256(path):
    """주석을 뺀 해시. 폴더(scan/kat)는 path_sha256 과 같고, 없으면 None."""
    if os.path.isfile(path):
        return hashlib.sha256(comment_free_text(path)).hexdigest()
    return path_sha256(path)


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
    return [{"path": p, "sha256": path_sha256(os.path.join(root, *p.split("/")))} for p, _ in sorted(RULESET_FILES)]


def current_ruleset_sha256(root=ROOT):
    return ruleset_digest({f["path"]: f["sha256"] for f in current_ruleset_files(root)})


def current_comment_free(root=ROOT):
    """지금 규칙 파일의 주석을 뺀 해시: {"sha256": 묶음 해시, "files": [{"path", "sha256"}]}."""
    files = [{"path": p, "sha256": comment_free_sha256(os.path.join(root, *p.split("/")))} for p, _ in sorted(RULESET_FILES)]
    return {"sha256": ruleset_digest({f["path"]: f["sha256"] for f in files}), "files": files}


def ruleset_entries(path=RULESET_JSON):
    """scan/ruleset.json 의 묶음 기록: (current, {이름: {"sha256", "since", "verdict_impact", "files", "aliases", "comment_free"}}).
    aliases: 주석만 고친 판의 해시 목록(규칙 묶음 5부터), comment_free: 그 묶음의 주석을 뺀 해시({"sha256", "files"}).
    새 꼴은 이름마다 객체({"sha256": …, "since": "0.1.0", "verdict_impact": "yes"|"no", "files": [{"path", "sha256"}]}),
    옛 꼴은 이름마다 sha256 문자열이다(그때 다른 칸은 None). 못 읽으면 (None, {})."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        out = {}
        for k, v in data["versions"].items():
            if isinstance(v, str):
                out[str(k)] = {"sha256": v, "since": None, "verdict_impact": None, "files": None, "aliases": [], "comment_free": None}
            else:
                out[str(k)] = {"sha256": str(v["sha256"]), "since": v.get("since"), "verdict_impact": v.get("verdict_impact"),
                               "files": v.get("files"), "aliases": [str(a["sha256"]) for a in v.get("aliases") or []],
                               "comment_free": v.get("comment_free")}
        return str(data["current"]), out
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None, {}


def ruleset_history(path=RULESET_JSON):
    """scan/ruleset.json 의 (current, {이름: sha256}). 못 읽으면 (None, {})."""
    current, entries = ruleset_entries(path)
    return current, {k: v["sha256"] for k, v in entries.items()}


def ruleset_hashes(path=RULESET_JSON):
    """{이름: 그 이름으로 받는 해시들(기록 해시와 별칭)}."""
    return {k: {v["sha256"], *v["aliases"]} for k, v in ruleset_entries(path)[1].items()}


def ruleset_label(digest, path=RULESET_JSON):
    """실행에 쓴 규칙 묶음의 이름: 기록된 해시나 별칭이면 그 이름, 아니면 '<현재 이름>+modified'(RESIDUE·CBOM_SCAN 을 바꿨거나 파일을 고쳤다)."""
    current, _ = ruleset_history(path)
    for name, hashes in ruleset_hashes(path).items():
        if digest in hashes:
            return name
    return f"{current or '0'}+modified"


def add_alias(root=ROOT, path=RULESET_JSON):
    """주석만 고친 지금 규칙 파일을 현재 묶음의 별칭으로 적는다. (종료 코드, 알림)."""
    current, entries = ruleset_entries(path)
    raw = current_ruleset_sha256(root)
    if raw in ruleset_hashes(path).get(current, set()):
        return 0, f"ruleset {current} already records {raw}"
    want = (entries.get(current) or {}).get("comment_free") or {}
    now = current_comment_free(root)
    if not want or want.get("sha256") != now["sha256"]:
        old = {f["path"]: f["sha256"] for f in want.get("files") or []}
        moved = [f["path"] for f in now["files"] if old.get(f["path"]) != f["sha256"]]
        return 1, (f"more than comments changed since ruleset {current} ({', '.join(moved) or 'no comment-free record'}): "
                   "add a new ruleset name (CONTRIBUTING.md, Changing a rule)")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data["versions"][current].setdefault("aliases", []).append({"sha256": raw, "files": current_ruleset_files(root)})
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    return 0, f"ruleset {current}: only comments changed, recorded {raw} as an alias"


def describe():
    current, _ = ruleset_history()
    return f"pqproof {tool_version()} (ruleset {current or 'unknown'}, evidence format {FORMAT_VERSION})"


def main(argv):
    if argv[:1] == ["--ruleset"]:
        print(current_ruleset_sha256())
        return 0
    if argv[:1] == ["--ruleset-json"]:
        print(json.dumps({"sha256": current_ruleset_sha256(), "files": current_ruleset_files(), "comment_free": current_comment_free()},
                         indent=1))
        return 0
    if argv[:1] == ["--alias"]:
        code, msg = add_alias()
        print(msg, file=sys.stderr if code else sys.stdout)
        return code
    print(describe())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
