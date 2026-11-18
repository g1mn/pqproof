#!/usr/bin/env python3
# version_policy.py: 버전 정책(DESIGN.md 'Versioning and maintenance')을 기계로 확인한다. CI·release.yml·tests/test_versioning.py 가 쓴다.
# 정책: Semantic Versioning. 판정이 바뀔 수 있는 변경(규칙 묶음 verdict_impact yes, golden 판정·검사·숫자 이동)은 0.x 동안 MINOR,
#   1.0 부터 MAJOR 로 올린다. 새 명령·옵션은 MINOR. 그 밖 고침은 PATCH. 그래서 판정이 바뀌는 릴리스는 PATCH 일 수 없다.
#   python3 -I tests/version_policy.py                지금 트리: ruleset.json 기록, CHANGELOG 판정 영향 줄, 판정 영향 있는 묶음의 첫 버전
#   python3 -I tests/version_policy.py --base v0.1.0  앞 태그와도 비교: 판정(golden)이 옮겨 갔으면 PATCH 릴리스가 아니어야 하고
#                                                     CHANGELOG 의 그 항목([Unreleased] 포함)이 판정 영향 yes 여야 한다.
#                                                     버전이 그대로면 다음 릴리스가 MINOR 여야 하는지도 알린다
# 표준 라이브러리만 쓴다. 저장소는 읽기만 한다(--base 는 git show 로 그 판의 파일을 읽는다).
# 종료: 0 맞음 · 1 어긋남 · 2 사용법 오류(git 없음, 그 판을 못 읽음)
"""Check the version policy: a release that can move a verdict is never a PATCH release."""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from pqlite import version as V  # noqa: E402

SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SECTION = re.compile(r"(?m)^## \[([^\]]+)\](?: - (.+))?$")
IMPACT = re.compile(r"(?m)^\*\*Verdict impact \(판정 영향\): (yes|none)\b")
SHA = re.compile(r"^[0-9a-f]{64}$")


def semver(s):
    m = SEMVER.match(s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def verdict_release_ok(v):
    """판정이 바뀌는 릴리스가 될 수 있는 버전인가: PATCH 0, 1.0 부터는 MINOR 도 0."""
    return v[2] == 0 and (v[0] == 0 or v[1] == 0)


def changelog_sections(text):
    """{'Unreleased' 또는 버전: (날짜 또는 None, 본문)}."""
    heads = list(SECTION.finditer(text))
    out = {}
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        out[m[1]] = (m[2], text[m.end():end])
    return out


def impact_of(body):
    m = IMPACT.search(body or "")
    return m[1] if m else None


def check_ruleset(doc):
    """ruleset.json 기록 꼴: 이름마다 sha256·since·verdict_impact·files, files 로 다시 계산한 해시가 sha256 과 같다."""
    bad = []
    versions = doc.get("versions") if isinstance(doc, dict) else None
    if not isinstance(versions, dict) or doc.get("current") not in (versions or {}):
        return ["scan/ruleset.json: current must name one of versions"]
    want_paths = sorted(p for p, _ in V.RULESET_FILES)
    for name, e in versions.items():
        where = f"scan/ruleset.json ruleset {name}"
        if not isinstance(e, dict):
            bad.append(f"{where}: old form (a bare hash); write sha256, since, verdict_impact and files")
            continue
        if not SHA.match(str(e.get("sha256", ""))):
            bad.append(f"{where}: sha256 is not 64 hex digits")
        if semver(e.get("since")) is None:
            bad.append(f"{where}: since {e.get('since')!r} is not a version X.Y.Z")
        if e.get("verdict_impact") not in ("yes", "no"):
            bad.append(f"{where}: verdict_impact must be yes or no")
        files = e.get("files")
        if not isinstance(files, list) or sorted(str(f.get("path")) for f in files if isinstance(f, dict)) != want_paths:
            bad.append(f"{where}: files must list the six rule files {want_paths}")
        elif V.ruleset_digest({f["path"]: f.get("sha256") for f in files}) != e.get("sha256"):
            bad.append(f"{where}: the hashes in files give {V.ruleset_digest({f['path']: f.get('sha256') for f in files})}, not sha256")
    if len({e.get("sha256") for e in versions.values() if isinstance(e, dict)}) != len(versions):
        bad.append("scan/ruleset.json: two ruleset names share a hash")
    return bad


def check_tree(version, changelog, ruleset_doc):
    """지금 트리의 버전·CHANGELOG·ruleset.json 이 정책에 맞는지. 어긋난 것의 목록([] 이면 맞다)."""
    bad = []
    v = semver(version)
    if v is None:
        return [f"tool version {version!r} is not X.Y.Z"]
    sections = changelog_sections(changelog)
    if version not in sections:
        bad.append(f"CHANGELOG.md has no '## [{version}]' entry")
    for name in [n for n in (version, "Unreleased") if n in sections]:
        if impact_of(sections[name][1]) is None:
            bad.append(f"CHANGELOG.md [{name}] has no '**Verdict impact (판정 영향): yes|none' line")
    if impact_of(sections.get(version, (None, ""))[1]) == "yes" and not verdict_release_ok(v):
        bad.append(f"CHANGELOG.md says verdict impact yes for {version}, a PATCH release: verdict changes bump MINOR "
                   "(MAJOR from 1.0)")
    bad += check_ruleset(ruleset_doc)
    if bad and any(b.startswith("scan/ruleset.json: current") for b in bad):
        return bad
    for name, e in (ruleset_doc.get("versions") or {}).items():
        if not isinstance(e, dict) or semver(e.get("since")) is None:
            continue
        since = semver(e["since"])
        if e.get("verdict_impact") == "yes":
            if not verdict_release_ok(since):
                bad.append(f"ruleset {name} has verdict impact yes but first ships in {e['since']}, a PATCH release")
            sec = e["since"] if e["since"] in sections else ("Unreleased" if since > v else None)
            if sec is None:
                bad.append(f"ruleset {name}: CHANGELOG.md has no entry for {e['since']}")
            elif impact_of(sections[sec][1]) != "yes":
                bad.append(f"ruleset {name} has verdict impact yes, but CHANGELOG.md [{sec}] does not say yes")
        if since > v and "Unreleased" not in sections:
            bad.append(f"ruleset {name} ships in {e['since']}, after this version {version}, but CHANGELOG.md has no [Unreleased] entry")
    return bad


def golden_moves(gold_base, gold_now):
    """두 판 모두에 있는 golden 사례 중 판정·검사 상태·숫자가 다른 것(묶음 이름 칸은 빼고 본다)."""
    strip = lambda g: {k: v for k, v in g.items() if k != "ruleset_version"}  # noqa: E731
    return sorted(c for c in set(gold_base) & set(gold_now) if strip(gold_base[c]) != strip(gold_now[c]))


def check_release(version, base_version, ruleset_now, ruleset_base, gold_now, gold_base, changelog=None):
    """앞 판(base)과 비교. (어긋난 것, 알림). 판정이 옮겨 갔으면 PATCH 릴리스가 아니어야 하고, CHANGELOG 의 그 항목(버전이 같으면
    [Unreleased])이 판정 영향 yes 여야 한다. 버전이 같으면 다음 릴리스가 MINOR 여야 하는지 알린다."""
    bad, notes = [], []
    v, b = semver(version), semver(base_version)
    if v is None or b is None:
        return [f"cannot compare versions {version!r} and {base_version!r}"], notes
    moved = golden_moves(gold_base, gold_now)
    cur_now, cur_base = ruleset_now.get("current"), ruleset_base.get("current")
    new_rs = cur_now != cur_base
    rs_impact = (ruleset_now.get("versions", {}).get(cur_now) or {}).get("verdict_impact") if new_rs else None
    needs_minor = bool(moved) or rs_impact == "yes"
    why = ", ".join(([f"golden cases moved: {', '.join(moved)}"] if moved else [])
                    + ([f"ruleset {cur_base} -> {cur_now} with verdict impact yes"] if rs_impact == "yes" else []))
    if v < b:
        bad.append(f"version {version} is older than {base_version}")
    elif v == b:
        notes.append(f"unreleased changes since {base_version}: " + (f"the next release must be MINOR ({why})" if needs_minor
                                                                     else "no verdict moved, a PATCH release is allowed"))
    elif needs_minor and (v[0], v[1]) == (b[0], b[1]):
        bad.append(f"{version} is a PATCH release after {base_version}, but {why}: bump MINOR (MAJOR from 1.0)")
    elif needs_minor and v[0] >= 1 and v[0] == b[0]:
        bad.append(f"{version} keeps MAJOR {v[0]} after {base_version}, but {why}: from 1.0 a verdict change bumps MAJOR")
    if needs_minor and changelog is not None and v >= b:
        sec = "Unreleased" if v == b else version
        if impact_of(changelog_sections(changelog).get(sec, (None, ""))[1]) != "yes":
            bad.append(f"{why}, but CHANGELOG.md [{sec}] does not say verdict impact yes")
    return bad, notes


def git_show(ref, path):
    r = subprocess.run(["git", "-C", ROOT, "show", f"{ref}:{path}"], capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        raise OSError(r.stderr.strip() or f"git show {ref}:{path} failed")
    return r.stdout


def read(path):
    with open(os.path.join(ROOT, *path.split("/")), encoding="utf-8") as f:
        return f.read()


def ruleset_doc(text):
    """ruleset.json 을 새 꼴로 읽는다(옛 꼴의 맨 해시는 {"sha256": …} 로 감싼다)."""
    doc = json.loads(text)
    doc["versions"] = {k: (v if isinstance(v, dict) else {"sha256": v}) for k, v in doc.get("versions", {}).items()}
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description="PQ-Proof version policy")
    ap.add_argument("--base", default=None, help="an earlier release (tag or commit) to compare with")
    a = ap.parse_args(argv)
    version = V.tool_version()
    try:
        changelog = read("CHANGELOG.md")
        raw_rules = json.loads(read("scan/ruleset.json"))
    except (OSError, ValueError) as e:
        print(f"version policy: cannot read {e}", file=sys.stderr)
        return 2
    bad = check_tree(version, changelog, raw_rules)
    notes = []
    if a.base:
        try:
            init = git_show(a.base, "src/pqproof/__init__.py")
            base_version = re.search(r'^__version__\s*=\s*"([^"]+)"', init, re.M)[1]
            r_base = ruleset_doc(git_show(a.base, "scan/ruleset.json"))
            g_base = json.loads(git_show(a.base, "tests/golden/verdicts.json"))["runs"]
            g_now = json.loads(read("tests/golden/verdicts.json"))["runs"]
        except (OSError, ValueError, TypeError, KeyError) as e:
            print(f"version policy: cannot read {a.base}: {e}", file=sys.stderr)
            return 2
        more, notes = check_release(version, base_version, ruleset_doc(json.dumps(raw_rules)), r_base, g_now, g_base, changelog)
        bad += more
    current = raw_rules.get("current")
    print(f"version policy: pqproof {version}, ruleset {current}" + (f", compared with {a.base}" if a.base else ""))
    for n in notes:
        print(f"  note: {n}")
    for b in bad:
        print(f"  FAIL {b}")
    print("version policy: " + ("ok" if not bad else f"{len(bad)} problem(s)"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
