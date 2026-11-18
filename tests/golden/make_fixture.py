#!/usr/bin/env python3
# make_fixture.py: 한 번 돌린 검증 증적 폴더를 하위 호환 시험용 고정물(tests/golden/evidence/<이름>/)로 옮긴다.
# 형식을 바꾸는 릴리스 전에, 지금 판이 쓴 증적을 하나 이렇게 남겨 두면 다음 판의 --verify 가 계속 읽는지 시험할 수 있다.
#   python3 -I tests/golden/make_fixture.py <증적 폴더> <이름> --label "설명" [--map 옛경로=새경로 ...]
#           [--replace 바꿀글.json] [--strip-report-from 제목]
# 하는 일
#   1) 먼저 원본 폴더를 지금 도구의 verify 로 확인한다(모두 통과해야 옮긴다). 원본 receipt_id 와 receipt.html 해시를 적어 둔다.
#   2) 모든 글 파일에서 --map 의 경로를 바꾼다(앞에 준 것부터). 개인 경로·작업 폴더 경로를 공개해도 되는 경로로 바꾸려는 것이다.
#   3) --replace 를 주면 그 JSON({"why": 이유, "pairs": [[옛 글, 새 글], ...]})의 글을 차례로 바꾼다. 공개하지 않을 글에만
#      맞춘 식별자·설명을 중립 문구로 바꾸려는 것이다. 옛 글은 manifest 에 적지 않고 개수와 이유만 적는다. 이 JSON 은 저장소에 넣지 않는다.
#   4) --strip-report-from 을 주면 tables/report.md 에서 그 줄부터 끝까지 뺀다(공개하지 않을 부분).
#   5) 바뀐 파일의 바이트 수·SHA-256, *_sha256 짝, receipt_id 를 다시 계산하고 receipt.html·deck.json 을 다시 그린 뒤 verify 한다.
#   6) tests/golden/evidence/manifest.json 에 한 줄 적는다(같은 이름이 있으면 그 자리에서 바꾼다).
# 판정·검사·숫자 칸은 건드리지 않는다. 바꾼 경로·글자·문구와 뺀 표 말고는 원본 그대로다.
"""Turn an evidence folder into a backward-compatibility fixture under tests/golden/evidence/."""
import argparse
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
from pqlite import receipt as R  # noqa: E402

DEST = os.path.join(HERE, "evidence")
MANIFEST = os.path.join(DEST, "manifest.json")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("name")
    ap.add_argument("--label", required=True)
    ap.add_argument("--map", action="append", default=[], help="OLD=NEW, applied in the order given")
    ap.add_argument("--replace", default=None, help='JSON {"why": ..., "pairs": [[OLD, NEW], ...]}, applied after --map')
    ap.add_argument("--strip-report-from", default=None)
    a = ap.parse_args(argv)
    repl = {"why": None, "pairs": []}
    if a.replace:
        with open(a.replace, encoding="utf-8") as f:
            repl = json.load(f)
    src = os.path.abspath(a.src)
    bad = [w for ok, w in R.verify(src) if not ok]
    if bad:
        print("source does not verify with this tool:\n  " + "\n  ".join(bad[:5]), file=sys.stderr)
        return 1
    with open(os.path.join(src, "receipt.json"), encoding="utf-8") as f:
        orig = json.load(f)
    with open(os.path.join(src, "receipt.html"), "rb") as f:
        orig_html = sha(f.read())
    dst = os.path.join(DEST, a.name)
    if os.path.exists(dst):
        print(f"{dst} exists", file=sys.stderr)
        return 1
    shutil.copytree(src, dst, symlinks=True)
    maps = [m.split("=", 1) for m in a.map]
    used = set()
    for dirpath, _, files in os.walk(dst):
        for n in files:
            p = os.path.join(dirpath, n)
            with open(p, "rb") as f:
                data = f.read()
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            new = text
            for old, rep in maps:
                new = new.replace(old, rep)
            for i, (old, rep) in enumerate(repl["pairs"]):
                if old in new:
                    used.add(i)
                    new = new.replace(old, rep)
            if a.strip_report_from and os.path.relpath(p, dst) == os.path.join("tables", "report.md"):
                k = new.find("\n" + a.strip_report_from)
                if k >= 0:
                    new = new[:k + 1]
            if new != text:
                with open(p, "wb") as f:
                    f.write(new.encode("utf-8"))
    unused = [i for i in range(len(repl["pairs"])) if i not in used]
    if unused:
        shutil.rmtree(dst)
        print(f"--replace pairs matched nothing: {unused}", file=sys.stderr)
        return 1
    with open(os.path.join(dst, "receipt.json"), encoding="utf-8") as f:
        r = json.load(f)
    digests = {}
    for item in r["artifacts"]:
        with open(os.path.join(dst, *item["path"].split("/")), "rb") as f:
            data = f.read()
        item["bytes"], item["sha256"] = len(data), sha(data)
        digests[item["path"]] = item["sha256"]

    def fix_refs(o):
        if isinstance(o, dict):
            for k in list(o):
                if isinstance(o[k], str) and k + "_sha256" in o and o[k] in digests:
                    o[k + "_sha256"] = digests[o[k]]
                fix_refs(o[k])
        elif isinstance(o, list):
            for x in o:
                fix_refs(x)
    fix_refs(r)
    r["receipt_id"] = R.compute_id(r)
    with open(os.path.join(dst, "receipt.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(r, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    with open(os.path.join(dst, "receipt.html"), "w", encoding="utf-8") as f:
        f.write(R.render_html(r))
    if "deck_meta" in r:
        with open(os.path.join(dst, "deck.json"), "w", encoding="utf-8") as f:
            f.write(R.render_deck(r))
    bad = [w for ok, w in R.verify(dst) if not ok]
    if bad:
        print("fixture does not verify:\n  " + "\n  ".join(bad[:5]), file=sys.stderr)
        return 1
    try:
        with open(MANIFEST, encoding="utf-8") as f:
            man = json.load(f)
    except OSError:
        man = {"about": "Evidence folders written by earlier versions. tests/test_golden.py checks that --verify still reads "
                        "each one and still catches a changed byte. make_fixture.py replaced local paths and recomputed the "
                        "hashes; verdicts, checks and counts are as the earlier version wrote them.", "fixtures": []}
    entry = {
        "name": a.name, "label": a.label, "format_version": R.format_version(r), "verdict": r["verdict"],
        "checks": {c["id"]: c["status"] for c in r["checks"]}, "receipt_id": r["receipt_id"],
        "source_receipt_id": orig["receipt_id"], "source_receipt_html_sha256": orig_html,
        "source_verified_by_this_tool": True, "paths_replaced": [m[1] for m in maps],
        "report_section_removed": a.strip_report_from}
    if repl["pairs"]:
        entry["strings_replaced"] = {"count": len(repl["pairs"]), "why": repl["why"]}
    names = [x["name"] for x in man["fixtures"]]
    if a.name in names:
        man["fixtures"][names.index(a.name)] = entry
    else:
        man["fixtures"].append(entry)
    with open(MANIFEST, "w", encoding="utf-8") as f:
        f.write(json.dumps(man, indent=1, ensure_ascii=False) + "\n")
    print(f"{a.name}: {r['verdict']} receipt_id {r['receipt_id']} (source {orig['receipt_id']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
