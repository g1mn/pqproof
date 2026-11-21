# mapping_draft.py: 새 기준 문서(예: KISA PQC 전환 가이드)가 나왔을 때 mappings/<id>.json 초안을 빨리 만드는 개발용 도구(표준 라이브러리만).
#   python3 -I tools/mapping_draft.py extract guide.pdf > guide.txt
#       pdftotext -layout 으로 글을 꺼내 쪽마다 '=== page N ===' 줄을 붙인다(인용과 쪽 번호를 고를 때 본다).
#   python3 -I tools/mapping_draft.py draft items.tsv --into mappings/kisa-pqc-guide.json > draft.json
#       사람이 고른 항목 목록(TSV: id, page, section, quote, about_ko, about_en)으로 항목 초안을 만든다. 상태는 "todo",
#       대응 글·근거는 비워 두고, 주제가 같은 기존 대응표 항목(상태·근거)을 "_suggest" 에 붙인다.
# 초안은 일부러 tests/test_mappings.py 를 통과하지 못한다("todo" 상태, "_suggest" 칸). 사람이 항목마다 상태·대응 글·근거·남은 것을
# 정하고 "_suggest" 를 지운 뒤 mappings/ 에 넣는다. 문서 내용을 추측해 채우지 않는다(mappings/README.md).
"""Draft a mappings/<id>.json file from a published document: extract its text, then turn chosen items into reviewable stubs."""
import argparse
import csv
import json
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TSV_COLUMNS = ["id", "page", "section", "quote", "about_ko", "about_en"]

# 주제 → 그 주제를 가리키는 말(영어·한국어). 새 항목과 기존 항목이 같은 주제에 걸리면 기존 항목의 상태·근거를 제안한다.
# ponytail: 낱말 맞추기다. 제안일 뿐이고 판단은 사람이 한다.
TOPICS = {
    "inventory": r"inventor|discover|CBOM|자산|목록|현황|인벤토리",
    "algorithms": r"ML-KEM|ML-DSA|SLH-DSA|KpqC|SMAUG|NTRU|HAETAE|AIMer|algorithm|알고리즘",
    "strength": r"security (?:strength|categor|level)|parameter set|보안\s*(?:강도|레벨|수준|등급)|파라미터",
    "deadline": r"deprecat|disallow|\b20[23]\d\b|일정|기한|폐기|퇴출",
    "hybrid": r"hybrid|composite|하이브리드|혼합|병행|호환",
    "agility": r"agil|민첩",
    "tls": r"\bTLS\b|key exchange|key establishment|키\s*(?:교환|합의|설정)|프로토콜",
    "verify": r"\btest|validat|verif|검증|시험",
}


def topics(text):
    return [t for t, rx in TOPICS.items() if re.search(rx, text, re.IGNORECASE)]


def extract(pdf):
    exe = shutil.which("pdftotext")
    if not exe:
        sys.exit("pdftotext not found (poppler-utils)")
    text = subprocess.run([exe, "-layout", str(pdf), "-"], check=True, capture_output=True, text=True).stdout
    for n, page in enumerate(text.split("\f"), 1):
        if page.strip():
            print(f"=== page {n} ===\n{page.rstrip()}\n")


def known_items(skip_id):
    """기존 대응표의 항목: [(문서 id, 항목, 주제 목록)]. 초안을 만드는 문서 자신은 뺀다."""
    out = []
    for p in sorted((ROOT / "mappings").glob("*.json")):
        doc = json.loads(p.read_text(encoding="utf-8"))
        if doc["id"] == skip_id:
            continue
        for it in doc["items"]:
            out.append((doc["id"], it, topics(" ".join([it["quote"] or "", it["about_en"], it["about_ko"]]))))
    return out


def stub(row, known):
    missing = [c for c in TSV_COLUMNS[:5] if not (row.get(c) or "").strip()]
    if missing:
        raise ValueError(f"item {row.get('id')!r}: empty {', '.join(missing)}")
    ref = {"page": int(row["page"]) if row["page"].strip().isdigit() else row["page"].strip(), "section": row["section"].strip()}
    tp = topics(" ".join([row["quote"], row["about_ko"], row.get("about_en") or ""]))
    like = [{"from": f"{d}/{it['id']}", "status": it["status"], "evidence": it["evidence"], "shared_topics": sorted(set(tp) & set(t))}
            for d, it, t in known if set(tp) & set(t)]
    like.sort(key=lambda x: -len(x["shared_topics"]))
    return {"id": row["id"].strip(), "ref": ref, "quote": row["quote"].strip(), "about_en": (row.get("about_en") or "").strip(),
            "about_ko": row["about_ko"].strip(), "status": "todo", "note_en": "", "note_ko": "", "evidence": [],
            "remaining_en": [], "remaining_ko": [], "_suggest": {"topics": tp, "like": like[:6]}}


def draft(tsv, into):
    doc = json.loads(pathlib.Path(into).read_text(encoding="utf-8"))
    with open(tsv, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    if not rows or set(TSV_COLUMNS[:5]) - set(rows[0]):
        sys.exit(f"{tsv}: need a header row with {', '.join(TSV_COLUMNS)} (about_en may be empty)")
    known = known_items(doc["id"])
    try:
        doc["items"] = [stub(r, known) for r in rows]
    except ValueError as e:
        sys.exit(f"{tsv}: {e}")
    ids = [it["id"] for it in doc["items"]]
    if len(ids) != len(set(ids)):
        sys.exit("item ids repeat")
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract", help="PDF text with page markers")
    e.add_argument("pdf")
    d = sub.add_parser("draft", help="mapping draft from a TSV of chosen items")
    d.add_argument("tsv")
    d.add_argument("--into", required=True, help="the mapping file to start from (its header is kept)")
    a = ap.parse_args(argv)
    if a.cmd == "extract":
        extract(a.pdf)
    else:
        json.dump(draft(a.tsv, a.into), sys.stdout, ensure_ascii=False, indent=1)
        print()


if __name__ == "__main__":
    main()
