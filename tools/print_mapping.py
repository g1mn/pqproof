# print_mapping.py: mappings/<id>.json 한 파일을 Markdown 표로 찍는다(표준 라이브러리만). 검토자가 풀 리퀘스트에서 대응표를 읽도록.
#   python3 -I tools/print_mapping.py mappings/nist-ir8547.json > table.md
# 열: id, reference(section·table·page·note), status, note(영어), remaining(영어). 항목마다 한 줄.
"""mappings/*.json 파일의 항목을 Markdown 표로 찍는다(id, reference, status, note, remaining)."""
import json
import pathlib
import sys


def cell(text):
    """표의 셀 하나를 만든다: 줄바꿈은 없애고, 파이프는 이스케이프한다."""
    return " ".join(str(text).split()).replace("|", "\\|")


def reference(ref):
    """ref 객체를 쓴다: 'section 4.1, page 6'."""
    return ", ".join(f"{k} {v}" for k, v in ref.items() if v is not None)


def to_markdown(doc):
    lines = ["| id | reference | status | note | remaining |", "| --- | --- | --- | --- | --- |"]
    for it in doc["items"]:
        remaining = "; ".join(it["remaining_en"]) if it["remaining_en"] else ""
        cells = [it["id"], reference(it["ref"]), it["status"], it["note_en"], remaining]
        lines.append("| " + " | ".join(cell(c) for c in cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) != 2:
        sys.stderr.reconfigure(encoding="utf-8")
        print("사용법: print_mapping.py <mappings/file.json>", file=sys.stderr)
        return 2
    doc = json.loads(pathlib.Path(argv[1]).read_text(encoding="utf-8"))
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdout.write(to_markdown(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
