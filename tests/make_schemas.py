# make_schemas.py: schemas/*.schema.json 을 코드에서 다시 만든다(손으로 고치지 않는다). receipt 스키마는 pqlite/receipt.py SCHEMA
# (--verify 가 쓰는 것)에 형식마다(2, 3, 4) 필수 칸을 더한 것이고, 허용 목록 스키마는 pqlite/allowlist.py 가 읽는 꼴을 적은 것이다.
# 형식 4 스키마는 두 꼴 중 하나(oneOf)다: 두 트리·한 트리 증적(SCHEMA, 형식 3과 같은 칸)과 구현 검증 증적(SCHEMA_IMPL, params.mode impl).
#   python3 -I -B tests/make_schemas.py           schemas/ 에 쓴다
#   python3 -I -B tests/make_schemas.py --check   지금 파일이 코드와 같은지만 본다(다르면 1)
"""Write the JSON Schemas under schemas/ from the code that reads the same files."""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from pqlite import receipt as R  # noqa: E402

BASE = "https://github.com/g1mn/pqproof/blob/main/schemas/"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
# 형식 2(0.1.0~)부터 도구가 늘 적는 맨 위 칸. --verify 의 SCHEMA 는 형식 1도 읽으려고 이 칸들을 필수로 두지 않는다.
# 형식마다 더한 칸(receipt.FORMAT_ONLY, 예: 형식 3의 skip_dirs)은 그 형식부터 필수이고 그 전 형식 스키마에는 없다
V2_REQUIRED = ("format_version", "tool_version", "ruleset_version", "ruleset_sha256", "allowlist", "excluded", "deck_meta",
               "test_paths")
ABOUT = {
    2: ("pqproof 0.1.0 and 0.1.1 (format_version 2)", R.NOTE_V2),
    3: ("pqproof 0.2.0 (format_version 3). Format 3 adds skip_dirs, the copy of scan/skip-dirs that the tree hash "
        "and the scanners used, and counts lines allowed by the name rule alone under r-allow", R.NOTE),
    4: ("pqproof 0.3.0 and later (format_version 4). A two-tree or one-tree receipt has the fields of format 3. An implementation "
        "check receipt (params.mode impl, pqproof impl judge) has the impl field instead of the tree fields and one check, i-kpqc", R.NOTE),
}
DESCRIBE = ("Generated from pqlite/receipt.py SCHEMA by tests/make_schemas.py. Fields named in guide/outputs.md as stable keep their "
            "meaning within a format_version. Text fields (checks[].title, expected, actual, note, warnings) are for people and can "
            "change in any release. pqproof --verify checks more than this schema: the receipt_id, every file hash and the "
            "consistency of the numbers.")


def receipt_body(fv):
    body = copy.deepcopy(R.SCHEMA)
    for key, since in R.FORMAT_ONLY.items():
        if fv < since:
            del body["properties"][key]
    for path, since in R.FORMAT_ONLY_NESTED.items():
        if fv < since:
            node = body
            for seg in path[:-1]:
                node = node["properties"][seg[:-2]]["items"] if seg.endswith("[]") else node["properties"][seg]
            node["properties"].pop(path[-1], None)  # 같은 꼴을 나눠 쓰는 칸(inputs.orig·fixed)은 한 번 지우면 둘 다 빠진다
    body["required"] = sorted(set(body["required"]) | set(V2_REQUIRED) | {k for k, s in R.FORMAT_ONLY.items() if fv >= s})
    body["properties"]["format_version"] = {"const": fv}
    body["properties"]["note"] = {"const": ABOUT[fv][1]}
    return body


def head(fv):
    return {"$schema": DRAFT, "$id": BASE + f"receipt-v{fv}.schema.json", "title": f"PQ-Proof receipt.json, evidence format {fv}",
            "description": f"Shape of receipt.json written by {ABOUT[fv][0]}. {DESCRIBE}"}


def receipt_schema(fv):
    return dict(head(fv), **receipt_body(fv))


def receipt_v2():
    return receipt_schema(2)


def receipt_v3():
    return receipt_schema(3)


def receipt_v4():
    impl = copy.deepcopy(R.SCHEMA_IMPL)
    impl["properties"]["format_version"] = {"const": 4}
    return dict(head(4), oneOf=[receipt_body(4), impl])


ENTRY = {
    "type": "object",
    "required": ["where", "why"],
    "properties": {
        "where": {"type": "string", "minLength": 1,
                  "description": "file:line, file:start-end, file:15,24-40, a path or a glob, relative to the fixed tree"},
        "why": {"type": "string", "minLength": 1, "description": "the reason a person can check, with when the entry goes away"},
        "what": {"type": "string"},
        "kind": {"type": "string", "description": "free word such as fallback, boundary or kept"},
        "reviewed_by": {"type": ["string", "null"], "description": "who read the entry (with reviewed_at)"},
        "reviewed_at": {"type": ["string", "null"], "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}",
                        "description": "ISO 8601 date or date and time"},
        "reviewed_digest": {"type": ["string", "null"], "pattern": "^[0-9a-f]{16}$",
                            "description": "first 16 hex digits printed by the run; optional on an entry"},
    },
}


def unconverted():
    entries = {"type": "array", "items": ENTRY}
    return {"$schema": DRAFT, "$id": BASE + "unconverted.schema.json",
            "title": "PQ-Proof allowlist (notes/unconverted.json)",
            "description": ("The allowlist that ALLOW= points to: a bare array of entries, or an object with the entries under "
                            "unconverted and one review pair at the top for the entries without their own. The top pair counts "
                            "only with a matching reviewed_digest. Fields not listed here are ignored today. Rules: "
                            "guide/allowlist.md."),
            "anyOf": [entries, {"type": "object", "required": ["unconverted"],
                                "properties": {"unconverted": entries,
                                               "reviewed_by": ENTRY["properties"]["reviewed_by"],
                                               "reviewed_at": ENTRY["properties"]["reviewed_at"],
                                               "reviewed_digest": ENTRY["properties"]["reviewed_digest"]}}]}


FILES = {"receipt-v2.schema.json": receipt_v2, "receipt-v3.schema.json": receipt_v3, "receipt-v4.schema.json": receipt_v4,
         "unconverted.schema.json": unconverted}


def text(make):
    return json.dumps(make(), indent=2, ensure_ascii=False) + "\n"


def main(argv):
    check = argv[:1] == ["--check"]
    bad = []
    for name, make in FILES.items():
        path = os.path.join(ROOT, "schemas", name)
        want = text(make)
        have = open(path, encoding="utf-8").read() if os.path.isfile(path) else None
        if check:
            if have != want:
                bad.append(name)
        elif have != want:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(want)
            print("wrote", path)
    if bad:
        print("schemas out of date (run python3 -I -B tests/make_schemas.py):", ", ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
