"""mappings/*.json(기준 대응표) 형식 검사: 상태 값, 출처, 근거 파일·이름이 이 저장소에 실제로 있는지.

가이드처럼 아직 나오지 않은 문서는 published false 이고 항목이 없어야 한다(내용을 추측해 적지 않는다).
"""
import json
import pathlib
import runpy
import subprocess
import sys
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
MAPS = sorted((PROOF / "mappings").glob("*.json"))
STATUSES = ("covered", "partial", "gap", "na")
ITEM_KEYS = {"id", "ref", "quote", "about_en", "about_ko", "status", "note_en", "note_ko", "evidence", "remaining_en", "remaining_ko"}


class Mappings(unittest.TestCase):
    def test_there_are_mappings(self):
        self.assertTrue(MAPS)
        readme = (PROOF / "mappings" / "README.md").read_text(encoding="utf-8")
        for p in MAPS:
            self.assertIn(p.name, readme, "mappings/README.md lists every mapping")

    def test_each_mapping(self):
        for p in MAPS:
            with self.subTest(mapping=p.name):
                d = json.loads(p.read_text(encoding="utf-8"))
                self.assertEqual(d["schema"], "pqproof-mapping 1")
                self.assertEqual(d["id"], p.stem)
                self.assertTrue(d["source"]["url"].startswith("https://"))
                for k in ("title_en", "title_ko", "wording_en", "wording_ko", "checked"):
                    self.assertTrue(d[k], k)
                if not d["published"]:
                    self.assertEqual(d["items"], [], "an unpublished document has no items")
                    continue
                self.assertTrue(d["items"])
                ids = [it["id"] for it in d["items"]]
                self.assertEqual(len(ids), len(set(ids)))
                for it in d["items"]:
                    self.check_item(it)

    def test_print_mapping_table(self):
        # tools/print_mapping.py는 Markdown 머리글 아래에 항목마다 한 줄을 출력한다.
        p = MAPS[0]
        proc = subprocess.run(
            [sys.executable, "-I", str(PROOF / "tools" / "print_mapping.py"), str(p)],
            capture_output=True, encoding="utf-8",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.splitlines()
        self.assertEqual(lines[0], "| id | reference | status | note | remaining |")
        self.assertEqual(lines[1], "| --- | --- | --- | --- | --- |")
        items = json.loads(p.read_text(encoding="utf-8"))["items"]
        self.assertEqual(len(lines), 2 + len(items))
        for it, line in zip(items, lines[2:]):
            self.assertTrue(line.startswith(f"| {it['id']} |"), line)
        self.assertEqual(
            lines[2],
            "| R1 | section 4.1, page 6 | partial | "
            "c-classic counts classical public-key lines left without a recorded reason and "
            "a-cbom blocks classical CBOM rows, while a hybrid TLS group passes b-tls. | "
            "Risk classes and dates are not encoded. |",
        )

    def test_to_markdown_escapes_pipes_and_flattens_note_newlines(self):
        to_markdown = runpy.run_path(
            str(PROOF / "tools" / "print_mapping.py")
        )["to_markdown"]
        doc = {
            "items": [
                {
                    "id": "R1",
                    "ref": {"section": "2.1"},
                    "status": "partial",
                    "note_en": "first | second\nthird",
                    "remaining_en": ["one", "two"],
                }
            ]
        }
        self.assertEqual(
            to_markdown(doc),
            "| id | reference | status | note | remaining |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| R1 | section 2.1 | partial | first \\| second third | one; two |\n",
        )

    def test_print_mapping_usage_is_korean(self):
        proc = subprocess.run(
            [sys.executable, "-I", str(PROOF / "tools" / "print_mapping.py")],
            capture_output=True, encoding="utf-8",
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, "사용법: print_mapping.py <mappings/file.json>\n")

    def check_item(self, it):
        with self.subTest(item=it["id"]):
            self.assertEqual(set(it), ITEM_KEYS)
            self.assertIn(it["status"], STATUSES)
            self.assertTrue(it["ref"] and it["about_en"] and it["about_ko"] and it["note_en"] and it["note_ko"])
            self.assertEqual(len(it["remaining_en"]), len(it["remaining_ko"]))
            if it["status"] in ("covered", "partial"):
                self.assertTrue(it["evidence"], "covered and partial need evidence")
            if it["status"] in ("partial", "gap"):
                self.assertTrue(it["remaining_en"], "partial and gap say what is missing")
            for e in it["evidence"]:
                text = (PROOF / e["file"]).read_text(encoding="utf-8")
                for sym in e["symbols"]:
                    self.assertIn(sym, text, f"{e['file']} has no {sym!r}")


if __name__ == "__main__":
    unittest.main()
