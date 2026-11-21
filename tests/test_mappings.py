"""mappings/*.json(기준 대응표) 형식 검사: 상태 값, 출처, 근거 파일·이름이 이 저장소에 실제로 있는지.

가이드처럼 아직 나오지 않은 문서는 published false 이고 항목이 없어야 한다(내용을 추측해 적지 않는다).
"""
import json
import pathlib
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
