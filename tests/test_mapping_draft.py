"""tools/mapping_draft.py: 고른 항목 TSV 로 대응표 초안을 만들고, 초안은 상태 "todo" 와 "_suggest" 때문에 대응표 검사를 통과하지 못한다."""
import importlib.util
import pathlib
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("mapping_draft", PROOF / "tools" / "mapping_draft.py")
md = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md)
GUIDE = PROOF / "mappings" / "kisa-pqc-guide.json"
HEAD = "\t".join(md.TSV_COLUMNS) + "\n"


class Draft(unittest.TestCase):
    def run_draft(self, body):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "items.tsv"
            p.write_text(HEAD + body, encoding="utf-8")
            return md.draft(p, GUIDE)

    def test_stubs_and_suggestions(self):
        doc = self.run_draft("G1\t3\t2.1\t전환 대상 암호 자산 목록을 만든다\t암호 자산 목록을 만든다\t\n"
                             "G2\t7\t3.4\t하이브리드 방식을 쓴다\t하이브리드를 쓴다\tUse hybrid.\n")
        self.assertEqual(doc["id"], "kisa-pqc-guide")
        g1, g2 = doc["items"]
        self.assertEqual((g1["status"], g1["ref"]), ("todo", {"page": 3, "section": "2.1"}))
        self.assertEqual(set(g1) - {"_suggest"}, set(__import__("test_mappings").ITEM_KEYS))
        self.assertIn("inventory", g1["_suggest"]["topics"])
        like = g1["_suggest"]["like"]
        self.assertTrue(like and all("inventory" in x["shared_topics"] and x["evidence"] for x in like), like)
        self.assertIn("hybrid", g2["_suggest"]["topics"])

    def test_empty_quote_or_repeated_id_stops(self):
        with self.assertRaises(SystemExit):
            self.run_draft("G1\t3\t2.1\t\t목록\t\n")
        with self.assertRaises(SystemExit):
            self.run_draft("G1\t3\t2.1\tq\ta\t\nG1\t4\t2.2\tq\ta\t\n")


if __name__ == "__main__":
    unittest.main()
