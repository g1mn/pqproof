"""하위 호환: 옛 판이 쓴 검증 증적(tests/golden/evidence)을 지금 --verify 가 계속 읽고, 바이트 하나 바뀐 것도 계속 잡는가.

고정물은 첫 공개본, 사람 확인 칸이 생긴 공개본, D1·D2 고침 뒤 0.1.0 전 공개본, 0.1.0(형식 2)이 쓴 증적이다
(manifest.json). make_fixture.py 가 개인 경로를 바꾸고 해시를 다시 계산했을 뿐 판정·검사·숫자는 그 판이 쓴 그대로다.
형식을 바꾸는 릴리스는 지금 판의 증적을 make_fixture.py 로 하나 더 남기고, 이 시험이 계속 통과해야 한다."""
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
from pqlite import receipt as R  # noqa: E402

GOLD = PROOF / "tests" / "golden" / "evidence"
MANIFEST = json.loads((GOLD / "manifest.json").read_text(encoding="utf-8"))


class LegacyEvidence(unittest.TestCase):
    def test_every_fixture_still_verifies(self):
        self.assertGreaterEqual(len(MANIFEST["fixtures"]), 4)
        for fx in MANIFEST["fixtures"]:
            with self.subTest(fixture=fx["name"]):
                d = GOLD / fx["name"]
                bad = [w for ok, w in R.verify(str(d)) if not ok]
                self.assertEqual(bad, [])
                r = json.loads((d / "receipt.json").read_text(encoding="utf-8"))
                self.assertEqual(R.format_version(r), fx["format_version"])
                self.assertEqual((r["receipt_id"], r["verdict"]), (fx["receipt_id"], fx["verdict"]))
                self.assertEqual({c["id"]: c["status"] for c in r["checks"]}, fx["checks"])

    def test_each_generation_is_covered(self):
        notes = {json.loads((GOLD / fx["name"] / "receipt.json").read_text(encoding="utf-8"))["note"]
                 for fx in MANIFEST["fixtures"]}
        self.assertIn(R.NOTE_PUBLIC1, notes)  # 첫 공개본
        self.assertIn(R.NOTE, notes)          # 사람 확인 칸 이후
        self.assertIn(2, {fx["format_version"] for fx in MANIFEST["fixtures"]}, "no format 2 fixture yet")

    def test_old_page_keeps_its_words(self):
        fx = next(x for x in MANIFEST["fixtures"] if x["name"] == "f1-public-a")
        page = (GOLD / fx["name"] / "receipt.html").read_text(encoding="utf-8")
        self.assertIn("<title>PQC 전환 영수증</title>", page)
        self.assertIn("bash prove.sh --verify", page)

    def test_a_changed_byte_is_still_caught(self):
        tmp = tempfile.mkdtemp(prefix="pqproof-gold-")
        try:
            for fx in MANIFEST["fixtures"]:
                with self.subTest(fixture=fx["name"]):
                    d = os.path.join(tmp, fx["name"])
                    shutil.copytree(GOLD / fx["name"], d)
                    p = os.path.join(d, "tables", "summary.csv")
                    data = bytearray(pathlib.Path(p).read_bytes())
                    data[-2] ^= 1
                    pathlib.Path(p).write_bytes(bytes(data))
                    bad = "\n".join(w for ok, w in R.verify(d) if not ok)
                    self.assertIn("tables/summary.csv", bad)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만


if __name__ == "__main__":
    unittest.main()
