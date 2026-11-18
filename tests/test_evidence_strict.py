"""증적을 엄격하게 읽는가(교차 리뷰 X32·X61·X62): receipt.json 의 중복 키·BOM·뒤따르는 바이트·NaN·다시 쓴 꼴을 --verify 와
SARIF 변환이 거부하고, RFC 8785 정규화가 부록 벡터와 다른 구현(sarif.py, 있으면 node)과 같은 해시를 내며, 폴더나 receipt.json 이
없으면 종료 2 인지 본다. 시험 대상은 tests/golden/evidence 고정물의 사본이라 도구를 돌리지 않는다."""
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
sys.path.insert(0, str(PROOF / "src"))
from pqlite import receipt as R  # noqa: E402
from pqproof import sarif  # noqa: E402

GOLD = PROOF / "tests" / "golden" / "evidence"
FIXTURES = sorted(p.name for p in GOLD.iterdir() if (p / "receipt.json").is_file())
F2 = "f2-v0.1.0"


class Copies(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pqproof-strict-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만

    def copy(self, name=F2):
        d = os.path.join(self.tmp, name)
        shutil.copytree(GOLD / name, d)
        return d

    def fails(self, d):
        return "\n".join(w for ok, w in R.verify(d) if not ok)


class StrictReceipt(Copies):
    def edit(self, change):
        d = self.copy()
        p = pathlib.Path(d, "receipt.json")
        p.write_bytes(change(p.read_bytes()))
        return d

    def test_golden_fixtures_are_the_tool_serialization(self):
        for name in FIXTURES:
            with self.subTest(fixture=name):
                raw = (GOLD / name / "receipt.json").read_bytes()
                self.assertEqual(raw, R.dumps(R.loads_strict(raw)).encode("utf-8"))

    def test_duplicate_key_with_the_same_receipt_id_fails(self):
        # 앞 값을 읽는 파서는 fail, 뒤 값을 읽는 파이썬은 pass 를 본다. receipt_id 는 그대로라 예전 verify 는 통과시켰다
        d = self.edit(lambda b: b.replace(b"{\n", b'{\n  "verdict": "fail",\n', 1))
        r = json.loads(pathlib.Path(d, "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(R.compute_id(r), r["receipt_id"])
        self.assertIn("duplicate key 'verdict'", self.fails(d))

    def test_bom_trailing_bytes_and_whitespace_fail(self):
        for label, change, word in (("bom", lambda b: b"\xef\xbb\xbf" + b, "byte order mark"),
                                    ("trailing object", lambda b: b + b"{}\n", "Extra data"),
                                    ("trailing newline", lambda b: b + b"\n", "own serialization"),
                                    ("compact", lambda b: json.dumps(json.loads(b)).encode(), "own serialization")):
            with self.subTest(label):
                d = self.edit(change)
                self.assertIn(word, self.fails(d))
                shutil.rmtree(d)

    def test_nan_and_infinity_fail(self):
        for const in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(const=const):
                d = self.edit(lambda b: b.replace(b'"unused": 0', b'"unused": ' + const, 1))
                self.assertIn("is not a JSON number", self.fails(d))
                shutil.rmtree(d)

    def test_sarif_refuses_the_same_edits(self):
        for label, change in (("duplicate", lambda b: b.replace(b"{\n", b'{\n  "verdict": "fail",\n', 1)),
                              ("bom", lambda b: b"\xef\xbb\xbf" + b),
                              ("nan", lambda b: b.replace(b'"unused": 0', b'"unused": NaN', 1)),
                              ("compact", lambda b: json.dumps(json.loads(b), ensure_ascii=False).encode("utf-8"))):
            with self.subTest(label):
                d = self.edit(change)
                with self.assertRaises(sarif.EvidenceError):
                    sarif.convert(d)
                shutil.rmtree(d)

    def test_untouched_copy_still_converts(self):
        doc = sarif.convert(self.copy())
        self.assertEqual(doc["runs"][0]["properties"]["verdict"], "pass")


class Canonical(unittest.TestCase):
    def test_rfc8785_sorting_vector(self):
        # RFC 8785 3.2.3: 키는 UTF-16 코드 단위 순서. 코드 포인트 순서였다면 이모지(U+1F600)가 U+FB33 뒤로 갔다
        value = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh", "1": "One",
                 "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"}
        order = json.loads(R.canonical(value), object_pairs_hook=lambda pairs: [k for k, _ in pairs])
        self.assertEqual(order, ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"])
        self.assertEqual(R.canonical(value).decode("utf-8"), sarif.jcs(value))

    def test_rfc8785_appendix_b_numbers(self):
        vectors = {"0000000000000000": "0", "8000000000000000": "0", "0000000000000001": "5e-324", "8000000000000001": "-5e-324",
                   "7fefffffffffffff": "1.7976931348623157e+308", "ffefffffffffffff": "-1.7976931348623157e+308",
                   "4340000000000000": "9007199254740992", "c340000000000000": "-9007199254740992",
                   "4430000000000000": "295147905179352830000", "44b52d02c7e14af5": "9.999999999999997e+22",
                   "44b52d02c7e14af6": "1e+23", "44b52d02c7e14af7": "1.0000000000000001e+23",
                   "444b1ae4d6e2ef4e": "999999999999999700000", "444b1ae4d6e2ef4f": "999999999999999900000",
                   "444b1ae4d6e2ef50": "1e+21", "3eb0c6f7a0b5ed8c": "9.999999999999997e-7", "3eb0c6f7a0b5ed8d": "0.000001",
                   "41b3de4355555553": "333333333.3333332", "41b3de4355555554": "333333333.33333325",
                   "41b3de4355555555": "333333333.3333333", "41b3de4355555556": "333333333.3333334",
                   "41b3de4355555557": "333333333.33333343", "becbf647612f3696": "-0.0000033333333333333333",
                   "43143ff3c1cb0959": "1424953923781206.2"}
        for hexbits, want in vectors.items():
            with self.subTest(bits=hexbits):
                x = struct.unpack(">d", bytes.fromhex(hexbits))[0]
                self.assertEqual(R.canonical(x), want.encode())

    def test_integers_beyond_2_53_are_refused(self):
        self.assertEqual(R.canonical(2 ** 53), b"9007199254740992")
        self.assertEqual(R.canonical(-(2 ** 53)), b"-9007199254740992")
        for x in (2 ** 53 + 1, -(2 ** 53) - 1, 10 ** 30):
            with self.subTest(x=x):
                with self.assertRaises(ValueError):
                    R.canonical({"n": x})
                with self.assertRaises(sarif.EvidenceError):
                    sarif.jcs({"n": x})

    def test_two_python_implementations_agree_on_golden_receipts(self):
        for name in FIXTURES:
            with self.subTest(fixture=name):
                r = json.loads((GOLD / name / "receipt.json").read_text(encoding="utf-8"))
                self.assertEqual(sarif.receipt_id(r), r["receipt_id"])
                self.assertEqual(R.compute_id(r), r["receipt_id"])


NODE = shutil.which("node")
JS = r"""
const fs = require("fs"), crypto = require("crypto");
function c(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(c).join(",") + "]";
  return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + c(v[k])).join(",") + "}";
}
for (const p of process.argv.slice(1)) {
  const r = JSON.parse(fs.readFileSync(p, "utf8"));
  delete r.receipt_id;
  console.log(crypto.createHash("sha256").update(c(r), "utf8").digest("hex"));
}
"""


@unittest.skipUnless(NODE, "node 없음(다른 언어 구현으로 receipt_id 를 다시 계산하는 시험)")
class OtherLanguage(unittest.TestCase):
    def test_javascript_recomputes_every_golden_receipt_id(self):
        paths = [str(GOLD / n / "receipt.json") for n in FIXTURES]
        out = subprocess.run([NODE, "-e", JS] + paths, capture_output=True, text=True, timeout=60, check=True).stdout.split()
        want = [json.loads(pathlib.Path(p).read_text(encoding="utf-8"))["receipt_id"] for p in paths]
        self.assertEqual(out, want)


class ExitCodes(Copies):
    def run_verify(self, *args):
        return subprocess.run([sys.executable, "-I", "-B", str(PROOF / "pqlite" / "receipt.py"), "verify", *args],
                              capture_output=True, text=True, timeout=120)

    def test_missing_folder_or_receipt_is_an_input_error(self):
        r = self.run_verify(os.path.join(self.tmp, "nope"))
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("no such folder", r.stderr)
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        r = self.run_verify(empty)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("no receipt.json", r.stderr)

    def test_changed_evidence_is_exit_1(self):
        d = self.copy()
        p = pathlib.Path(d, "tables", "summary.csv")
        p.write_bytes(p.read_bytes() + b" ")
        self.assertEqual(self.run_verify(d).returncode, 1)
        self.assertEqual(self.run_verify(str(GOLD / F2)).returncode, 0)


class OpenerWithoutNofollow(Copies):
    """O_NOFOLLOW·dir_fd 가 없는 플랫폼(Windows)의 열기 경로를 이 기계에서 강제로 태운다."""

    def test_fallback_reads_evidence_and_refuses_links(self):
        with mock.patch.object(R, "NOFOLLOW_FD", False):
            self.assertEqual(self.fails(str(GOLD / F2)), "")
            d = self.copy()
            target = pathlib.Path(d, "tables", "summary.csv")
            moved = pathlib.Path(self.tmp, "summary.csv")
            shutil.move(str(target), moved)
            os.symlink(moved, target)
            self.assertIn("tables/summary.csv", self.fails(d))


if __name__ == "__main__":
    unittest.main()
