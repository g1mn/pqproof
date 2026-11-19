"""공개 JSON Schema(교차 리뷰 X45): schemas/*.schema.json 이 코드에서 만든 것과 같고, 지금 판이 쓰는 receipt.json·허용 목록 예시가
맞으며, 형식 1·모르는 칸·빠진 칸은 맞지 않는지 본다. 스키마 검사는 jsonschema 가 있을 때만(CI 는 설치한다)."""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402

GOLD = PROOF / "tests" / "golden" / "evidence"
SCHEMAS = PROOF / "schemas"
try:
    import jsonschema
except ImportError:
    jsonschema = None


class Generated(unittest.TestCase):
    def test_schema_files_match_the_code(self):
        r = subprocess.run([sys.executable, "-I", "-B", str(PROOF / "tests" / "make_schemas.py"), "--check"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


@unittest.skipUnless(jsonschema, "jsonschema 없음(CI 는 설치한다)")
class Validate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt2 = cls.validator("receipt-v2.schema.json")
        cls.receipt3 = cls.validator("receipt-v3.schema.json")
        cls.receipt = cls.validator("receipt-v4.schema.json")  # 지금 판이 쓰는 형식(두 트리·한 트리 꼴 또는 구현 검증 꼴)
        cls.allow = cls.validator("unconverted.schema.json")

    @staticmethod
    def validator(name):
        schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        return jsonschema.Draft202012Validator(schema)

    def errors(self, v, doc):
        return [e.message for e in v.iter_errors(doc)]

    def test_golden_format_2_fits_and_format_1_does_not(self):
        seen = set()
        for d in sorted(GOLD.iterdir()):
            if not (d / "receipt.json").is_file():
                continue
            r = json.loads((d / "receipt.json").read_text(encoding="utf-8"))
            fv = r.get("format_version")
            seen.add(fv)
            with self.subTest(fixture=d.name):
                by = {2: self.receipt2, 3: self.receipt3, 4: self.receipt}
                if fv not in by:
                    self.assertTrue(any("format_version" in m for m in self.errors(self.receipt2, r)))
                    continue
                self.assertEqual(self.errors(by[fv], r), [])
                for other in (v for k, v in by.items() if k != fv):
                    self.assertTrue(self.errors(other, r))  # 다른 형식 스키마에는 맞지 않는다(format_version·note·칸)
        self.assertLessEqual({2, 3, 4}, seen)

    def test_a_fresh_run_fits(self):
        tmp = tempfile.mkdtemp(prefix="pqproof-schema-")
        try:
            out = os.path.join(tmp, "out")
            env = {"EXPECT": "kem,sig", "ALLOW": str(PROOF / "examples" / "allowlist" / "unconverted.json"), "RECON": "none"}
            r, _, _ = prove.run(str(PROOF / "examples" / "classic"), str(PROOF / "examples" / "pqc"), prove.Params(env), out,
                                quiet=True)
            self.assertEqual(self.errors(self.receipt, r), [])
            on_disk = json.loads(pathlib.Path(out, "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(self.errors(self.receipt, on_disk), [])
            self.assertTrue(self.errors(self.receipt2, on_disk))  # 형식 4 증적은 형식 2·3 스키마에 맞지 않는다
            self.assertTrue(self.errors(self.receipt3, on_disk))
            from pqlite import impl
            key = impl.build_key(impl.load_manifest(), ["ntruplus/768"])
            ans = os.path.join(tmp, "answers.json")
            pathlib.Path(ans).write_text(impl.dumps(impl.example_answers(key, {"ntruplus/768": "2026-01"})), encoding="utf-8")
            r, code, _ = prove.impl_judge(ans, [], prove.Params({}, mode="impl"), os.path.join(tmp, "impl"), quiet=True)
            self.assertEqual((r["verdict"], code), ("pass", 0))
            self.assertEqual(self.errors(self.receipt, r), [])
            self.assertTrue(self.errors(self.receipt, dict(r, inputs={})))  # 구현 검증 꼴에 두 트리 칸을 더하면 맞지 않는다
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만

    def test_unknown_or_missing_fields_do_not_fit(self):
        r = json.loads((GOLD / "f2-v0.1.0" / "receipt.json").read_text(encoding="utf-8"))
        extra = dict(r, surprise=1)
        self.assertTrue(self.errors(self.receipt2, extra))
        self.assertTrue(self.errors(self.receipt2, dict(r, skip_dirs={"file": "artifacts/skip-dirs", "file_sha256": "0" * 64})))
        missing = {k: v for k, v in r.items() if k != "ruleset_sha256"}
        self.assertTrue(self.errors(self.receipt2, missing))
        bad_check = json.loads(json.dumps(r))
        bad_check["checks"][0]["status"] = "ok"
        self.assertTrue(self.errors(self.receipt2, bad_check))

    def test_allowlist_forms(self):
        example = json.loads((PROOF / "examples" / "allowlist" / "unconverted.json").read_text(encoding="utf-8"))
        self.assertEqual(self.errors(self.allow, example), [])
        self.assertEqual(self.errors(self.allow, example["unconverted"]), [])  # 배열만 있는 꼴
        self.assertTrue(self.errors(self.allow, {"unconverted": [{"where": "A.java:1"}]}))  # why 없음
        self.assertTrue(self.errors(self.allow, {"unconverted": [{"where": "A.java:1", "why": "x", "reviewed_at": "soon"}]}))
        self.assertTrue(self.errors(self.allow, "A.java:1"))


if __name__ == "__main__":
    unittest.main()
