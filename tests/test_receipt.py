# 일부 from g1mn/pq-proof 7b7803f (MIT): test_numbers_are_written_as_ecmascript_writes_them·test_validate_names_each_problem의
# 시험 벡터는 pq-proof tests/test_receipt.py에서 가져왔다(모듈 이름만 R로). 나머지는 오프라인판에서 새로 썼다.
"""검증 증적: RFC 8785 정규화(PQ-Proof 시험 벡터), 스키마 검사, 그리고 실제 검증 증적의 변조 탐지."""
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import zipfile

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import receipt as R  # noqa: E402
from pqlite import tlsprobe as T  # noqa: E402


class Canonical(unittest.TestCase):
    """from g1mn/pq-proof 7b7803f (MIT) tests/test_receipt.py Canonical: 다른 언어 검증기와 같은 receipt_id가 나와야 한다."""

    def test_numbers_are_written_as_ecmascript_writes_them(self):
        for x, want in ((0.0, "0"), (-0.0, "0"), (5e-06, "0.000005"), (1e-07, "1e-7"), (0.015523, "0.015523"),
                        (1e21, "1e+21"), (1e20, "100000000000000000000"), (123.0, "123"), (0.1, "0.1"),
                        (1.5e300, "1.5e+300"), (-2.5, "-2.5"), (7, "7"), (1.2345678901234567e-05, "0.000012345678901234568"),
                        (True, "true"), (None, "null")):
            with self.subTest(x=x):
                self.assertEqual(R.canonical(x), want.encode())
        self.assertEqual(R.canonical({"b": [1.0, "é\n"], "a": {}}), '{"a":{},"b":[1,"é\\n"]}'.encode())

    def test_korean_values_stay_utf8(self):
        self.assertEqual(R.canonical({"k": "통과"}), '{"k":"통과"}'.encode("utf-8"))


class Schema(unittest.TestCase):
    def test_validate_names_each_problem(self):
        schema = R.strict(a=R.SHA, b={"type": "array", "minItems": 1, "items": R.INT})
        self.assertEqual(R.validate({"a": "0" * 64, "b": [1]}, schema), [])
        self.assertEqual(len(R.validate({"a": "xyz", "b": [True], "c": 1}, schema)), 3)
        self.assertEqual(R.validate({"b": []}, schema), ["receipt: missing a", "receipt.b: needs at least 1 items"])

    def test_artifact_paths_stay_inside(self):
        art = R.Artifacts(tempfile.gettempdir())
        for bad in ("artifacts/../x", "/etc/passwd", "other/x", "artifacts/a b"):
            with self.assertRaises(ValueError):
                art._check(bad)


def small_tree(root, files):
    for path, text in files.items():
        p = pathlib.Path(root, path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


@unittest.skipUnless(os.access(str(T.host_binary()), os.X_OK), "tls_probe 바이너리 없음")
class Tamper(unittest.TestCase):
    """zip 입력 + TLS 대상·기준선 + EXTRA_EV로 검증 증적 하나를 만들고, 한 곳씩 바꿔 verify가 잡는지 본다."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name
        orig = small_tree(os.path.join(t, "o"), {"app/README.md": "x\n", "app/run.sh": "echo hi\n"})
        z = os.path.join(t, "fixed.zip")
        with zipfile.ZipFile(z, "w") as f:
            f.writestr("app/README.md", "x\n")
            f.writestr("app/run.sh", "echo hi\n")
            f.writestr("app/server.py", "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n")
        extra = os.path.join(t, "extra-test-log.txt")
        pathlib.Path(extra).write_text("app tests: ok\n")
        cls.runner = T.HostRunner(os.path.join(t, "srv"))
        os.makedirs(cls.runner.tls_dir)
        cls.runner.run(["cert", "-hosts=localhost,127.0.0.1", cls.runner.tls_dir])
        a, b = cls.runner.ref_addr(), cls.runner.ref_addr()
        cls.runner.start(T.serve_args(a, T.REFERENCE_POSITIVE, cls.runner.path("cert.pem"), cls.runner.path("key.pem")))
        cls.runner.start(T.serve_args(b, "X25519", cls.runner.path("cert.pem"), cls.runner.path("key.pem")))
        env = {"EXPECT": "tls", "TLS_TARGETS": f"{a}@localhost#{cls.runner.path('ca.pem')}", "TLS_TARGETS_ORIG": b,
               "EXTRA_EV": extra}
        cls.out = os.path.join(t, "out")
        cls.r, cls.code, _ = prove.run(os.path.join(orig, "app"), z, prove.Params(env), cls.out, quiet=True)

    @classmethod
    def tearDownClass(cls):
        cls.runner.stop()
        cls.tmp.cleanup()

    def copy(self, name):
        d = os.path.join(self.tmp.name, name)
        shutil.copytree(self.out, d, symlinks=True)
        return d

    def fails(self, d):
        return [w for ok, w in R.verify(d) if not ok]

    def test_run_passes_and_records_everything(self):
        self.assertEqual((self.r["verdict"], self.code), ("pass", 0), self.r["checks"])
        self.assertEqual(self.fails(self.out), [])
        self.assertEqual(self.r["inputs"]["fixed"]["kind"], "zip")
        self.assertEqual(self.r["inputs"]["fixed"]["root"], "in/fixed/app")
        self.assertEqual(self.r["tls"]["baseline"][0]["hybrid"]["kind"], "failed")  # 기준선(X25519 전용)은 기록만
        # 교차 확인 칸은 늘 있다. OpenSSL 3.5 이상이면 맞았는지(True), 아니면(우분투 러너의 3.0, 맥 LibreSSL) null 과 '교차 확인 불가'
        t0 = self.r["tls"]["targets"][0]
        self.assertIn("openssl_agrees", t0)
        if prove.openssl_35(prove.Params({}).openssl):
            self.assertTrue(t0["openssl_agrees"])
        else:
            self.assertIsNone(t0["openssl_agrees"])
            self.assertIn("교차 확인 불가", t0.get("openssl_note", ""))
        self.assertEqual(len(self.r["extra"]), 1)
        self.assertTrue(any("server.py" in s for s in self.r["tls"]["signals"]))

    def test_changed_verdict_breaks_the_id(self):
        d = self.copy("verdict")
        p = os.path.join(d, "receipt.json")
        r = json.loads(pathlib.Path(p).read_text())
        r["verdict"] = "fail"
        pathlib.Path(p).write_text(json.dumps(r))
        bad = self.fails(d)
        self.assertTrue(any("receipt_id" in w for w in bad))
        self.assertTrue(any("checks give" in w for w in bad))

    def test_residue_hash_in_tools_must_match_the_copy(self):
        d = self.copy("residue-tool")
        p = os.path.join(d, "receipt.json")
        r = json.loads(pathlib.Path(p).read_text())
        res = next(t for t in r["tools"] if t["name"] == "residue")
        self.assertEqual(res["sha256"], r["java"]["script_sha256"])
        res["sha256"] = "0" * 64
        r["receipt_id"] = R.compute_id(r)  # id 를 다시 맞춰도 칸끼리 어긋난 것은 잡는다
        pathlib.Path(p).write_text(json.dumps(r))
        self.assertTrue(any("tools[] lists the residue script" in w for w in self.fails(d)))

    def test_changed_artifact_unlisted_file_tree_and_page(self):
        d = self.copy("files")
        with open(os.path.join(d, "artifacts", "weakening.json"), "a") as f:
            f.write(" ")
        pathlib.Path(d, "artifacts", "note.txt").write_text("added later\n")
        with open(os.path.join(d, "in", "fixed", "app", "run.sh"), "a") as f:
            f.write("rm x\n")
        with open(os.path.join(d, "receipt.html"), "a") as f:
            f.write("<!-- -->")
        bad = "\n".join(self.fails(d))
        self.assertIn("artifacts/weakening.json", bad)
        self.assertIn("artifacts/note.txt: in the receipt directory but not in the receipt", bad)
        self.assertIn("inputs.fixed: tree hashes to", bad)
        self.assertIn("receipt.html differs", bad)

    def test_page_is_self_contained(self):
        page = pathlib.Path(self.out, "receipt.html").read_text()
        self.assertNotRegex(page, r"(?i)<(?:script|link|img)[^>]+(?:src|href)=\"?https?:")
        self.assertIn('data-theme="dark"', page)
        self.assertIn("word-break:keep-all", page)
        frag = pathlib.Path(self.out, "tables", "fragment.html").read_text()
        self.assertTrue(frag.startswith('<section class="pqcproof">'))
        self.assertNotIn("<script", frag)


if __name__ == "__main__":
    unittest.main()
