"""pqproof 패키지: SARIF 변환(sarif.py), 바깥 도구 점검(deps.py), 콘솔 명령(cli.py).

SARIF 스키마 검사는 jsonschema 와 스키마 파일(환경 변수 SARIF_SCHEMA)이 있을 때 한다. 없으면 건너뛰고 unittest 가 skipped 로 센다
(CI 는 둘 다 넣고 skipped 0 을 확인한다: 건너뛴 시험은 통과로 세지 않는다).
"""
import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PROOF = pathlib.Path(__file__).resolve().parent.parent
try:
    import pqproof  # noqa: F401  설치본
except ImportError:
    sys.path.insert(0, str(PROOF / "src"))  # 저장소 체크아웃
from pqproof import cli, deps, sarif  # noqa: E402

EXAMPLES = PROOF / "examples"


def prove(orig, fixed, out, **env):
    e = {k: v for k, v in os.environ.items() if k not in ("ALLOW", "EXCLUDE", "REQUIRE_REVIEW", "TLS_TARGETS", "OUT")}
    e.update({"OUT": str(out), "ALLOW": "none", "RECON": "none", "PYTHON": sys.executable}, **env)
    return subprocess.run(["bash", str(PROOF / "prove.sh"), str(orig), str(fixed)], env=e, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL).returncode


@unittest.skipUnless(shutil.which("bash") and deps.find_openssl(os.environ)[0], "bash 또는 openssl 없음")
class SarifTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-sarif-")
        cls.fail_out = pathlib.Path(cls.tmp, "cc")
        cls.pass_out = pathlib.Path(cls.tmp, "cp")
        cls.fail_code = prove(EXAMPLES / "classic", EXAMPLES / "classic", cls.fail_out)
        cls.pass_code = prove(EXAMPLES / "classic", EXAMPLES / "pqc", cls.pass_out)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def test_classic_to_classic_lists_every_left_position(self):
        self.assertEqual(self.fail_code, 1)
        rec = json.loads((self.fail_out / "receipt.json").read_text(encoding="utf-8"))
        doc = sarif.convert(str(self.fail_out))
        run = doc["runs"][0]
        self.assertEqual(doc["version"], "2.1.0")
        by = {}
        for r in run["results"]:
            by.setdefault(r["ruleId"], []).append(r)
        self.assertEqual(len(by["a-cbom"]), rec["cbom"]["fixed"]["blocking"])
        residue_code = sum(v["code"] for v in rec["java"]["fixed"]["families"].values())
        self.assertEqual(len(by["c-classic"]), residue_code)
        self.assertTrue(all(r["level"] == "error" for r in run["results"]))
        fps = [r["partialFingerprints"][sarif.FINGERPRINT] for r in run["results"]]
        self.assertEqual(len(fps), len(set(fps)))
        self.assertEqual(run["properties"]["verdict"], "fail")
        self.assertEqual(run["properties"]["receiptId"], rec["receipt_id"])

    def test_skipped_checks_are_not_counted_as_passed(self):
        run = sarif.convert(str(self.pass_out))["runs"][0]
        self.assertEqual(self.pass_code, 0)
        self.assertEqual(run["results"], [])
        self.assertIn("b-tls", run["properties"]["notCountedAsPass"])
        notes = run["invocations"][0]["toolExecutionNotifications"]
        self.assertTrue(any(n["descriptor"]["id"] == "b-tls" and "not counted as passed" in n["message"]["text"] for n in notes))

    def test_uri_prefix_and_anchor(self):
        run = sarif.convert(str(self.fail_out), uri_prefix="./services/app", anchor="services/app/pom.xml")["runs"][0]
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]}
        self.assertTrue(all(u.startswith("services/app/") for u in uris), uris)
        self.assertTrue(any(r["ruleId"] == "c-expect" for r in run["results"]))  # 위치 없는 실패 검사는 anchor 1행으로
        self.assertEqual(sarif.norm_prefix("."), "")
        self.assertEqual(sarif.norm_prefix(".github/x"), ".github/x/")

    def test_changed_evidence_is_refused(self):
        bad = pathlib.Path(self.tmp, "bad")
        shutil.copytree(self.fail_out, bad)
        rec = json.loads((bad / "receipt.json").read_text(encoding="utf-8"))
        rec["cbom"]["fixed"]["blocking"] = 0
        (bad / "receipt.json").write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(sarif.EvidenceError):
            sarif.convert(str(bad))
        bad2 = pathlib.Path(self.tmp, "bad2")
        shutil.copytree(self.fail_out, bad2)
        csv_path = bad2 / rec["cbom"]["fixed"]["csv"]
        csv_path.write_bytes(csv_path.read_bytes() + b"\n")
        with self.assertRaises(sarif.EvidenceError):
            sarif.convert(str(bad2))

    def test_rules_outside_c_classic_are_not_results(self):
        # AES-128 은 residue 표(G-AES128)에 나오지만 c-classic 판정에 안 들어간다. c-classic 이 다른 줄로 실패해도
        # AES-128 줄은 SARIF 결과로 내면 안 된다(고전 원본 + AES 파일)
        fixed = pathlib.Path(self.tmp, "aes-fixed")
        shutil.copytree(EXAMPLES / "classic", fixed)
        (fixed / "src/main/java/demo/sealer/Tokens.java").write_text(
            "package demo.sealer;\n\nimport javax.crypto.KeyGenerator;\n\nfinal class Tokens {\n"
            "    byte[] key() throws Exception {\n        KeyGenerator g = KeyGenerator.getInstance(\"AES\");\n        g.init(128);\n"
            "        return g.generateKey().getEncoded();\n    }\n}\n", encoding="utf-8")
        out = pathlib.Path(self.tmp, "aes")
        prove(EXAMPLES / "classic", fixed, out)
        residue = (out / "artifacts" / "residue-fixed.txt").read_text(encoding="utf-8")
        self.assertRegex(residue, r"GEN\s+G-AES128\s+LEFT")  # 전제: 표에는 남는다
        rec = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
        st = {c["id"]: c["status"] for c in rec["checks"]}
        run = sarif.convert(str(out))["runs"][0]
        self.assertEqual(st["c-classic"], "fail")
        cc = [r for r in run["results"] if r["ruleId"] == "c-classic"]
        self.assertTrue(cc)
        self.assertFalse([r for r in cc if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("Tokens.java")])

    def test_jcs_matches_the_tool(self):
        rec = json.loads((self.pass_out / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(sarif.receipt_id(rec), rec["receipt_id"])
        self.assertEqual(sarif.jcs({"b": [1, True, None], "a": "x"}), '{"a":"x","b":[1,true,null]}')

    def test_schema(self):
        schema_path = os.environ.get("SARIF_SCHEMA")
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema 없음(CI 는 설치한다)")
        if not schema_path or not os.path.isfile(schema_path):
            self.skipTest("SARIF_SCHEMA 파일 없음(CI 는 내려받아 SHA-256 을 맞춘 뒤 넘긴다)")
        schema = json.loads(pathlib.Path(schema_path).read_text(encoding="utf-8"))
        validator = jsonschema.validators.validator_for(schema)(schema)
        for out in (self.fail_out, self.pass_out):
            for lang in ("en", "ko"):
                errors = list(validator.iter_errors(sarif.convert(str(out), lang=lang)))
                self.assertEqual(errors, [], [e.message for e in errors[:3]])


class DepsTest(unittest.TestCase):
    def test_missing_openssl_is_a_clear_error(self):
        with mock.patch.object(deps, "OPENSSL_CANDIDATES", ()), mock.patch.object(deps.shutil, "which",
                                                                               side_effect=lambda n: None if n == "openssl" else "/bin/" + n):
            rep = deps.check(env={}, bin_dir=None)
        self.assertFalse(rep.ok())
        self.assertTrue(any("openssl not found" in e for e in rep.errors), rep.errors)

    def test_old_openssl_is_a_warning(self):
        with mock.patch.object(deps, "find_openssl", return_value=("/usr/bin/openssl", (3, 0, 13), "OpenSSL 3.0.13")):
            rep = deps.check(env={}, bin_dir=None)
        self.assertTrue(any("below 3.5" in w for w in rep.warnings), rep.warnings)

    def test_tls_targets_without_probe(self):
        empty = tempfile.mkdtemp(prefix="pqproof-bin-")
        try:
            rep = deps.check(env={"TLS_TARGETS": "127.0.0.1:8443"}, bin_dir=empty)
        finally:
            os.rmdir(empty)
        self.assertTrue(any("tls_probe" in e and "SHA256SUMS" in e for e in rep.errors), rep.errors)

    def test_keystore_without_keytool(self):
        d = tempfile.mkdtemp(prefix="pqproof-ks-")
        try:
            pathlib.Path(d, "app.p12").write_bytes(b"x")
            self.assertTrue(deps.has_keystores([d]))
            with mock.patch.object(deps.shutil, "which", side_effect=lambda n: None if n == "keytool" else "/bin/" + n):
                rep = deps.check(env={}, inputs=[d], bin_dir=None)
            self.assertTrue(any("keytool" in w for w in rep.warnings), rep.warnings)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class CliTest(unittest.TestCase):
    def test_usage_and_version(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main([]), 2)
            self.assertEqual(cli.main(["--help"]), 0)
            self.assertEqual(cli.main(["--version"]), 0)
            self.assertEqual(cli.main(["--nope"]), 2)
            self.assertEqual(cli.main(["only-one-arg"]), 2)
        self.assertIn("pqproof 0.1.0", out.getvalue())
        self.assertIn("never counted as passed", out.getvalue())

    def test_tool_root_found(self):
        root = cli.tool_root()
        self.assertIsNotNone(root)
        self.assertTrue(os.path.isfile(os.path.join(root, "prove.sh")))
        self.assertTrue(os.path.isfile(os.path.join(root, "scan", "cbom-scan.sh")))

    def test_sarif_subcommand_refuses_missing_folder(self):
        missing = os.path.join(tempfile.gettempdir(), "no-such-pqproof-out-" + hashlib.sha256(b"x").hexdigest()[:8])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["sarif", missing]), 2)
        self.assertIn("no receipt.json", err.getvalue())


if __name__ == "__main__":
    unittest.main()
