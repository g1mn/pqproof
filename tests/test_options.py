"""0.2.0 의 새 설정과 종료 코드: FAIL_ON_REVIEW·EXPECT_FROM(교차 리뷰 X30), 도구 오류 종료 4(X62), 허용 항목 만료·결재 번호·
모르는 칸(X31), REVIEW_MAX_AGE_DAYS, 크기 한도 기록(X56), 열지 못한 키 자료와 REQUIRE_RESOLVED(X27).
examples/ 를 임시 폴더에 복사해 prove.run 을 돌리고, 증적을 --verify 와 같은 식으로 다시 맞춰 본다."""
import datetime
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import allowlist as al  # noqa: E402
from pqlite import receipt as rc  # noqa: E402

CLASSIC = str(PROOF / "examples" / "classic")
PQC = str(PROOF / "examples" / "pqc")
SEALER = "src/main/java/demo/sealer/Sealer.java"


def st(r):
    return {c["id"]: c["status"] for c in r["checks"]}


@unittest.skipUnless(shutil.which("bash") and prove.default_openssl(), "bash 또는 openssl 없음")
class Runs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-options-")
        cls.cache = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def tree(self, name, files, base=PQC):
        d = os.path.join(self.tmp, name)
        shutil.copytree(base, d)
        for rel, text in files.items():
            p = pathlib.Path(d, rel)
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(text, bytes):
                p.write_bytes(text)
            else:
                p.write_text(text, encoding="utf-8")
        return d

    def run_(self, name, fixed, orig=CLASSIC, **env):
        e = {"EXPECT": "kem,sig", "ALLOW": "none", "RECON": "none"}
        e.update(env)
        out = os.path.join(self.tmp, "out-" + name)
        r, code, lines = prove.run(orig, fixed, prove.Params(e), out, self.cache, quiet=True)
        bad = [w for ok, w in rc.verify(out) if not ok]
        self.assertEqual(bad, [], f"{name}: the evidence does not re-verify")
        return r, code, lines

    # X30 -------------------------------------------------------------------------------------
    def test_fail_on_review_gives_exit_5_and_keeps_the_verdict(self):
        fx = self.tree("review", {"vendor/acme/key.go": 'package acme\nimport "crypto/rsa"\nvar _ = rsa.GenerateKey\n'})
        r, code, lines = self.run_("review", fx)
        self.assertEqual((r["verdict"], code, st(r)["a-input"]), ("pass", 0, "review"))
        verdict = next(x for x in lines if x.startswith("VERDICT="))
        self.assertIn("needs review: a-input", verdict)
        r, code, _ = self.run_("review-strict", fx, FAIL_ON_REVIEW="1")
        self.assertEqual((r["verdict"], code, r["params"]["fail_on_review"]), ("pass", prove.EXIT_REVIEW, True))
        _, code, _ = self.run_("clean-strict", PQC, FAIL_ON_REVIEW="1")
        self.assertEqual(code, 0)

    def test_expect_from_api_does_not_count_bare_constants(self):
        # 암호 호출을 지우고 상수만 남긴 판(교차 리뷰 X30 hollow): 이름 줄로 세면 통과, API 로 세면 실패
        hollow = ("package demo.sealer;\n\nfinal class Sealer {\n    private static final String KEM_KEYS = \"ML-KEM-768\";\n"
                  "    private static final String SIGNING_KEYS = \"ML-DSA-65\";\n}\n")
        fx = self.tree("hollow", {SEALER: hollow})
        os.remove(os.path.join(fx, "tools", "sign_manifest.py"))
        r, _, _ = self.run_("hollow-names", fx)
        self.assertEqual(st(r)["c-expect"], "pass")
        r, _, _ = self.run_("hollow-api", fx, EXPECT_FROM="api")
        self.assertEqual(st(r)["c-expect"], "fail")
        self.assertEqual(r["params"]["expect_from"], "api")
        r, _, _ = self.run_("pqc-api", PQC, EXPECT_FROM="api")
        self.assertEqual(st(r)["c-expect"], "pass", next(c for c in r["checks"] if c["id"] == "c-expect"))

    # X13 -------------------------------------------------------------------------------------
    def test_check_mode_judges_one_tree(self):
        out = os.path.join(self.tmp, "out-check-pqc")
        r, code, lines = prove.run(PQC, PQC, prove.Params({"ALLOW": "none", "RECON": "none"}, mode="check"), out, self.cache, quiet=True)
        self.assertEqual((r["verdict"], code, r["params"]["mode"]), ("pass", 0, "check"))
        self.assertEqual((st(r)["a-input"], st(r)["b-weakening"], st(r)["r-review"]), ("na", "na", "na"))
        self.assertEqual([w for ok, w in rc.verify(out) if not ok], [])
        out = os.path.join(self.tmp, "out-check-classic")
        r, code, _ = prove.run(CLASSIC, CLASSIC, prove.Params({"ALLOW": "none", "RECON": "none"}, mode="check"), out, self.cache,
                               quiet=True)
        self.assertEqual((r["verdict"], code, st(r)["a-cbom"], st(r)["c-classic"]), ("fail", 1, "fail", "fail"))
        # 같은 트리를 두 번 넣는 옛 방법은 a-input 미판정이었다(원본에서 고칠 것을 못 찾음)
        r, code, _ = self.run_("pair-same", PQC, orig=PQC)
        self.assertEqual((r["verdict"], st(r)["a-input"]), ("undecided", "undecided"))

    def test_check_mode_code_link_outside_the_tree_is_undecided(self):
        # 한 트리 점검에서 a-input 은 처음에 na 다. 트리 밖 코드 링크는 짝 판정과 같이 미판정, REQUIRE_REVIEW=1 이면 실패여야 한다
        ext = os.path.join(self.tmp, "outside-ext")
        os.makedirs(ext, exist_ok=True)
        pathlib.Path(ext, "Rsa.java").write_text('class Rsa { Object k = java.security.KeyPairGenerator.getInstance("RSA"); }\n',
                                                 encoding="utf-8")
        fx = self.tree("check-link", {})
        os.symlink(ext, os.path.join(fx, "src", "ext"))
        base = {"ALLOW": "none", "RECON": "none"}
        out = os.path.join(self.tmp, "out-check-link")
        r, code, lines = prove.run(fx, fx, prove.Params(base, mode="check"), out, self.cache, quiet=True)
        self.assertEqual((r["verdict"], code, st(r)["a-input"]), ("undecided", 3, "undecided"))
        self.assertIn("src/ext", next(c for c in r["checks"] if c["id"] == "a-input")["actual"])
        self.assertEqual([w for ok, w in rc.verify(out) if not ok], [])
        out = os.path.join(self.tmp, "out-check-link-strict")
        r, code, _ = prove.run(fx, fx, prove.Params(dict(base, REQUIRE_REVIEW="1"), mode="check"), out, self.cache, quiet=True)
        self.assertEqual((r["verdict"], code, st(r)["a-input"]), ("fail", 1, "fail"))

    def test_inventory_default_folder_name_keeps_the_working_folder(self):
        # cwd 이름에 'proof-' 가 들어 있어도 결과 폴더 이름만 inventory-out-<시각> 이다(형제 폴더를 새로 만들지 않는다)
        cwd = os.path.join(self.tmp, "pqproof-demo")
        os.makedirs(cwd, exist_ok=True)
        here = os.getcwd()
        try:
            os.chdir(cwd)
            with mock.patch.object(prove.time, "strftime", return_value="20261119-000000"):
                got = prove.default_out(CLASSIC, "inventory")
                self.assertEqual(os.path.basename(prove.default_out(CLASSIC)), "proof-out-20261119-000000")
                os.makedirs(got)
                self.assertEqual(prove.default_out(CLASSIC, "inventory"), got + "-2")
        finally:
            os.chdir(here)
        self.assertEqual(os.path.realpath(os.path.dirname(got)), os.path.realpath(cwd))
        self.assertEqual(os.path.basename(got), "inventory-out-20261119-000000")

    def test_inventory_has_no_verdict(self):
        out = os.path.join(self.tmp, "out-inv")
        s, code = prove.inventory(CLASSIC, prove.Params({}), out, quiet=True)
        self.assertEqual(code, 0)
        self.assertNotIn("verdict", s)
        doc = json.loads(pathlib.Path(out, "inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["format"], "pqproof inventory 1")
        self.assertGreater(doc["cbom"]["blocking"], 0)
        self.assertGreater(doc["classic_code_lines"], 0)
        self.assertEqual(doc["ruleset_version"], prove.ver.ruleset_history()[0])
        self.assertTrue(pathlib.Path(out, "tables", "cbom.csv").is_file())
        with mock.patch("sys.stderr"):
            self.assertEqual(prove.main(["--inventory"]), 2)
            self.assertEqual(prove.main(["--check", PQC, PQC]), 2)

    # 결과 폴더 안내 파일(README.txt, 형식 3) -------------------------------------------------
    def test_readme_in_the_result_folder_is_checked(self):
        out = os.path.join(self.tmp, "out-readme")
        r, _, _ = prove.run(CLASSIC, PQC, prove.Params({"ALLOW": "none", "RECON": "none"}), out, self.cache, quiet=True)
        text = pathlib.Path(out, "README.txt").read_text(encoding="utf-8")
        self.assertIn(r["receipt_id"], text)
        self.assertIn("--verify " + out, text)
        self.assertTrue(all(ok for ok, _ in rc.verify(out)))
        pathlib.Path(out, "README.txt").write_text(text + "note\n", encoding="utf-8")
        self.assertIn((False, "README.txt differs from this receipt"), rc.verify(out))
        os.remove(os.path.join(out, "README.txt"))
        self.assertTrue(any(not ok and w.startswith("README.txt cannot be read") for ok, w in rc.verify(out)))

    # X62 -------------------------------------------------------------------------------------
    def test_unexpected_exception_is_exit_4(self):
        with mock.patch.object(prove, "run", side_effect=RuntimeError("boom")), mock.patch("sys.stderr"):
            self.assertEqual(prove.main([CLASSIC, PQC]), prove.EXIT_TOOL_ERROR)
        with mock.patch.object(rc, "verify", side_effect=RuntimeError("boom")), mock.patch("sys.stderr"), mock.patch("sys.stdout"):
            d = os.path.join(self.tmp, "fake-out")
            os.makedirs(d, exist_ok=True)
            pathlib.Path(d, "receipt.json").write_text("{}", encoding="utf-8")
            self.assertEqual(rc.main(["verify", d]), 4)

    # X56 -------------------------------------------------------------------------------------
    def test_oversize_code_file_needs_review_and_the_limit_is_a_setting(self):
        big = "// padding\n" * 100_000 + 'class Big { Object k = java.security.KeyPairGenerator.getInstance("RSA"); }\n'
        fx = self.tree("big", {"src/main/java/demo/sealer/Big.java": big})
        r, _, _ = self.run_("big", fx)
        self.assertEqual(st(r)["a-input"], "review")
        self.assertTrue(r["inputs"]["fixed"]["oversize"][0].startswith("src/main/java/demo/sealer/Big.java ("))
        self.assertEqual(r["params"]["max_file_bytes"], 1 << 20)
        self.assertEqual(st(r)["c-classic"], "fail")  # residue.sh 는 큰 파일도 읽는다
        r, _, _ = self.run_("big-limit", fx, MAX_FILE_MIB="2")
        self.assertEqual(r["inputs"]["fixed"]["oversize"], [])
        self.assertEqual(r["params"]["max_file_bytes"], 2 << 20)
        with self.assertRaises(prove.UsageError):
            prove.Params({"MAX_FILE_MIB": "0"})

    # X27 -------------------------------------------------------------------------------------
    def test_unresolved_key_material_needs_review_and_fails_with_require_resolved(self):
        enc = ("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI" * 2 + "\n"
               "-----END ENCRYPTED PRIVATE KEY-----\n")
        fx = self.tree("enc", {"deploy/keys/server.key": enc})
        r, code, lines = self.run_("enc", fx)
        self.assertEqual((r["verdict"], st(r)["a-cbom"], r["cbom"]["fixed"]["unresolved"]), ("pass", "review", 1))
        self.assertIn("1 unresolved key or algorithm name", next(x for x in lines if x.startswith("VERDICT=")))
        r, code, _ = self.run_("enc-strict", fx, REQUIRE_RESOLVED="1")
        self.assertEqual((r["verdict"], code, st(r)["a-cbom"]), ("fail", 1, "fail"))

    def test_traced_pqc_check_rows_become_info(self):
        r, _, _ = self.run_("traced", PQC)
        self.assertEqual(r["cbom"]["fixed"]["check"], 0)
        self.assertEqual(r["cbom"]["fixed"]["unresolved"], 0)

    # X31 -------------------------------------------------------------------------------------
    def allow(self, name, entries, top=None):
        data = dict(top or {}, unconverted=entries)
        p = os.path.join(self.tmp, f"{name}.json")
        pathlib.Path(p).write_text(json.dumps(data), encoding="utf-8")
        return p

    LEGACY_LINE = "src/main/java/demo/sealer/Old.java"
    OLD = ("package demo.sealer;\n\nfinal class Old {\n    static Object kf() throws Exception {\n"
           "        return java.security.KeyFactory.getInstance(\"RSA\");\n    }\n}\n")

    def test_expired_entry_needs_review_and_fails_under_require_review(self):
        fx = self.tree("expired", {self.LEGACY_LINE: self.OLD})
        today = datetime.datetime.now(datetime.timezone.utc).date()
        entry = {"where": self.LEGACY_LINE + ":5", "why": "reads records sealed before the switch", "kind": "fallback",
                 "reviewed_by": "j.kim", "reviewed_at": today.isoformat(), "approval_ref": "SEC-1234",
                 "expires_at": (today - datetime.timedelta(days=1)).isoformat()}
        r, code, lines = self.run_("expired", fx, ALLOW=self.allow("expired", [entry]))
        e = r["allowlist"]["entries"][0]
        self.assertEqual((e["status"], e["expired"], e["approval_ref"], r["allowlist"]["expired"]), ("allowed", True, "SEC-1234", 1))
        self.assertEqual((r["verdict"], st(r)["r-allow"]), ("pass", "review"))
        self.assertIn("1 allowlist entry expired", next(x for x in lines if x.startswith("VERDICT=")))
        r, code, _ = self.run_("expired-strict", fx, ALLOW=self.allow("expired", [entry]), REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], st(r)["r-allow"]), ("fail", "fail"))
        later = dict(entry, expires_at=(today + datetime.timedelta(days=10)).isoformat())
        r, _, _ = self.run_("soon", fx, ALLOW=self.allow("soon", [later]), REQUIRE_REVIEW="1")
        self.assertEqual(st(r)["r-allow"], "pass")
        self.assertTrue(any("일 뒤(" in w and "만료" in w for w in r["allowlist"]["warnings"]), r["allowlist"]["warnings"])

    def test_unknown_fields_and_kinds_warn(self):
        fx = self.tree("unknown", {self.LEGACY_LINE: self.OLD})
        entry = {"where": self.LEGACY_LINE + ":5", "why": "reads old records", "kind": "temporary", "expires": "2020-01-01",
                 "ticket": "SEC-1"}
        r, _, _ = self.run_("unknown", fx, ALLOW=self.allow("unknown", [entry], {"owner": "x"}))
        w = "\n".join(r["allowlist"]["warnings"])
        self.assertIn("모르는 칸 expires, ticket 은 읽지 않는다", w)
        self.assertIn("목록 맨 위의 모르는 칸 owner", w)
        self.assertIn("kind 'temporary' 은 정해 둔 낱말이 아니다", w)
        self.assertEqual(r["allowlist"]["entries"][0]["status"], "allowed")  # 경고만, 허용은 그대로

    def test_review_max_age(self):
        fx = self.tree("age", {self.LEGACY_LINE: self.OLD})
        entry = {"where": self.LEGACY_LINE + ":5", "why": "reads old records", "kind": "fallback", "reviewed_by": "j.kim",
                 "reviewed_at": "2020-01-02"}
        r, _, _ = self.run_("age-off", fx, ALLOW=self.allow("age", [entry]), REQUIRE_REVIEW="1")
        self.assertEqual(st(r)["r-allow"], "pass")
        r, _, _ = self.run_("age-on", fx, ALLOW=self.allow("age", [entry]), REQUIRE_REVIEW="1", REVIEW_MAX_AGE_DAYS="365")
        self.assertEqual((st(r)["r-allow"], r["params"]["review_max_age_days"]), ("fail", 365))
        self.assertTrue(any("REVIEW_MAX_AGE_DAYS=365" in w for w in r["allowlist"]["warnings"]))


class SmallInputs(unittest.TestCase):
    def test_report_cells_escape_html(self):
        # 링크 대상처럼 입력이 정하는 글이 report.md 표에 날것의 태그로 남지 않는다(receipt.html 은 이미 이스케이프한다)
        self.assertEqual(prove.md_cell("/x/<img src=x onerror=alert(1)>"), "/x/&lt;img src=x onerror=alert(1)&gt;")
        self.assertEqual(prove.md_cell("a|b & c"), "a\\|b &amp; c")
        self.assertEqual(prove.md_cell("a<b", html=False), "a<b")

    def test_number_settings_take_ascii_digits_only(self):
        for v in ("\u00b2", "\u0663", "1e3", "-1", "+5"):
            with self.subTest(v=v), self.assertRaises(prove.UsageError):
                prove.number({"N": v}, "N", 1, 0, 100)
        self.assertEqual(prove.number({"N": " 30 "}, "N", 1, 0, 100), 30)


class Digest(unittest.TestCase):
    def test_optional_fields_enter_the_digest_only_when_present(self):
        old = {"where": "A.java:1-5", "why": "w", "kind": "fallback"}
        self.assertEqual(al.review_digest([old]), al.review_digest([dict(old, approval_ref=" ", expires_at="")]))
        self.assertNotEqual(al.review_digest([old]), al.review_digest([dict(old, expires_at="2027-01-01")]))
        self.assertNotEqual(al.review_digest([old]), al.review_digest([dict(old, approval_ref="SEC-1")]))

    def test_known_kinds(self):
        self.assertIn("false-positive", al.KINDS)
        self.assertIn("vendored", al.KINDS)

    def test_stale(self):
        self.assertTrue(al.stale("2026-01-01T10:00", "2026-11-19", 30))
        self.assertFalse(al.stale("2026-11-01", "2026-11-19", 30))
        self.assertFalse(al.stale("2020-01-01", "2026-11-19", None))


if __name__ == "__main__":
    unittest.main()
