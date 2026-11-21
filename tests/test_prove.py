"""prove.py: 입력 풀기, residue 일반판·출력 읽기, 허용 규칙, 작은 Java 트리 끝에서 끝까지(통과·실패·미판정)."""
import contextlib
import io
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import rules  # noqa: E402

ORIG_JAVA = {
    "src/main/java/x/Crypto.java": """package x;
import java.security.*;
import javax.crypto.*;
class Crypto {
  KeyPair keys() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(2048); return g.generateKeyPair(); }
  byte[] wrap(PublicKey k, byte[] d) throws Exception { Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding"); c.init(Cipher.WRAP_MODE, k); return c.doFinal(d); }
  byte[] sign(PrivateKey k, byte[] m) throws Exception { Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(k); s.update(m); return s.sign(); }
  boolean verify(PublicKey k, byte[] m, byte[] sig) throws Exception { Signature s = Signature.getInstance("SHA256withECDSA"); s.initVerify(k); s.update(m); return s.verify(sig); }
}
""",
    "README.md": "demo\n",
}
FIXED_JAVA = {
    "src/main/java/x/Crypto.java": """package x;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jcajce.spec.*;
class Crypto {
  static final String SIG = "ML-DSA-65";
  KeyPair keys() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM", "BC"); g.initialize(MLKEMParameterSpec.ml_kem_768); return g.generateKeyPair(); }
  byte[] sign(PrivateKey k, byte[] m) throws Exception { Signature s = Signature.getInstance(SIG, "BC"); s.initSign(k); s.update(m); return s.sign(); }
  boolean verify(PublicKey k, byte[] m, byte[] sig) throws Exception { Signature s = Signature.getInstance("ML-DSA-65", "BC"); s.initVerify(k); s.update(m); return s.verify(sig); }
}
""",
    "src/main/java/x/LegacyRecords.java": """package x;
import java.security.*;
class LegacyRecords {
  // read-only path for v1 data signed with ECDSA
  boolean verifyOld(PublicKey k, byte[] m, byte[] sig) throws Exception { Signature s = Signature.getInstance("SHA256withECDSA"); s.initVerify(k); s.update(m); return s.verify(sig); }
}
""",
    "README.md": "demo\n",
}
TRUST_ALL = """package x;
class Insecure {
  javax.net.ssl.TrustManager[] t = { new javax.net.ssl.X509TrustManager() {
    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; } } };
}
"""


def write(root, files):
    for path, text in files.items():
        p = pathlib.Path(root, path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def params(**kw):
    env = {"EXPECT": "kem,sig"}
    env.update(kw)
    return prove.Params(env)


class Inputs(unittest.TestCase):
    def test_zip_traversal_is_refused_and_one_folder_is_unwrapped(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.zip")
            with zipfile.ZipFile(bad, "w") as z:
                z.writestr("../escape.txt", "x")
            with self.assertRaises(prove.UsageError):
                prove.unzip_safe(bad, os.path.join(d, "u1"))
            good = os.path.join(d, "good.zip")
            with zipfile.ZipFile(good, "w") as z:
                z.writestr("app/src/A.java", "class A {}\n")
                z.writestr("__MACOSX/app/._A.java", "junk")
                info = zipfile.ZipInfo("app/link")
                info.external_attr = (0o120777 << 16)
                z.writestr(info, "/etc/passwd")
            dest = os.path.join(d, "u2")
            os.makedirs(dest)
            self.assertEqual(prove.unzip_safe(good, dest), [("app/link", "/etc/passwd")])  # 풀지 않고 이름과 대상 글만
            self.assertEqual(prove.unwrap(dest), os.path.join(dest, "app"))
            self.assertFalse(os.path.lexists(os.path.join(dest, "app", "link")))

    def test_ambiguous_zip_names_are_input_errors(self):
        """같은 이름 두 번, 대소문자·정규화만 다른 이름, 제어 문자, 파일 아래 파일은 기계마다 트리가 달라지거나 풀리지 않는다(X62)."""
        cases = {
            "duplicate": [("app/A.java", "class A {}"), ("app/A.java", "class A { int rsa; }")],
            "case": [("app/Crypto.java", "a"), ("app/crypto.java", "b")],
            "normalization": [("app/caf\u00e9.py", "a"), ("app/cafe\u0301.py", "b")],
            "control": [("app/a\nb.py", "a")],
            "file-under-file": [("app/x", "a"), ("app/x/y.py", "b")],
        }
        with tempfile.TemporaryDirectory() as d:
            for label, entries in cases.items():
                with self.subTest(label):
                    zp = os.path.join(d, f"{label}.zip")
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")  # zipfile 은 같은 이름에 UserWarning 을 낸다
                        with zipfile.ZipFile(zp, "w") as z:
                            for name, text in entries:
                                z.writestr(name, text)
                    dest = os.path.join(d, label)
                    os.makedirs(dest)
                    with self.assertRaises(prove.UsageError):
                        prove.unzip_safe(zp, dest)
            notzip = os.path.join(d, "broken.zip")
            pathlib.Path(notzip).write_bytes(b"PK\x03\x04 not really a zip")
            with self.assertRaises(prove.UsageError):
                prove.unzip_safe(notzip, os.path.join(d, "broken"))
            self.assertIsNone(prove.zip_names_problem(["app/", "app/A.java", "app/B.java", "__MACOSX/app/._A.java"]))
            with mock.patch.object(prove, "MAX_ZIP_ENTRIES", 2):
                self.assertIn("상한", prove.zip_names_problem(["a", "b", "c"]))

    def test_params(self):
        with self.assertRaises(prove.UsageError):
            params(CLASSIC="maybe")
        with self.assertRaises(prove.UsageError):
            params(TLS_VIA="container:bad name")
        with self.assertRaises(prove.UsageError):
            params(EXPECT="kem,xyz")
        with self.assertRaises(prove.UsageError):
            params(TLS_TARGETS="localhost")
        self.assertEqual(params(EXPECT="none").expect, [])
        self.assertEqual(prove.parse_target("127.0.0.1:8443@api.local"), ("127.0.0.1:8443", "api.local", None))


class Settings(unittest.TestCase):
    def test_typos_and_unknown_pqproof_names_warn(self):
        env = {"REQUIRE_REVEIW": "1", "TLS_TARGET": "127.0.0.1:8443", "EXPCET": "kem", "PQPROOF_OUT": "x",
               "REQUIRE_REVIEW": "0", "PQPROOF_HOME": "/x", "PQPROOF_ENTRY": "pqproof"}
        w = "\n".join(prove.env_warnings(env))
        self.assertIn("REQUIRE_REVEIW: 설정 이름이 아니다. REQUIRE_REVIEW 를 뜻했나? 엄격 모드", w)
        self.assertIn("TLS_TARGET: 설정 이름이 아니다. TLS_TARGETS", w)
        self.assertIn("EXPCET: 설정 이름이 아니다. EXPECT", w)
        self.assertIn("PQPROOF_OUT: PQ-Proof 가 모르는 이름", w)
        self.assertEqual(len(prove.env_warnings(env)), 4)

    def test_settings_match_the_help_and_params(self):
        """SETTINGS(오타 경고의 기준)는 prove.sh 머리 주석의 설정 목록, Params 가 읽는 이름과 같아야 한다."""
        import re
        head = pathlib.Path(prove.HERE, "prove.sh").read_text(encoding="utf-8").split("\nset -uo pipefail")[0]
        documented = set(re.findall(r"(?m)^#   ([A-Z][A-Z_]+)=", head))
        src = pathlib.Path(prove.HERE, "prove.py").read_text(encoding="utf-8")
        params_src = src[src.index("class Params:"):src.index("TARGET = re.compile")]
        read = set(re.findall(r'env\.get\("([A-Z_]+)"|(?:flag|number)\(env, "([A-Z_]+)"', params_src))
        read = {a or b for a, b in read}
        msg = "a setting is listed in one place only: add it to prove.py SETTINGS and to the settings list in the prove.sh header comment"
        self.assertEqual(documented, set(prove.SETTINGS), msg)
        self.assertLessEqual(read, set(prove.SETTINGS), msg)
        self.assertEqual(set(prove.SETTINGS) - read, {"PROBE_BIN_DIR"})  # prove.sh·cli.py·tlsprobe.py 가 읽는다

    def test_common_environment_is_quiet(self):
        env = dict.fromkeys(("PATH", "HOME", "SHELL", "LANG", "TERM", "USER", "PWD", "OLDPWD", "TMPDIR", "LOGNAME", "EDITOR",
                             "PAGER", "PYTHONPATH", "PYTHONHOME", "OPENSSL_CONF", "OPENSSL_DIR", "JAVA_HOME", "CLASSPATH",
                             "GOPATH", "GITHUB_ACTIONS", "RUNNER_TEMP", "RUNNER_OS", "CI", "SSH_AUTH_SOCK", "EXPECTED",
                             "OUTPUT", "OUTDIR", "SCOPES_DIR", "ALLOWED_HOSTS", "KEEP", "STRICT"), "x")
        env.update({k: "x" for k in prove.SETTINGS + prove.OTHER_ENV})
        self.assertEqual(prove.env_warnings(env), [])

    def test_default_out_has_the_date_and_never_collides(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            os.chdir(d)
            try:
                first = prove.default_out(os.path.join(d, "orig-tree"))
                self.assertRegex(os.path.basename(first), r"^proof-out-[0-9]{8}-[0-9]{6}$")
                os.makedirs(first)
                with mock.patch.object(prove.time, "strftime", return_value=os.path.basename(first)[len("proof-out-"):]):
                    second = prove.default_out(os.path.join(d, "orig-tree"))
                self.assertEqual(second, first + "-2")
            finally:
                os.chdir(cwd)


class Residue(unittest.TestCase):
    def test_generic_residue_file(self):
        text = prove.slurp(prove.GENERIC_RESIDUE)
        self.assertNotIn("\nSITE@@", text)  # 서비스별 자리 규칙은 일반판에 없다(RESIDUE= 로 준 판에만)
        for rule in rules.FAMILIES + ["G-WEAK-PQC", "LW-legacy-write", "E-MLKEM768", "E-MLDSA65"]:
            self.assertIn(f"@@{rule}@@", text)
        self.assertIn("MAXD = 100000", text)
        self.assertIn("ISTEST = (TP ~ TESTRE)", text)  # 시험 경로는 scan/test-paths.ere 한 곳(cbom-scan.sh 와 같은 목록)
        self.assertIn('match(TP, MAINRE)', text)  # 둘째 줄 본 소스 표시(/src/main/) 앞부분만 본다
        self.assertIn("test-paths.ere", text)
        self.assertIn('SKIP_FILE=${SKIP_DIRS:-$HERE/skip-dirs}', text)  # 건너뛰는 폴더는 scan/skip-dirs 한 곳(X09)
        self.assertNotIn("-name vendor", text)

    def test_parse(self):
        out = ("GEN  G-RSA              LEFT   code=2 allow=1 comment=0 test=1  - RSA\n"
               "      LEFT src/A.java:5: KeyPairGenerator.getInstance(\"RSA\")\n"
               "      ALLOW src/LegacyB.java:3: x\n"
               "      TEST src/test/java/ATest.java:9: KeyPairGenerator.getInstance(\"RSA\")\n"
               "GEN  G-WEAK-PQC         GONE   code=0 allow=0 comment=0  - w\n"
               "LWRITE LW-legacy-write   OK     code=0  - l\n"
               "EXPECT E-MLKEM768       PRESENT  n=3  L1,2,3  - k\n"
               "EXPECT E-MLDSA65        MISSING  n=0  L-  - s\n"
               "SUMMARY files=3 sites=0 LEFT=0 | VERDICT=RESIDUE\n")
        p = rules.parse_residue(out)
        self.assertEqual(p["families"]["G-RSA"], {"code": 2, "allow": 1, "comment": 0, "test": 1})
        self.assertEqual(p["families"]["G-EC"], {"code": 0, "allow": 0, "comment": 0, "test": 0})
        self.assertEqual(p["tests"], {"count": 1, "lines": ["src/test/java/ATest.java:9"]})  # 시험 경로 줄은 따로 센다
        self.assertEqual(p["expect"], {"E-MLKEM768": 3, "E-MLDSA65": 0})
        self.assertEqual((p["weak_pqc"], p["legacy_write"], p["sites_left"], p["verdict"]), (0, 0, None, "RESIDUE"))
        self.assertEqual(len(p["rules"]["G-RSA"]["lines"]), 3)
        self.assertIsNone(rules.parse_residue("no summary\n"))


class Allow(unittest.TestCase):
    def test_rules(self):
        self.assertIsNotNone(rules.allow_reason("src/LegacyBox.java", 'Signature.getInstance("SHA256withECDSA")', "ECDSA"))
        self.assertIsNone(rules.allow_reason("src/LegacyBox.java", "c.init(Cipher.ENCRYPT_MODE, k)", "RSA"))
        self.assertIsNotNone(rules.allow_reason("src/A.java", "verifyLegacy(sig) // ECDSA", "ECDSA"))
        self.assertIsNotNone(rules.allow_reason("src/A.java", 'KEM.getInstance("X25519MLKEM768")', "X25519"))
        self.assertIsNone(rules.allow_reason("src/A.java", 'KeyAgreement.getInstance("X25519")', "X25519"))
        # ML-KEM이 주석에만 있으면 하이브리드가 아니다
        self.assertIsNone(rules.allow_reason("src/A.java", 'KeyAgreement.getInstance("ECDH"); // ML-KEM-768 전환 전 임시', "ECDH"))
        self.assertIsNone(rules.allow_reason("src/A.java", 'KeyAgreement.getInstance("ECDH"); /* MLKEM */', "ECDH"))
        self.assertIsNone(rules.allow_reason("nginx/nginx.conf", "ssl_ecdh_curve X25519:prime256v1; # X25519MLKEM768", "X25519"))
        self.assertIsNotNone(rules.allow_reason("nginx/nginx.conf", "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;", "X25519"))
        self.assertIsNotNone(rules.allow_reason("a.go", 'g := "X25519MLKEM768,X25519" // https://go.dev/doc', "X25519"))


class EndToEnd(unittest.TestCase):
    """작은 Java 트리로 cbom-scan·residue·scan.py·weakening·검증 증적을 실제로 돈다(트리당 몇 초)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name
        cls.orig = write(os.path.join(t, "orig"), ORIG_JAVA)
        cls.fixed = write(os.path.join(t, "fixed"), FIXED_JAVA)
        cls.cache = {}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_(self, name, fixed, **kw):
        with mock.patch.dict(os.environ):
            os.environ.pop("PQPROOF_ENTRY", None)  # pqproof --unit 으로 돌아도 기본 진입점(bash prove.sh)을 본다
            return prove.run(self.orig, fixed, params(**kw), os.path.join(self.tmp.name, "out-" + name), self.cache, quiet=True)

    def test_pass(self):
        r, code, lines = self.run_("pass", self.fixed)
        self.assertEqual((r["verdict"], code), ("pass", 0), [c for c in r["checks"] if c["status"] != "pass"])
        self.assertGreater(r["cbom"]["orig"]["blocking"], 0)
        self.assertEqual(r["cbom"]["fixed"]["blocking"], 0)
        self.assertGreater(r["cbom"]["fixed"]["allowed"], 0)  # LegacyRecords.java 검증 줄
        self.assertEqual(r["java"]["residue_kind"], "generic")
        self.assertGreaterEqual(r["java"]["fixed"]["expect"]["E-MLKEM768"], 1)
        self.assertEqual(r["tls"]["applicable"], False)
        frag = prove.slurp(os.path.join(self.tmp.name, "out-pass", "evidence-fragment.json"))
        self.assertIn('"ML-KEM-768"', frag)
        self.assertIn('"ML-DSA-65"', frag)
        self.assertTrue(any(line.startswith("VERDICT=PASS") for line in lines))

    def test_trust_all_fails(self):
        bad = write(os.path.join(self.tmp.name, "bad"), dict(FIXED_JAVA, **{"src/main/java/x/Insecure.java": TRUST_ALL}))
        r, code, _ = self.run_("bad", bad)
        self.assertEqual((r["verdict"], code), ("fail", 1))
        self.assertTrue(any("X509TrustManager" in d for d in r["weakening"]["deny"]))

    def test_classical_left_fails(self):
        r, code, lines = self.run_("same", self.orig)
        self.assertEqual(r["verdict"], "fail")
        st = {c["id"]: c["status"] for c in r["checks"]}
        self.assertEqual((st["a-cbom"], st["c-classic"], st["c-expect"]), ("fail", "fail", "fail"))
        # 실패면 고칠 곳 전체 목록과 허용 목록 안내가 콘솔 끝에, report.md 에 막는 위치 표가 나온다(X49)
        text = "\n".join(lines)
        self.assertIn("다음 할 일:", text)
        self.assertIn("tables/cbom-fixed.csv", text)
        self.assertIn("artifacts/residue-fixed.txt", text)
        self.assertIn(os.path.join("examples", "allowlist", "unconverted.json"), text)
        self.assertTrue(os.path.isfile(os.path.join(prove.HERE, "examples", "allowlist", "unconverted.json")))
        md = prove.slurp(os.path.join(self.tmp.name, "out-same", "tables", "report.md"))
        self.assertIn("막는 위치(실패 원인)", md)
        self.assertIn("Crypto.java:", md)
        self.assertIn("실패 원인은 위 '막는 위치' 표", md)
        self.assertIn("guide/allowlist.md", md)

    def test_tls_signal_without_targets_is_undecided(self):
        tls = write(os.path.join(self.tmp.name, "tls"), dict(FIXED_JAVA, **{
            "src/main/resources/application.properties": "server.port=8443\nserver.ssl.key-store=classpath:ks.p12\n"}))
        r, code, _ = self.run_("tls", tls)
        self.assertEqual((r["verdict"], code), ("undecided", 3))
        self.assertTrue(r["tls"]["signals"])

    def test_console_points_to_what_to_open_first(self):
        r, code, lines = self.run_("first", self.fixed)
        text = "\n".join(lines)
        self.assertIn("사람이 볼 것: receipt.html", text)
        self.assertIn("bash prove.sh --verify " + os.path.join(self.tmp.name, "out-first"), text)
        self.assertNotIn("다음 할 일", text)
        self.assertTrue(lines[0].startswith("== PQ-Proof "), lines[0])
        with mock.patch.dict(os.environ, {"PQPROOF_ENTRY": "pqproof"}):
            r, code, lines = prove.run(self.orig, self.fixed, params(), os.path.join(self.tmp.name, "out-entry"), self.cache,
                                       quiet=True)
        self.assertIn("pqproof --verify " + os.path.join(self.tmp.name, "out-entry"), "\n".join(lines))
        self.assertTrue(r["deck_meta"]["verify_cmd"].startswith("pqproof --verify "))
        md = prove.slurp(os.path.join(self.tmp.name, "out-entry", "tables", "report.md"))
        self.assertIn("`pqproof --verify <출력 폴더>`", md)

    def test_progress_goes_to_stderr_unless_quiet(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            prove.run(self.orig, self.fixed, params(), os.path.join(self.tmp.name, "out-progress"), self.cache, quiet=False)
        text = err.getvalue()
        self.assertIn("pqproof: 설정: EXPECT=kem,sig", text)
        self.assertIn("REQUIRE_REVIEW=0", text)
        for step in ("[1/6] 준비", "[2/6] (a) CBOM", "[3/6] (c)", "[4/6] (b)", "[5/6] (b) TLS", "[6/6] (d)"):
            self.assertIn(step, text)
        self.assertEqual(text.count(" 끝 "), 6)

    def test_output_folder_is_never_reused(self):
        os.makedirs(os.path.join(self.tmp.name, "out-exists"))
        with self.assertRaises(prove.UsageError):
            self.run_("exists", self.fixed)

    def test_report_md_tables(self):
        self.run_("rep", self.fixed)
        md = prove.slurp(os.path.join(self.tmp.name, "out-rep", "tables", "report.md"))
        for want in ("검사 결과", "| # | 검사 | 도구 | 기대 | 실제 |", "전환 뒤 남은 항목", "| 남은 고전 항목 | 위치 | 남은 이유 | 할 일 |",
                     "LegacyRecords.java", "bash prove.sh --verify"):
            self.assertIn(want, md)
        self.assertNotIn("<style", md)  # 붙여 넣는 문서의 글꼴·색을 건드리지 않는다


class FalsePass(unittest.TestCase):
    """반박 검증에서 찾은 꼴: 아무것도 못 찾고 통과하던 입력이 이제 미판정·사용법 오류로 끝나는지."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_(self, name, orig, fixed, **kw):
        t = self.tmp.name
        return prove.run(write(os.path.join(t, name + "-o"), orig), write(os.path.join(t, name + "-f"), fixed),
                         params(**dict({"EXPECT": "none"}, **kw)), os.path.join(t, "out-" + name), quiet=True)

    def test_empty_fixed_is_a_usage_error(self):
        with self.assertRaises(prove.UsageError):
            self.run_("empty", ORIG_JAVA, {})

    def test_nothing_found_in_orig_is_undecided(self):
        netty = {"src/main/java/a/Srv.java": "package a;\nimport io.netty.handler.ssl.SslContextBuilder;\nclass Srv {\n"
                                             "  Object c(java.io.File c, java.io.File k) throws Exception {"
                                             " return SslContextBuilder.forServer(c, k).build(); }\n}\n"}
        r, code, _ = self.run_("netty", netty, netty)
        st = {c["id"]: c["status"] for c in r["checks"]}
        self.assertEqual((r["verdict"], code, st["a-input"], st["b-tls"]), ("undecided", 3, "undecided", "undecided"))

    def test_other_tree_is_undecided(self):
        other = {"x/y/README.md": "other\n", "x/y/main.py": "print(1)\n"}
        r, code, _ = self.run_("other", ORIG_JAVA, other)
        self.assertEqual(next(c for c in r["checks"] if c["id"] == "a-input")["status"], "undecided")
        self.assertNotEqual(r["verdict"], "pass")

    def test_tls_removed_is_undecided(self):
        tls = {"main.go": "package main\nimport (\"crypto/tls\"; \"net/http\")\nfunc main() {\n"
                          "\ts := &http.Server{TLSConfig: &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}}}\n"
                          "\t_ = s.ListenAndServeTLS(\"c.pem\", \"k.pem\")\n}\n"}
        plain = {"main.go": "package main\nimport \"net/http\"\nfunc main() {\n\t_ = http.ListenAndServe(\":8080\", nil)\n}\n"}
        r, code, _ = self.run_("tlsgone", tls, plain)
        b = next(c for c in r["checks"] if c["id"] == "b-tls")
        self.assertEqual((b["status"], r["verdict"]), ("undecided", "undecided"))

    # 반박 검증에서 찾은 꼴: 서버 TLS를 못 봐서 '해당 없음'으로 통과하던 꼴과 클라이언트 TLS만 있는 꼴
    def b_tls(self, name, extra, **kw):
        r, code, _ = self.run_(name, dict(ORIG_JAVA, **extra), dict(FIXED_JAVA, **extra), **kw)
        return {c["id"]: c["status"] for c in r["checks"]}, r

    def test_tomcat_server_xml_is_a_tls_signal(self):
        xml = {"conf/server.xml": '<Server><Service><Connector port="8443" SSLEnabled="true">\n'
                                  '<SSLHostConfig><Certificate certificateKeystoreFile="ks.p12"/></SSLHostConfig>\n'
                                  "</Connector></Service></Server>\n"}
        st, r = self.b_tls("tomcat", xml)
        self.assertEqual((st["b-tls"], r["verdict"]), ("undecided", "undecided"))

    def test_spring_ssl_in_dockerfile_is_a_tls_signal(self):
        df = {"Dockerfile": 'FROM eclipse-temurin:21-jre\nENV JAVA_OPTS="-Dserver.ssl.enabled=true -Dserver.port=8443"\n'
                            "ENV SERVER_SSL_KEY_STORE=/k/ks.p12\nCMD java $JAVA_OPTS -jar app.jar\n"}
        st, r = self.b_tls("dockerfile", df)
        self.assertEqual(st["b-tls"], "undecided")
        self.assertTrue(any(s.startswith("Dockerfile:") for s in r["tls"]["signals"]), r["tls"]["signals"])

    def test_client_only_tls_is_review_not_silent(self):
        cl = {"src/main/java/x/Up.java": "package x;\nclass Up {\n  javax.net.ssl.SSLContext c() throws Exception {"
                                         ' return javax.net.ssl.SSLContext.getInstance("TLS"); }\n}\n'}
        st, r = self.b_tls("client", cl, EXPECT="kem,sig")
        self.assertEqual((st["b-tls"], r["verdict"]), ("review", "pass"))
        st, r = self.b_tls("client-expect-tls", cl, EXPECT="kem,sig,tls")
        self.assertEqual((st["c-expect"], r["verdict"]), ("undecided", "undecided"))

    def test_app_key_agreement_is_not_a_tls_signal(self):
        hy = {"src/main/java/x/Wrap.java": "package x;\nclass Wrap {\n  Object k() throws Exception {"
                                           ' return javax.crypto.KeyAgreement.getInstance("X25519"); }\n}\n'}
        st, r = self.b_tls("keyagree", hy)
        self.assertEqual(st["b-tls"], "na", r["tls"]["signals"])

    def test_openssl_version_gate(self):
        if sys.platform == "darwin" and os.path.isfile("/usr/bin/openssl"):
            self.assertFalse(prove.openssl_35("/usr/bin/openssl"))  # 맥 LibreSSL 3.3
        self.assertFalse(prove.openssl_35(None))
        brew = "/opt/homebrew/opt/openssl@3.5/bin/openssl"
        if os.path.isfile(brew):
            self.assertTrue(prove.openssl_35(brew))


if __name__ == "__main__":
    unittest.main()
