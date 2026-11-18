"""허용 목록(notes/unconverted.json)·실행 데이터 제외·하이브리드 결합·import 규칙·사람 확인 칸(DESIGN.md Allow rules).

거짓 통과를 먼저 본다: 목록 밖 새 고전 줄은 실패, 없는 파일·범위 밖 줄 항목은 무효, 코드 파일은 제외 글롭에 걸려도 검사한다.
사람 확인 칸(reviewed_by·reviewed_at)이 없는 허용은 판정 옆에 '허용 n건 사람 확인 전', REQUIRE_REVIEW=1 이면 실패다.
목록 맨 위 칸은 reviewed_digest 가 맞을 때만 물려주므로, 확인 뒤 더하거나 고친 항목은 예전 확인을 물려받지 않는다.
"""
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
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import rules  # noqa: E402
from pqlite import allowlist as al  # noqa: E402
from pqlite import receipt as rc  # noqa: E402

BOX = "src/main/java/x/Box.java"
ORIG = {
    BOX: """package x;
import java.security.*;
import javax.crypto.*;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.*;
class Box {
  KeyPair keys() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(2048); return g.generateKeyPair(); }
  byte[] wrap(PublicKey k, byte[] d) throws Exception { Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding"); c.init(Cipher.WRAP_MODE, k); return c.doFinal(d); }
  byte[] unwrap(PrivateKey k, byte[] d) throws Exception {
    Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
    c.init(Cipher.DECRYPT_MODE, k, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    return c.doFinal(d);
  }
  byte[] sign(PrivateKey k, byte[] m) throws Exception { Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(k); s.update(m); return s.sign(); }
}
""",
    "README.md": "demo\n",
}
# 11~15줄: 옛 자료 풀기(요구 사항 때문에 남긴 읽기 전용 분기). 4줄 import 는 13줄에서만 쓴다
FIXED_BOX = """package x;
import java.security.*;
import javax.crypto.*;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.*;
import org.bouncycastle.jcajce.spec.*;
class Box {
  KeyPair keys() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM", "BC"); g.initialize(MLKEMParameterSpec.ml_kem_768); return g.generateKeyPair(); }
  byte[] sign(PrivateKey k, byte[] m) throws Exception { Signature s = Signature.getInstance("ML-DSA-65", "BC"); s.initSign(k); s.update(m); return s.sign(); }
  // old records: read only
  byte[] unwrapOld(PrivateKey k, byte[] d) throws Exception {
    Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
    c.init(Cipher.DECRYPT_MODE, k, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    return c.doFinal(d);
  }
%s}
"""
NEW_CLASSIC = ('  boolean check(PublicKey k, byte[] m, byte[] s) throws Exception { Signature x = Signature.getInstance("SHA256withECDSA"); '
               "x.initVerify(k); x.update(m); return x.verify(s); }\n")
# 허용 목록 범위 안에 새 암호화(쓰기 경로)를 넣은 판: 11~16줄
WRITE_BOX = FIXED_BOX.replace("    return c.doFinal(d);\n  }\n%s", "    return c.doFinal(d);\n  }\n"
                              "  byte[] wrapOld(PublicKey k, byte[] d) throws Exception { Cipher c = Cipher.getInstance(\"RSA/ECB/OAEPPadding\"); "
                              "c.init(Cipher.ENCRYPT_MODE, k); return c.doFinal(d); }\n%s")
HYB = {
    "src/main/java/x/Hyb.java": """package x;
import java.security.*;
import javax.crypto.*;
class Hyb {
  byte[] wrap(PublicKey kem, PublicKey peer) throws Exception {
    var enc = KEM.getInstance("ML-KEM", "BC").newEncapsulator(kem).encapsulate();
    KeyPairGenerator xg = KeyPairGenerator.getInstance("X25519", "BC");
    KeyPair eph = xg.generateKeyPair();
    KeyAgreement a = KeyAgreement.getInstance("X25519", "BC");
    a.init(eph.getPrivate()); a.doPhase(peer, true);
    return a.generateSecret();
  }
}
""",
}
PLAIN = {
    "src/main/java/x/Plain.java": """package x;
import java.security.*;
import javax.crypto.*;
class Plain {
  // ML-KEM-768 later
  byte[] agree(PrivateKey k, PublicKey peer) throws Exception {
    KeyAgreement a = KeyAgreement.getInstance("X25519", "BC");
    a.init(k); a.doPhase(peer, true);
    return a.generateSecret();
  }
}
""",
}
OK_LIST = [{"where": "src/main/java/x/Box.java:11-15", "what": "옛 자료 RSA-OAEP 풀기", "why": "전환 전 자료 열람(요구 사항), 새 자료에는 안 씀",
            "kind": "fallback"}]


def write(root, files):
    for path, text in files.items():
        p = pathlib.Path(root, path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text) if isinstance(text, str) else p.write_bytes(text)
    return root


def params(**kw):
    env = {"EXPECT": "kem,sig", "ALLOW": "none", "RECON": "none"}
    env.update(kw)
    return prove.Params(env)


def st(r):
    return {c["id"]: c["status"] for c in r["checks"]}


class Parse(unittest.TestCase):
    def test_where_forms(self):
        w = al.parse_where("Sealer.java:78-84")
        self.assertEqual(w, [(["Sealer.java"], [[78, 84]], False)])
        w = al.parse_where("/app/data/keys/<user>.enc.pem, <user>.sign.pem, service.log.pem")
        self.assertEqual([c for c, _, _ in w], [["/app/data/keys/<user>.enc.pem"], ["/app/data/keys/<user>.sign.pem",
                                                "<user>.sign.pem"], ["/app/data/keys/service.log.pem", "service.log.pem"]])
        self.assertTrue(al.parse_where("backup/old-data.tgz (앱 폴더 밖)")[0][2])
        self.assertTrue(al.parse_where("notes/migrate.py(앱 폴더 밖, 일회성)")[0][2])
        self.assertFalse(al.parse_where("a/B.java:3-5 · data/x.db")[0][2])
        self.assertEqual(al.parse_where("A.java:15,24-40")[0][1], [[15, 15], [24, 40]])

    def test_exclusions(self):
        ex = al.Exclusions()
        for bad in ("*", "**", "/", "**/*"):
            self.assertFalse(ex.add(bad, "t"))
        self.assertTrue(ex.add("data/", "t"))
        self.assertTrue(ex.add("*.db", "t"))
        self.assertTrue(ex.match("data/keys/a.pem") and ex.match("x/y/app.db"))
        self.assertFalse(ex.match("src/data.java"))
        self.assertTrue(al.KEEP_FILE.search("data/Seed.java") and al.KEEP_FILE.search("data/app.yml"))
        self.assertFalse(al.KEEP_FILE.search("data/keys/a.pem") or al.KEEP_FILE.search("data/app.sqlite3"))

    def test_recon_paths(self):
        roots, data = al.recon_paths({"app": "svc, 컨테이너 /app", "runtime": "sh -lc 'cd /app && DATA_DIR=/app/data java -jar a.jar'"})
        self.assertEqual((roots, data), (["/app"], ["/app/data"]))
        ex = al.Exclusions()
        roots, notes = al.from_recon(ex, {"app": "컨테이너 /opt/svc, 데이터 /var/lib/svc"}, "recon")
        self.assertEqual(ex.patterns, [])  # 앱 밖 데이터 폴더는 뺄 것이 없다
        self.assertTrue(any("밖" in n for n in notes))

    def test_imported_names(self):
        self.assertEqual(rules.imported_names("A.java", "import java.security.spec.MGF1ParameterSpec;"), ["MGF1ParameterSpec"])
        self.assertIsNone(rules.imported_names("A.java", "import java.security.*;"))
        self.assertEqual(rules.imported_names("a.py", "from cryptography.hazmat.primitives.asymmetric import ec, rsa as r"), ["ec", "r"])
        self.assertEqual(rules.imported_names("a.ts", "import { generateKeyPairSync, createSign as cs } from 'crypto';"),
                         ["generateKeyPairSync", "cs"])
        self.assertEqual(rules.imported_names("a.go", 'import "crypto/ecdsa"'), ["ecdsa"])
        self.assertIsNone(rules.imported_names("a.go", '"crypto/ecdsa"'))  # import 블록 밖 글자열은 import 가 아니다


class EndToEnd(unittest.TestCase):
    """작은 Java 트리로 prove.run 을 실제로 돈다(cbom-scan·residue 포함, 한 번에 1~2초)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name
        cls.cache = {}
        cls.orig = write(os.path.join(t, "orig"), ORIG)
        cls.fixed = write(os.path.join(t, "fixed"), dict(ORIG, **{BOX: FIXED_BOX % ""}))
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def allow(self, entries):
        EndToEnd.n += 1
        p = os.path.join(self.tmp.name, f"allow-{self.n}.json")
        pathlib.Path(p).write_text(json.dumps(entries, ensure_ascii=False))
        return p

    def tree(self, name, files):
        return write(os.path.join(self.tmp.name, name), dict(ORIG, **files))

    def run_(self, name, fixed, orig=None, **kw):
        out = os.path.join(self.tmp.name, "out-" + name)
        return prove.run(orig or self.orig, fixed, params(**kw), out, self.cache, quiet=True) + (out,)

    def test_without_allow_fails(self):
        r, code, _, _ = self.run_("noallow", self.fixed)
        self.assertEqual((r["verdict"], code), ("fail", 1))
        self.assertEqual((st(r)["a-cbom"], st(r)["c-classic"]), ("fail", "fail"))

    def test_allow_passes_and_is_recorded(self):
        r, code, lines, out = self.run_("allow", self.fixed, ALLOW=self.allow(OK_LIST))
        self.assertEqual((r["verdict"], code), ("pass", 0), [c for c in r["checks"] if c["status"] != "pass"])
        e = r["allowlist"]["entries"][0]
        self.assertEqual(e["status"], "allowed")
        self.assertIn(f"{BOX}:12", e["allowed"])
        self.assertIn(f"{BOX}:4", e["allowed"])  # 13줄에서만 쓰는 import
        self.assertIn(f"{BOX}:4", r["allowlist"]["imports"])
        self.assertTrue(all(ok for ok, _ in rc.verify(out)))
        deck = json.loads(prove.slurp(os.path.join(out, "deck.json")))
        self.assertEqual((deck["verdict"], deck["classic_lines"]["left"], deck["cbom"]["blocking_after"]), ("pass", 0, 0))
        self.assertGreaterEqual(deck["classic_lines"]["allowed"], 2)
        self.assertEqual(deck["classic_lines"]["after"], deck["classic_lines"]["allowed"] + deck["classic_lines"]["review"])
        self.assertEqual(deck["allowed"][0]["where"], "Box.java:11-15")
        self.assertIsInstance(deck["ev"], list)
        html = prove.slurp(os.path.join(out, "receipt.html"))
        self.assertIn("허용 목록(남긴 고전과 사유)", html)
        self.assertIn("(import)", html)
        self.assertTrue(any(x.startswith("허용 목록:") for x in lines))

    def test_file_name_only_where(self):
        r, _, _, _ = self.run_("short", self.fixed, ALLOW=self.allow([dict(OK_LIST[0], where="Box.java:11-15")]))
        self.assertEqual(r["verdict"], "pass")

    def test_new_classic_outside_list_fails(self):
        fx = self.tree("newc", {BOX: FIXED_BOX % NEW_CLASSIC})
        r, code, _, _ = self.run_("newc", fx, ALLOW=self.allow(OK_LIST))
        self.assertEqual((r["verdict"], code), ("fail", 1))
        self.assertEqual(st(r)["c-classic"], "fail")
        self.assertTrue(any(x.endswith(f"{BOX}:16") for x in r["java"]["fixed"]["listed"]["left"]), r["java"]["fixed"]["listed"]["left"])

    def test_missing_file_and_out_of_range_are_invalid(self):
        lst = [dict(OK_LIST[0], where="src/main/java/x/Nope.java:1-3"), dict(OK_LIST[0], where=f"{BOX}:11-99")]
        r, code, lines, _ = self.run_("invalid", self.fixed, ALLOW=self.allow(lst))
        self.assertEqual(r["verdict"], "fail")
        self.assertEqual([e["status"] for e in r["allowlist"]["entries"]], ["invalid", "invalid"])
        self.assertTrue(all(w.startswith("허용 무효") for w in r["allowlist"]["warnings"]))
        self.assertIn("범위 밖 줄", r["allowlist"]["entries"][1]["note"])

    def test_import_used_outside_list_stays(self):
        r, _, _, _ = self.run_("imp", self.fixed, ALLOW=self.allow([dict(OK_LIST[0], where=f"{BOX}:11-12")]))
        self.assertEqual(r["verdict"], "fail")
        left = r["java"]["fixed"]["listed"]["left"]
        self.assertTrue(any(x.endswith(f"{BOX}:4") for x in left) and any(x.endswith(f"{BOX}:13") for x in left), left)

    def test_write_path_needs_review(self):
        fx = self.tree("write", {BOX: WRITE_BOX % ""})
        r, code, _, out = self.run_("write", fx, ALLOW=self.allow([dict(OK_LIST[0], where=f"{BOX}:11-16")]))
        e = r["allowlist"]["entries"][0]
        self.assertEqual(e["status"], "review")
        self.assertIn(f"{BOX}:16", e["review"])
        self.assertIn("review", (st(r)["a-cbom"], st(r)["c-classic"]))
        self.assertNotEqual(r["verdict"], "fail")  # 검토 필요는 판정을 바꾸지 않고 사유를 남긴다
        deck = json.loads(prove.slurp(os.path.join(out, "deck.json")))
        self.assertGreaterEqual(deck["classic_lines"]["review"], 1)
        self.assertTrue(any(c["status"] == "review" for c in deck["checks"]))

    def test_outside_entry_allows_nothing(self):
        lst = OK_LIST + [{"where": "backup/rollback.tgz (앱 폴더 밖)", "why": "되돌리기용 사본", "kind": "fallback"}]
        r, _, _, _ = self.run_("outside", self.fixed, ALLOW=self.allow(lst))
        self.assertEqual(r["verdict"], "pass")
        self.assertEqual(r["allowlist"]["entries"][1]["status"], "outside")
        self.assertEqual(r["allowlist"]["warnings"], [])

    @unittest.skipUnless(os.path.isfile(prove.default_openssl()), "openssl 3.5 없음")
    def test_data_folder_excluded(self):
        fx = self.tree("data", {BOX: FIXED_BOX % "", "data/app.db": b"SQLite format 3\x00" + bytes(64)})
        key = os.path.join(fx, "data", "keys", "old.sign.pem")
        os.makedirs(os.path.dirname(key))
        subprocess.run([prove.default_openssl(), "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key],
                       check=True, capture_output=True)
        r, _, _, _ = self.run_("data-in", fx, ALLOW=self.allow(OK_LIST))
        self.assertEqual(r["verdict"], "fail")
        self.assertTrue(any("data/keys/old.sign.pem" in c["actual"] for c in r["checks"] if c["id"] == "a-cbom"))
        r, code, _, _ = self.run_("data-out", fx, ALLOW=self.allow(OK_LIST), EXCLUDE="data/**")
        self.assertEqual((r["verdict"], code), ("pass", 0), [c for c in r["checks"] if c["status"] != "pass"])
        self.assertEqual(r["excluded"]["items"][0]["pattern"], "data/**")
        self.assertEqual(r["excluded"]["count_fixed"], 2)
        self.assertEqual(r["params"]["exclude"], ["data/**"])

    def test_exclude_never_drops_code(self):
        r, _, _, _ = self.run_("excode", self.fixed, EXCLUDE="src/**")
        self.assertEqual(r["verdict"], "fail")
        self.assertEqual(r["excluded"]["count_fixed"], 0)
        self.assertTrue(any("코드·설정 파일" in n for n in r["excluded"]["notes"]))

    def test_work_folder_auto(self):
        w = os.path.join(self.tmp.name, "W")
        shutil.copytree(self.orig, os.path.join(w, "orig"))
        shutil.copytree(self.fixed, os.path.join(w, "repo"))
        write(os.path.join(w, "repo"), {"data/keys/a.pem": "not a key\n", "data/state.db": "x\n"})
        write(w, {"notes/unconverted.json": json.dumps(OK_LIST, ensure_ascii=False),
                  "notes/recon.json": json.dumps({"app": "box, 컨테이너 /app",
                                                  "runtime": "sh -lc 'cd /app && DATA_DIR=/app/data java -jar a.jar'"})})
        out = os.path.join(self.tmp.name, "out-auto")
        r, code, _ = prove.run(os.path.join(w, "orig"), os.path.join(w, "repo"), prove.Params({"EXPECT": "kem,sig"}), out, self.cache,
                               quiet=True)
        self.assertEqual((r["verdict"], code), ("pass", 0), [c for c in r["checks"] if c["status"] != "pass"])
        self.assertTrue(r["allowlist"]["auto"])
        self.assertEqual([i["pattern"] for i in r["excluded"]["items"]], ["data/**"])
        self.assertEqual(r["excluded"]["count_fixed"], 2)

    def test_legacy_name_line_counts_for_entry_and_is_listed(self):
        # 이름 규칙(코드의 legacy)으로 먼저 허용된 줄도 허용 목록이 덮으면 그 항목 몫
        leg = FIXED_BOX.replace('    Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");\n',
                                '    Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding"); String mode = "legacy records";\n')
        self.assertNotEqual(leg, FIXED_BOX)
        fx = self.tree("legacy", {BOX: leg % ""})
        r, code, _, out = self.run_("legacy", fx, ALLOW=self.allow(OK_LIST))
        self.assertEqual((r["verdict"], code), ("pass", 0), [c for c in r["checks"] if c["status"] != "pass"])
        self.assertIn(f"{BOX}:12", r["allowlist"]["entries"][0]["allowed"])
        self.assertNotIn(f"{BOX}:12", r["allowlist"]["legacy"])
        # 목록이 없으면 그 줄은 이름 규칙 몫으로 따로 남고 덱 allowed 에도 legacy-name 으로 나온다. 사람 확인이 없는 허용이라
        # r-allow 는 검토 필요(판정은 통과), REQUIRE_REVIEW=1 이면 실패다(형식 3, 교차 리뷰 X01)
        r, code, lines, out = self.run_("legacy-nolist", fx)
        self.assertIn(f"{BOX}:12", r["allowlist"]["legacy"])
        st = {c["id"]: c for c in r["checks"]}
        self.assertEqual(st["r-allow"]["status"], "review")  # 판정은 13줄(OAEP 매개변수)과 그 import 때문에 실패다
        self.assertIn("이름 규칙(legacy)으로만 허용한 곳", st["r-allow"]["actual"])
        deck = json.loads(prove.slurp(os.path.join(out, "deck.json")))
        self.assertTrue(any(a["kind"] == "legacy-name" and a["where"] == "Box.java:12" for a in deck["allowed"]), deck["allowed"])
        self.assertIn("이름 규칙으로만 허용", prove.slurp(os.path.join(out, "receipt.html")))
        r, code, _, _ = self.run_("legacy-strict", fx, REQUIRE_REVIEW="1")
        self.assertEqual({c["id"]: c["status"] for c in r["checks"]}["r-allow"], "fail")
        # 주석의 legacy 는 이름 규칙이 아니다: 같은 줄을 주석 낱말로만 표시하면 막는 위치다
        com = FIXED_BOX.replace('    Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");\n',
                                '    Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding"); // legacy records\n')
        r, code, _, _ = self.run_("legacy-comment", self.tree("legacy-comment", {BOX: com % ""}))
        self.assertNotIn(f"{BOX}:12", r["allowlist"]["legacy"])
        table = prove.slurp(os.path.join(self.tmp.name, "out-legacy-comment", "tables", "cbom-fixed.csv")).split("\n")
        self.assertTrue(any(x.startswith(f"{BOX}:12,") and ",막음," in x for x in table), table[:6])

    def test_exclude_duplicate_of_recon_note(self):
        w = os.path.join(self.tmp.name, "W2")
        shutil.copytree(self.orig, os.path.join(w, "orig"))
        shutil.copytree(self.fixed, os.path.join(w, "repo"))
        write(w, {"notes/recon.json": json.dumps({"runtime": "sh -lc 'cd /app && DATA_DIR=/app/data java -jar a.jar'"})})
        out = os.path.join(self.tmp.name, "out-dup")
        r, _, _ = prove.run(os.path.join(w, "orig"), os.path.join(w, "repo"),
                            prove.Params({"EXPECT": "kem,sig", "ALLOW": "none", "EXCLUDE": "data/ *"}), out, self.cache, quiet=True)
        self.assertEqual(r["excluded"]["items"][0]["pattern"], "data/**")
        self.assertTrue(any("이미 뺀" in n for n in r["excluded"]["notes"]), r["excluded"]["notes"])
        self.assertTrue(any("전부 빼는" in n for n in r["excluded"]["notes"]), r["excluded"]["notes"])

    def test_deck_json_contract_in_work_evidence(self):
        # deck.json 요약 꼴. 작업 폴더 꼴: OUT=<W>/evidence/proof-<시각>, ev 는 기본 <출력 폴더 이름>.txt
        w = os.path.join(self.tmp.name, "W3")
        shutil.copytree(self.orig, os.path.join(w, "orig"))
        shutil.copytree(self.fixed, os.path.join(w, "repo"))
        write(w, {"notes/unconverted.json": json.dumps(OK_LIST, ensure_ascii=False)})
        os.makedirs(os.path.join(w, "evidence"))
        out = os.path.join(w, "evidence", "proof-101500")
        with mock.patch.dict(os.environ):
            os.environ.pop("PQPROOF_ENTRY", None)
            r, code, _ = prove.run(os.path.join(w, "orig"), os.path.join(w, "repo"), prove.Params({"EXPECT": "kem,sig"}), out,
                                   self.cache, quiet=True)
        self.assertEqual(code, 0)
        deck = json.loads(prove.slurp(os.path.join(out, "deck.json")))
        need = {"verdict", "receipt", "receipt_file", "cbom", "classic_lines", "pqc_lines", "allowed", "checks", "excluded", "tls",
                "verify_cmd", "ev"}
        self.assertLessEqual(need, set(deck), need - set(deck))
        self.assertRegex(deck["receipt"], r"^[0-9a-f]{12}$")
        self.assertTrue(r["receipt_id"].startswith(deck["receipt"]))
        self.assertEqual(deck["receipt_file"], "evidence/proof-101500/receipt.json")
        self.assertEqual(deck["verify_cmd"], "bash prove.sh --verify evidence/proof-101500")
        self.assertEqual(deck["ev"], ["proof-101500.txt"])
        self.assertEqual(prove.default_out(os.path.join(w, "orig"))[:len(os.path.join(w, "evidence", "proof-"))],
                         os.path.join(w, "evidence", "proof-"))
        self.assertLessEqual({"before", "after", "blocking_before", "blocking_after"}, set(deck["cbom"]))
        self.assertLessEqual({"before", "after", "allowed"}, set(deck["classic_lines"]))
        self.assertEqual(set(deck["pqc_lines"]), {"mlkem", "mldsa"})
        ids = ["a-input", "a-cbom", "b-weakening", "b-tls", "c-classic", "c-expect", "r-review", "r-allow"]
        self.assertEqual([c["id"] for c in deck["checks"]], ids)
        self.assertTrue(all(c["status"] in ("pass", "fail", "undecided", "review", "skip") and c["label"] for c in deck["checks"]))
        self.assertTrue(all({"where", "kind", "why"} <= set(a) for a in deck["allowed"]))
        self.assertIsNone(deck["tls"])

    def test_hybrid_component_allowed_standalone_fails(self):
        r, code, _, _ = self.run_("hyb", self.tree("hyb", dict(HYB, **{BOX: FIXED_BOX % ""})), ALLOW=self.allow(OK_LIST))
        self.assertEqual((r["verdict"], code), ("pass", 0), [c for c in r["checks"] if c["status"] != "pass"])
        self.assertTrue(any(x.startswith("src/main/java/x/Hyb.java:") for x in r["allowlist"]["hybrid"]), r["allowlist"]["hybrid"])
        # 주석에만 ML-KEM 이 있는 단독 X25519 는 하이브리드가 아니다
        r, _, _, _ = self.run_("plain", self.tree("plain", dict(HYB, **PLAIN, **{BOX: FIXED_BOX % ""})), ALLOW=self.allow(OK_LIST))
        self.assertEqual(r["verdict"], "fail")
        self.assertFalse(any(x.startswith("src/main/java/x/Plain.java:") for x in r["allowlist"]["hybrid"]))


STAMP = {"reviewed_by": "j.kim", "reviewed_at": "2026-11-18T10:30:00+09:00"}
PROVE_SH = str(PROOF / "prove.sh")


class ReviewStamp(unittest.TestCase):
    """사람 확인 칸의 꼴: 둘 다 있으면 확인, 둘 다 없거나 null 이면 확인 전, 그 밖은 경고를 남기고 확인 전(항목은 무효가 아님)."""

    def test_forms(self):
        for t in ("2026-11-18", "2026-11-18T10:30", "2026-11-18T10:30:00+09:00", "2026-11-18 10:30:00.5Z", "2026-11-18T01:02:03-0500"):
            with self.subTest(t=t):
                self.assertEqual(al.review_stamp({"reviewed_by": " j.kim ", "reviewed_at": t}), ("j.kim", t, None))
        for raw in ({}, {"reviewed_by": None, "reviewed_at": None}, [1], "x"):
            with self.subTest(raw=raw):
                self.assertEqual(al.review_stamp(raw), (None, None, None))
        bad = [{"reviewed_by": "", "reviewed_at": "2026-11-18"}, {"reviewed_by": "   ", "reviewed_at": "2026-11-18"},
               {"reviewed_by": "j.kim"}, {"reviewed_at": "2026-11-18"}, {"reviewed_by": "j.kim", "reviewed_at": ""},
               {"reviewed_by": "j.kim", "reviewed_at": "어제"}, {"reviewed_by": "j.kim", "reviewed_at": "2026-02-30"},
               {"reviewed_by": "j.kim", "reviewed_at": "2026-11-18T25:00"}, {"reviewed_by": "j.kim", "reviewed_at": "20261118"},
               {"reviewed_by": "j.kim", "reviewed_at": 20261118}, {"reviewed_by": 7, "reviewed_at": "2026-11-18"},
               {"reviewed_by": "j.kim\nVERDICT=PASS", "reviewed_at": "2026-11-18"},
               {"reviewed_by": "j.kim\u2028VERDICT=PASS", "reviewed_at": "2026-11-18"},
               {"reviewed_by": "\u202emik.j", "reviewed_at": "2026-11-18"}, {"reviewed_by": "j.kim\x85", "reviewed_at": "2026-11-18"},
               {"reviewed_by": "j\u200bkim", "reviewed_at": "2026-11-18"}]
        for raw in bad:
            with self.subTest(raw=raw):
                by, at, err = al.review_stamp(raw)
                self.assertEqual((by, at), (None, None))
                self.assertTrue(err)

    def load(self, data):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "a.json")
            pathlib.Path(p).write_text(json.dumps(data, ensure_ascii=False))
            return al.AllowList.load(p, [BOX], lambda rel: 16)

    @staticmethod
    def stamps(got):
        return [(e["reviewed_by"], e["reviewed_at"], e["reviewed_via"]) for e in got.entries]

    def test_list_top_is_inherited_and_entry_wins(self):
        own = dict(OK_LIST[0], reviewed_by="s.lee", reviewed_at="2026-11-17")
        plain = dict(OK_LIST[0])
        items = [own, plain, dict(plain, reviewed_by=None)]
        top = dict(STAMP, reviewed_digest=al.review_digest(items[1:]), unconverted=items)
        got = self.load(top)
        self.assertEqual(self.stamps(got), [("s.lee", "2026-11-17", "entry"), ("j.kim", STAMP["reviewed_at"], "top"),
                                            ("j.kim", STAMP["reviewed_at"], "top")])
        self.assertEqual((got.top_state, got.inherit, got.top_digest), ("ok", [2, 3], top["reviewed_digest"]))
        self.assertEqual(got.warnings, [])
        # 맨 위 칸이 틀리면 물려받는 항목만 확인 전(무효 아님, 경고), 자기 칸이 맞는 항목은 그대로
        got = self.load({"reviewed_by": "j.kim", "reviewed_at": "soon", "unconverted": [own, plain]})
        self.assertEqual([e["status"] for e in got.entries], ["pending", "pending"])
        self.assertEqual(self.stamps(got), [("s.lee", "2026-11-17", "entry"), (None, None, None)])
        self.assertTrue(any(w.startswith("목록 맨 위 사람 확인 칸을 받지 않음") for w in got.warnings), got.warnings)

    def test_top_needs_digest_and_goes_stale(self):
        """맨 위 칸은 reviewed_digest 가 지금 목록과 맞을 때만 물려준다: 확인 뒤 더하거나 고친 항목은 확인 전으로 돌아간다."""
        two = [dict(OK_LIST[0]), dict(OK_LIST[0], where="Box.java:12", why="같은 자리 다른 사유")]
        digest = al.review_digest(two)
        self.assertRegex(digest, "^[0-9a-f]{16}$")
        self.assertEqual(al.review_digest([dict(x, where=" " + x["where"] + " ") for x in two]), digest)  # 앞뒤 공백은 같다
        got = self.load(dict(STAMP, unconverted=two))  # digest 없음
        self.assertEqual([v for _, _, v in self.stamps(got)], [None, None])
        self.assertEqual(got.top_state, "bad")
        self.assertTrue(any("reviewed_digest 가 없음" in w and f"reviewed_digest={digest}" in w for w in got.warnings), got.warnings)
        got = self.load(dict(STAMP, reviewed_digest=digest.upper(), unconverted=two))  # 대문자도 받는다
        self.assertEqual([v for _, _, v in self.stamps(got)], ["top", "top"])
        cases = {"added": two + [dict(OK_LIST[0], where="Box.java:15", why="나중에 더한 항목")],
                 "why-edited": [two[0], dict(two[1], why="사유를 나중에 바꿈")],
                 "where-edited": [dict(two[0], where="Box.java:11-16"), two[1]],
                 # 자기 칸이 있던 셋째 항목(아래 마지막 검사)에서 칸을 지우면 맨 위 칸이 덮는 항목이 늘어난다
                 "own-pair-dropped": two + [dict(OK_LIST[0], where="Box.java:13")],
                 "kind-edited": [dict(two[0], kind="kept"), two[1]]}
        for name, items in cases.items():
            with self.subTest(name=name):
                got = self.load(dict(STAMP, reviewed_digest=digest, unconverted=items))
                self.assertEqual({v for _, _, v in self.stamps(got)}, {None}, got.warnings)
                self.assertTrue(any("지금 목록과 다름" in w and f"reviewed_digest={got.top_digest}" in w for w in got.warnings),
                                got.warnings)
        # 사람이 따로 확인해 자기 칸을 단 새 항목은 맨 위 칸이 덮는 항목을 바꾸지 않는다
        got = self.load(dict(STAMP, reviewed_digest=digest, unconverted=two + [dict(OK_LIST[0], where="Box.java:13", **STAMP)]))
        self.assertEqual([v for _, _, v in self.stamps(got)], ["top", "top", "entry"])

    def test_entry_digest_is_optional_and_checked(self):
        e = dict(OK_LIST[0], **STAMP)
        self.assertEqual([v for _, _, v in self.stamps(self.load([e]))], ["entry"])  # 적지 않으면 그대로 받는다
        ok = dict(e, reviewed_digest=al.review_digest([e]))
        got = self.load([ok])
        self.assertEqual(([v for _, _, v in self.stamps(got)], got.entries[0]["digest"]), (["entry"], ok["reviewed_digest"]))
        for bad in (dict(ok, why="확인 뒤 바꾼 사유"), dict(ok, reviewed_digest="0" * 16), dict(ok, reviewed_digest=7)):
            with self.subTest(bad=bad):
                got = self.load([bad])
                self.assertEqual((self.stamps(got), got.entries[0]["status"]), ([(None, None, None)], "pending"))
                self.assertTrue(any(w.startswith("#1 reviewed_digest 가 지금 항목과 다름") for w in got.warnings), got.warnings)

    def test_future_date_warns(self):
        got = self.load([dict(OK_LIST[0], reviewed_by="j.kim", reviewed_at="2099-01-01")])
        self.assertEqual(self.stamps(got), [("j.kim", "2099-01-01", "entry")])  # 받기는 한다
        self.assertIn("#1 reviewed_at 이 미래 날짜(2099-01-01)", got.warnings)


class HumanReview(unittest.TestCase):
    """prove.run 을 실제로 돌려 판정 표시·엄격 모드·검증 증적을 본다(EndToEnd 와 같은 작은 Java 트리)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name
        cls.cache = {}
        cls.orig = write(os.path.join(t, "orig"), ORIG)
        cls.fixed = write(os.path.join(t, "fixed"), dict(ORIG, **{BOX: FIXED_BOX % ""}))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_(self, name, entries, **kw):
        p = os.path.join(self.tmp.name, f"allow-{name}.json")
        pathlib.Path(p).write_text(json.dumps(entries, ensure_ascii=False))
        out = os.path.join(self.tmp.name, "out-" + name)
        return prove.run(self.orig, self.fixed, params(ALLOW=p, **kw), out, self.cache, quiet=True) + (out,)

    def files(self, out):
        md = prove.slurp(os.path.join(out, "tables", "report.md"))
        html = prove.slurp(os.path.join(out, "receipt.html"))
        frag = prove.slurp(os.path.join(out, "tables", "fragment.html"))
        deck = json.loads(prove.slurp(os.path.join(out, "deck.json")))
        ev = json.loads(prove.slurp(os.path.join(out, "evidence-fragment.json")))
        return md, html, frag, deck, ev

    def test_unreviewed_passes_with_note_everywhere(self):
        r, code, lines, out = self.run_("unrev", OK_LIST)
        self.assertEqual((r["verdict"], code), ("pass", 0))  # 사람 확인은 기록 문제지 판정 실패가 아니다
        self.assertEqual((st(r)["r-allow"], r["allowlist"]["unreviewed"]), ("review", 1))
        self.assertEqual((r["allowlist"]["entries"][0]["reviewed_by"], r["allowlist"]["entries"][0]["reviewed_at"]), (None, None))
        self.assertIs(r["params"]["require_review"], False)
        verdict = [x for x in lines if x.startswith("VERDICT=")][0]
        self.assertTrue(verdict.startswith("VERDICT=PASS (1 allowed entry not yet reviewed by a person)  receipt_id="), verdict)
        self.assertTrue(any(x.startswith("허용 목록:") and x.endswith("사람 확인 전 1") for x in lines), lines)
        self.assertTrue(any(x.startswith("[r-allow] 검토 필요  허용 항목 1건 중 사람 확인 전 1건: #1 ") for x in lines), lines)
        hint = f'reviewed_digest="{al.review_digest(OK_LIST)}"'
        self.assertTrue(any(x.startswith("  사람 확인: 자기 칸이 없는 항목 1건") and hint in x for x in lines), lines)
        self.assertEqual(r["allowlist"]["top_digest"], al.review_digest(OK_LIST))
        md, html, frag, deck, ev = self.files(out)
        self.assertIn("판정 **통과(허용 1건 사람 확인 전)**", md)
        self.assertIn('<span class="badge undecided">통과(허용 1건 사람 확인 전)</span>', html)
        self.assertIn("확인 전", html)
        self.assertIn("판정 <b>통과(허용 1건 사람 확인 전)</b>", frag)
        self.assertEqual((deck["verdict"], deck["verdict_text"], deck["verdict_text_en"], deck["allow_unreviewed"]),
                         ("pass", "통과(허용 1건 사람 확인 전)", "pass (1 allowed entry not yet reviewed by a person)", 1))
        self.assertEqual((deck["allowed"][0]["reviewed_by"], deck["allowed"][0]["reviewed_at"]), (None, None))
        self.assertEqual(deck["checks"][-1], {"id": "r-allow", "status": "review", "label": "허용 항목 사람 확인"})
        self.assertEqual((ev["proof"]["verdict_text"], ev["proof"]["allow_unreviewed"]), ("통과(허용 1건 사람 확인 전)", 1))
        self.assertTrue(all(ok for ok, _ in rc.verify(out)), [w for ok, w in rc.verify(out) if not ok])
        # 용어: NIST 보안레벨(범주 아님)
        self.assertIn("보안레벨 3 미만 0", next(c["actual"] for c in r["checks"] if c["id"] == "c-classic"))
        self.assertNotIn("범주", html + md + prove.slurp(os.path.join(out, "receipt.json")))

    def test_reviewed_entry_and_list_top(self):
        top = dict(STAMP, reviewed_digest=al.review_digest(OK_LIST), unconverted=OK_LIST)
        for name, entries in (("entry", [dict(OK_LIST[0], **STAMP)]), ("top", top)):
            with self.subTest(name=name):
                r, code, lines, out = self.run_("rev-" + name, entries)
                self.assertEqual((r["verdict"], code, st(r)["r-allow"], r["allowlist"]["unreviewed"]), ("pass", 0, "pass", 0))
                e = r["allowlist"]["entries"][0]
                self.assertEqual((e["reviewed_by"], e["reviewed_at"], e["reviewed_via"]), ("j.kim", STAMP["reviewed_at"], name))
                self.assertTrue(any(x.startswith("VERDICT=PASS  receipt_id=") for x in lines), lines)
                self.assertFalse(any(x.startswith("  사람 확인:") for x in lines), lines)
                md, html, frag, deck, ev = self.files(out)
                self.assertIn("판정 **통과**", md)
                self.assertIn('<span class="badge pass">통과</span>', html)
                self.assertIn("j.kim", html)
                self.assertEqual("목록 맨 위 칸</span>" in html, name == "top")
                self.assertEqual((deck["verdict_text"], deck["allow_unreviewed"], deck["allowed"][0]["reviewed_by"]), ("통과", 0, "j.kim"))
                self.assertTrue(all(ok for ok, _ in rc.verify(out)))

    def test_bad_stamp_counts_as_unreviewed(self):
        """칸 꼴이 틀리면 경고를 남기고 사람 확인 전으로 센다. 허용 판정(위치 축)은 그대로 두고 r-allow 가 다룬다."""
        for name, stamp in (("empty", {"reviewed_by": "", "reviewed_at": "2026-11-18"}),
                            ("notdate", {"reviewed_by": "j.kim", "reviewed_at": "2026/11/18"}),
                            ("half", {"reviewed_by": "j.kim"})):
            with self.subTest(name=name):
                r, code, _, out = self.run_("bad-" + name, [dict(OK_LIST[0], **stamp)])
                e = r["allowlist"]["entries"][0]
                self.assertEqual((e["status"], e["reviewed_by"], e["reviewed_via"]), ("allowed", None, None))
                self.assertEqual((r["verdict"], code, st(r)["r-allow"], r["allowlist"]["unreviewed"]), ("pass", 0, "review", 1))
                self.assertTrue(any(w.startswith("#1 사람 확인 칸을 받지 않음(reviewed_") for w in r["allowlist"]["warnings"]),
                                r["allowlist"]["warnings"])
                self.assertTrue(all(ok for ok, _ in rc.verify(out)), [w for ok, w in rc.verify(out) if not ok])
                r, code, _, _ = self.run_("bad-strict-" + name, [dict(OK_LIST[0], **stamp)], REQUIRE_REVIEW="1")
                self.assertEqual((r["verdict"], code, st(r)["r-allow"]), ("fail", 1, "fail"))

    def test_stale_top_after_agent_adds_entry(self):
        """사람이 확인하고 맨 위에 적은 뒤 에이전트가 항목을 더하면, 물려받던 항목이 모두 확인 전으로 돌아간다."""
        top = dict(STAMP, reviewed_digest=al.review_digest(OK_LIST),
                   unconverted=OK_LIST + [dict(OK_LIST[0], where="src/main/java/x/Box.java:16", why="나중에 더한 항목")])
        r, code, lines, out = self.run_("stale-top", top)
        self.assertEqual((r["verdict"], code, st(r)["r-allow"]), ("pass", 0, "review"))
        self.assertEqual([e["reviewed_via"] for e in r["allowlist"]["entries"]], [None, None])
        self.assertEqual(r["allowlist"]["unreviewed"], sum(1 for e in r["allowlist"]["entries"] if e["status"] in al.IN_EFFECT))
        self.assertTrue(any("지금 목록과 다름" in x for x in lines), lines)
        self.assertFalse(any(x.startswith("  사람 확인:") for x in lines), lines)  # 값은 경고 줄에 이미 있다
        self.assertTrue(all(ok for ok, _ in rc.verify(out)), [w for ok, w in rc.verify(out) if not ok])
        r, code, _, _ = self.run_("stale-top-strict", top, REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code, st(r)["r-allow"]), ("fail", 1, "fail"))

    def test_require_review(self):
        r, code, lines, out = self.run_("strict", OK_LIST, REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code, st(r)["r-allow"]), ("fail", 1, "fail"))
        self.assertTrue(r["params"]["require_review"])
        self.assertTrue(any(x.startswith("VERDICT=FAIL  receipt_id=") for x in lines), lines)
        self.assertIn("REQUIRE_REVIEW=1", prove.slurp(os.path.join(out, "tables", "report.md")))
        self.assertTrue(all(ok for ok, _ in rc.verify(out)))
        r, code, _, _ = self.run_("strict-ok", [dict(OK_LIST[0], **STAMP)], REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code, st(r)["r-allow"]), ("pass", 0, "pass"))
        with self.assertRaises(prove.UsageError):
            params(REQUIRE_REVIEW="maybe")
        # 허용 목록이 없으면 확인할 것이 없다
        out = os.path.join(self.tmp.name, "out-strict-none")
        r, code, _ = prove.run(self.orig, self.orig, params(REQUIRE_REVIEW="1"), out, self.cache, quiet=True)
        self.assertEqual((st(r)["r-allow"], r["allowlist"]["unreviewed"]), ("na", 0))

    def test_stamp_is_in_the_evidence_hash_and_verify(self):
        r, _, _, out = self.run_("hash", [dict(OK_LIST[0], **STAMP)])
        rec = json.loads(prove.slurp(os.path.join(out, "receipt.json")))
        self.assertEqual(rec["allowlist"]["entries"][0]["reviewed_by"], "j.kim")
        self.assertEqual(rc.compute_id(rec), rec["receipt_id"])
        res = subprocess.run(["bash", PROVE_SH, "--verify", out], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout[-800:])
        # 이름만 바꾼 사본: 증적 해시가 달라지고 --verify 가 잡는다
        bad = os.path.join(self.tmp.name, "out-hash-edit")
        shutil.copytree(out, bad)
        rec["allowlist"]["entries"][0]["reviewed_by"] = "someone.else"
        self.assertNotEqual(rc.compute_id(rec), r["receipt_id"])
        pathlib.Path(bad, "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        res = subprocess.run(["bash", PROVE_SH, "--verify", bad], capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("receipt_id is", res.stdout)
        # 해시를 새로 써도 receipt.html·deck.json 이 이름을 따로 들고 있어 다르다
        rec["receipt_id"] = rc.compute_id(rec)
        pathlib.Path(bad, "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        fails = [w for ok, w in rc.verify(bad) if not ok]
        self.assertTrue(any("receipt.html differs" in w for w in fails) and any("deck.json differs" in w for w in fails), fails)
        # 확인 칸을 지우고 확인 전 수·r-allow 를 그대로 두면 판정·숫자 일치 검사가 잡는다
        rec["allowlist"]["entries"][0]["reviewed_by"] = rec["allowlist"]["entries"][0]["reviewed_at"] = None
        self.assertTrue(any("allowlist.unreviewed is 0" in p for p in rc.consistency(rec)), rc.consistency(rec))
        rec["allowlist"]["unreviewed"] = 1
        self.assertTrue(any(p.startswith("r-allow is pass") for p in rc.consistency(rec)), rc.consistency(rec))
        rec["checks"] = [c for c in rec["checks"] if c["id"] != "r-allow"]
        self.assertIn("allowlist.unreviewed is recorded, but there is no r-allow check", rc.consistency(rec))

    def test_verify_matches_review_fields_with_list_copy(self):
        """이름을 바꾸고 해시·receipt.html·deck.json 을 모두 다시 써도, 증적 폴더의 목록 사본과 대조해 잡는다."""
        r, _, _, out = self.run_("copy", [dict(OK_LIST[0], **STAMP)])
        res = dict((w.split(" (")[0], ok) for ok, w in rc.verify(out) if w.startswith("allowlist review fields"))
        self.assertEqual(res, {"allowlist review fields match artifacts/allow-list.json": True})
        bad = os.path.join(self.tmp.name, "out-copy-edit")
        shutil.copytree(out, bad)
        rec = json.loads(prove.slurp(os.path.join(bad, "receipt.json")))
        rec["allowlist"]["entries"][0]["reviewed_by"] = "someone.else"
        rec["receipt_id"] = rc.compute_id(rec)
        pathlib.Path(bad, "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        pathlib.Path(bad, "receipt.html").write_text(rc.render_html(rec))
        pathlib.Path(bad, "deck.json").write_text(rc.render_deck(rec))
        fails = [w for ok, w in rc.verify(bad) if not ok]
        self.assertEqual(len(fails), 1, fails)
        self.assertTrue(fails[0].startswith("allowlist review fields disagree with the copied allow list"), fails)
        self.assertIn("someone.else", fails[0])
        res = subprocess.run(["bash", PROVE_SH, "--verify", bad], capture_output=True, text=True)  # 스크립트로 돌 때도 같다
        self.assertEqual(res.returncode, 1)
        self.assertIn("FAIL allowlist review fields disagree", res.stdout)
        # r-allow 는 있는데 unreviewed 칸이 없는 증적
        del rec["allowlist"]["unreviewed"]
        self.assertIn("there is an r-allow check, but allowlist.unreviewed is not recorded", rc.consistency(rec))
        # reviewed_via 와 이름·시각이 어긋난 증적
        rec["allowlist"]["unreviewed"] = 0
        rec["allowlist"]["entries"][0]["reviewed_via"] = None
        self.assertTrue(any("reviewed_via is None, but reviewed_by and reviewed_at are set" in p for p in rc.consistency(rec)),
                        rc.consistency(rec))

    def test_old_receipt_keeps_old_verdict_note(self):
        """결함 D1 뒤 칸(unused·write_review)이 없는 옛 증적은 판정 옆 표시가 예전 그대로다(옛 receipt.html·deck.json 이 맞게)."""
        old = {"verdict": "pass", "allowlist": {"unreviewed": 2}}
        self.assertEqual(rc.verdict_text(old), "통과(허용 2건 사람 확인 전)")
        self.assertEqual(rc.verdict_text(old, en=True), "pass (2 allowed entries not yet reviewed by a person)")
        new = {"verdict": "pass", "allowlist": {"unreviewed": 1, "write_review": 3, "unused": 1}}
        self.assertEqual(rc.verdict_text(new), "통과(허용 1건 사람 확인 전 · 허용 범위 쓰기 경로 3곳 검토 필요 · 안 쓰인 항목 1건)")
        self.assertEqual(rc.verdict_text(new, en=True), "pass (1 allowed entry not yet reviewed by a person; 3 write paths in allowed "
                                                        "ranges need review; 1 allowlist entry unused in the fixed tree)")
        self.assertEqual(rc.verdict_text(dict(new, verdict="fail")), "실패")  # 실패·미판정에는 붙이지 않는다

    def test_weak_pqc_wording(self):
        from pqlite import scan as scanmod
        name, threat, nist, note = scanmod._classify("ML-KEM-512")
        self.assertEqual((threat, note), (scanmod.WEAK_PQC, "보안레벨 1(ML-KEM-512)"))
        self.assertIn("NIST security category 3", nist)  # 영어는 FIPS 203·204 용어, 한국어 비고만 보안레벨
        self.assertEqual(scanmod._classify("ML-DSA-44")[3], "보안레벨 2(ML-DSA-44)")



# 결함 D1: 고친 판 기준 목록에 고친 판에서 안 쓰인 항목이 있으면, 그 목록을 원본 같은 다른 트리에 댈 때 그 범위의 고전 줄을 가린다.
# 원본 Box.java 7~10줄은 RSA 키 생성·RSA 래핑(쓰기 경로)과 RSA-OAEP getInstance 이고, 고친 판 7~10줄에는 고전 줄이 없다.
UNUSED = {"where": "src/main/java/x/Box.java:7-10", "what": "옛 키 로더", "why": "옛 키 파일 읽기", "kind": "kept"}
NAMES = {"src/main/java/x/PqcNames.java": 'package x;\nfinal class PqcNames {\n  static final String KEM = "ML-KEM-768";\n'
                                          '  static final String SIG = "ML-DSA-65";\n}\n'}


class UnusedEntries(unittest.TestCase):
    """prove.run 을 실제로 돌린다(EndToEnd 와 같은 작은 Java 트리). 허용 목록 가림(결함 D1)을 공개 예제로 재현한다."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name
        cls.cache = {}
        cls.orig = write(os.path.join(t, "orig"), ORIG)
        cls.fixed = write(os.path.join(t, "fixed"), dict(ORIG, **{BOX: FIXED_BOX % ""}))
        cls.masked = write(os.path.join(t, "masked"), dict(ORIG, **NAMES))  # 원본 그대로 + PQC 이름 두 줄

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_(self, name, fixed, entries, orig=None, **kw):
        p = os.path.join(self.tmp.name, f"allow-{name}.json")
        pathlib.Path(p).write_text(json.dumps(entries, ensure_ascii=False))
        out = os.path.join(self.tmp.name, "out-" + name)
        return prove.run(orig or self.orig, fixed, params(ALLOW=p, **kw), out, self.cache, quiet=True) + (out,)

    def test_unused_entry_warns_and_counts_original_lines(self):
        lst = [dict(OK_LIST[0], **STAMP), dict(UNUSED, **STAMP)]  # 둘 다 사람 확인 칸이 있어도
        r, code, lines, out = self.run_("unused", self.fixed, lst)
        a = r["allowlist"]
        e1, e2 = a["entries"]
        self.assertEqual((e1["status"], e2["status"]), ("allowed", "unused"))
        self.assertEqual(e2["lines_fixed"], 0)
        self.assertGreater(e1["lines_fixed"], 0)
        self.assertEqual(e1["lines_fixed"], len(set(e1["allowed"]) | set(e1["review"])))
        self.assertTrue({f"{BOX}:7", f"{BOX}:8", f"{BOX}:10"} <= set(e2["orig"]), e2["orig"])  # 원본에서 덮는 고전 줄
        self.assertEqual(e2["lines_orig"], len(e2["orig"]))
        self.assertEqual((a["unused"], a["unused_orig_lines"]), (1, e2["lines_orig"]))
        self.assertEqual((r["verdict"], code), ("pass", 0))  # 기본 판정은 그대로
        ra = next(c for c in r["checks"] if c["id"] == "r-allow")
        self.assertEqual(ra["status"], "review")
        self.assertIn(f"고친 판에서 안 쓰인 항목 1건(원본 고전 {e2['lines_orig']}줄을 덮음, 사람 확인 전): #2 {BOX}:7-10", ra["actual"])
        self.assertTrue(any(w.startswith(f"#2 {BOX}:7-10: 고친 판에서 덮은 고전 줄 0(안 쓰인 항목). 원본에서는 고전") for w in a["warnings"]),
                        a["warnings"])
        verdict = [x for x in lines if x.startswith("VERDICT=")][0]
        self.assertTrue(verdict.startswith("VERDICT=PASS (1 allowlist entry unused in the fixed tree)  receipt_id="), verdict)
        deck = json.loads(prove.slurp(os.path.join(out, "deck.json")))
        self.assertEqual((deck["allow_unused"], deck["allow_unused_orig_lines"], deck["verdict_text"]),
                         (1, e2["lines_orig"], "통과(안 쓰인 항목 1건)"))
        self.assertIn("원본에서 덮는 줄", prove.slurp(os.path.join(out, "receipt.html")))
        self.assertTrue(all(ok for ok, _ in rc.verify(out)), [w for ok, w in rc.verify(out) if not ok])
        # REQUIRE_REVIEW=1: 사람 확인 칸이 다 있어도 안 쓰인 항목이 있으면 실패. 지우면 통과
        r, code, _, _ = self.run_("unused-strict", self.fixed, lst, REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code, st(r)["r-allow"]), ("fail", 1, "fail"))
        r, code, _, _ = self.run_("pruned-strict", self.fixed, lst[:1], REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code, st(r)["r-allow"], r["allowlist"]["unused"]), ("pass", 0, "pass", 0))

    def test_masking_shows_write_paths_and_pruned_list_blocks(self):
        """가림 재현: 원본 그대로에 PQC 이름 두 줄만 더한 트리 + 같은 목록. 목록이 원본 고전 줄을 모두 덮어 막는 위치 0이 된다.
        이 실행에서는 그 항목이 쓰이므로 안 쓰인 항목인지 알 수 없다(목록에 어느 트리 기준인지 기록이 없다). 그래서 판정은 그대로 두고
        쓰기 경로 수를 판정 옆에 적고, REQUIRE_REVIEW=1 이면 실패한다. 고친 판 실행이 안 쓰인 항목을 지우게 만든 목록이면 가리지 못한다."""
        lst = [OK_LIST[0], UNUSED]
        r, code, lines, out = self.run_("masked", self.masked, lst)
        self.assertEqual(r["cbom"]["fixed"]["blocking"], 0)
        self.assertEqual((r["verdict"], code), ("pass", 0))
        w = r["allowlist"]["write_review"]
        self.assertGreaterEqual(w, 3)  # 7(RSA 키 생성)·8(WRAP_MODE)·14(initSign)
        self.assertEqual(w, len({x for e in r["allowlist"]["entries"] for x in e["review"]}))
        self.assertIn(f"허용 범위 쓰기 경로 {w}곳 검토 필요", rc.verdict_text(r))
        verdict = [x for x in lines if x.startswith("VERDICT=")][0]
        self.assertIn(f"{w} write paths in allowed ranges need review", verdict)
        self.assertIn(f"허용 범위 쓰기 경로 {w}곳 검토 필요", prove.slurp(os.path.join(out, "tables", "report.md")))
        self.assertTrue(all(ok for ok, _ in rc.verify(out)), [x for ok, x in rc.verify(out) if not ok])
        r, code, _, _ = self.run_("masked-strict", self.masked, lst, REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code), ("fail", 1))
        r, code, _, _ = self.run_("masked-pruned", self.masked, lst[:1])
        self.assertEqual((r["verdict"], code), ("fail", 1))
        self.assertGreater(r["cbom"]["fixed"]["blocking"], 0)
        self.assertTrue(any(x.endswith(f"{BOX}:10") for x in r["java"]["fixed"]["listed"]["left"]), r["java"]["fixed"]["listed"]["left"])

    def test_verify_cross_checks_the_new_counts(self):
        r, _, _, out = self.run_("tamper", self.fixed, [OK_LIST[0], UNUSED])
        rec = json.loads(prove.slurp(os.path.join(out, "receipt.json")))
        self.assertEqual(rc.consistency(rec), [])
        for path, value, want in ((("unused",), 0, "allowlist.unused is 0"),
                                  (("unused_orig_lines",), 0, "allowlist.unused_orig_lines is 0"),
                                  (("write_review",), 5, "allowlist.write_review is 5"),
                                  (("entries", 0, "lines_fixed"), 99, "lines_fixed is 99"),
                                  (("entries", 1, "lines_orig"), 99, "lines_orig is 99"),
                                  (("entries", 1, "status"), "allowed", "status is 'allowed'")):
            bad = json.loads(json.dumps(rec))
            node = bad["allowlist"]
            for k in path[:-1]:
                node = node[k]
            node[path[-1]] = value
            with self.subTest(path=path):
                self.assertTrue(any(want in p for p in rc.consistency(bad)), rc.consistency(bad))
        # r-allow 를 통과로 바꾼 증적: 안 쓰인 항목이 있으면 검토 필요여야 한다
        bad = json.loads(json.dumps(rec))
        next(c for c in bad["checks"] if c["id"] == "r-allow")["status"] = "pass"
        self.assertTrue(any("1 entries are unused" in p for p in rc.consistency(bad)), rc.consistency(bad))
        # 해시를 다시 써도 --verify 가 숫자 대조로 잡는다
        bad = os.path.join(self.tmp.name, "out-tamper-edit")
        shutil.copytree(out, bad)
        rec["allowlist"]["unused"] = 0
        rec["receipt_id"] = rc.compute_id(rec)
        pathlib.Path(bad, "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        pathlib.Path(bad, "receipt.html").write_text(rc.render_html(rec))
        pathlib.Path(bad, "deck.json").write_text(rc.render_deck(rec))
        res = subprocess.run(["bash", PROVE_SH, "--verify", bad], capture_output=True, text=True)
        self.assertEqual(res.returncode, 1, res.stdout[-600:])
        self.assertIn("allowlist.unused is 0, but 1 entries count as unused", res.stdout)

    def test_entry_for_a_file_deleted_in_the_fixed_tree_counts_as_unused(self):
        """독립 검토에서 찾은 D1 빈틈: 고친 판에서 지운 파일을 가리킨 항목은 고친 판에서 무효(파일 없음)지만 원본에서는 유효해 그
        고전 줄을 가린다. 사람 확인 칸이 있어도 안 쓰인 항목으로 센다(r-allow 검토 필요, REQUIRE_REVIEW=1 이면 실패)."""
        old = "src/main/java/x/OldBox.java"
        orig = write(os.path.join(self.tmp.name, "orig-old"), dict(ORIG, **{old: ORIG[BOX].replace("class Box", "class OldBox")}))
        lst = [dict(OK_LIST[0], **STAMP), {"where": f"{old}:1-15", "why": "옛 기록 열람", "kind": "kept", **STAMP}]
        r, code, lines, out = self.run_("deleted", self.fixed, lst, orig=orig)
        a = r["allowlist"]
        e2 = a["entries"][1]
        self.assertEqual((e2["status"], e2["lines_fixed"]), ("invalid", 0))
        self.assertGreater(e2["lines_orig"], 0)
        self.assertEqual((a["unused"], a["unused_orig_lines"]), (1, e2["lines_orig"]))
        self.assertEqual((r["verdict"], code, st(r)["r-allow"]), ("pass", 0, "review"))
        ra = next(c for c in r["checks"] if c["id"] == "r-allow")
        self.assertIn(f"#2 {old}:1-15 (고친 판에서 무효)", ra["actual"])
        self.assertTrue(any(w.startswith(f"#2 {old}:1-15: 고친 판에서는 무효라 아무것도 허용하지 않는다(안 쓰인 항목으로 셈). 원본에서는 고전")
                            for w in a["warnings"]), a["warnings"])
        verdict = [x for x in lines if x.startswith("VERDICT=")][0]
        # 지운 OldBox.java 의 검증 호출이 빠져 r-review 도 검토 필요다. 0.1.0(증적 형식 2)부터 판정 줄에 그 수가 먼저 붙는다
        self.assertEqual(st(r)["r-review"], "review")
        # 형식 3: 판정 줄에 검토 필요인 a-input(원본 막는 위치가 있던 파일이 사라짐)도 적는다(교차 리뷰 X30)
        self.assertTrue(verdict.startswith("VERDICT=PASS (1 removed verification needs review; 1 allowlist entry unused in the fixed tree; "
                                           "needs review: a-input)"
                                           "  receipt_id="), verdict)
        self.assertTrue(all(ok for ok, _ in rc.verify(out)), [w for ok, w in rc.verify(out) if not ok])
        r, code, _, _ = self.run_("deleted-strict", self.fixed, lst, orig=orig, REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code, st(r)["r-allow"]), ("fail", 1, "fail"))
        # 같은 증적에서 그 항목을 안 쓰인 항목으로 세지 않게 고치면 consistency 가 잡는다
        rec = json.loads(prove.slurp(os.path.join(out, "receipt.json")))
        rec["allowlist"]["unused"], rec["allowlist"]["unused_orig_lines"] = 0, 0
        self.assertTrue(any("allowlist.unused is 0, but 1 entries count as unused" in x for x in rc.consistency(rec)), rc.consistency(rec))

    def test_deleting_the_new_counts_is_caught(self):
        """독립 검토(낮음): 안 쓰인 항목 1개로 REQUIRE_REVIEW=1 실패가 난 증적에서 unused·unused_orig_lines·write_review 를 지우고
        r-allow 를 통과로, 판정을 통과로 바꾸고 receipt.html·deck.json·receipt_id 를 다시 쓴 위조. 새 형식 증적이라 칸이 빠지면 실패이고,
        evidence-fragment.json·tables/report.md 에 남은 판정과도 어긋난다."""
        r, code, _, out = self.run_("downgrade", self.fixed, [dict(OK_LIST[0], **STAMP), dict(UNUSED, **STAMP)], REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code), ("fail", 1))
        self.assertTrue(all(ok for ok, _ in rc.verify(out)), [w for ok, w in rc.verify(out) if not ok])
        rec = json.loads(prove.slurp(os.path.join(out, "receipt.json")))
        for k in ("unused", "unused_orig_lines", "write_review"):
            del rec["allowlist"][k]
        next(c for c in rec["checks"] if c["id"] == "r-allow")["status"] = "pass"
        rec["verdict"] = rc.derive_verdict(rec["checks"])
        self.assertEqual(rec["verdict"], "pass")
        self.assertTrue(any("allowlist.unused, allowlist.unused_orig_lines, allowlist.write_review is missing" in x
                            for x in rc.consistency(rec)), rc.consistency(rec))
        bad = os.path.join(self.tmp.name, "out-downgrade-edit")
        shutil.copytree(out, bad)
        rec["receipt_id"] = rc.compute_id(rec)
        pathlib.Path(bad, "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        pathlib.Path(bad, "receipt.html").write_text(rc.render_html(rec))
        pathlib.Path(bad, "deck.json").write_text(rc.render_deck(rec))
        fails = [w for ok, w in rc.verify(bad) if not ok]
        self.assertTrue(any("is missing" in w for w in fails), fails)
        self.assertTrue(any(w.startswith("evidence-fragment.json says") for w in fails), fails)
        self.assertTrue(any(w.startswith("tables/report.md does not say") for w in fails), fails)


if __name__ == "__main__":
    unittest.main()
