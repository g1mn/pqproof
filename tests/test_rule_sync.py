"""같은 규칙 값이 여러 파일에 있을 때 서로 맞는지(동기 시험). 판정은 바꾸지 않고 어긋남만 잡는다.

residue.sh 의 규칙 표와 쓰기 연산·legacy·Legacy*.java 규칙을 prove.py(공개키 9계열, 허용 규칙)와 sarif.py(결과로 내는 규칙)에
맞춰 보고, prove.py 와 deps.py 가 OpenSSL 을 같은 순서로 고르는지 가짜 openssl 로 돌려 본다. 한 곳만 고치면 residue 는 LEFT 로
세는데 prove.py 는 허용으로 빼거나 SARIF 수가 증적과 어긋난다. 0.2.0 에서 파이썬 쪽 값을 한 모듈에서 읽게 되면 그 부분은
import 로 바뀐다. 건너뛰는 폴더는 scan/skip-dirs 한 곳이고, 그 규칙을 쓰는 세 곳(pqlite/skipdirs.py, residue.sh·cbom-scan.sh 의
skip_dirs 셸 함수)이 같은 트리에서 같은 파일을 보는지 돌려서 맞춘다(교차 리뷰 X09).
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
try:
    import pqproof  # noqa: F401  설치본
except ImportError:
    sys.path.insert(0, str(PROOF / "src"))  # 저장소 체크아웃
import prove  # noqa: E402
from pqlite import rules  # noqa: E402
import rulesrc  # noqa: E402
from pqlite import receipt as rc  # noqa: E402
from pqlite import scan as scanmod  # noqa: E402
from pqlite import skipdirs  # noqa: E402
from pqproof import deps, sarif  # noqa: E402

# 알려진 실패: 지금 동작 그대로 고정했다. 고친 판에서는 그 시험이 실패하니 기대값을 뒤집고 여기서 지운다(tests/run_unit.py 가 센다).
# 규칙 묶음 2에서 X09(건너뛰는 폴더 목록 넷)를 고쳐 비었다
KNOWN_GAPS = {}


def ids(kind):
    return [r["id"] for r in rulesrc.residue_rules() if r["kind"] == kind]


class ResidueAndProve(unittest.TestCase):
    def test_families_are_the_first_nine_gen_rules(self):
        # residue.sh 머리 주석: 앞의 아홉 줄(G-RSA ~ G-DH-DSA)이 prove.sh 가 세는 '공개키 9계열'이다
        self.assertEqual(ids("GEN")[:9], rules.FAMILIES)

    def test_expect_rule_ids(self):
        self.assertEqual(ids("EXPECT"), list(rules.EXPECT_IDS))
        # 프로필(scan/profiles.json)이 고르는 규칙은 모두 residue.sh 에 있고, kem·sig 묶음(자산 칸)이 맞다
        group = {r["id"]: r for r in rulesrc.residue_rules() if r["kind"] == "EXPECT"}
        for name, prof in rules.PROFILES.items():
            for kind in ("kem", "sig"):
                for rid in prof[kind]:
                    with self.subTest(profile=name, rule=rid):
                        self.assertIn(rid, group)
        self.assertEqual(rules.DEFAULT_PROFILE, "nist-cat3")
        self.assertEqual(rules.PROFILES["nist-cat3"]["tls_group"], "X25519MLKEM768")
        self.assertEqual((rules.PROFILES["cnsa2"]["kem"], rules.PROFILES["cnsa2"]["sig"], rules.PROFILES["cnsa2"]["tls_group"]),
                         (["E-MLKEM1024"], ["E-MLDSA87"], "SecP384r1MLKEM1024"))
        self.assertEqual(rules.PROFILES["nist-cat3"]["kem"], ["E-MLKEM768", "E-MLKEM1024"])
        self.assertTrue(set(rules.PROFILES["kpqc"]["kem"]) >= {"E-MLKEM768", "E-KPQC-KEM"})
        # EXPECT_FROM=api 의 파이썬 정규식이 residue.sh EXPECT 규칙과 같은 이름을 잡는다
        res = {r["id"]: r["re"] for r in rulesrc.residue_rules() if r["kind"] == "EXPECT"}
        samples = ["ML-KEM-768", "mlkem768", "ML_KEM_1024", "ml-dsa-65", "MLDSA87", "SMAUG-T3", "NTRU+576", "ntruplus", "HAETAE3",
                   "AIMer128f", "disclaimer", "ML-KEM-512", "MLDSA44", "SLH-DSA-SHA2-192s", "slh_dsa_shake_256f",
                   "SLHDSA-SHA2-256s", "SLH-DSA-SHA2-128s", "SPHINCS+-SHA2-192s-simple", "SLH-DSA"]
        self.assertEqual(set(res), set(rules.EXPECT_RE))
        for rid in res:
            for s in samples:
                with self.subTest(rule=rid, name=s):
                    self.assertEqual(bool(re.search(res[rid], s)), bool(re.search(rules.EXPECT_RE[rid], s)))

    def test_composite_names(self):
        # 복합 서명 이름표: residue.sh RES_COMPOSITE(ML-DSA-65·87 만), pqlite/scan.py COMPOSITE_NAME, cbom-scan.sh COMPRE 가 같은 이름을 잡는다
        ere = rulesrc.residue_export("RES_COMPOSITE")
        text = (PROOF / "scan" / "cbom-scan.sh").read_text(encoding="utf-8")
        cbom = re.search(r"^COMPRE='([^']+)'$", text, re.M)[1]
        rows = ["MLDSA65-ECDSA-P256-SHA512", "id-MLDSA87-RSA4096-PSS-SHA512", "ML-DSA-65-Ed25519-SHA512", "mldsa65_ed448",
                "MLDSA65", "ML-DSA-65", "MLDSA65withECDSA", "RSA-MLDSA65"]
        for row in rows:
            with self.subTest(name=row):
                want = bool(scanmod.COMPOSITE_NAME.search(row))
                self.assertEqual(bool(re.search(ere, row)), want)
                self.assertEqual(bool(re.search(cbom, row.lower())), want)
        self.assertTrue(scanmod.COMPOSITE_NAME.search("MLDSA44-RSA2048-PSS-SHA256"))  # 44 는 scan.py 가 잡아 보안레벨 3 미만으로 막는다
        self.assertFalse(re.search(ere, "MLDSA44-RSA2048-PSS-SHA256"))  # residue 는 44 를 허용하지 않는다

    def test_weak_pqc_rule_is_the_one_prove_counts(self):
        self.assertIn("G-WEAK-PQC", ids("GEN"))
        self.assertIn('rules.get("G-WEAK-PQC"', (PROOF / "pqlite" / "rules.py").read_text(encoding="utf-8"))

    def test_name_rule_write_operations(self):
        # residue.sh 이름 규칙의 쓰기 연산(ERE)과 pqlite/rules.py ALLOW_WRITEOPS 가 같은 줄을 잡는다(교차 리뷰 X01)
        ere = rulesrc.residue_export("RES_ALLOW_WRITEOPS")
        self.assertTrue(ere and ere.startswith(rulesrc.residue_export("RES_WRITEOPS") + "|"))
        as_py = re.compile(ere.replace("[[:space:]]", r"\s"))
        import test_rules  # noqa: E402  같은 표(WRITES·NOT_WRITES)를 쓴다
        rows = test_rules.AllowRules.WRITES + test_rules.AllowRules.NOT_WRITES + [
            "xSign(k)", "doEncryptOAEP(x)", "mygenerate_private_key", "myjwt.encode(x)", "x509CreateCertificate(a)"]
        for line in rows:
            with self.subTest(line=line):
                self.assertEqual(bool(as_py.search(line)), bool(rules.ALLOW_WRITEOPS.search(line)))

    def test_write_operations(self):
        res = rulesrc.residue_export("RES_WRITEOPS")
        self.assertEqual(res, rules.WRITEOPS.pattern)
        self.assertTrue(rules.ALLOW_WRITEOPS.pattern.startswith(res + "|"), "ALLOW_WRITEOPS must extend WRITEOPS")
        lwrite = [r["re"] for r in rulesrc.residue_rules() if r["kind"] == "LWRITE"]
        self.assertEqual(len(lwrite), 1)
        self.assertTrue(lwrite[0].startswith(res + "|"), "the LWRITE rule must start with RES_WRITEOPS")

    def test_legacy_word(self):
        res = rulesrc.residue_export("RES_ALLOWLINE")
        pairs = re.findall(r"\[(\w)(\w)\]", res)
        self.assertEqual("".join(f"[{a}{b}]" for a, b in pairs), res, "RES_ALLOWLINE is no longer one [Xx] class per letter")
        self.assertTrue(all(a.upper() == a and b == a.lower() for a, b in pairs))
        self.assertEqual("".join(b for _, b in pairs), rules.ALLOWLINE.pattern)
        self.assertTrue(rules.ALLOWLINE.flags & re.I)

    def test_legacy_file_name(self):
        awk = rulesrc.residue_legacy_file()
        self.assertTrue(awk and awk.startswith("^"))
        self.assertEqual(rules.LEGACY_FILE.pattern, "(?:^|/)" + awk[1:])

    def test_same_line_ml_kem_forms_agree(self):
        # 같은 줄 ML-KEM 인정 꼴: 규칙 묶음 2부터 residue.sh(G-X25519·G-CURVE)와 pqlite/rules.py 가 같다(대소문자·밑줄 무관).
        # 0.1.1 의 residue.sh 는 대소문자를 가리고 밑줄을 안 받아 ml_kem_768 X25519 줄이 LEFT 였다
        allow = {r["id"]: r["allow"] for r in rulesrc.residue_rules()}
        self.assertEqual(allow["G-X25519"], allow["G-CURVE"])
        self.assertEqual((rules.HYBRID_LINE.pattern, bool(rules.HYBRID_LINE.flags & re.I)), ("ML[-_]?KEM", True))
        for row in ("X25519MLKEM768", "x25519mlkem768", "X25519_ml_kem_768", "ML-KEM-768", "SecP256r1MLKEM768", "MLKEM", "ML KEM",
                    "MLK EM"):
            with self.subTest(row=row):
                self.assertEqual(bool(re.search(allow["G-X25519"], row)), bool(rules.HYBRID_LINE.search(row)))


class RulesInOnePlace(unittest.TestCase):
    """판정 규칙은 pqlite/rules.py 한 곳에 두고 그 파일이 규칙 묶음 해시에 든다(교차 리뷰 X10)."""

    # prove.py 에 남아도 되는 정규식: 입력 꼴 검사(TLS 대상, zip 이름)뿐. 판정에 쓰는 정규식이 생기면 pqlite/rules.py 로 옮긴다
    PROVE_PATTERNS = {"TARGET", "ZIP_CONTROL"}

    def test_rules_file_is_in_the_ruleset(self):
        from pqlite import version as V
        paths = [p for p, _ in V.RULESET_FILES]
        self.assertIn("pqlite/rules.py", paths)
        self.assertIn("pqlite/tlsprobe.py", paths)  # TLS 대상 판정(target_verdict)과 대조 서버 판정

    def test_prove_has_no_rule_patterns(self):
        got = {k for k, v in vars(prove).items() if isinstance(v, re.Pattern) and getattr(rules, k, None) is not v}
        self.assertEqual(got, self.PROVE_PATTERNS, "prove.py 에 판정용 정규식 상수가 생겼다: pqlite/rules.py 로 옮기고 규칙 묶음을 올린다")
        src = (PROOF / "prove.py").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"(?m)^([A-Z][A-Z0-9_]*) = re\.compile", src), sorted(self.PROVE_PATTERNS, key=src.index))

    def test_prove_uses_the_rules_module(self):
        for name in ("FAMILIES", "merge_cbom", "parse_residue", "reclass_residue", "hybrid_ok", "Lines", "read_text"):
            self.assertIs(getattr(prove, name), getattr(rules, name), name)


class SarifRules(unittest.TestCase):
    def test_counted_gen_rules(self):
        # c-classic 이 세는 GEN 규칙: 공개키 9계열과 보안레벨 3 미만 PQC. G-AES128 은 표에만 나온다
        self.assertEqual(sarif.COUNTED_GEN, set(rules.FAMILIES) | {"G-WEAK-PQC"})
        self.assertEqual(sarif.COUNTED_GEN, set(ids("GEN")) - {"G-AES128"})

    def test_every_counted_rule_has_an_english_name(self):
        self.assertEqual(set(sarif.FAMILY_EN), sarif.COUNTED_GEN | set(ids("LWRITE")))


class OpenSSLChoice(unittest.TestCase):
    """prove.default_openssl 과 deps.find_openssl 이 같은 openssl 을 고르는지: 가짜 openssl 스크립트로 돌린다."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-sync-")
        cls.fake = {}
        for name, line in (("o30", "OpenSSL 3.0.13 30 Jan 2024"), ("o35", "OpenSSL 3.5.1 1 Jul 2025"),
                           ("libre", "LibreSSL 3.3.6")):
            p = os.path.join(cls.tmp, name)
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"#!/bin/sh\necho '{line}'\n")
            os.chmod(p, 0o755)
            cls.fake[name] = p
        cls.path_dir = os.path.join(cls.tmp, "path")
        os.mkdir(cls.path_dir)
        shutil.copy(cls.fake["o35"], os.path.join(cls.path_dir, "openssl"))
        cls.empty = os.path.join(cls.tmp, "empty")
        os.mkdir(cls.empty)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def test_same_candidates(self):
        self.assertEqual(prove.OPENSSL_CANDIDATES, deps.OPENSSL_CANDIDATES)

    def choose(self, candidates, given=None, path=None):
        env = {k: v for k, v in os.environ.items() if k != "OPENSSL"}
        env["PATH"] = path or self.empty
        if given:
            env["OPENSSL"] = given
        with mock.patch.object(prove, "OPENSSL_CANDIDATES", candidates), \
                mock.patch.object(deps, "OPENSSL_CANDIDATES", candidates), mock.patch.dict(os.environ, env, clear=True):
            return prove.default_openssl(), deps.find_openssl(env)[0]

    def test_same_choice(self):
        f = self.fake
        cases = [
            ((f["o30"], f["o35"]), None, None, f["o35"]),          # 3.5 이상을 먼저
            ((f["libre"], f["o30"]), None, None, f["libre"]),      # 3.5 이상이 없으면 처음 찾은 것
            ((f["o35"],), f["o30"], None, f["o30"]),               # OPENSSL 을 주면 3.5 미만이어도 그것
            ((f["o30"],), None, self.path_dir, os.path.join(self.path_dir, "openssl")),  # PATH 의 3.5
            ((), None, None, None),                                # 아무것도 없음
        ]
        for cands, given, path, want in cases:
            with self.subTest(candidates=[os.path.basename(c) for c in cands], given=given and os.path.basename(given)):
                self.assertEqual(self.choose(cands, given, path), (want, want))


class SkipDirs(unittest.TestCase):
    """건너뛰는 폴더(scan/skip-dirs): 트리 목록(pqlite/skipdirs.py)과 두 셸 스캐너가 같은 트리에서 같은 파일을 본다(교차 리뷰 X02·X03·X09)."""

    # 폴더마다 고전 키 한 줄짜리 K.java. 빌드 파일: 트리 맨 위 go.mod, svc-a/pom.xml, web/package.json, src/main/webapp/package.json
    # main 표시 아래 any 이름(venv·node_modules·.idea)은 빌드 파일 옆이 아니면 운영 소스로 읽는다. 그 이름이 있으면 셸 스캐너는 이름으로
    # 잘라 내지 않고 skip_dirs 목록으로 거른다(맨 위 node_modules/z·web/node_modules/y 는 그래도 빠져야 한다)
    DIRS = ["", "src/main/java/com/bank/vendor", "src/main/java/demo/build", "src/main/java/demo/target", "vendor/x", "build/gen",
            "dist", "svc-a/target/gen", "svc-a/src/main/java/a", "svc-b/target", "web/dist", "web/node_modules/y", "lib/vendor",
            "node_modules/z", ".venv/lib", "pkg/.terraform", "src/main/java/demo/vendor/build", "tools/out", ".svn/pristine",
            "src/main/webapp/dist", "src/main/java/com/bank/venv", "src/main/java/com/bank/node_modules", "src/main/java/com/bank/.idea",
            "src/main/webapp/node_modules/q", "app/.tox/env", "svc-a/.venv/lib"]
    WANT = ["K.java", "lib/vendor/K.java", "src/main/java/com/bank/.idea/K.java", "src/main/java/com/bank/node_modules/K.java",
            "src/main/java/com/bank/vendor/K.java", "src/main/java/com/bank/venv/K.java", "src/main/java/demo/build/K.java",
            "src/main/java/demo/target/K.java", "src/main/java/demo/vendor/build/K.java", "src/main/webapp/dist/K.java",
            "svc-a/src/main/java/a/K.java",
            "svc-b/target/K.java", "tools/out/K.java"]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-skip-")
        cls.root = os.path.join(cls.tmp, "t")
        for d in cls.DIRS:
            p = os.path.join(cls.root, *d.split("/")) if d else cls.root
            os.makedirs(p, exist_ok=True)
            pathlib.Path(p, "K.java").write_text('KeyFactory kf = KeyFactory.getInstance("RSA");\n', encoding="utf-8")
        for f in ("go.mod", "svc-a/pom.xml", "web/package.json", "src/main/webapp/package.json"):  # webapp/dist 는 운영 소스 아래라 본다
            pathlib.Path(cls.root, *f.split("/")).write_text("x\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def test_tree_list(self):
        got = sorted(r for r, _, _ in rc.tree_files(self.root) if r.endswith("K.java"))
        self.assertEqual(got, self.WANT)
        skipped = skipdirs.walk(self.root, skipdirs.load())[1]
        self.assertEqual(skipped, [(".svn", "any"), (".venv", "any"), ("app/.tox", "output"), ("build", "output"), ("dist", "output"),
                                   ("node_modules", "any"), ("pkg/.terraform", "output"), ("src/main/webapp/node_modules", "output"),
                                   ("svc-a/.venv", "any"), ("svc-a/target", "output"), ("vendor", "output"), ("web/dist", "output"),
                                   ("web/node_modules", "any")])

    def test_misplaced_dependency_folders_are_counted(self):
        # 제자리(트리 맨 위·빌드 파일 옆)가 아닌 any 폴더는 산출물 폴더처럼 세고, 코드가 있으면 a-input 검토 필요로 간다
        out = tempfile.mkdtemp(prefix="prep-", dir=self.tmp)
        info, _, _, extra = prove.prepare_input(self.root, out, "fixed")
        got = {x["path"]: x["code"] for x in extra["skipped_output"]}
        self.assertEqual(got["app/.tox"], 1)
        self.assertEqual(got["src/main/webapp/node_modules"], 1)
        self.assertEqual(got["pkg/.terraform"], 1)
        self.assertNotIn("node_modules", got)
        self.assertNotIn("svc-a/.venv", got)
        self.assertIn("app/.tox/ 파일 1 · 코드 1", info["skipped"])

    def test_residue_sees_the_same_files(self):
        parsed = rules.parse_residue(prove.run_residue(prove.GENERIC_RESIDUE, self.root)[1])
        got = sorted(x["path"] for x in parsed["rules"]["G-RSA"]["lines"])
        self.assertEqual(got, self.WANT)

    def test_cbom_scan_sees_the_same_files(self):
        out = os.path.join(self.tmp, "cbom")
        ok, _, rows = prove.run_cbom_scan(prove.CBOM_SCAN, self.root, out, prove.default_openssl())
        self.assertTrue(ok, prove.slurp(os.path.join(out, "run.log"))[-1500:])
        got = sorted({r["위치"].rsplit(":", 1)[0] for r in rows if r["위치"].endswith("K.java:1")})
        self.assertEqual(got, self.WANT)

    def test_scan_py_walks_the_same_files(self):
        got = sorted(r for r, _ in scanmod._files(self.root) if r.endswith("K.java"))
        self.assertEqual(got, self.WANT)

    def test_one_list_left(self):
        # 옛 목록이 남아 있지 않다: 넷 모두 scan/skip-dirs 를 읽는다(형식 1·2 를 다시 재는 receipt.LEGACY_TREE_SKIP_DIRS 만 남는다)
        for name in ("residue.sh", "cbom-scan.sh"):
            text = (PROOF / "scan" / name).read_text(encoding="utf-8")
            self.assertIn("skip-dirs", text)
            self.assertNotIn("-name vendor", text)
            self.assertNotIn("--exclude-dir=vendor", text)
        self.assertFalse(hasattr(scanmod, "SKIP_DIRS"))
        self.assertFalse(hasattr(rc, "TREE_SKIP_DIRS"))
        self.assertEqual(rc.LEGACY_TREE_SKIP_DIRS, {".git", "node_modules", "target", "build", "__pycache__", ".gradle", ".idea",
                                                    "__MACOSX", ".venv", "venv"})
        # 두 셸 스캐너의 skip_dirs 함수는 같은 글이다
        part = re.compile(r"(?s)# --- 건너뛰는 폴더\(scan/skip-dirs\).*?# --- 건너뛰는 폴더 끝")
        texts = [part.search((PROOF / "scan" / n).read_text(encoding="utf-8")) for n in ("residue.sh", "cbom-scan.sh")]
        self.assertTrue(all(texts))
        self.assertEqual(texts[0][0], texts[1][0])

    def test_bad_list_is_a_usage_error(self):
        bad = os.path.join(self.tmp, "bad-skip")
        pathlib.Path(bad).write_text("skip build\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            skipdirs.load(bad)
        for script in ("residue.sh", "cbom-scan.sh"):
            r = subprocess.run(["bash", str(PROOF / "scan" / script), self.root], capture_output=True, text=True,
                               env=dict(os.environ, SKIP_DIRS=bad, OUT=os.path.join(self.tmp, "o-" + script)))
            self.assertEqual(r.returncode, 2, (script, r.stdout[-500:], r.stderr[-500:]))


if __name__ == "__main__":
    unittest.main()
