"""같은 규칙 값이 여러 파일에 있을 때 서로 맞는지(동기 시험). 판정은 바꾸지 않고 어긋남만 잡는다.

residue.sh 의 규칙 표와 쓰기 연산·legacy·Legacy*.java 규칙을 prove.py(공개키 9계열, 허용 규칙)와 sarif.py(결과로 내는 규칙)에
맞춰 보고, prove.py 와 deps.py 가 OpenSSL 을 같은 순서로 고르는지 가짜 openssl 로 돌려 본다. 한 곳만 고치면 residue 는 LEFT 로
세는데 prove.py 는 허용으로 빼거나 SARIF 수가 증적과 어긋난다. 0.2.0 에서 파이썬 쪽 값을 한 모듈에서 읽게 되면 그 부분은
import 로 바뀐다. 건너뛰는 폴더 목록 넷(residue.sh·cbom-scan.sh·scan.py·receipt.py)은 지금 서로 다르고 0.2.0 에서 하나로 모은다(알려진 실패 X09, 지금 값 그대로 고정).
"""
import os
import pathlib
import re
import shutil
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
from pqproof import deps, sarif  # noqa: E402

# 알려진 실패: 지금 동작 그대로 고정했다. 고친 판에서는 그 시험이 실패하니 기대값을 뒤집고 여기서 지운다(tests/run_unit.py 가 센다)
KNOWN_GAPS = {"X09": "건너뛰는 폴더 목록이 residue.sh·cbom-scan.sh·scan.py·receipt.py 네 곳에 따로 있고 서로 다르다"}


def ids(kind):
    return [r["id"] for r in rulesrc.residue_rules() if r["kind"] == kind]


class ResidueAndProve(unittest.TestCase):
    def test_families_are_the_first_nine_gen_rules(self):
        # residue.sh 머리 주석: 앞의 아홉 줄(G-RSA ~ G-DH-DSA)이 prove.sh 가 세는 '공개키 9계열'이다
        self.assertEqual(ids("GEN")[:9], rules.FAMILIES)

    def test_expect_rule_ids(self):
        self.assertEqual(set(ids("EXPECT")), set(rules.EXPECT_IDS.values()))

    def test_weak_pqc_rule_is_the_one_prove_counts(self):
        self.assertIn("G-WEAK-PQC", ids("GEN"))
        self.assertIn('rules.get("G-WEAK-PQC"', (PROOF / "pqlite" / "rules.py").read_text(encoding="utf-8"))

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

    def test_same_line_ml_kem_forms_differ_as_recorded(self):
        # 같은 줄 ML-KEM 인정 꼴이 두 곳에서 다르다: residue.sh 는 대소문자를 가리고 밑줄을 안 받는다(ml_kem_768 X25519 는 LEFT),
        # prove.py 는 둘 다 받는다. 지금 값을 적어 두어 한쪽만 바뀌면 여기서 알린다(바꿀 때는 판정 영향을 따진다)
        allow = {r["id"]: r["allow"] for r in rulesrc.residue_rules()}
        self.assertEqual(allow["G-X25519"], "ML-?KEM|MLKEM")
        self.assertEqual((rules.HYBRID_LINE.pattern, bool(rules.HYBRID_LINE.flags & re.I)), ("ML[-_]?KEM", True))


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
    def test_known_gap_X09_four_skip_lists(self):
        names, top = rulesrc.residue_skips()
        cbom = (PROOF / "scan" / "cbom-scan.sh").read_text(encoding="utf-8")
        prune = re.search(r"^PRUNE='-mindepth 1 \( (.*?) \) -prune -o'$", cbom, re.M)
        got = {
            "residue.sh -name": sorted(names), "residue.sh top": sorted(top), "cbom-scan.sh": sorted(re.findall(r"-name (\S+)", prune[1])),
            "scan.py": sorted(scanmod.SKIP_DIRS), "receipt.py": sorted(rc.TREE_SKIP_DIRS),
        }
        now = {
            "residue.sh -name": [".git", "__pycache__", "node_modules", "vendor"], "residue.sh top": ["build", "data", "target"],
            "cbom-scan.sh": [".git", ".venv", "__pycache__", "build", "dist", "evidence", "node_modules", "target", "vendor", "venv"],
            "scan.py": [".git", ".gradle", "__pycache__", "build", "node_modules", "target", "vendor"],
            "receipt.py": [".git", ".gradle", ".idea", ".venv", "__MACOSX", "__pycache__", "build", "node_modules", "target", "venv"],
        }
        self.assertEqual(got, now, "알려진 실패 X09 가 바뀌었다: 목록을 하나로 모았다면 이 시험을 동기 시험으로 바꾸고 KNOWN_GAPS 에서 지운다")


if __name__ == "__main__":
    unittest.main()
