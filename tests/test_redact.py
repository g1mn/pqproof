"""발췌의 비밀 값 가림(교차 리뷰 X33): prove.py 가 쓰는 표 발췌와 SARIF snippet, 스캐너 출력(artifacts/ 의 CBOM·residue)이
-storepass·pass:·ssh-keygen -N·password=·토큰 값을 같은 규칙으로 가리는지 본다(규칙 묶음 6부터). 가짜 토큰은 조각을 이어 만든다(저장소에 토큰 꼴 글자가 남지 않게)."""
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
sys.path.insert(0, str(PROOF / "src"))
import prove  # noqa: E402
from pqproof import sarif  # noqa: E402

GH = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123"
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"


class Patterns(unittest.TestCase):
    def test_masks(self):
        cases = {
            "keytool -genkeypair -keyalg RSA -storepass s3cr3tpass1 -keystore a.p12": "-storepass ***",
            "keytool -importkeystore -srcstorepass 'old pw' -deststorepass new": "-srcstorepass *** -deststorepass ***",
            "openssl genrsa -aes256 -passout pass:hunter2hunter2 -out k.pem 2048": "pass:***",
            'char[] password = "changeit".toCharArray();': "password = ***.toCharArray()",
            '{"client_secret": "abc123", "alg": "RS256"}': '"client_secret": ***',
            "spring.ssl.key-store-password=changeit": None,
            "Authorization: Bearer abcdefghijklmnop": "Bearer ***",
            f"export TOKEN={GH}": "TOKEN=***",
            f"aws configure set aws_access_key_id {AWS}": "aws_access_key_id ***",
            "api_key: 'k-123456'": "api_key: ***",
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                got, n = prove.redact(text)
                if want is None:  # key-store-password 는 password 앞이 '-' 라 \b 가 맞고 값이 가려진다
                    self.assertNotIn("changeit", got)
                    continue
                self.assertIn(want, got)
                self.assertGreaterEqual(n, 1)
                for secret in ("s3cr3tpass1", "old pw", "hunter2hunter2", "changeit", "abc123", "abcdefghijklmnop", GH, AWS,
                               "k-123456"):
                    self.assertNotIn(secret, got)

    def test_leaves_ordinary_code_alone(self):
        for text in ('KeyPairGenerator.getInstance("RSA")', "keytool -genkeypair -storepass:env STOREPASS -keyalg RSA",
                     "openssl pkcs12 -passin env:P12_PASS -in a.p12", "int maxTokens = 5;", "csrf_token_name = 'x'",
                     'Signature.getInstance("SHA256withECDSA")'):
            with self.subTest(text=text):
                self.assertEqual(prove.redact(text), (text, 0))

    def test_masking_twice_counts_once(self):
        once, n1 = prove.redact("x -storepass secretpw1 password=abc")
        twice, n2 = prove.redact(once)
        self.assertEqual((n1, n2, once), (2, 0, twice))

    def test_prove_and_sarif_share_the_rules(self):
        msg = "prove.py REDACT/MASK and src/pqproof/sarif.py REDACT/MASK hide the same values in tables and SARIF: change both"
        self.assertEqual(prove.REDACT, sarif.REDACT, msg)
        self.assertEqual(prove.MASK, sarif.MASK, msg)


# 같은 줄을 prove.py REDACT 와 cbom-scan.sh MASKAWK(스캐너 원본 출력 artifacts/ 의 발췌 가림)에 넣었을 때 비밀 값이 사라지는가
MASK_CASES = [
    ("keytool -genkeypair -keyalg RSA -storepass s3cr3tpass1 -keystore a.p12", "s3cr3tpass1"),
    ("keytool -importkeystore -srcstorepass oldpw1234 -deststorepass newpw5678", "oldpw1234"),
    ("openssl genrsa -aes256 -passout pass:hunter2hunter2 -out k.pem 2048", "hunter2hunter2"),
    ('char[] password = "changeit".toCharArray();', "changeit"),
    ('{"client_secret": "abc123xyz", "alg": "RS256"}', "abc123xyz"),
    ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
    (f"export TOKEN={GH}", GH),
    ("api_key: 'k-123456'", "k-123456"),
    ("secret_key = 'sk-test-1234567890'", "sk-test-1234567890"),
    (f"aws configure set aws_access_key_id {AWS}", AWS),
    (f"url = 'https://x/?q={GH}'", GH),
    ("ssh-keygen -t rsa -b 4096 -N 'shpassphrase999' -f id", "shpassphrase999"),
    ('{"refresh_token": "rt-0123456789abcdef"}', "rt-0123456789abcdef"),
    (f'Cipher c = Cipher.getInstance("RSA"); String k = "{AWS}";', AWS),
]
# 가리면 안 되는 값: ssh-keygen -n 은 인증서 주체 이름, 8자 미만 Bearer 는 자리표시, 숫자 상수
KEEP_CASES = [
    ("ssh-keygen -s ca -n alice,bob -I id k.pub", "alice,bob"),
    ("Authorization: Bearer token", "token"),
    ("int maxTokens = 5;", "maxTokens = 5"),
]


@unittest.skipUnless(shutil.which("awk"), "awk 없음")
class ScannerMaskAgrees(unittest.TestCase):
    """cbom-scan.sh·residue.sh 의 awk 가림(MASKFN, 두 파일에 같은 글)이 prove.py REDACT 와 같은 값을 가리고 같은 값을 남긴다."""

    def test_scanner_hides_what_prove_hides(self):
        import re
        import subprocess
        text = (PROOF / "scan" / "cbom-scan.sh").read_text(encoding="utf-8")
        prog = re.search(r"(?ms)^MASKFN='(.*?)'$", text)[1] + "\n{ print mask($0) }"
        cases = MASK_CASES + KEEP_CASES
        out = subprocess.run(["awk", prog], input="\n".join(c for c, _ in cases) + "\n", capture_output=True, text=True,
                             check=True).stdout.splitlines()
        self.assertEqual(len(out), len(cases))
        msg = ("scan/cbom-scan.sh and scan/residue.sh MASKFN and prove.py REDACT must hide the same values: change MASKFN in both "
               "shell scanners and REDACT in prove.py and src/pqproof/sarif.py together (a ruleset change, CONTRIBUTING.md)")
        for (line, value), masked in zip(MASK_CASES, out):
            with self.subTest(line=line):
                self.assertNotIn(value, prove.redact(line)[0], msg)
                self.assertNotIn(value, masked, msg)
        for (line, value), kept in zip(KEEP_CASES, out[len(MASK_CASES):]):
            with self.subTest(line=line):
                self.assertIn(value, prove.redact(line)[0], msg)
                self.assertIn(value, kept, msg)


@unittest.skipUnless(shutil.which("bash") and prove.default_openssl(), "bash 또는 openssl 없음")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-redact-")
        orig = os.path.join(cls.tmp, "orig")
        fixed = os.path.join(cls.tmp, "fixed")
        shutil.copytree(PROOF / "examples" / "classic", orig)
        shutil.copytree(PROOF / "examples" / "classic", fixed)
        os.makedirs(os.path.join(fixed, "ops"))
        pathlib.Path(fixed, "ops", "make-keys.sh").write_text(
            "#!/bin/sh\n"
            "keytool -genkeypair -alias app -keyalg RSA -keysize 2048 -keystore app.p12 -storepass s3cr3tpass1\n"
            "openssl genrsa -aes256 -passout pass:hunter2hunter2 -out k.pem 2048\n"
            "ssh-keygen -t rsa -N 'shpassphrase999' -f id\n"
            f"export API_TOKEN={GH}\n", encoding="utf-8")
        pathlib.Path(fixed, "ops", "K.java").write_text(f'class K {{ Object c = javax.crypto.Cipher.getInstance("RSA"); String k = "{AWS}"; }}\n',
                                                         encoding="utf-8")
        cls.out = os.path.join(cls.tmp, "out")
        env = {"EXPECT": "kem,sig", "ALLOW": "none", "RECON": "none"}
        cls.r, cls.code, cls.lines = prove.run(orig, fixed, prove.Params(env), cls.out, quiet=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def test_tables_and_sarif_hide_the_secrets(self):
        self.assertEqual(self.code, 1)
        secrets = ("s3cr3tpass1", "hunter2hunter2")
        tables = "".join(p.read_text(encoding="utf-8") for p in pathlib.Path(self.out, "tables").iterdir())
        tables += "".join(pathlib.Path(self.out, n).read_text(encoding="utf-8") for n in ("receipt.json", "receipt.html", "deck.json",
                                                                                         "evidence-fragment.json"))
        self.assertIn("make-keys.sh", tables)
        for s in secrets:
            self.assertNotIn(s, tables)
        doc = sarif.convert(self.out)
        text = json.dumps(doc, ensure_ascii=False)
        self.assertIn("make-keys.sh", text)
        for s in secrets:
            self.assertNotIn(s, text)
        self.assertGreaterEqual(doc["runs"][0]["properties"]["redactedSnippets"], 1)
        self.assertTrue(any("*** 로 가렸다" in line for line in self.lines), self.lines[-6:])

    def test_scanner_output_hides_them_too(self):
        # 규칙 묶음 6부터 artifacts/ 의 스캐너 출력(CBOM 발췌, residue 줄)도 가린다. 입력 사본 in/ 만 원문이다(zip 입력일 때)
        secrets = ("s3cr3tpass1", "hunter2hunter2", "shpassphrase999", GH, AWS)
        left = []
        for path in pathlib.Path(self.out).rglob("*"):
            rel = path.relative_to(self.out).as_posix()
            if path.is_file() and not rel.startswith("in/"):
                text = path.read_text(encoding="utf-8", errors="replace")
                left += [f"{rel}: {s[:4]}..." for s in secrets if s in text]
        self.assertEqual(left, [], "a secret value is still in the output folder")
        raw = pathlib.Path(self.out, "artifacts", "residue-fixed.txt").read_text(encoding="utf-8")
        self.assertIn("-storepass ***", raw)


if __name__ == "__main__":
    unittest.main()
