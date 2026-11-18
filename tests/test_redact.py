"""발췌의 비밀 값 가림(교차 리뷰 X33): prove.py 가 쓰는 표 발췌와 SARIF snippet 에서 -storepass·pass:·password=·토큰 값을 가리고,
두 파일의 규칙이 같으며, 원문(artifacts/)은 그대로 남는지 본다. 가짜 토큰은 조각을 이어 만든다(저장소에 토큰 꼴 글자가 남지 않게)."""
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
        self.assertEqual(prove.REDACT, sarif.REDACT)
        self.assertEqual(prove.MASK, sarif.MASK)


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
            f"export API_TOKEN={GH}\n", encoding="utf-8")
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
        # 원문은 그대로 남는다(문서의 '넘기기 전 확인' 대상). 스캐너 출력의 가림은 규칙 묶음 2(0.2.0)에서
        raw = pathlib.Path(self.out, "artifacts", "residue-fixed.txt").read_text(encoding="utf-8")
        self.assertIn("s3cr3tpass1", raw)


if __name__ == "__main__":
    unittest.main()
