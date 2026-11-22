"""0.6.0, NIS draft guidelines (November 2026): 112-bit key floor (S1), PQ/PQ hybrid mark (S2), allowlist exception fields (G9),
TLS cipher suite and certificate expiry (G7)."""
import pathlib
import shutil
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from pqlite import allowlist as al  # noqa: E402
from pqlite import rules  # noqa: E402
from pqlite import tlsprobe as T  # noqa: E402
from test_tlsprobe import HYBRID_OUT, OPENSSL_HYBRID  # noqa: E402


def row(loc, alg, threat="쇼어로 깨짐", use="키교환", note=""):
    return {"위치": loc, "양자 위협": threat, "근거·비고": note, "알고리즘·키 길이": alg, "용도": use}


class Floor(unittest.TestCase):
    def test_sizes(self):
        below = ("RSA-1024", "rsa1024", "DSA-1024", "DH-1024", "ElGamal-1536", "EC-192 prime192v1", "secp192r1", "P-192",
                 "sect163k1", "brainpoolP160r1", "RSA-512")
        fine = ("RSA-2048", "rsa:3072", "RSA", "ECDSA-256", "secp224r1", "secp256r1", "P-256", "ffdhe2048", "RSA-OAEP-256",
                "X25519", "ecdh", "ML-KEM-768")
        for a in below:
            with self.subTest(a=a):
                self.assertTrue(rules.below_floor(a))
        for a in fine:
            with self.subTest(a=a):
                self.assertFalse(rules.below_floor(a))


class Merge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pqp-nis-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        src = pathlib.Path(self.tmp, "src")
        src.mkdir()
        (src / "LegacyKeys.java").write_text('final class LegacyKeys {\n    static final String ALG = "RSA";\n}\n', encoding="utf-8")
        (src / "Kem.py").write_text("kem = combine(MLKEM768(), SmaugT3())  # PQ/PQ\nsig = MLDSA65()\n", encoding="utf-8")
        self.lines = rules.Lines(self.tmp)

    def merge(self, rows_):
        return rules.merge_cbom(rows_, [], self.lines, False)[0]

    def test_a_weak_classical_key_is_not_allowed_by_the_name_rule(self):
        weak, ok = self.merge([row("src/LegacyKeys.java:2", "RSA-1024", use="서명")]), self.merge([row("src/LegacyKeys.java:2", "RSA-2048", use="서명")])
        self.assertEqual((weak[0]["status"], weak[0]["reason"]), ("block", rules.FLOOR_REASON))
        self.assertEqual((ok[0]["status"], ok[0]["reason"]), ("allow", rules.LEGACY_REASONS[0]))

    def test_pq_pq_lines_are_marked_and_still_info(self):
        items = self.merge([row("src/Kem.py:1", "ML-KEM-768", threat="안전(PQC)", note="일반 패턴"),
                            row("src/Kem.py:2", "ML-DSA-65", threat="안전(PQC)", note="일반 패턴")])
        self.assertEqual([it["status"] for it in items], ["info", "info"])
        self.assertTrue(items[0]["reason"].startswith(rules.PQPQ_REASON))
        self.assertIn("SMAUG-T", items[0]["reason"])
        self.assertEqual(items[1]["reason"], "")

    def test_pq_pq_families(self):
        self.assertEqual(rules.pqpq_families("mldsa65 + haetae3"), ["ML-DSA", "HAETAE"])
        self.assertEqual(rules.pqpq_families("sig=ML-DSA-65; kem=SMAUG-T"), [])  # a KEM and a signature are not a hybrid


class ExceptionDigest(unittest.TestCase):
    def test_fields_enter_the_digest_only_when_set(self):
        old = {"where": "A.java:1-5", "why": "w", "kind": "exception"}
        self.assertEqual(al.review_digest([old]), al.review_digest([dict(old, residual_risk=" ")]))
        for k in al.EXCEPTION_FIELDS:
            with self.subTest(k=k):
                self.assertNotEqual(al.review_digest([old]), al.review_digest([dict(old, **{k: "x"})]))


class TlsDetail(unittest.TestCase):
    def test_new_probe_lines(self):
        h = T.parse(HYBRID_OUT.replace("group: X25519MLKEM768\n", "group: X25519MLKEM768\ncipher: TLS_AES_128_GCM_SHA256\n")
                    + "cert_not_after: 2027-11-22T00:00:00Z\n")
        self.assertEqual((h.cipher, h.cert_not_after, h.kind), ("TLS_AES_128_GCM_SHA256", "2027-11-22T00:00:00Z", "hybrid"))
        self.assertEqual(h.to_json()["cert_not_after"], "2027-11-22T00:00:00Z")

    def test_old_probe_and_openssl(self):
        self.assertEqual((T.parse(HYBRID_OUT).cipher, T.parse(HYBRID_OUT).cert_not_after), (None, None))
        self.assertEqual(T.parse(OPENSSL_HYBRID).cipher, "TLS_AES_256_GCM_SHA384")

    def test_go_source_prints_them(self):
        src = (HERE.parent / "probe" / "tls_probe.go").read_text(encoding="utf-8")
        self.assertIn('cert_not_after: %s', src)
        self.assertIn("tls.CipherSuiteName(st.CipherSuite)", src)
        self.assertIn(f'const version = "{T.PROBE_VERSION}"', src)


if __name__ == "__main__":
    unittest.main()
