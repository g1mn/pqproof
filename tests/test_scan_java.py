"""오프라인판이 scan.py에 보탠 Java BC/JCA 규칙: getInstance 호출, PQC 이름, BC 공급자 등록, TLS 그룹 설정, 런타임 이미지."""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from pqlite import scan as S


def rows_of(files):
    with tempfile.TemporaryDirectory() as d:
        for path, text in files.items():
            p = pathlib.Path(d, path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        return S.scan(d)


def brief(rows):
    return [(r.line, r.kind, r.algorithm, r.threat) for r in rows]


CLASSIC = """package x;
import java.security.*;
import javax.crypto.*;
class C {
  static final String SIG = "SHA256withECDSA";
  KeyPair a(boolean e) throws Exception { return KeyPairGenerator.getInstance(e ? "RSA" : "EC").generateKeyPair(); }
  Signature b() throws Exception { return Signature.getInstance(SIG); }
  Cipher c() throws Exception { return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC"); }
  KeyAgreement d() throws Exception { return KeyAgreement.getInstance("X25519"); }
  KeyFactory f() throws Exception { return KeyFactory.getInstance("EC"); }
  Cipher g() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
  // KeyPairGenerator.getInstance("DSA") in a comment is not a row
}
"""

PQC = """package x;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.*;
class P {
  static { Security.addProvider(new BouncyCastleProvider()); }
  KeyPair k() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM", "BC");
    g.initialize(MLKEMParameterSpec.ml_kem_768);
    return g.generateKeyPair();
  }
  Signature s() throws Exception { return Signature.getInstance("ML-DSA-65", "BC"); }
  Signature w() throws Exception { return Signature.getInstance("ML-DSA-44", "BC"); }
  Object old() { return KyberParameterSpec.kyber512; }
  Object dil() { return DilithiumParameterSpec.dilithium3; }
  KeyPairGenerator v(String alg) throws Exception { return KeyPairGenerator.getInstance(alg, "BC"); }
}
"""


class JavaRules(unittest.TestCase):
    def test_classical_calls(self):
        rows = rows_of({"src/main/java/x/C.java": CLASSIC})
        self.assertEqual(brief(rows), [
            (6, "key-generation", "RSA", "shor"), (6, "key-generation", "EC", "shor"),
            (7, "signature", "SHA256withECDSA", "shor"),
            (8, "key-encryption", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "shor"),
            (9, "key-exchange", "X25519", "shor"),
            (10, "key-encoding", "EC", "shor"),
        ])
        self.assertIn("공급자 BC", rows[3].detail)
        self.assertIn("(상수)", rows[2].detail)
        self.assertTrue(all(r.component == "java" and r.blocks_hybrid is False for r in rows))

    def test_pqc_names_provider_and_weak_categories(self):
        got = brief(rows_of({"src/main/java/x/P.java": PQC}))
        self.assertIn((6, "provider", "BouncyCastleProvider", "info"), got)
        self.assertIn((8, "key-generation", "ML-KEM", "pqc"), got)
        self.assertIn((9, "pqc-parameter", "ml_kem_768", "pqc"), got)
        self.assertIn((12, "signature", "ML-DSA-65", "pqc"), got)
        self.assertIn((13, "signature", "ML-DSA-44", "weak-pqc"), got)
        self.assertIn((14, "pqc-parameter", "kyber512", "weak-pqc"), got)
        self.assertIn((15, "pqc-parameter", "dilithium3", "pqc"), got)
        self.assertIn((16, "key-generation", "unrecognized (variable)", "unknown"), got)

    def test_slhdsa_levels(self):
        # 규칙 묶음 4: FIPS 205 SLH-DSA 128 은 보안레벨 1이라 막고, 192·256 은 PQC. 해시 이름이 없는 SLH-DSA 는 예전처럼 PQC
        got = {n: S._classify(n)[1] for n in ("SLH-DSA-SHA2-128s", "slh_dsa_shake_128f", "SLH-DSA-SHA2-192s",
                                                 "SLH-DSA-SHAKE-256f", "SLH-DSA")}
        self.assertEqual(got, {"SLH-DSA-SHA2-128s": "weak-pqc", "slh_dsa_shake_128f": "weak-pqc", "SLH-DSA-SHA2-192s": "pqc",
                               "SLH-DSA-SHAKE-256f": "pqc", "SLH-DSA": "pqc"})

    def test_prestandard_names_are_flagged_in_detail(self):
        rows = rows_of({"src/main/java/x/P.java": PQC})
        dil = next(r for r in rows if r.algorithm == "dilithium3")
        self.assertIn("Dilithium", dil.detail)

    def test_test_sources_and_strings_in_comments_are_skipped(self):
        self.assertEqual(rows_of({"src/test/java/x/CTest.java": CLASSIC}), [])
        self.assertEqual(rows_of({"src/main/java/x/D.java": "/* Signature.getInstance(\"SHA1withRSA\") */ class D {}\n"}), [])

    def test_hybrid_ml_kem_name_is_pqc(self):
        rows = rows_of({"A.java": 'class A { Object k() throws Exception { return KEM.getInstance("X25519MLKEM768"); } }\n'})
        self.assertEqual(brief(rows), [(1, "key-encapsulation", "X25519MLKEM768", "pqc")])
        self.assertIn("하이브리드", rows[0].detail)

    def test_symmetric_cipher_has_no_row(self):
        self.assertEqual(rows_of({"A.java": 'class A { Object c() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); } }\n'}), [])

    def test_named_groups_in_code_and_settings(self):
        rows = rows_of({
            "A.java": 'class A { void f(javax.net.ssl.SSLParameters p) { p.setNamedGroups(new String[]{"x25519", "secp256r1"}); } }\n',
            "B.java": 'class B { void f(javax.net.ssl.SSLParameters p) { p.setNamedGroups(new String[]{"X25519MLKEM768", "x25519"}); } }\n',
            "Dockerfile": 'FROM eclipse-temurin:21-jre-noble\nENV JAVA_TOOL_OPTIONS="-Djdk.tls.namedGroups=x25519,secp256r1"\n',
            "src/main/resources/application.properties": "# jdk.tls.namedGroups=x25519\n",
        })
        kx = [(r.path, r.algorithm, r.threat, r.blocks_hybrid) for r in rows if r.kind == "key-exchange"]
        self.assertEqual(kx, [("A.java", "X25519, P-256", "shor", True), ("B.java", "X25519MLKEM768, X25519", "pqc", False),
                              ("Dockerfile", "X25519, P-256", "shor", True)])

    def test_ubuntu_runtime_images(self):
        rows = rows_of({"Dockerfile": "FROM maven:3.9 AS build\nFROM eclipse-temurin:21-jdk-jammy\n"})
        self.assertEqual([(r.algorithm, r.blocks_hybrid, r.threat) for r in rows], [("eclipse-temurin:21-jdk-jammy", True, "shor")])
        rows = rows_of({"Dockerfile": "FROM debian:trixie-slim\n"})
        self.assertEqual([(r.blocks_hybrid, r.threat) for r in rows], [(False, "pqc")])

    def test_build_output_is_skipped(self):
        self.assertEqual(rows_of({"target/classes/C.java": CLASSIC, "build/C.java": CLASSIC}), [])


# 변이 시험에서 놓친 꼴: 같은 이름 지역 변수, Map.of 표, 분기 대입, 다른 파일 상수
TRACE = """package x;
import java.security.*;
import java.util.Map;
class T {
  private static final Map<String, String> ALGS = Map.of("enc", "RSA", "sig", "ML-DSA-65");
  boolean old(PublicKey k) throws Exception { String alg = "SHA256withECDSA"; Signature v = Signature.getInstance(alg); return true; }
  byte[] cur(PrivateKey k) throws Exception { String alg = "ML-DSA-65"; Signature s = Signature.getInstance(alg, "BC"); return null; }
  KeyPair gen(String purpose) throws Exception { String a = ALGS.get(purpose); return KeyPairGenerator.getInstance(a, "BC").generateKeyPair(); }
  Signature branch(boolean x) throws Exception { String alg; if (x) { alg = "ML-DSA-65"; } else { alg = "SHA384withECDSA"; } return Signature.getInstance(alg, "BC"); }
  Signature other() throws Exception { return Signature.getInstance(Algs.SIG, "BC"); }
  KeyPairGenerator conf(Map<String, String> cfg) throws Exception { return KeyPairGenerator.getInstance(cfg.get("x.alg")); }
  Cipher sym(Map<String, String> cfg) throws Exception { return Cipher.getInstance(cfg.get("t")); }
}
"""
ALGS = "package x;\nfinal class Algs {\n  static final String SIG = \"SHA512withRSA\";\n}\n"

# BC 경량 API, JCA 키 스펙, 키 형, JWT/JOSE 상수, OID, 곡선 표
LIGHT = """package x;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.crypto.signers.ECDSASigner;
class L {
  Object a() { return new ECDSASigner(); }
  Object b() { return new org.bouncycastle.crypto.encodings.OAEPEncoding(new org.bouncycastle.crypto.engines.RSAEngine()); }
  Object c() { return new java.security.spec.RSAKeyGenParameterSpec(3072, java.security.spec.RSAKeyGenParameterSpec.F4); }
  Object d() { return new java.security.spec.ECGenParameterSpec("secp384r1"); }
  Object e(java.security.Key k) { return ((RSAPublicKey) k).getModulus(); }
  Object f() { return io.jsonwebtoken.SignatureAlgorithm.RS256; }
  Object g() { return com.auth0.jwt.algorithms.Algorithm.ECDSA256(null, null); }
  Object h() { return org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey; }
  Object i() { return "ES256"; }
  Object j() { return org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("curve25519"); }
  Object k() { return new X25519Agreement(); }
}
"""

# PQC만 쓰는 비슷한 꼴: shor·확인 행이 나오면 오탐
PQ_ONLY = """package x;
class Q {
  static final String SIG = "ML-DSA-65";
  Object a() throws Exception { return java.security.Signature.getInstance(SIG, "BC"); }
  Object b() throws Exception { return new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("ML-DSA-65").setProvider("BC"); }
  Object c() { return new java.security.spec.NamedParameterSpec("ML-KEM-768"); }
  boolean d(java.security.Key k) { return k instanceof org.bouncycastle.jcajce.interfaces.MLDSAPublicKey; }
  Object e() throws Exception { String alg = "ML-KEM-768"; return java.security.KeyPairGenerator.getInstance(alg, "BC"); }
  Object f() throws Exception { return javax.crypto.Cipher.getInstance("AES/GCM/NoPadding"); }
  // RSAPublicKey, new RSAEngine(), SignatureAlgorithm.RS256 in a comment
}
"""


class JavaTracing(unittest.TestCase):
    def test_locals_maps_branches_and_other_files(self):
        got = brief(r for r in rows_of({"src/main/java/x/T.java": TRACE, "src/main/java/x/Algs.java": ALGS}) if r.path.endswith("T.java"))
        by_line = {}
        for line, _kind, alg, threat in got:
            by_line.setdefault(line, set()).add((alg, threat))
        self.assertEqual(by_line[6], {("SHA256withECDSA", "shor")})  # 다른 메서드의 alg = "ML-DSA-65"에 가리지 않는다
        self.assertEqual(by_line[7], {("ML-DSA-65", "pqc")})
        self.assertEqual(by_line[8] - {("ML-DSA-65", "pqc")}, {("RSA", "shor")})  # Map.of 표 값
        self.assertIn(("SHA384withECDSA", "shor"), by_line[9])  # 값 없는 선언 뒤 분기 대입
        self.assertEqual(by_line[10], {("SHA512withRSA", "shor")})  # 다른 파일 Class.NAME
        self.assertEqual(by_line[11], {("unrecognized (name)", "unknown")})  # 설정 키 문자열은 알고리즘이 아니다
        self.assertNotIn(12, by_line)  # Cipher는 못 읽으면 행 없음(대칭일 때가 많다)
        rows = rows_of({"src/main/java/x/T.java": TRACE, "src/main/java/x/Algs.java": ALGS})
        self.assertIn("(변수 추적)", next(r for r in rows if r.line == 8 and r.algorithm == "RSA").detail)
        self.assertIn("(상수)", next(r for r in rows if r.line == 10 and r.path.endswith("T.java")).detail)

    def test_lightweight_api_specs_key_types_jwt_oid_curves(self):
        got = {(line, kind, alg) for line, kind, alg, threat in brief(rows_of({"src/main/java/x/L.java": LIGHT})) if threat == "shor"}
        self.assertEqual(got, {
            (5, "signature", "ECDSA"), (6, "key-encryption", "RSA-OAEP"), (6, "key-encryption", "RSA"),
            (7, "key-generation", "RSA"), (8, "key-generation", "EC secp384r1"), (9, "key-type", "RSA"),
            (10, "signature", "JWT RS256"), (11, "signature", "JWT ECDSA256"), (12, "key-encoding", "OID id_ecPublicKey"),
            (13, "signature", "JWT ES256 (ECDSA)"), (14, "key-encoding", "EC curve25519"), (15, "key-exchange", "X25519"),
        })  # import 줄(2·3)은 행이 아니다

    def test_pqc_only_lookalikes_have_no_shor_or_check_rows(self):
        rows = rows_of({"src/main/java/x/Q.java": PQ_ONLY})
        self.assertEqual([r for r in rows if r.threat in ("shor", "unknown")], [])
        self.assertIn((4, "signature", "ML-DSA-65", "pqc"), brief(rows))
        self.assertIn((8, "key-generation", "ML-KEM-768", "pqc"), brief(rows))


if __name__ == "__main__":
    unittest.main()
