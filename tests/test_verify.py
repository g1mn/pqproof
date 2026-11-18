# 일부 from g1mn/pq-proof 7b7803f (MIT): OriginalRules의 기대 문구(proxy_ssl_verify on removed 등)는 pq-proof
# tests/test_verify.py의 경우를 줄여 옮겼다. 나머지는 오프라인판에서 새로 썼다.
"""TLS 약화 수정 검사: 오프라인판이 보탠 Java·Spring·JDK 규칙(deny)과 review 등급, PQ-Proof 원래 규칙 몇 가지."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from pqlite.verify import JAVA, kind_of, review, views, weakening  # noqa: E402

BASE = "package x;\nclass A {\n  void f() {}\n}\n"


def java(body):
    return "package x;\nclass A {\n  void f() {}\n" + body + "\n}\n"


def rules(changed):
    return [w.split(": ", 1)[1].split(" (before")[0] for w in weakening(changed)]


class JavaDeny(unittest.TestCase):
    def test_trust_all_manager(self):
        after = java("  TrustManager[] t = { new X509TrustManager() {\n"
                     "    public void checkServerTrusted(X509Certificate[] c, String a) {}\n"
                     "    public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { }\n"
                     "    public X509Certificate[] getAcceptedIssuers() { return null; } } };")
        got = rules({"A.java": (BASE, after)})
        self.assertIn("TrustManager that trusts every certificate (X509TrustManager, trustAll)", got)
        self.assertIn("checkServerTrusted/checkClientTrusted with an empty body", got)

    def test_hostname_verifier_lambda_and_okhttp(self):
        self.assertTrue(rules({"A.java": (BASE, java("  void g(HttpsURLConnection c) { c.setHostnameVerifier((h, s) -> true); }"))}))
        self.assertTrue(rules({"A.kt": ("class A\n", "class A { val c = OkHttpClient.Builder().hostnameVerifier { _, _ -> true } }\n")}))
        self.assertTrue(rules({"A.kt": ("class A\n", "val c = b.hostnameVerifier(x)\n")}))
        self.assertTrue(rules({"A.java": (BASE, java("  Object v = NoopHostnameVerifier.INSTANCE;"))}))

    def test_old_protocols_in_java_code(self):
        self.assertIn("SSLContext for SSL 3.0 or TLS 1.0/1.1",
                      rules({"A.java": (BASE, java('  Object c = SSLContext.getInstance("TLSv1.1");'))}))
        self.assertIn("TLS 1.0/1.1 or SSLv3 in setEnabledProtocols/setProtocols",
                      rules({"A.java": (BASE, java('  void g(SSLSocket s) { s.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.3"}); }'))}))
        self.assertEqual(rules({"A.java": (BASE, java('  void g(SSLSocket s) { s.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"}); }'))}), [])
        self.assertEqual(rules({"A.java": (BASE, java('  Object c = SSLContext.getInstance("TLS");'))}), [])

    def test_endpoint_identification_off_and_trust_strategies(self):
        self.assertTrue(rules({"A.java": (BASE, java("  void g(SSLParameters p) { p.setEndpointIdentificationAlgorithm(null); }"))}))
        self.assertTrue(rules({"A.java": (BASE, java("  Object s = new TrustSelfSignedStrategy();"))}))
        self.assertTrue(rules({"A.java": (BASE, java("  Object f = InsecureTrustManagerFactory.INSTANCE;"))}))

    def test_disabled_algorithms_in_code_and_options(self):
        self.assertTrue(rules({"A.java": (BASE, java('  static { Security.setProperty("jdk.tls.disabledAlgorithms", ""); }'))}))
        self.assertTrue(rules({"Dockerfile": ("FROM x\n", 'FROM x\nENV JAVA_TOOL_OPTIONS="-Djdk.tls.disabledAlgorithms=NULL"\n')}))
        self.assertTrue(rules({"conf/java.security": ("jdk.tls.disabledAlgorithms=SSLv3, TLSv1, RC4\n",
                                                      "jdk.tls.disabledAlgorithms=RC4\n")}))

    def test_comments_and_strings_do_not_count_and_moves_are_fine(self):
        self.assertEqual(rules({"A.java": (BASE, java("  // X509TrustManager trustAll HostnameVerifier\n  /* setHostnameVerifier */"))}), [])
        moved_b = java("  void g(HttpsURLConnection c) { c.setHostnameVerifier(v); }")
        moved_a = java("  void h() {}\n  void g(HttpsURLConnection c) { c.setHostnameVerifier(v); }")
        self.assertEqual(rules({"A.java": (moved_b, moved_a)}), [])

    def test_text_block_is_a_string(self):
        code, bare = views('class A { String s = """\n  X509TrustManager\n"""; }\n', JAVA)
        self.assertIn("X509TrustManager", code)
        self.assertNotIn("X509TrustManager", bare)

    def test_kind_of(self):
        self.assertEqual([kind_of(p) for p in ("a/B.java", "B.kt", "b.kts", "c.groovy", "d.scala")], [JAVA] * 5)


class SpringDeny(unittest.TestCase):
    BEFORE = ("server.port=8443\nserver.ssl.enabled=true\nserver.ssl.client-auth=need\n"
              "server.ssl.trust-store=classpath:trust.p12\nserver.ssl.enabled-protocols=TLSv1.3\n")

    def test_properties(self):
        after = "server.port=8443\nserver.ssl.enabled=false\nserver.ssl.client-auth=want\nserver.ssl.enabled-protocols=TLSv1.1,TLSv1.3\n"
        got = rules({"src/main/resources/application.properties": (self.BEFORE, after)})
        self.assertEqual(sorted(got), sorted([
            "server.ssl.enabled=false (Spring Boot TLS turned off)",
            "TLS 1.0/1.1 or SSLv3 in a Spring or JDK protocol setting",
            "server.ssl.client-auth none or want (client certificate no longer required)",
            "server.ssl.client-auth=need removed",
            "trust store setting removed"]))

    def test_trust_store_changed(self):
        after = self.BEFORE.replace("classpath:trust.p12", "file:/tmp/other.p12")
        self.assertEqual(rules({"application.properties": (self.BEFORE, after)}), ["trust store changed"])

    def test_yaml_lists_and_env_names(self):
        yb = "server:\n  ssl:\n    enabled-protocols:\n      - TLSv1.3\n"
        ya = "server:\n  ssl:\n    enabled-protocols:\n      - TLSv1.3\n      - TLSv1\n"
        self.assertEqual(rules({"application.yml": (yb, ya)}), ["TLS 1.0/1.1 or SSLv3 in a Spring or JDK protocol setting"])
        self.assertTrue(rules({"compose.yaml": ("services: {}\n", "services:\n  app:\n    environment:\n      SERVER_SSL_ENABLED: \"false\"\n")}))
        flow = "server:\n  ssl:\n    enabled-protocols: [TLSv1.2, TLSv1.3]\n"
        self.assertEqual(rules({"application.yml": (yb, flow)}), [])

    def test_unrelated_settings_pass(self):
        self.assertEqual(rules({"application.properties": (self.BEFORE, self.BEFORE + "app.crypto.kem=ML-KEM-768\n")}), [])


class Review(unittest.TestCase):
    def test_stub_verify_method(self):
        before = java("  boolean verifySignature(byte[] m, byte[] s) throws Exception {\n    Signature v = Signature.getInstance(\"ML-DSA-65\", \"BC\");\n"
                      "    v.initVerify(key); v.update(m); return v.verify(s);\n  }")
        after = java("  boolean verifySignature(byte[] m, byte[] s) throws Exception { return true; }")
        got = review({"A.java": (before, after)})
        self.assertEqual({x["rule"] for x in got}, {
            "signature verification calls decreased across the patch (initVerify, verify)",
            "verify/isValid/check method that only returns success"})
        self.assertEqual(weakening({"A.java": (before, after)}), [])  # review는 deny가 아니다

    def test_moving_verification_to_another_file_is_not_flagged(self):
        b1, a1 = java("  boolean ok() { v.initVerify(k); return v.verify(s); }"), java("  boolean ok() { return Checker.run(s); }")
        b2, a2 = "class Checker {}\n", "class Checker { static boolean run(byte[] s) { v.initVerify(k); return v.verify(s); } }\n"
        self.assertEqual(review({"A.java": (b1, a1), "Checker.java": (b2, a2)}), [])

    def test_decrypt_calls_decreased(self):
        before = java("  byte[] d(Cipher c) throws Exception { c.init(Cipher.DECRYPT_MODE, k); return c.doFinal(x); }")
        after = java("  byte[] d(Cipher c) { return x; }")
        self.assertEqual([x["rule"] for x in review({"A.java": (before, after)})],
                         ["decryption, unwrap or decapsulation calls decreased across the patch"])

    def test_go_and_python_stubs(self):
        self.assertTrue(review({"a.go": ("package a\n", "package a\nfunc verifyToken(t string) bool { return true }\n")}))
        self.assertTrue(review({"a.py": ("", "def verify_sig(m, s) -> bool: return True\n")}))


class OriginalRules(unittest.TestCase):
    """PQ-Proof 원래 규칙이 사본에서도 그대로 도는지(일부)."""

    def test_go_insecure_skip_verify(self):
        b = "package a\nvar c = tls.Config{MinVersion: tls.VersionTLS12}\n"
        a = "package a\nvar c = tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}\n"
        self.assertEqual(rules({"a.go": (b, a)}), ["InsecureSkipVerify"])

    def test_go_existing_construct_is_not_new(self):
        a = "package a\nvar c = tls.Config{InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}\n"
        b = "package a\nvar c = tls.Config{InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.CurveP256}}\n"
        self.assertEqual(rules({"a.go": (b, a)}), [])

    def test_nginx_verify_off_and_min_version(self):
        b = "http { server { proxy_ssl_verify on; ssl_protocols TLSv1.2 TLSv1.3; } }\n"
        a = "http { server { proxy_ssl_verify off; ssl_protocols TLSv1 TLSv1.2 TLSv1.3; } }\n"
        self.assertEqual(sorted(rules({"nginx/nginx.conf": (b, a)})), sorted([
            "proxy_ssl_verify off", "proxy_ssl_verify on removed (nginx's default is off)", "TLS 1.0/1.1 or SSLv3 in a protocol list"]))

    def test_js_and_python(self):
        self.assertTrue(rules({"a.js": ("", "https.request({rejectUnauthorized: false})\n")}))
        self.assertTrue(rules({"a.py": ("", "requests.get(u, verify=False)\n")}))


if __name__ == "__main__":
    unittest.main()
