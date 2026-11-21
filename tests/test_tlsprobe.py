"""tls_probe 출력 읽기, 대조 판정, 대상 판정, 컨테이너 명령 꼴, 그리고 맥에서 참조 서버를 띄운 실측."""
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from pqlite import tlsprobe as T

HYBRID_OUT = """probe: tls_probe 0.4.0 (go1.27.3)
target: 127.0.0.1:8443
offered: X25519MLKEM768
trust: tofu ca_spki_sha256=ab self_signed=true
result: connected
protocol: TLS 1.3
group: X25519MLKEM768
cert_sig: ML-DSA-65
cert_key: ML-DSA-65
cert_chain: 1
"""
FAILED_OUT = "probe: tls_probe 0.4.0\ntarget: x\noffered: X25519MLKEM768\ntrust: ca-file\nresult: failed\nerror: remote error: tls: handshake failure\n"
CLASSIC_OUT = HYBRID_OUT.replace("offered: X25519MLKEM768", "offered: X25519,P-256").replace("group: X25519MLKEM768", "group: X25519")
OPENSSL_HYBRID = """CONNECTED(00000003)
Peer signature type: ecdsa_secp256r1_sha256
Negotiated TLS1.3 group: X25519MLKEM768
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Protocol  : TLSv1.3
"""
OPENSSL_CLASSIC = "Peer Temp Key: X25519, 253 bits\nNew, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\n    Protocol  : TLSv1.3\n"
OPENSSL_FAILED = ("4001E0F7:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure\n"
                  "Negotiated TLS1.3 group NID: 0\nNew, (NONE), Cipher is (NONE)\n")


class Parse(unittest.TestCase):
    def test_tls_probe_lines(self):
        h = T.parse(HYBRID_OUT)
        self.assertEqual((h.ok, h.kind, h.group, h.protocol, h.cert_sig, h.cert_key, h.client),
                         (True, "hybrid", "X25519MLKEM768", "TLS 1.3", "ML-DSA-65", "ML-DSA-65", "tls_probe"))
        self.assertTrue(h.trust.startswith("tofu"))
        f = T.parse(FAILED_OUT)
        self.assertEqual((f.ok, f.kind, f.group), (False, "failed", None))
        self.assertIn("handshake failure", f.error)

    def test_openssl_lines(self):
        self.assertEqual((T.parse(OPENSSL_HYBRID).group, T.parse(OPENSSL_HYBRID).kind), ("X25519MLKEM768", "hybrid"))
        self.assertEqual(T.parse(OPENSSL_HYBRID).cert_sig, "ecdsa_secp256r1_sha256")
        self.assertEqual((T.parse(OPENSSL_CLASSIC).group, T.parse(OPENSSL_CLASSIC).kind), ("X25519", "classical"))
        self.assertEqual(T.parse(OPENSSL_FAILED).kind, "failed")


class Verdicts(unittest.TestCase):
    def test_controls(self):
        good = {"positive": (T.parse(HYBRID_OUT), ""), "negative_hybrid": (T.parse(FAILED_OUT), ""),
                "negative_classical": (T.parse(CLASSIC_OUT), "")}
        self.assertIsNone(T.control_problem(good))
        liar = dict(good, negative_hybrid=(T.parse(HYBRID_OUT), "always hybrid"))
        self.assertIn("음성 대조", T.control_problem(liar))
        self.assertIn("양성 대조", T.control_problem(dict(good, positive=(T.parse(CLASSIC_OUT), ""))))

    def test_target(self):
        hyb, cls, fail = T.parse(HYBRID_OUT), T.parse(CLASSIC_OUT), T.parse(FAILED_OUT)
        self.assertEqual(T.target_verdict(hyb, cls, "allow"), (True, []))
        self.assertFalse(T.target_verdict(hyb, cls, "deny")[0])
        self.assertEqual(T.target_verdict(hyb, fail, "deny"), (True, []))
        self.assertFalse(T.target_verdict(cls, cls, "allow")[0])
        self.assertFalse(T.target_verdict(fail, cls, "allow")[0])
        tls12 = T.parse(HYBRID_OUT.replace("TLS 1.3", "TLS 1.2"))
        self.assertFalse(T.target_verdict(tls12, cls, "allow")[0])
        self.assertTrue(T.target_verdict(T.parse(OPENSSL_HYBRID), cls, "allow")[0])


class ContainerArgv(unittest.TestCase):
    def test_separate_container_in_the_target_namespace(self):
        with tempfile.TemporaryDirectory() as d:
            r = T.ContainerRunner(d, "p2-api-1", inspect={"image": "sha256:abc", "arch": "amd64"})
            argv = r.argv(T.connect_args("127.0.0.1:8443", T.OFFER_HYBRID, tofu=r.path("t1-tofu.pem")))
            self.assertEqual(argv[:4], ["docker", "run", "--rm", "--network"])
            self.assertIn("container:p2-api-1", argv)
            self.assertIn(f"{T.BIN_DIR}:/b:ro", argv)
            self.assertIn(f"{d}:/t", argv)
            self.assertEqual(argv[argv.index("--entrypoint") + 1], "/b/tls_probe-linux-amd64")
            self.assertIn("sha256:abc", argv)
            self.assertIn("-tofu=/t/t1-tofu.pem", argv)
            a, b = r.ref_addr(), r.ref_addr()
            self.assertNotEqual(a, b)


@unittest.skipUnless(os.access(str(T.host_binary()), os.X_OK), "tls_probe 바이너리 없음(build-probe.sh)")
class Live(unittest.TestCase):
    """맥에서 참조 서버를 띄워 대조와 -tofu, ML-DSA-65 인증서를 실제로 잰다(인터넷 없음, 127.0.0.1만)."""

    def test_controls_tofu_and_mldsa_cert(self):
        with tempfile.TemporaryDirectory() as d:
            r = T.HostRunner(d)
            try:
                results, problem, addrs = T.references(r, r)
                self.assertIsNone(problem)
                out = T.probe_target(r, addrs["positive"], label="p")
                self.assertEqual(out["hybrid"][0].group, "X25519MLKEM768")
                self.assertTrue(out["hybrid"][0].trust.startswith("tofu"))
                self.assertTrue(os.path.isfile(os.path.join(d, "p-hybrid-tofu-ca.pem")))
                neg = T.probe_target(r, addrs["negative"], label="n")
                self.assertEqual((neg["hybrid"][0].kind, neg["classical"][0].group), ("failed", "X25519"))
                m = os.path.join(d, "m")
                os.makedirs(m)
                self.assertEqual(r.run(["cert", "-alg=mldsa65", "-hosts=localhost,127.0.0.1", m])[0], 0)
                addr = r.ref_addr()
                r.start(T.serve_args(addr, T.REFERENCE_POSITIVE, os.path.join(m, "cert.pem"), os.path.join(m, "key.pem")))
                got = T.probe_target(r, addr, ca=os.path.join(m, "ca.pem"), label="m")["hybrid"][0]
                self.assertEqual((got.group, got.cert_key, got.cert_sig), ("X25519MLKEM768", "ML-DSA-65", "ML-DSA-65"))
            finally:
                r.stop()


class ReleaseHashes(unittest.TestCase):
    """교차 리뷰 X47: 탐침 바이너리를 릴리스 해시(휠에 든 tls_probe-release.sha256)와 대조한다."""

    def test_provenance(self):
        sums = {"tls_probe-linux-amd64": "a" * 64}
        self.assertEqual(T.provenance("/x/tls_probe-linux-amd64", "a" * 64, sums), "release")
        self.assertEqual(T.provenance("/x/tls_probe-linux-amd64", "b" * 64, sums), "local")
        self.assertEqual(T.provenance("/x/tls_probe-linux-amd64", "a" * 64, {}), "unchecked")

    def test_release_sums_reads_shasum_lines(self):
        d = tempfile.mkdtemp(prefix="pqproof-sums-")
        try:
            p = os.path.join(d, "s")
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"{'c' * 64}  tls_probe-darwin-arm64\n{'d' * 64} *bin/tls_probe-linux-arm64\nnot a line\n")
            self.assertEqual(T.release_sums(p), {"tls_probe-darwin-arm64": "c" * 64, "tls_probe-linux-arm64": "d" * 64})
            self.assertEqual(T.release_sums(os.path.join(d, "none")), {})
        finally:
            shutil.rmtree(d, ignore_errors=True)  # 이 시험이 만든 자기 폴더만
        self.assertFalse(T.RELEASE_SUMS.exists(), "the source tree must not carry release hashes; the release job adds them")


if __name__ == "__main__":
    unittest.main()
