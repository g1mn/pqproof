"""tls_probe 출력 읽기, 대조 판정, 대상 판정, 신뢰 방식(system·ca-file·tofu)과 검증 실패, b-tls 분류(rules.tls_status),
탐침 판 확인, 컨테이너 명령 꼴, OpenSSL 교차 확인 인자, 그리고 맥에서 참조 서버를 띄운 실측."""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import prove
from pqlite import rules
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
# tls_probe 0.6.0 이 시스템 신뢰 저장소로 검증하다 실패한 출력(맥에서 자체 서명 참조 서버에 붙여 받은 꼴)
VERIFY_OUT = ("probe: tls_probe 0.6.0 (go1.27.4)\ntarget: 127.0.0.1:8443\noffered: X25519MLKEM768\ntrust: system\nresult: failed\n"
              "error: certificate verification failed: x509: \u201ctls_probe test server\u201d certificate is not trusted\n")
VERIFY_CLASSIC_OUT = VERIFY_OUT.replace("offered: X25519MLKEM768", "offered: X25519,P-256")
# OpenSSL 3.5 s_client -verify_return_error 가 시스템 기본 경로로 검증하다 끊은 출력(같은 서버에서 받은 꼴, 앞부분)
OPENSSL_VERIFY = ("Connecting to 127.0.0.1\ndepth=0 CN=tls_probe test server\nverify error:num=20:unable to get local issuer certificate\n"
                  "0093F2EE01000000:error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:"
                  "ssl/statem/statem_clnt.c:2125:\nCONNECTED(00000003)\nNegotiated TLS1.3 group: X25519MLKEM768\n"
                  "Verification error: unable to get local issuer certificate\n---\nNew, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\n"
                  "Protocol: TLSv1.3\nVerify return code: 20 (unable to get local issuer certificate)\n")
OPENSSL_OK_VERIFIED = OPENSSL_HYBRID + "Verification: OK\nVerified peername: localhost\nVerify return code: 0 (ok)\n"


class Parse(unittest.TestCase):
    def test_tls_probe_lines(self):
        h = T.parse(HYBRID_OUT)
        self.assertEqual((h.ok, h.kind, h.group, h.protocol, h.cert_sig, h.cert_key, h.client),
                         (True, "hybrid", "X25519MLKEM768", "TLS 1.3", "ML-DSA-65", "ML-DSA-65", "tls_probe"))
        self.assertTrue(h.trust.startswith("tofu"))
        f = T.parse(FAILED_OUT)
        self.assertEqual((f.ok, f.kind, f.group), (False, "failed", None))
        self.assertIn("handshake failure", f.error)

    def test_verification_failure_is_marked(self):
        v = T.parse(VERIFY_OUT)
        self.assertEqual((v.ok, v.kind, v.trust), (False, "failed", "system"))
        self.assertTrue(T.verify_failed(v))
        self.assertTrue(T.verify_failed(v.to_json()))
        self.assertFalse(T.verify_failed(T.parse(FAILED_OUT)), "a refused handshake is not a verification failure")
        self.assertFalse(T.verify_failed(T.parse(HYBRID_OUT)))
        self.assertFalse(T.verify_failed(None))
        # 옛 탐침(0.5.0 이하, ca-file)은 Go 의 기본 낱말을 그대로 찍었다
        old = FAILED_OUT.replace("remote error: tls: handshake failure", "tls: failed to verify certificate: x509: certificate signed by unknown authority")
        self.assertTrue(T.verify_failed(T.parse(old)))
        o = T.parse(OPENSSL_VERIFY)
        self.assertEqual((o.ok, o.client), (False, "openssl"))
        self.assertTrue(T.verify_failed(o))
        self.assertIn("unable to get local issuer certificate", o.error)
        self.assertFalse(T.verify_failed(T.parse(OPENSSL_FAILED)))
        # s_client 는 검증으로 끊겨도 'Cipher is <스위트>' 와 그룹을 찍는다: 그것을 협상 성공으로 읽으면 안 된다
        self.assertIsNone(o.group)
        only_code = "New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\nVerify return code: 62 (hostname mismatch)\n"
        self.assertEqual(T.parse(only_code).error, T.VERIFY_FAILED + "hostname mismatch")
        good = T.parse(OPENSSL_OK_VERIFIED)
        self.assertEqual((good.ok, good.group), (True, "X25519MLKEM768"))

    def test_go_prefix_matches(self):
        src = (T.PROBE_SRC / "tls_probe.go").read_text(encoding="utf-8")
        m = re.search(r'^const verifyFailed = "([^"]*)"', src, re.M)
        self.assertIsNotNone(m, "probe/tls_probe.go must define const verifyFailed")
        self.assertEqual(m[1], T.VERIFY_FAILED, "tls_probe's verification-failure prefix and pqlite/tlsprobe.py VERIFY_FAILED must be the same text")
        self.assertIn(f'const version = "{T.PROBE_VERSION}"', src)

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

    def test_verification_failure_is_never_a_refusal_or_a_pass(self):
        hyb, vh, vc = T.parse(HYBRID_OUT), T.parse(VERIFY_OUT), T.parse(VERIFY_CLASSIC_OUT)
        # CLASSIC=deny 에서 옛 클라이언트의 검증 실패를 '거부'로 읽으면 통과가 된다
        ok, why = T.target_verdict(hyb, vc, "deny")
        self.assertFalse(ok)
        self.assertIn("인증서 검증 실패", why[0])
        self.assertIn("trust=system", why[0])
        for classic in ("allow", "deny"):
            ok, why = T.target_verdict(vh, vc, classic)
            self.assertFalse(ok)
            self.assertEqual(len(why), 2)
            self.assertTrue(T.only_unverified({"ok": ok, "why": why}))
        ok, why = T.target_verdict(hyb, T.parse(FAILED_OUT), "allow")
        self.assertFalse(T.only_unverified({"ok": ok, "why": why}), "a refused classical offer under CLASSIC=allow is measured")

    def test_measured_failure_is_kept_next_to_a_verification_failure(self):
        # X25519 전용 자체 서명 서버를 CA 없이(system) 잰 꼴: 하이브리드 전용 제시는 인증서 전에 거부되고(잰 실패),
        # 옛 클라이언트는 붙었지만 인증서 검증에 실패한다. 0.7.0(TOFU)에서 실패였고, 미판정으로 내려가면 안 된다
        refused, vc = T.parse(FAILED_OUT), T.parse(VERIFY_CLASSIC_OUT)
        for classic in ("allow", "deny"):
            ok, why = T.target_verdict(refused, vc, classic)
            self.assertFalse(ok)
            self.assertEqual(len(why), 2, why)
            self.assertIn("handshake failure", why[0])
            self.assertTrue(why[1].startswith(T.UNVERIFIED_WHY), why)
            self.assertFalse(T.only_unverified({"ok": ok, "why": why}))
        # 반대로 하이브리드는 검증 실패, 옛 클라이언트는 CLASSIC=deny 인데 실제로 붙었다: 잰 실패
        ok, why = T.target_verdict(T.parse(VERIFY_OUT), T.parse(CLASSIC_OUT), "deny")
        self.assertFalse(T.only_unverified({"ok": ok, "why": why}), why)
        # 남은 판단이 검증 실패한 쪽에만 달렸으면 재지 못한 것
        ok, why = T.target_verdict(T.parse(VERIFY_OUT), refused, "deny")
        self.assertTrue(T.only_unverified({"ok": ok, "why": why}), why)


def item(hyb, cls, classic="allow", trust="system", openssl=None, addr="127.0.0.1:1"):
    """prove.tls_runs 가 증적 tls.targets 에 쓰는 한 칸과 같은 꼴."""
    ok, why = T.target_verdict(T.parse(hyb), T.parse(cls), classic)
    o = T.parse(openssl) if openssl else None
    agrees = None if o is None else ((o.group == T.parse(hyb).group) if T.parse(hyb).ok else (not o.ok))
    return {"target": addr, "addr": addr, "servername": "localhost", "trust": trust, "hybrid": T.parse(hyb).to_json(),
            "classical": T.parse(cls).to_json(), "ok": ok, "why": why, "openssl": o.to_json() if o else None,
            "openssl_agrees": agrees}


class BTlsStatus(unittest.TestCase):
    """rules.tls_status: b-tls 의 실패·미판정·교차 확인 불일치 우선순위와 실제 칸 문구."""
    SIG = (["srv.go:1"], [])

    def status(self, items, via="host", problem=None):
        return rules.tls_status(items, problem, self.SIG, {"via": via, "probe_build": None})

    def test_only_verification_failures_are_undecided_with_the_fix(self):
        st, act = self.status([item(VERIFY_OUT, VERIFY_CLASSIC_OUT)])
        self.assertEqual(st, "undecided")
        self.assertIn("trust=system", act)
        self.assertIn("#tofu", act)
        self.assertIn("#/절대경로/ca.pem", act)

    def test_a_real_failure_next_to_a_verification_failure_fails(self):
        st, act = self.status([item(HYBRID_OUT, CLASSIC_OUT, addr="a:1"), item(VERIFY_OUT, VERIFY_CLASSIC_OUT, addr="b:2"),
                               item(FAILED_OUT, CLASSIC_OUT, addr="c:3")])
        self.assertEqual(st, "fail")
        self.assertIn("c:3@localhost", act)
        self.assertIn("b:2@localhost", act, "the unmeasured target is still named next to the failure")
        # 같은 대상 안에서 하이브리드 거부(잰 실패)와 옛 클라이언트 검증 실패가 섞여도 실패
        st, act = self.status([item(FAILED_OUT, VERIFY_CLASSIC_OUT)])
        self.assertEqual(st, "fail")
        self.assertIn("handshake failure", act)
        self.assertIn(T.UNVERIFIED_WHY, act)

    def test_openssl_verification_failure_alone_is_undecided(self):
        # 맥에서 tls_probe 는 키체인, OpenSSL 은 cert.pem 을 본다: 탐침은 검증하고 OpenSSL 만 실패할 수 있다
        st, act = self.status([item(HYBRID_OUT, CLASSIC_OUT, openssl=OPENSSL_VERIFY)])
        self.assertEqual(st, "undecided")
        self.assertIn("(OpenSSL 인증서 검증 실패)", act)
        st, act = self.status([item(HYBRID_OUT, CLASSIC_OUT, openssl=OPENSSL_OK_VERIFIED)])
        self.assertEqual(st, "pass", act)

    def test_control_problem_wins(self):
        st, act = self.status([item(FAILED_OUT, CLASSIC_OUT)], problem="tls_probe 바이너리 판이 0.5.0\n...")
        self.assertEqual(st, "undecided")
        self.assertIn("0.5.0", act)

    def test_container_system_trust_is_named(self):
        st, act = self.status([item(HYBRID_OUT, CLASSIC_OUT)], via="container:api")
        self.assertEqual(st, "pass")
        self.assertIn("대상 이미지의 신뢰 저장소", act)
        self.assertNotIn("대상 이미지", self.status([item(HYBRID_OUT, CLASSIC_OUT, trust="ca-file")], via="container:api")[1])
        self.assertNotIn("대상 이미지", self.status([item(HYBRID_OUT, CLASSIC_OUT)])[1])


OLD_PROBE = """#!/bin/sh
case "$1" in
  version) echo "tls_probe 0.5.0 (go1.25.0)";;
  *) echo "usage: tls_probe connect -groups=G1,G2 (-ca=PATH | -tofu=PATH) [-servername=NAME] HOST:PORT" >&2; exit 2;;
esac
"""


class ProbeVersion(unittest.TestCase):
    """0.5.0 탐침은 -ca·-tofu 없는 connect 를 사용법 오류(exit 2)로 끝낸다. 그 빈 출력을 협상 실패로 읽으면 안 된다."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def fake(self, text, name="tls_probe-old"):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, 0o755)
        return pathlib.Path(path)

    def params(self):
        return types.SimpleNamespace(tls_via="host", openssl=None, profile="nist-cat3", classic="allow")

    def test_reported_version(self):
        self.assertEqual(T.reported_version("tls_probe 0.6.0 (go1.27.4)\n"), "0.6.0")
        self.assertIsNone(T.reported_version("probe: tls_probe 0.6.0\n"), "a connect line is not the version output")
        self.assertIsNone(T.version_problem(T.PROBE_VERSION))
        self.assertIn("build-probe", T.version_problem("0.5.0"))
        self.assertIn("알 수 없음", T.version_problem(None))
        self.assertEqual(T.binary_version(self.fake(OLD_PROBE)), "0.5.0")
        self.assertIsNone(T.binary_version(os.path.join(self.tmp.name, "none")))

    def test_old_binary_leaves_tls_undecided_without_measuring(self):
        old = self.fake(OLD_PROBE)
        log = []
        with mock.patch.object(T, "host_binary", return_value=old):
            controls, problem, t, b = prove.tls_runs(self.params(), os.path.join(self.tmp.name, "tls"), log, ["127.0.0.1:1"], [], [])
            rec = prove.probe_tool()
        self.assertIsNone(controls)
        self.assertEqual((t, b), ([], []))
        self.assertIn("0.5.0", problem)
        self.assertIn(T.PROBE_VERSION, problem)
        self.assertEqual([x["argv"][1:] for x in log], [["version"]], "nothing but the version is run")
        self.assertTrue(rec["version"].startswith("0.5.0 ("), rec)

    def test_usage_error_is_a_tool_error_not_a_handshake(self):
        broken = self.fake(OLD_PROBE.replace("0.5.0", T.PROBE_VERSION), "tls_probe-usage")
        with mock.patch.object(T, "host_binary", return_value=broken), \
                mock.patch.object(T, "references", return_value=(None, None, {})):
            controls, problem, t, b = prove.tls_runs(self.params(), os.path.join(self.tmp.name, "tls"), [], ["127.0.0.1:1"], [], [])
        self.assertIn("tls_probe 도구 오류", problem)
        self.assertIn("exit=2", problem)
        self.assertEqual(rules.tls_status(t, problem, ([], []), {"via": "host"})[0], "undecided")

    def test_unreadable_system_roots_is_a_tool_error_not_a_refusal(self):
        # 0.7.0 on macOS reads Apple's system roots before it connects; when that fails it exits 3 without a handshake
        no_roots = self.fake(f"""#!/bin/sh
case "$1" in
  version) echo "tls_probe {T.PROBE_VERSION} (go1.27.4)";;
  *) printf 'probe: tls_probe {T.PROBE_VERSION} (go1.27.4)\ntarget: 127.0.0.1:1\noffered: X25519MLKEM768\ntrust: system\n'
     echo "system roots: exit status 1" >&2; exit 3;;
esac
""", "tls_probe-noroots")
        with mock.patch.object(T, "host_binary", return_value=no_roots), \
                mock.patch.object(T, "references", return_value=(None, None, {})):
            controls, problem, t, b = prove.tls_runs(self.params(), os.path.join(self.tmp.name, "tls"), [], ["127.0.0.1:1"], [], [])
        self.assertIn("exit=3", problem)
        self.assertEqual(rules.tls_status(t, problem, ([], []), {"via": "host"})[0], "undecided")


class Args(unittest.TestCase):
    def test_connect_trust_flags(self):
        sys_args = T.connect_args("h:1", T.OFFER_HYBRID, servername="api.example")
        self.assertFalse([a for a in sys_args if a.startswith(("-ca=", "-tofu="))], "no CA and no TOFU means system trust")
        self.assertIn("-servername=api.example", sys_args)
        self.assertIn("-ca=/c.pem", T.connect_args("h:1", T.OFFER_HYBRID, ca="/c.pem"))
        self.assertIn("-tofu=/t.pem", T.connect_args("h:1", T.OFFER_HYBRID, tofu="/t.pem"))

    def test_probe_target_uses_tofu_only_when_asked(self):
        class Rec(T.HostRunner):
            def run(self, args, timeout=60):
                self.log.append(args)
                return 1, "result: failed\nerror: x\n", ""
        with tempfile.TemporaryDirectory() as d:
            r = Rec(d, binary="/nonexistent")
            T.probe_target(r, "h:1", label="a")
            T.probe_target(r, "h:1", label="b", ca="/c.pem")
            T.probe_target(r, "h:1", label="c", tofu=True)
            T.probe_target(r, "h:1", label="d", ca="/c.pem", tofu=True)
            flags = [[a.split("=")[0] for a in args if a.startswith(("-ca=", "-tofu="))] for args in r.log]
            self.assertEqual(flags, [[], [], ["-ca"], ["-ca"], ["-tofu"], ["-tofu"], ["-ca"], ["-ca"]])

    def test_openssl_cross_check_always_verifies(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, OPENSSL_HYBRID, "")
        real = T.subprocess.run
        T.subprocess.run = fake_run
        try:
            T.openssl_cross_check("/o", "h:1", "api.example", None)
            T.openssl_cross_check("/o", "h:1", "localhost", "/c.pem")
            T.openssl_cross_check("/o", "127.0.0.1:1", "127.0.0.1", "/c.pem")
        finally:
            T.subprocess.run = real
        system, ca, ip = calls
        for argv in calls:
            self.assertIn("-verify_return_error", argv)
        self.assertNotIn("-CAfile", system)
        self.assertNotIn("-partial_chain", system)
        self.assertIn("-partial_chain", ca)
        self.assertEqual(system[system.index("-verify_hostname") + 1], "api.example")
        self.assertEqual(ca[ca.index("-CAfile") + 1], "/c.pem")
        self.assertEqual(ca[ca.index("-verify_hostname") + 1], "localhost")
        self.assertEqual(ip[ip.index("-verify_ip") + 1], "127.0.0.1")


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
            # 대상 이미지의 ENV 가 '시스템' 신뢰 저장소를 고르지 못하게 비운다
            for env in ("SSL_CERT_FILE=", "SSL_CERT_DIR="):
                self.assertEqual(argv[argv.index(env) - 1], "-e")
            a, b = r.ref_addr(), r.ref_addr()
            self.assertNotEqual(a, b)


@unittest.skipUnless(os.access(str(T.host_binary()), os.X_OK), "tls_probe 바이너리 없음(build-probe.sh)")
class Live(unittest.TestCase):
    """맥에서 참조 서버를 띄워 대조와 -tofu, ML-DSA-65 인증서를 실제로 잰다(인터넷 없음, 127.0.0.1만)."""

    def test_controls_trust_modes_and_mldsa_cert(self):
        with tempfile.TemporaryDirectory() as d:
            r = T.HostRunner(d)
            try:
                results, problem, addrs = T.references(r, r)
                self.assertIsNone(problem)
                # 기본: 시스템 신뢰 저장소. 시험 CA 는 거기 없으니 검증 실패이고, TOFU 파일은 생기지 않는다
                out = T.probe_target(r, addrs["positive"], label="s")
                for name in ("hybrid", "classical"):
                    self.assertEqual(out[name][0].trust, "system")
                    self.assertTrue(T.verify_failed(out[name][0]), out[name][1])
                self.assertFalse(os.path.exists(os.path.join(d, "s-hybrid-tofu-ca.pem")))
                ca = r.path("ref", "ca.pem")
                got = T.probe_target(r, addrs["positive"], ca=ca, label="c")["hybrid"][0]
                self.assertEqual((got.group, got.trust), ("X25519MLKEM768", "ca-file"))
                # 같은 CA 라도 이름이 다르면 검증 실패
                bad = T.probe_target(r, addrs["positive"], servername="other.example", ca=ca, label="x")["hybrid"][0]
                self.assertTrue(T.verify_failed(bad), bad)
                out = T.probe_target(r, addrs["positive"], label="p", tofu=True)
                self.assertEqual(out["hybrid"][0].group, "X25519MLKEM768")
                self.assertTrue(out["hybrid"][0].trust.startswith("tofu"))
                self.assertTrue(os.path.isfile(os.path.join(d, "p-hybrid-tofu-ca.pem")))
                neg = T.probe_target(r, addrs["negative"], label="n", tofu=True)
                self.assertEqual((neg["hybrid"][0].kind, neg["classical"][0].group), ("failed", "X25519"))
                # 같은 X25519 전용 서버를 CA 없이(system): 하이브리드 전용 제시는 인증서 전에 거부되므로 잰 실패로 남는다
                sneg = T.probe_target(r, addrs["negative"], label="ns")
                hn, cn = sneg["hybrid"][0], sneg["classical"][0]
                self.assertFalse(T.verify_failed(hn), sneg["hybrid"][1])
                self.assertTrue(T.verify_failed(cn), sneg["classical"][1])
                ok, why = T.target_verdict(hn, cn, "allow")
                self.assertFalse(ok)
                self.assertFalse(T.only_unverified({"ok": ok, "why": why}), why)
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
