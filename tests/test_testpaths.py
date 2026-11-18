"""시험·예제 경로 기준 하나(결함 D2와 그 고침의 회귀).

본선판은 시험 경로를 세 곳이 따로 정했다. cbom-scan.sh 는 시험·예제 폴더 열두 가지와 시험 파일 이름 규칙, pqlite/scan.py 는 Java
src/test·test·tests·*Test 와 Go _test.go, residue.sh 는 src/test·test·tests 폴더만 뺐다. 그래서 고전 키를 거부하는 음성 시험을 _test.go 에
둔 전환본이 a-cbom 통과·c-classic 실패가 됐다. 지금은 scan/test-paths.ere 를 cbom-scan.sh·residue.sh·pqlite/scan.py·prove.py 가 같이
읽고, 시험 경로의 고전 코드 줄은 판정에 안 넣되 '시험'으로 따로 센다.
처음 고친 판은 폴더 이름을 경로 어디서든 맞춰 src/main/java/com/example/… 이 통째로 시험이 됐다(독립 검토에서 찾음). 그래서 목록 둘째 줄에
본 소스 표시(/src/main/)를 두고 그 앞부분만 맞춰 보며, examples·samples·spec·fixtures·mock(s) 는 트리 맨 위 폴더만 본다.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import rules  # noqa: E402
from pqlite import scan as scanmod  # noqa: E402

LIST = PROOF / "scan" / "test-paths.ere"
# (상대 경로, 시험·예제 경로인가)
CASES = [
    ("src/test/java/demo/BoxTest.java", True), ("internal/seal/seal_test.go", True), ("pkg/testdata/old.pem", True),
    ("app/tests/test_box.py", True), ("tools/test_sign.py", True), ("box_test.py", True), ("conftest.py", True),
    ("web/src/box.spec.ts", True), ("web/src/box.test.mjs", True), ("web/test.js", True), ("web/__tests__/a.js", True),
    ("spec/box_spec.rb", True), ("fixtures/keys.yml", True), ("mock/kms.go", True), ("mocks/Kms.java", True),
    ("examples/demo/Main.java", True), ("samples/a.py", True), ("lib/BoxTests.kt", True),
    ("src/test/java/com/example/BoxTest.java", True), ("examples/demo/src/main/java/Main.java", True),
    ("tests/it/src/main/java/A.java", True), ("svc/src/test/java/com/example/A.java", True),
    ("src/main/java/demo/Box.java", False), ("src/main/java/demo/Contest.java", False), ("cmd/latest.go", False),
    ("testing/helper.go", False), ("lib/protest_helper.py", False), ("src/main/java/demo/Attestation.java", False),
    ("web/src/testimony.ts", False), ("docs/example.md", False), ("contest/README.md", False),
    # 본 소스 표시(/src/main/) 뒤쪽은 시험이 아니다: Spring 기본 패키지 com.example, 이름이 …Test 인 본 소스 클래스
    ("src/main/java/com/example/sealer/Sealer.java", False), ("app/src/main/java/com/example/Box.java", False),
    ("src/main/java/com/example/tests/Helper.java", False), ("src/main/java/demo/SelfTest.java", False),
    ("src/main/kotlin/BoxTests.kt", False), ("src/main/resources/fixtures/keys.yml", False),
    # examples·samples·spec·fixtures·mock(s) 는 트리 맨 위 폴더일 때만
    ("lib/examples/a.py", False), ("pkg/samples/b.go", False), ("internal/mocks/kms.go", False), ("src/mocks/Kms.java", False),
    ("app/spec/x.rb", False),
]


def rule_lines():
    """test-paths.ere 의 (시험 경로 규칙, 본 소스 표시)."""
    xs = [x.strip() for x in LIST.read_text(encoding="utf-8").splitlines() if x.strip() and not x.lstrip().startswith("#")]
    return xs[0], xs[1]


class OneList(unittest.TestCase):
    def test_python_matches_cases(self):
        got = [(p, scanmod.is_test(p)) for p, _ in CASES]
        self.assertEqual(got, CASES)

    def test_cbom_scan_flag_of_gives_the_same_answers(self):
        """cbom-scan.sh 의 목록 읽기 줄과 flag_of 를 그대로 떼어 bash 로 돈다(bash [[ =~ ]] 와 본 소스 표시 앞부분 자르기)."""
        src = (PROOF / "scan" / "cbom-scan.sh").read_text(encoding="utf-8").splitlines()
        load = [x for x in src if x.startswith(("TESTRE=", "MAINRE="))]
        start = next(i for i, x in enumerate(src) if x.startswith("flag_of() {"))
        end = next(i for i in range(start, len(src)) if src[i] == "}")
        note = next(x for x in src if x.startswith("note() {"))
        self.assertEqual(len(load), 2)
        script = "\n".join(["export LC_ALL=C", "set -f", 'TESTRE_FILE="$1"; shift', note] + load + src[start:end + 1]
                           + ['for p in "$@"; do flag_of "$p" "x"; case "$FL" in *테스트*) echo 1;; *) echo 0;; esac; done'])
        out = subprocess.run(["bash", "-c", script, "x", str(LIST)] + [p for p, _ in CASES], capture_output=True, text=True, check=True)
        self.assertEqual(list(zip([p for p, _ in CASES], out.stdout.split())), [(p, "1" if t else "0") for p, t in CASES])

    def test_awk_reads_the_same_two_lines(self):
        """residue.sh 와 같은 awk 식(match·substr 로 본 소스 표시 앞부분만 본다)."""
        src = (PROOF / "scan" / "residue.sh").read_text(encoding="utf-8")
        line = next(x.strip() for x in src.splitlines() if "ISTEST = (TP ~ TESTRE)" in x)
        prog = ('BEGIN { TESTRE = ENVIRON["RES_TESTRE"]; MAINRE = ENVIRON["RES_MAINRE"] } { REL = $0; '
                + line.split("#")[0].strip() + "; print ISTEST ? 1 : 0 }")
        re_, mre = rule_lines()
        awk = subprocess.run(["awk", prog], input="\n".join(p for p, _ in CASES) + "\n", capture_output=True, text=True, check=True,
                             env=dict(os.environ, LC_ALL="C", RES_TESTRE=re_, RES_MAINRE=mre))
        self.assertEqual(list(zip([p for p, _ in CASES], awk.stdout.split())), [(p, "1" if t else "0") for p, t in CASES])

    def test_residue_marks_test_lines_by_the_same_rule(self):
        """residue.sh 를 실제로 돌린다: 고전 줄 하나를 코드 파일 경로마다 두고 TEST(시험)·LEFT(남은 고전) 를 본다."""
        code = [(p, t) for p, t in CASES if p.endswith((".java", ".kt", ".go", ".py", ".ts", ".js", ".mjs", ".rb"))]
        with tempfile.TemporaryDirectory() as d:
            for p, _ in code:
                q = pathlib.Path(d, p)
                q.parent.mkdir(parents=True, exist_ok=True)
                q.write_text('alg = "RSA"\n')
            out = subprocess.run(["bash", str(PROOF / "scan" / "residue.sh"), d], capture_output=True, text=True).stdout
        got = {}
        for x in out.splitlines():
            parts = x.split()
            if len(parts) >= 2 and parts[0] in ("TEST", "LEFT") and parts[1].endswith(":1:"):
                got[parts[1][:-3]] = parts[0] == "TEST"
        self.assertEqual(got, dict(code))

    def test_no_second_list_left(self):
        """옛 목록이 남아 있지 않다: 네 곳 모두 test-paths.ere 를 읽는다."""
        cbom = (PROOF / "scan" / "cbom-scan.sh").read_text(encoding="utf-8")
        res = (PROOF / "scan" / "residue.sh").read_text(encoding="utf-8")
        scan = (PROOF / "pqlite" / "scan.py").read_text(encoding="utf-8")
        pro = (PROOF / "prove.py").read_text(encoding="utf-8") + (PROOF / "pqlite" / "rules.py").read_text(encoding="utf-8")
        self.assertNotIn("*/__tests__/*", cbom)
        self.assertIn("test-paths.ere", cbom)
        self.assertNotIn("(src\\/test|test|tests)", res)
        self.assertIn("test-paths.ere", res)
        self.assertNotIn("JAVA_TEST", scan)
        self.assertNotIn('endswith("_test.go")', scan)
        self.assertNotIn("TEST_PATH = re.compile", pro)
        self.assertIn("scanmod.is_test(path)", pro)

    def test_missing_list_is_a_usage_error_for_both_scanners(self):
        with tempfile.TemporaryDirectory() as t:
            pathlib.Path(t, "a.txt").write_text("x\n")
            for script in ("residue.sh", "cbom-scan.sh"):
                r = subprocess.run(["bash", str(PROOF / "scan" / script), t], capture_output=True, text=True,
                                   env=dict(os.environ, TEST_PATHS=os.path.join(t, "nope.ere"), OUT=os.path.join(t, "o-" + script)))
                self.assertEqual(r.returncode, 2, (script, r.stderr))
                self.assertIn("시험 경로 목록 없음", r.stderr)


GO_TEST = """package seal

import (
\t"crypto/ecdsa"
\t"crypto/elliptic"
\t"crypto/rand"
\t"testing"
)

// 옛 P-256 키를 거부하는지 보는 음성 시험
func TestRejectsP256(t *testing.T) {
\tk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
\tif accept(k) {
\t\tt.Fatal("P-256 key must be rejected")
\t}
}
"""
CLASSIC = str(PROOF / "examples" / "classic")
PQC = str(PROOF / "examples" / "pqc")


def st(r):
    return {c["id"]: c["status"] for c in r["checks"]}


class EndToEnd(unittest.TestCase):
    """공개 예제(examples/)만 쓴다. 시험 경로 재현과 같은 꼴(전환본 + Go 음성 시험 한 개)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cache = {}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def tree(self, name, files, base=PQC):
        d = os.path.join(self.tmp.name, name)
        shutil.copytree(base, d)
        for rel, text in files.items():
            p = pathlib.Path(d, rel)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        return d

    def run_(self, name, orig, fixed, **kw):
        env = {"EXPECT": "kem,sig", "ALLOW": "none", "RECON": "none"}
        env.update(kw)
        out = os.path.join(self.tmp.name, "out-" + name)
        return prove.run(orig, fixed, prove.Params(env), out, self.cache, quiet=True) + (out,)

    def test_go_negative_test_passes_both_checks_and_is_counted(self):
        fx = self.tree("gotest", {"internal/seal/seal_test.go": GO_TEST})
        r, code, lines, out = self.run_("gotest", CLASSIC, fx)
        self.assertEqual((r["verdict"], code, st(r)["a-cbom"], st(r)["c-classic"]), ("pass", 0, "pass", "pass"),
                         [c for c in r["checks"] if c["status"] not in ("pass", "na")])
        t = r["java"]["fixed"]["tests"]
        self.assertEqual(t["count"], 5)  # 규칙 묶음 2: 소문자 ecdsa(crypto/ecdsa, ecdsa.GenerateKey)도 G-EC 로 센다(X19)
        self.assertIn("internal/seal/seal_test.go:12", t["lines"])
        cc = next(c for c in r["checks"] if c["id"] == "c-classic")
        self.assertIn("시험 경로 코드 5줄(판정에 안 넣고 따로 셈: internal/seal/seal_test.go:4", cc["actual"])
        self.assertGreaterEqual(r["cbom"]["fixed"]["tests"], 1)  # cbom-scan 의 '테스트·예제' 위치
        self.assertIn("(시험 ", next(c for c in r["checks"] if c["id"] == "a-cbom")["actual"])
        # 증적: 시험 경로 목록 사본과 해시, 도구 목록
        self.assertEqual(r["test_paths"]["file"], "artifacts/test-paths.ere")
        self.assertEqual(prove.slurp(os.path.join(out, "artifacts", "test-paths.ere")), LIST.read_text(encoding="utf-8"))
        self.assertIn("test-paths.ere", [x["name"] for x in r["tools"]])
        res = prove.slurp(os.path.join(out, "artifacts", "residue-fixed.txt"))
        self.assertIn("      TEST internal/seal/seal_test.go:12:", res)
        html = prove.slurp(os.path.join(out, "receipt.html"))
        self.assertIn("시험 경로 코드 줄(판정에 안 넣고 따로 셈", html)
        from pqlite import receipt as rc
        self.assertTrue(all(ok for ok, _ in rc.verify(out)), [w for ok, w in rc.verify(out) if not ok])

    def test_pqc_only_in_tests_is_not_pqc_use(self):
        """시험 경로의 ML-KEM·ML-DSA 줄은 PQC 사용으로 세지 않는다(시험만 고쳐 c-expect 를 통과하지 못하게)."""
        fx = self.tree("pqc-in-test", {"src/test/java/demo/sealer/NamesTest.java":
                                       'class NamesTest { String k = "ML-KEM-768"; String s = "ML-DSA-65"; }\n'}, base=CLASSIC)
        r, _, _, _ = self.run_("pqc-in-test", CLASSIC, fx)
        self.assertEqual(r["java"]["fixed"]["expect"], dict.fromkeys(rules.EXPECT_IDS, 0))
        self.assertEqual(st(r)["c-expect"], "fail")

    def test_classic_code_under_a_test_looking_folder_is_visible(self):
        """넓게 빼는 쪽의 위험: 시험처럼 보이는 폴더(fixtures/)에 둔 고전 코드는 판정에서 빠진다. 대신 줄마다 '시험'으로 남는다."""
        fx = self.tree("fixtures-dir", {"fixtures/demo/OldSigner.java":
                                        'class OldSigner { java.security.Signature s() throws Exception { '
                                        'return java.security.Signature.getInstance("SHA256withECDSA"); } }\n'})
        r, _, _, _ = self.run_("fixtures-dir", CLASSIC, fx)
        self.assertEqual(r["verdict"], "pass")
        self.assertTrue(any(x.startswith("fixtures/demo/OldSigner.java:") for x in r["java"]["fixed"]["tests"]["lines"]),
                        r["java"]["fixed"]["tests"])
        cc = next(c for c in r["checks"] if c["id"] == "c-classic")
        self.assertIn("fixtures/demo/OldSigner.java:1", cc["actual"])


if __name__ == "__main__":
    unittest.main()
