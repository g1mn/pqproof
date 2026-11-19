"""pq-verify 다리(검사 i-nist): 실제 출력 고정물(tests/fixtures/pqverify, pq-verify 2.19.0)의 판정, 인자 검사(네트워크·출력 옵션 거부,
줄임말·자리 인자·짧은 옵션 거부, 셸 없이 나눔), 가짜 pq-verify 스크립트로 prove.impl_judge 를 돌린 시험(셸 해석 없음, 넘긴 환경,
보고서 위치, 실행 파일 없음, 시간 초과, KpqC 답안과 한 증적, 답안 없이 pq-verify 만), 증적의 다시 판정(보고서·요약을 바꾸면 실패),
그리고 pq-verify 와 ML-KEM 라이브러리가 있을 때(PQ_VERIFY 또는 PATH, PQPROOF_PQV_LIB·PQPROOF_PQV_BAD_LIB) 실측."""
import json
import os
import pathlib
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import impl  # noqa: E402
from pqlite import receipt as rc  # noqa: E402

FIX = PROOF / "tests" / "fixtures" / "pqverify"
CASES = json.loads((FIX / "cases.json").read_text(encoding="utf-8"))["cases"]
REPORT_GOOD = json.loads((FIX / "a2-full-mlkemnative-kem" / "report.json").read_text(encoding="utf-8"))
REPORT_BAD = json.loads((FIX / "b2-full-mlkemnative-bad-kem" / "report.json").read_text(encoding="utf-8"))


def load_case(name):
    """고정물 하나 → (감사 옵션, 실행 기록, 보고서 바이트 또는 None)."""
    d = FIX / name
    argv = json.loads((d / "argv.json").read_text(encoding="utf-8"))["argv"]
    audit = next((a for a in argv if a in impl.PQV_AUDITS), None)
    run = {"exit_code": int((d / "exit_code").read_text(encoding="utf-8").strip()), "stdout": (d / "stdout.txt").read_text(encoding="utf-8"),
           "stderr": (d / "stderr.txt").read_text(encoding="utf-8"), "timed_out": False, "timeout": 60, "error": None}
    report = (d / "report.json").read_bytes() if (d / "report.json").exists() else None
    return audit, run, report


def judge_case(name, **kw):
    audit, run, report = load_case(name)
    args = dict(audit=audit, run=run, report=report, library_sha256=CASES[name]["library_sha256"])
    args.update(kw)
    s = impl.pqverify_summary(args["audit"], args["run"], args["report"], args["library_sha256"])
    return s, impl.pqverify_status(s)


class Fixtures(unittest.TestCase):
    """pq-verify 2.19.0 이 실제로 낸 19가지 출력: 통과·실패·미판정이 기대와 같다."""

    def test_every_case(self):
        self.assertEqual(len(CASES), 19)
        for name, c in CASES.items():
            with self.subTest(case=name):
                s, (st, detail) = judge_case(name)
                self.assertEqual(st, c["expect"], detail)
                self.assertEqual(sorted(s), sorted(impl.SUMMARY_KEYS))
                self.assertEqual(rc.validate(s, rc.IMPL_PQV_SUMMARY), [])

    def test_details_name_the_target_and_the_counts(self):
        _, (st, d) = judge_case("a2-full-mlkemnative-kem")
        self.assertEqual(st, "pass")
        for part in ("libmlkemnative768_good.dylib ML-KEM-768", "pq-verify 2.19.0", "VERIFIED", "검사 1436/1436", "KEM 필수 단계 9개"):
            self.assertIn(part, d)
        _, (st, d) = judge_case("a-full-good-kem")
        self.assertEqual(st, "fail")
        self.assertIn("검사 532/1436", d)
        self.assertIn("ekCheck 5/10", d)
        self.assertIn("입력 검사 단계만 실패", d)
        _, (st, d) = judge_case("b2-full-mlkemnative-bad-kem")
        self.assertIn("decaps 0/10", d)
        self.assertNotIn("입력 검사 단계만", d)
        _, (st, d) = judge_case("f-full-dsa65")
        self.assertIn("범위가 완전하지 않다(partial: 362 checked; 171 not applicable", d)
        _, (st, d) = judge_case("h-full-mlkemnative-kem-constant-time")
        self.assertIn("돌지 못한 검사: constant-time: valgrind", d)
        _, (st, d) = judge_case("e-input-error-missing-path")
        self.assertIn("입력 오류(종료 2): cannot audit <BUILD>/does-not-exist", d)
        _, (st, d) = judge_case("j-full-mlkemnative-contained")
        self.assertIn("대상 파일에 묶이지 않았다", d)
        _, (st, d) = judge_case("g3-full-acvp-kem-require-full-coverage")
        self.assertIn("받는 감사 옵션", d)
        s, (st, d) = judge_case("g-min-acvp-kem", audit="--audit-kem")
        self.assertTrue(s["degraded"])
        self.assertIn("보고서 꼴 'pq-verify/acvp-result' 이 --audit-kem 의 pq-verify/kem-audit-result 가 아니다", d)

    def test_degraded_line_makes_a_pass_undecided(self):
        audit, run, report = load_case("a2-full-mlkemnative-kem")
        run = dict(run, stdout=run["stdout"] + "  DEGRADED RUN - this run verified LESS than pq-verify claims:\n")
        s = impl.pqverify_summary(audit, run, report, CASES["a2-full-mlkemnative-kem"]["library_sha256"])
        self.assertEqual(impl.pqverify_status(s)[0], "undecided")
        self.assertIn("DEGRADED", impl.pqverify_status(s)[1])

    def test_a_real_failure_next_to_a_check_that_could_not_run_fails(self):
        audit, run, report = load_case("h-full-mlkemnative-kem-constant-time")
        lib = CASES["h-full-mlkemnative-kem-constant-time"]["library_sha256"]
        s = impl.pqverify_summary(audit, run, report, lib)
        self.assertEqual((s["failed"], s["unavailable"][1:]), ([], ["ct:unavailable (돌지 못함)"]))
        doc = json.loads(report)
        doc["stages"]["decaps"]["passed"] = 9
        st, d = impl.pqverify_status(impl.pqverify_summary(audit, run, json.dumps(doc).encode(), lib))
        self.assertEqual(st, "fail", d)
        self.assertIn("decaps 9/10", d)
        self.assertIn("돌지 못한 검사도 있다: constant-time", d)

    def test_the_audited_file_must_be_the_one_measured(self):
        _, (st, d) = judge_case("a2-full-mlkemnative-kem", library_sha256="0" * 64)
        self.assertEqual(st, "undecided")
        self.assertIn("PQ-Proof 가 잰 대상", d)
        _, (st, d) = judge_case("a2-full-mlkemnative-kem", library_sha256=None)  # 대상이 폴더·없는 파일이라 재지 못했다
        self.assertEqual(st, "undecided")
        self.assertIn("SHA-256 을 재지 못했다", d)

    def test_report_text_is_shown_safely(self):
        audit, run, report = load_case("a-full-good-kem")
        doc = json.loads(report)
        doc["stages"]["ek\x1b[2Jcheck"] = {"passed": 0, "total": 1}
        doc["constant_time"] = {"unavailable": [[["deep"]]]}
        s = impl.pqverify_summary(audit, run, json.dumps(doc).encode(), CASES["a-full-good-kem"]["library_sha256"])
        self.assertTrue(any("\\x1b" in f for f in s["failed"]))
        self.assertFalse(any("\x1b" in f for f in s["failed"]))
        self.assertIn("constant-time: 돌지 못함", s["unavailable"])

    def test_broken_or_odd_reports_are_undecided(self):
        audit, run, report = load_case("a2-full-mlkemnative-kem")
        lib = CASES["a2-full-mlkemnative-kem"]["library_sha256"]

        def status(rep, **kw):
            r = dict(run, **kw)
            return impl.pqverify_status(impl.pqverify_summary(audit, r, rep, lib))

        def changed(**top):
            doc = json.loads(report)
            doc.update(top)
            return json.dumps(doc).encode()
        no_acc = json.loads(report)
        del no_acc["stages"]["accumulated"]
        bad_stage = json.loads(report)
        bad_stage["stages"]["decaps"] = {"passed": True, "total": 10}
        cases = {
            "JSON 이 아니다": status(b"{"),
            "JSON 객체가 아니다": status(b"[]"),
            "두 번 있다": status(b'{"schema": 1, "schema": 2}'),
            "주 버전": status(changed(schema_version="2.0")),
            "보고서를 쓰지 않았다": status(None),
            "시간 초과": status(report, timed_out=True),
            "띄우지 못했다": status(None, exit_code=None, error="permission denied"),
            "돌지 않은 KEM 필수 단계: accumulated": status(json.dumps(no_acc).encode()),
            "칸이 틀림": status(json.dumps(bad_stage).encode()),
            "통과나 실패 꼴이 아니다": status(changed(status="FINDINGS PRESENT", verified=False)),  # 종료 0 인데 문제 있음(--no-fail 꼴)
            "종료 1 와 보고서 status 'VERIFIED'": status(report, exit_code=1),
            "VERIFIED 지만": status(changed(scope={"complete": False, "statement": "partial"})),
        }
        for want, (st, d) in cases.items():
            with self.subTest(want=want):
                self.assertEqual(st, "undecided", d)
                self.assertIn(want, d)
        with mock.patch.object(impl, "PQV_MAX_REPORT", 100):
            self.assertIn("상한", status(report)[1])
        self.assertEqual(impl.pqverify_status(impl.pqverify_summary("--audit-kem", None, None, None, "없음"))[0], "undecided")

    def test_version_line(self):
        self.assertEqual(impl.pqverify_version((FIX / "version.txt").read_text(encoding="utf-8")), "2.19.0")
        self.assertEqual(impl.pqverify_version("something else"), "")


class Args(unittest.TestCase):
    """--pq-verify 인자: 셸 없이 나누고, 받는 감사 하나와 정해진 옵션만 받는다."""

    def test_accepts_an_audit_with_modifiers(self):
        spec = impl.pqverify_args("--audit-kem 'my libs/libx.so' ML-KEM-768 --symbol-prefix PQCLEAN_ --accumulated=100 --constant-time")
        self.assertEqual((spec["audit"], spec["target"], spec["param_set"], spec["target_index"]),
                         ("--audit-kem", "my libs/libx.so", "ML-KEM-768", 1))
        argv = impl.pqverify_argv("/x/pq-verify", spec, "/abs/my libs/libx.so", "/out/report.json")
        self.assertEqual(argv, ["/x/pq-verify", "--audit-kem", "/abs/my libs/libx.so", "ML-KEM-768", "--symbol-prefix", "PQCLEAN_",
                                "--accumulated=100", "--constant-time", "--require-full-coverage", "--json", "/out/report.json"])
        spec = impl.pqverify_args("--require-full-coverage --audit-dsa lib.so ML-DSA-65 --dsa-symbol keypair=k --dsa-symbol sign=s")
        argv = impl.pqverify_argv("pv", spec, "/l.so", "/r.json")
        self.assertEqual(argv.count("--require-full-coverage"), 1)
        self.assertEqual(spec["audit"], "--audit-dsa")
        for audit in impl.PQV_AUDITS:
            self.assertEqual(impl.pqverify_args(f"{audit} l x")["audit"], audit)

    def test_refuses_network_output_and_command_options(self):
        for text, why in (("--audit-kem l ML-KEM-768 --live", "네트워크"), ("--live --audit-kem l ML-KEM-768", "네트워크"),
                          ("--audit-kem l ML-KEM-768 --live=yes", "네트워크"), ("--audit-kem l ML-KEM-768 --liv", "네트워크"),
                          ("--audit-kem l ML-KEM-768 --json r.json", "보고서 경로"), ("--audit-kem l ML-KEM-768 --json=r.json", "보고서 경로"),
                          ("--audit-kem l ML-KEM-768 --js r.json", "보고서 경로"), ("--audit-kem l ML-KEM-768 --sarif s", "증적 폴더 밖"),
                          ("--audit-kem l ML-KEM-768 --prompt-out p", "증적 폴더 밖"), ("--audit-kem l ML-KEM-768 --no-fail", "종료 코드"),
                          ("--audit-kem l ML-KEM-768 --vector-dir v", "다른 폴더의 벡터"),
                          ("--audit-harness 'java -jar h.jar' ML-KEM-768", "명령을 그대로 실행"), ("--audit-source src", "컴파일")):
            with self.subTest(text=text):
                with self.assertRaises(ValueError) as cm:
                    impl.pqverify_args(text)
                self.assertIn(why, str(cm.exception))

    def test_refuses_other_shapes(self):
        for text in ("", "   ", "--audit-kem l", "--audit-kem l ML-KEM-768 --audit-dsa l2 ML-DSA-65", "--acvp",
                     "--audit-kem l ML-KEM-768 --acvp-all", "--audit-kem l ML-KEM-768 extra", "-h", "--audit-kem l ML-KEM-768 --",
                     "--audit-k l ML-KEM-768", "--audit-kem l ML-KEM-768 --symbol-prefix", "--audit-kem l ML-KEM-768 --constant-time=1",
                     "--audit-kem 'l ML-KEM-768", "--audit-kem=l ML-KEM-768", "--audit-kem l --symbol-prefix", "--audit-mceliece l x",
                     "--audit-kem l ML-KEM-768 --params ML-KEM-768", "--audit-kem l ML-KEM-768 -x",
                     "--audit-kem l ML-KEM-768 --accumulated -5", "--audit-kem l ML-KEM-768 --symbol-prefix ''"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    impl.pqverify_args(text)

    def test_a_value_starting_with_a_dash_needs_the_equals_form(self):
        self.assertIn("--accumulated=-5", impl.pqverify_args("--audit-kem l ML-KEM-768 --accumulated=-5")["args"])

    def test_shell_text_stays_literal(self):
        spec = impl.pqverify_args("--audit-kem '/tmp/x;touch PWNED' ML-KEM-768 --symbol-prefix '$(touch PWNED2)'")
        self.assertEqual(spec["target"], "/tmp/x;touch PWNED")
        self.assertIn("$(touch PWNED2)", spec["args"])

    def test_environment(self):
        env, drop = impl.pqverify_env({"PATH": "/bin", "HOME": "/h", "PQV_IN_PROCESS": "1", "PQV_CFL_SO": "/x.so", "LD_PRELOAD": "x",
                                       "DYLD_INSERT_LIBRARIES": "y", "PYTHONPATH": "z", "PYTHONSTARTUP": "s"})
        self.assertEqual(env, {"PATH": "/bin", "HOME": "/h"})
        self.assertEqual(drop, ["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "PQV_CFL_SO", "PQV_IN_PROCESS", "PYTHONPATH", "PYTHONSTARTUP"])

    def test_clip(self):
        text = "a" * (impl.PQV_MAX_TEXT + 10) + "\nDEGRADED RUN\n"
        out = impl.clip_text(text)
        self.assertLessEqual(len(out), impl.PQV_MAX_TEXT + 100)
        self.assertIn("characters cut", out)
        self.assertTrue(out.endswith("DEGRADED RUN\n"))
        self.assertEqual(impl.clip_text("short"), "short")

    def test_check_rows(self):
        self.assertEqual(impl.nist_check_row(None)["status"], "na")
        self.assertEqual(impl.check_row([], answered=False)["status"], "na")

    def test_deps_finds_the_same_executable(self):
        sys.path.insert(0, str(PROOF / "src"))
        from pqproof import deps
        self.assertEqual(deps.PQV_NAME, impl.PQV_NAME)
        self.assertEqual((deps.PQV_ENV_DROP_PREFIX, set(deps.PQV_ENV_DROP)), (impl._ENV_DROP_PREFIX, set(impl._ENV_DROP)))
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "pq-verify")
            pathlib.Path(fake).write_text("#!/bin/sh\n[ -z \"$PQV_X$LD_X\" ] || exit 7\necho 'pq-verify 2.19.0'\n", encoding="utf-8")
            os.chmod(fake, 0o755)
            self.assertEqual(deps.find_pqverify({"PQ_VERIFY": fake}), (fake, "2.19.0"))
            self.assertEqual(deps.find_pqverify({"PQ_VERIFY": fake, "PQV_X": "1", "LD_X": "1"}), (fake, "2.19.0"))  # 뺀 환경으로 부른다
            self.assertEqual(deps.find_pqverify({"PATH": d}), (fake, "2.19.0"))
            self.assertEqual(deps.find_pqverify({"PQ_VERIFY": os.path.join(d, "none"), "PATH": d}), (None, ""))
            rep = deps.check({"PQ_VERIFY": fake, "PATH": os.environ.get("PATH", "")}, need_tls=False, need_pqverify=False)
            self.assertTrue(any(x.startswith(f"pq-verify: {fake} (pq-verify 2.19.0") for x in rep.info))
            rep = deps.pqv_line(deps.Report(), {"PATH": os.path.join(d, "empty")}, need=True)
            self.assertTrue(rep.warnings and "undecided" in rep.warnings[0])
            self.assertFalse(any("pq-verify" in x for x in deps.check({"PQ_VERIFY": fake}, need_tls=False).info))


FAKE = r"""#!/bin/sh
# fake pq-verify for tests: records argv, environment and working folder, then behaves as FAKE_MODE says
if [ "$1" = "--version" ]; then echo "pq-verify 2.19.0"; exit 0; fi
printf '%s\n' "$@" > "$FAKE_DIR/argv.txt"
env > "$FAKE_DIR/env.txt"
pwd > "$FAKE_DIR/pwd.txt"
out=""; prev=""
for a in "$@"; do [ "$prev" = "--json" ] && out="$a"; prev="$a"; done
case "$FAKE_MODE" in
  pass) cp "$FAKE_DIR/good.json" "$out"; echo "  RESULT: 1436/1436 VERIFIED"; echo "  INTEGRITY: nothing this run needed was missing"; exit 0;;
  fail) cp "$FAKE_DIR/bad.json" "$out"; echo "  FAILING: KEM audit FINDINGS PRESENT"; exit 1;;
  input) echo "  cannot audit $3: No such file or directory"; exit 2;;
  sleep) sleep 30 & echo $! > "$FAKE_DIR/child.pid"; wait; exit 0;;
esac
exit 9
"""


class FakeRuns(unittest.TestCase):
    """prove.impl_judge 를 가짜 pq-verify(셸 스크립트)로 돌린다. 진짜 pq-verify 나 라이브러리 없이 다리의 실행·기록·판정을 본다."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pqproof-pqv-")
        self.fake = os.path.join(self.tmp, "bin", "pq-verify")
        os.makedirs(os.path.dirname(self.fake))
        pathlib.Path(self.fake).write_text(FAKE, encoding="utf-8")
        os.chmod(self.fake, stat.S_IRWXU)
        self.lib = os.path.join(self.tmp, "lib dir", "libfake;x.so")
        os.makedirs(os.path.dirname(self.lib))
        pathlib.Path(self.lib).write_bytes(b"not a real library\n")
        self.lib_sha = prove.sha256_file(self.lib)
        for name, doc in (("good.json", REPORT_GOOD), ("bad.json", REPORT_BAD)):
            doc = json.loads(json.dumps(doc))
            doc["artifact"]["sha256"] = self.lib_sha
            doc["artifact"]["path"] = doc["library"] = self.lib
            pathlib.Path(self.tmp, name).write_text(json.dumps(doc, indent=2), encoding="utf-8")
        key = impl.build_key(impl.load_manifest(), ["smaug-t/mode1"])
        self.answer = os.path.join(self.tmp, "answers.json")
        pathlib.Path(self.answer).write_text(impl.dumps(impl.example_answers(key, {"smaug-t/mode1": "1.2.0"})), encoding="utf-8")
        self.arg = f"--audit-kem '{self.lib}' ML-KEM-768"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)  # setUp 이 만든 자기 폴더만

    def judge(self, mode, name, answer=True, arg=None, env=None, pq_verify=True):
        params = prove.Params(dict({"PQ_VERIFY": self.fake}, **(env or {})), mode="impl")
        out = os.path.join(self.tmp, name)
        extra = {"FAKE_DIR": self.tmp, "FAKE_MODE": mode, "PQV_SHOULD_GO": "1", "LD_SHOULD_GO": "1", "PYTHONPATH": "/nowhere"}
        with mock.patch.dict(os.environ, extra):
            r, code, lines = prove.impl_judge(self.answer if answer else None, [], params, out, quiet=True,
                                              pq_verify=(arg or self.arg) if pq_verify else None)
        return r, code, lines, out

    def fails(self, d):
        return "\n".join(w for ok, w in rc.verify(d) if not ok)

    def test_pass_with_kpqc_answers_in_one_receipt(self):
        r, code, lines, out = self.judge("pass", "pass")
        self.assertEqual(([c["status"] for c in r["checks"]], r["verdict"], code), (["pass", "pass"], "pass", 0))
        self.assertEqual(self.fails(out), "")
        n = r["impl"]["nist"]
        report = os.path.join(out, "artifacts", "impl", "pq-verify", "report.json")
        want = [self.fake, "--audit-kem", self.lib, "ML-KEM-768", "--require-full-coverage", "--json", report]
        self.assertEqual(n["argv"], want)
        self.assertEqual(pathlib.Path(self.tmp, "argv.txt").read_text(encoding="utf-8").splitlines(), want[1:])
        env = pathlib.Path(self.tmp, "env.txt").read_text(encoding="utf-8")
        self.assertNotRegex(env, r"(?m)^(PQV_|LD_|DYLD_|PYTHONPATH=)")
        self.assertEqual(n["env_removed"], sorted(n["env_removed"]))
        self.assertLessEqual({"LD_SHOULD_GO", "PQV_SHOULD_GO", "PYTHONPATH"}, set(n["env_removed"]))
        self.assertNotEqual(os.path.realpath(pathlib.Path(self.tmp, "pwd.txt").read_text(encoding="utf-8").strip()),
                            os.path.realpath(os.getcwd()))
        self.assertEqual((n["library"]["sha256"], n["summary"]["artifact_sha256"], n["exit_code"]), (self.lib_sha, self.lib_sha, 0))
        tool = [t for t in r["tools"] if t["name"] == "pq-verify"]
        self.assertEqual(tool, [{"name": "pq-verify", "path": self.fake, "sha256": prove.sha256_file(self.fake), "version": "2.19.0"}])
        log = json.loads(pathlib.Path(out, n["log"]).read_text(encoding="utf-8"))
        self.assertEqual([(e["role"], e["exit_code"]) for e in log], [("version", 0), ("audit", 0)])
        self.assertIn("RESULT: 1436/1436 VERIFIED", log[1]["stdout"])
        self.assertTrue(any("[i-nist] 통과" in x for x in lines))
        page = pathlib.Path(out, "receipt.html").read_text(encoding="utf-8")
        self.assertIn("NIST 구현 감사(pq-verify)", page)
        self.assertIn("KpqC 구현 KAT 대조 · NIST 구현 감사 증적", page)
        deck = json.loads(pathlib.Path(out, "deck.json").read_text(encoding="utf-8"))
        self.assertEqual((deck["nist"]["status"], deck["nist"]["checks_total"]), ("pass", 1436))
        self.assertIn("NIST 구현 감사(pq-verify)", pathlib.Path(out, "tables", "report.md").read_text(encoding="utf-8"))
        self.assertIn("artifacts/impl/pq-verify/", pathlib.Path(out, "README.txt").read_text(encoding="utf-8"))
        sys.path.insert(0, str(PROOF / "src"))
        from pqproof import sarif
        rules = {x["id"] for x in sarif.convert(out)["runs"][0]["tool"]["driver"]["rules"]}
        self.assertLessEqual({"i-kpqc", "i-nist"}, rules)

    def test_shell_text_in_arguments_is_not_run(self):
        odd = os.path.join(self.tmp, "x;touch PWNED $(touch PWNED2)")
        shutil.copyfile(self.lib, odd)
        arg = f"--audit-kem '{odd}' ML-KEM-768 --symbol-prefix '`touch PWNED3`'"
        r, code, _, out = self.judge("pass", "odd", arg=arg)
        for name in ("PWNED", "PWNED2", "PWNED3"):
            self.assertFalse(os.path.exists(os.path.join(self.tmp, name)))
            self.assertFalse(os.path.exists(name))
        got = pathlib.Path(self.tmp, "argv.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(got[:5], ["--audit-kem", odd, "ML-KEM-768", "--symbol-prefix", "`touch PWNED3`"])
        self.assertEqual(r["impl"]["nist"]["status"], "pass")  # 대상은 경로 글자가 아니라 PQ-Proof 가 잰 SHA-256 으로 맞춘다
        self.assertEqual(self.fails(out), "")

    def test_fail_and_input_error(self):
        r, code, _, out = self.judge("fail", "fail")
        self.assertEqual(([c["status"] for c in r["checks"]], r["verdict"], code), (["pass", "fail"], "fail", 1))
        self.assertIn("decaps 0/10", r["checks"][1]["actual"])
        self.assertEqual(self.fails(out), "")
        r, code, _, out = self.judge("input", "input")
        self.assertEqual((r["checks"][1]["status"], code, r["impl"]["nist"]["report"]), ("undecided", 3, None))
        self.assertIn("입력 오류(종료 2)", r["checks"][1]["actual"])
        self.assertEqual(self.fails(out), "")

    def test_missing_executable_is_undecided_and_not_listed(self):
        r, code, _, out = self.judge("pass", "none", env={"PQ_VERIFY": os.path.join(self.tmp, "no-such")})
        self.assertEqual((r["checks"][1]["status"], r["verdict"], code), ("undecided", "undecided", 3))
        self.assertIn("실행 파일이 아니다", r["checks"][1]["actual"])
        self.assertFalse([t for t in r["tools"] if t["name"] == "pq-verify"])
        self.assertEqual((r["impl"]["nist"]["argv"], r["impl"]["nist"]["executable"]), (None, None))
        self.assertEqual(self.fails(out), "")
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        with mock.patch.dict(os.environ, {"PATH": empty}):
            params = prove.Params({}, mode="impl")
            r, code, _ = prove.impl_judge(self.answer, [], params, os.path.join(self.tmp, "nopath"), quiet=True, pq_verify=self.arg)
        self.assertIn("찾지 못했다", r["checks"][1]["actual"])
        self.assertEqual(self.fails(os.path.join(self.tmp, "nopath")), "")

    def test_no_option_is_not_applicable(self):
        r, code, _, out = self.judge("pass", "noopt", pq_verify=False)
        self.assertEqual(([c["status"] for c in r["checks"]], code, r["impl"]["nist"]), (["pass", "na"], 0, None))
        self.assertFalse([t for t in r["tools"] if t["name"] == "pq-verify"])
        self.assertFalse(os.path.exists(os.path.join(out, "artifacts", "impl", "pq-verify")))

    def test_pq_verify_alone(self):
        r, code, lines, out = self.judge("pass", "alone", answer=False)
        self.assertEqual(([c["status"] for c in r["checks"]], r["verdict"], code), (["na", "pass"], "pass", 0))
        self.assertEqual((r["impl"]["input"], r["impl"]["key"], r["params"]["params"], r["params"]["input"]), (None, None, [], None))
        self.assertEqual(self.fails(out), "")
        self.assertIn("답안</div>없음(KpqC KAT 대조를 하지 않음)", pathlib.Path(out, "receipt.html").read_text(encoding="utf-8"))
        self.assertTrue(lines[0].startswith("== PQ-Proof") and "pq-verify 감사" in lines[0] and "KpqC" not in lines[0])

    def test_timeout_stops_the_process_group(self):
        t = time.time()
        r, code, _, out = self.judge("sleep", "slow", env={"PQ_VERIFY_TIMEOUT": "1"})
        self.assertLess(time.time() - t, 20)
        self.assertEqual((r["checks"][1]["status"], code), ("undecided", 3))
        self.assertIn("시간 초과(1초", r["checks"][1]["actual"])
        self.assertEqual(self.fails(out), "")
        pid = int(pathlib.Path(self.tmp, "child.pid").read_text(encoding="utf-8").strip())
        for _ in range(40):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail(f"the child of the fake pq-verify (pid {pid}) still runs after the timeout")

    def test_changed_report_or_summary_is_caught(self):
        r, code, _, out = self.judge("pass", "orig")
        d = os.path.join(self.tmp, "report-changed")
        shutil.copytree(out, d)
        rel = r["impl"]["nist"]["report"]
        doc = json.loads(pathlib.Path(d, rel).read_text(encoding="utf-8"))
        doc["stages"]["decaps"]["passed"] = 9
        rehash(d, rel, json.dumps(doc), "report")
        self.assertIn("pq-verify report judged again gives i-nist", self.fails(d))
        d = os.path.join(self.tmp, "summary-changed")
        shutil.copytree(out, d)

        def change(x):
            x["impl"]["nist"]["summary"]["checks_passed"] = 1
        rewrite(d, change)
        self.assertIn("impl.nist.status is pass, but its summary gives undecided", self.fails(d))
        d = os.path.join(self.tmp, "status-changed")
        shutil.copytree(out, d)
        rewrite(d, lambda x: x["checks"][1].update(status="na"))
        self.assertIn("i-nist is na, but impl.nist gives pass", self.fails(d))
        d = os.path.join(self.tmp, "argv-changed")
        shutil.copytree(out, d)
        rewrite(d, lambda x: x["impl"]["nist"]["argv"].remove("--require-full-coverage"))
        self.assertIn("impl.nist.argv is not the command pqproof builds", self.fails(d))

    def test_usage_errors(self):
        for argv in (["--impl", "judge"], ["--impl", "judge", "--pq-verify", "--live"], ["--impl", "prompt", "--pq-verify", "x"],
                     ["--impl", "judge", "--param", "TiMER", "--pq-verify", self.arg],
                     ["--impl", "judge", "--pq-verify", self.arg, "--pq-verify", self.arg],
                     ["--impl", "judge", self.answer, "--pq-verify", f"--audit-kem '{self.lib}' ML-KEM-768 --json x"],
                     ["--impl", "judge", "--pq-verify"]):
            with self.subTest(argv=argv):
                self.assertEqual(prove.main(argv), 2)


def rewrite(d, change):
    p = pathlib.Path(d, "receipt.json")
    r = json.loads(p.read_text(encoding="utf-8"))
    change(r)
    r["receipt_id"] = rc.compute_id(r)
    p.write_text(rc.dumps(r), encoding="utf-8")


def rehash(d, rel, text, field):
    """산출물 하나를 바꾸고 receipt.json 의 해시·receipt_id 를 다시 써서 해시 검사는 통과하게 만든다(위조 흉내)."""
    data = text.encode("utf-8")
    pathlib.Path(d, *rel.split("/")).write_bytes(data)
    sha = impl.hashlib.sha256(data).hexdigest()

    def change(r):
        for a in r["artifacts"]:
            if a["path"] == rel:
                a["sha256"], a["bytes"] = sha, len(data)
        r["impl"]["nist"][field + "_sha256"] = sha
    rewrite(d, change)


def live_pqverify():
    """실측에 쓸 pq-verify(PQ_VERIFY 또는 PATH)와 ML-KEM 라이브러리 둘(PQPROOF_PQV_LIB 통과할 것, PQPROOF_PQV_BAD_LIB 실패할 것)."""
    exe, _ = prove.pqverify_exe(prove.Params(mode="impl"))
    libs = [os.environ.get(k, "") for k in ("PQPROOF_PQV_LIB", "PQPROOF_PQV_BAD_LIB")]
    return (exe, *libs) if exe and all(os.path.isfile(x) for x in libs) else None


@unittest.skipUnless(live_pqverify(), "pq-verify 또는 PQPROOF_PQV_LIB·PQPROOF_PQV_BAD_LIB 없음(tests/pqverify_targets.sh)")
class Live(unittest.TestCase):
    """진짜 pq-verify 로 ML-KEM-768 라이브러리를 감사한다(대상을 실행하는 것은 pq-verify, 인터넷 없음): 맞는 판은 통과, 한 바이트를 바꾼
    판은 실패, 증적은 --verify 를 통과한다."""

    def test_good_passes_and_bad_fails(self):
        exe, good, bad = live_pqverify()
        tmp = tempfile.mkdtemp(prefix="pqproof-pqv-live-")
        try:
            for name, lib, want in (("good", good, "pass"), ("bad", bad, "fail")):
                out = os.path.join(tmp, name)
                r, code, _ = prove.impl_judge(None, [], prove.Params({"PQ_VERIFY": exe}, mode="impl"), out, quiet=True,
                                              pq_verify=f"--audit-kem '{lib}' ML-KEM-768")
                with self.subTest(lib=name):
                    self.assertEqual(r["checks"][1]["status"], want, r["checks"][1]["actual"])
                    self.assertEqual("\n".join(w for ok, w in rc.verify(out) if not ok), "")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만


if __name__ == "__main__":
    unittest.main()
