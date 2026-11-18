"""변이 시험 실행기(tests/mutations/run_mutations.py)의 golden 비교: 규칙 묶음 이름만 다른 것은 사례별 FAIL 이 아니고 맨 위 한 줄로
알린다. 판정·검사 상태·숫자가 바뀐 사례만 FAIL 이고, --diff-golden 은 사례 x 바뀐 칸 표(CHANGELOG '판정 영향' 초안)를 쓰며,
--write-golden 은 지금 파일과 비교한 요약을 먼저 찍고 쓴다. 실제 고정 기록(tests/golden/verdicts.json)으로도 돌려 본다."""
import contextlib
import copy
import importlib.util
import io
import json
import os
import pathlib
import shutil
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_mutations", PROOF / "tests" / "mutations" / "run_mutations.py")
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)
GOLD = json.loads((PROOF / "tests" / "golden" / "verdicts.json").read_text(encoding="utf-8"))["runs"]
RS = next(iter({v["ruleset_version"] for v in GOLD.values()}))  # golden 이 쓰인 규칙 묶음 이름
MOD = f"{RS}+modified"


def relabel(runs, name):
    out = copy.deepcopy(runs)
    for v in out.values():
        v["ruleset_version"] = name
    return out


class GoldenCompare(unittest.TestCase):
    def test_ruleset_name_alone_moves_no_case(self):
        now = relabel(GOLD, MOD)
        moved, rs_gold, rs_now, missing = M.golden_compare(GOLD, now)
        self.assertEqual((moved, missing), ({}, []))
        self.assertEqual((rs_gold, rs_now), ({RS}, {MOD}))
        lines = M.golden_summary(GOLD, now)
        self.assertIn(f"ruleset {RS} in the golden file, {MOD} now", lines[0])
        self.assertEqual(lines[1], f"golden: 0 of {len(GOLD)} cases moved")
        self.assertEqual(len(lines), 2)
        # 실행기가 사례마다 붙이는 FAIL 줄도 같은 규칙(묶음 이름은 빼고 비교)
        for cid in GOLD:
            self.assertEqual(M.golden_diff(M.split_ruleset(GOLD[cid])[1], M.split_ruleset(now[cid])[1]), [])

    def test_the_golden_file_matches_itself(self):
        self.assertEqual(M.golden_summary(GOLD, GOLD), [f"golden: 0 of {len(GOLD)} cases moved"])

    def test_a_verdict_move_is_reported_per_case_and_field(self):
        now = relabel(GOLD, MOD)
        cid = "c01-examples-classic-to-pqc"
        now[cid]["verdict"] = "fail"
        now[cid]["checks"]["c-classic"] = "fail"
        now[cid]["exit"] = 1
        moved, _, _, _ = M.golden_compare(GOLD, now)
        self.assertEqual(list(moved), [cid])
        self.assertEqual(moved[cid], [("checks.c-classic", '"pass"', '"fail"'), ("exit", "0", "1"), ("verdict", '"pass"', '"fail"')])
        lines = M.golden_summary(GOLD, now)
        self.assertTrue(lines[0].startswith(f"golden: ruleset {RS} in the golden file"))
        self.assertEqual(lines[1], f"golden: 1 of {len(GOLD)} cases moved")
        self.assertIn(f'  {cid}  verdict: "pass" -> "fail"', lines)

    def test_markdown_draft(self):
        now = copy.deepcopy(GOLD)
        now["m01-trust-all"]["checks"]["b-weakening"] = "pass"
        now["new-case"] = copy.deepcopy(GOLD["m01-trust-all"])
        md = M.golden_markdown(GOLD, now)
        self.assertTrue(md.startswith(f"**Verdict impact (판정 영향) draft: yes.** 1 of {len(GOLD)} golden cases moved."))
        self.assertIn("| Case | Field | Golden | Now |", md)
        self.assertIn('| `m01-trust-all` | `checks.b-weakening` | "fail" | "pass" |', md)
        self.assertIn("New cases without a golden entry: `new-case`", md)
        self.assertTrue(M.golden_markdown(GOLD, GOLD).startswith("**Verdict impact (판정 영향) draft: none.**"))


class WriteGolden(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pqproof-wgold-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)  # setUp 이 만든 자기 폴더만

    def test_summary_comes_before_the_write(self):
        path = os.path.join(self.tmp, "verdicts.json")
        shutil.copy(PROOF / "tests" / "golden" / "verdicts.json", path)
        now = copy.deepcopy(GOLD)
        now["m03-cert-check-off"]["verdict"] = "pass"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            M.write_golden(path, now)
        out = buf.getvalue().splitlines()
        self.assertEqual(out[0], f"write-golden: 1 of {len(GOLD)} cases moved")
        self.assertIn('  m03-cert-check-off  verdict: "fail" -> "pass"', out)
        self.assertTrue(out[-1].startswith(f"wrote {path}"))
        self.assertEqual(json.loads(pathlib.Path(path).read_text(encoding="utf-8"))["runs"], now)

    def test_new_file(self):
        path = os.path.join(self.tmp, "new.json")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            M.write_golden(path, GOLD)
        self.assertIn("is new", buf.getvalue())
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        self.assertEqual((data["format"], data["runs"]), ("pqproof golden verdicts 1", GOLD))

    def test_written_file_keeps_its_form(self):
        # 다시 쓴 파일이 지금 저장소의 고정 기록과 글자 하나까지 같아야 한다(about·정렬·들여쓰기)
        path = os.path.join(self.tmp, "same.json")
        with contextlib.redirect_stdout(io.StringIO()):
            M.write_golden(path, GOLD)
        self.assertEqual(pathlib.Path(path).read_text(encoding="utf-8"),
                         (PROOF / "tests" / "golden" / "verdicts.json").read_text(encoding="utf-8"))


class Arguments(unittest.TestCase):
    def test_diff_golden_needs_golden(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(M.main(["--diff-golden", "-", "--only", "c01-examples-classic-to-pqc"]), 2)
        self.assertIn("--diff-golden needs --golden", err.getvalue())


if __name__ == "__main__":
    unittest.main()
