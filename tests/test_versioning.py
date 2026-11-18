"""버전 관리: 도구 버전 한 곳, 규칙 묶음 해시 고정, 증적 형식 2 칸(tool_version·ruleset_version·ruleset_sha256·format_version),
판정 고정 기록(golden)이 지금 규칙 묶음과 맞는지, 판정 옆 '검증 호출 제거' 표시가 형식 2에만 붙는지,
버전 정책(tests/version_policy.py: 판정이 바뀌는 릴리스는 PATCH 가 아니다, CHANGELOG 항목마다 판정 영향 줄)."""
import copy
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
import version_policy as VP  # noqa: E402
from pqlite import receipt as R  # noqa: E402
from pqlite import version as V  # noqa: E402

EXAMPLES = PROOF / "examples"


def rewrite(d, change):
    """증적 폴더의 receipt.json 을 고치고 receipt_id 를 다시 계산해 쓴다(위조 흉내)."""
    p = pathlib.Path(d, "receipt.json")
    r = json.loads(p.read_text(encoding="utf-8"))
    change(r)
    r["receipt_id"] = R.compute_id(r)
    p.write_text(json.dumps(r, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


class SingleVersion(unittest.TestCase):
    def test_one_place(self):
        # 저장소: src/pqproof/__init__.py 와 pyproject(dynamic). 설치본: pqproof/_tool 바로 위 __init__.py(휠에 pyproject 는 없다)
        src = PROOF / "src" / "pqproof" / "__init__.py"
        init_path = src if src.is_file() else PROOF.parent / "__init__.py"
        init = init_path.read_text(encoding="utf-8")
        want = re.search(r'^__version__\s*=\s*"([^"]+)"', init, re.M)[1]
        self.assertEqual(V.tool_version(), want)
        self.assertRegex(want, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        if src.is_file():
            py = (PROOF / "pyproject.toml").read_text(encoding="utf-8")
            self.assertIn('dynamic = ["version"]', py)
            self.assertIn('path = "src/pqproof/__init__.py"', py)
            self.assertNotRegex(py, r'(?m)^version\s*=')  # 버전 숫자를 pyproject 에 따로 적지 않는다
        else:
            self.assertEqual(PROOF.name, "_tool")

    def test_prove_sh_version(self):
        out = subprocess.run(["bash", str(PROOF / "prove.sh"), "--version"], capture_output=True, text=True,
                             env=dict(os.environ, PYTHON=sys.executable)).stdout.strip()
        self.assertEqual(out, V.describe())
        self.assertIn(f"pqproof {V.tool_version()}", out)

    def test_sarif_file_run_uses_the_same_version(self):
        # prove.sh sarif 와 action.yml 은 sarif.py 를 파일로(-I) 돌린다. 그때도 driver.version 이 __version__ 이어야 한다.
        # 옆 __init__.py 만 바꾼 사본으로도 돌려, 손으로 적은 대체값이 다시 생기면 이 시험이 잡는다
        sarif = PROOF / "src" / "pqproof" / "sarif.py"
        if not sarif.is_file():
            sarif = PROOF.parent / "sarif.py"  # 설치본: pqproof/_tool 바로 위
        ev = PROOF / "tests" / "golden" / "evidence" / "f2-v0.1.0"
        tmp = tempfile.mkdtemp(prefix="pqproof-sarifver-")
        try:
            for init, want in ((None, V.tool_version()), ('__version__ = "9.8.7"\n', "9.8.7")):
                with self.subTest(want=want):
                    script = sarif
                    if init:
                        d = pathlib.Path(tmp, "copy")
                        d.mkdir()
                        shutil.copy(sarif, d / "sarif.py")
                        (d / "__init__.py").write_text(init, encoding="utf-8")
                        script = d / "sarif.py"
                    out = pathlib.Path(tmp, f"{want}.sarif")
                    run = subprocess.run([sys.executable, "-I", "-B", str(script), str(ev), "-o", str(out)],
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    driver = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["tool"]["driver"]
                    self.assertEqual((driver["version"], driver["semanticVersion"]), (want, want))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만

    def test_changelog_has_this_version(self):
        log = (PROOF / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertRegex(log, rf"(?m)^## \[{re.escape(V.tool_version())}\]")
        current, _ = V.ruleset_history()
        self.assertIn(f"ruleset {current}", log)


class RulesetPin(unittest.TestCase):
    def test_rule_files_match_the_recorded_ruleset(self):
        current, history = V.ruleset_history()
        self.assertIn(current, history)
        got = V.current_ruleset_sha256()
        self.assertEqual(got, history[current],
                         "A rule file changed (scan/cbom-scan.sh, scan/residue.sh, scan/test-paths.ere, pqlite/scan.py, "
                         "pqlite/verify.py or pqlite/allowlist.py). Add a new ruleset name with this hash to scan/ruleset.json, "
                         f"make it current, rewrite tests/golden/verdicts.json if verdicts moved, and add a CHANGELOG entry: {got}")
        self.assertEqual(len(set(history.values())), len(history), "two ruleset names share a hash")

    def test_golden_verdicts_follow_the_current_ruleset(self):
        gold = json.loads((PROOF / "tests" / "golden" / "verdicts.json").read_text(encoding="utf-8"))["runs"]
        spec = json.loads((PROOF / "tests" / "mutations" / "mutations.json").read_text(encoding="utf-8"))["mutations"]
        trees = {m["id"] for m in spec if m["kind"] == "tree"}
        self.assertEqual(set(gold), trees, "tests/golden/verdicts.json and the tree cases in mutations.json differ")
        current, _ = V.ruleset_history()
        self.assertEqual({g["ruleset_version"] for g in gold.values()}, {current},
                         "golden verdicts were written under another ruleset: rerun run_mutations.py --write-golden")

    def test_label(self):
        current, history = V.ruleset_history()
        self.assertEqual(V.ruleset_label(history[current]), current)
        self.assertEqual(V.ruleset_label("0" * 64), f"{current}+modified")


class FormatTwo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-ver-")
        cls.out = os.path.join(cls.tmp, "cp")
        env = {"EXPECT": "kem,sig", "ALLOW": "none", "RECON": "none"}
        cls.r, cls.code, cls.lines = prove.run(str(EXAMPLES / "classic"), str(EXAMPLES / "pqc"), prove.Params(env), cls.out,
                                               quiet=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def copy(self, name):
        d = os.path.join(self.tmp, name)
        shutil.copytree(self.out, d)
        return d

    def fails(self, d):
        return "\n".join(w for ok, w in R.verify(d) if not ok)

    def test_fields_and_verify(self):
        r = self.r
        self.assertEqual(self.code, 0)
        self.assertEqual(r["format_version"], V.FORMAT_VERSION)
        self.assertEqual(r["tool_version"], V.tool_version())
        current, history = V.ruleset_history()
        self.assertEqual((r["ruleset_version"], r["ruleset_sha256"]), (current, history[current]))
        self.assertEqual(r["ruleset_sha256"], V.ruleset_from_tools(r["tools"]))
        self.assertEqual(self.fails(self.out), "")
        self.assertTrue(any(f"규칙 묶음 {current}" in x for x in self.lines))
        self.assertTrue(any(x.startswith("검사 8개: 통과 ") and "통과로 세는 것은" in x for x in self.lines), self.lines[-4:])
        page = pathlib.Path(self.out, "receipt.html").read_text(encoding="utf-8")
        self.assertIn("판정 근거", page)
        deck = json.loads(pathlib.Path(self.out, "deck.json").read_text(encoding="utf-8"))
        self.assertEqual((deck["tool_version"], deck["ruleset_version"]), (r["tool_version"], current))
        self.assertIn("규칙 묶음", pathlib.Path(self.out, "tables", "report.md").read_text(encoding="utf-8"))

    def test_missing_field_fails(self):
        d = self.copy("nofield")
        rewrite(d, lambda r: r.pop("ruleset_sha256"))
        self.assertIn("needs ruleset_sha256", self.fails(d))

    def test_wrong_ruleset_claims_fail(self):
        d = self.copy("rs-name")
        rewrite(d, lambda r: r.update(ruleset_version="9"))
        self.assertIn("not in this tool's ruleset history", self.fails(d))
        d = self.copy("rs-mod")
        rewrite(d, lambda r: r.update(ruleset_version=r["ruleset_version"] + "+modified"))
        self.assertIn("says modified", self.fails(d))
        d = self.copy("rs-tool")

        def swap(r):
            next(t for t in r["tools"] if t["name"] == "test-paths.ere")["sha256"] = "0" * 64
        rewrite(d, swap)
        self.assertIn("rule files listed in tools[] hash to", self.fails(d))

    def test_newer_format_is_refused_clearly(self):
        d = self.copy("fv9")
        rewrite(d, lambda r: r.update(format_version=9))
        got = self.fails(d)
        self.assertIn("format_version 9", got)
        self.assertIn("this tool reads 1, 2", got)

    def test_old_note_on_format_two_fails(self):
        d = self.copy("oldnote")
        rewrite(d, lambda r: r.update(note=R.NOTE_PUBLIC1))
        self.assertIn("current note", self.fails(d))

    def test_version_fields_on_format_one_fail(self):
        d = self.copy("f1fields")
        rewrite(d, lambda r: r.pop("format_version"))
        self.assertIn("without format_version", self.fails(d))

    def test_custom_residue_is_modified(self):
        res = os.path.join(self.tmp, "my-residue.sh")
        shutil.copyfile(PROOF / "scan" / "residue.sh", res)
        with open(res, "a", encoding="utf-8") as f:
            f.write("# site copy\n")
        out = os.path.join(self.tmp, "custom")
        env = {"EXPECT": "kem,sig", "ALLOW": "none", "RECON": "none", "RESIDUE": res}
        r, code, _ = prove.run(str(EXAMPLES / "classic"), str(EXAMPLES / "pqc"), prove.Params(env), out, quiet=True)
        current, _ = V.ruleset_history()
        self.assertEqual(r["ruleset_version"], f"{current}+modified")
        self.assertEqual(self.fails(out), "")


class RemovedVerificationNote(unittest.TestCase):
    def base(self, fv):
        r = {"verdict": "pass", "weakening": {"review": [{"path": "a.java", "rule": "verify only returns success"}]},
             "allowlist": {"unreviewed": 0}}
        if fv:
            r["format_version"] = fv
        return r

    def test_format_two_shows_it(self):
        r = self.base(2)
        self.assertEqual(R.verdict_text(r), "통과(검증 호출 제거 1건 검토 필요)")
        self.assertEqual(R.verdict_text(r, en=True), "pass (1 removed verification needs review)")
        two = copy.deepcopy(r)
        two["weakening"]["review"].append({"path": "a.java", "rule": "verify calls dropped"})
        self.assertEqual(R.verdict_text(two, en=True), "pass (2 removed verifications need review)")

    def test_format_one_keeps_the_old_text(self):
        self.assertEqual(R.verdict_text(self.base(None)), "통과")  # 옛 receipt.html 이 그대로 맞게

    def test_fail_has_no_note(self):
        r = self.base(2)
        r["verdict"] = "fail"
        self.assertEqual(R.verdict_text(r), "실패")


RULESET = json.loads((PROOF / "scan" / "ruleset.json").read_text(encoding="utf-8"))


def changelog(*sections):
    """CHANGELOG 흉내: (이름, 판정 영향 또는 None) 마다 '## [이름]' 절."""
    out = ["# Changelog", ""]
    for name, impact in sections:
        out += [f"## [{name}]" + ("" if name == "Unreleased" else " - 2026-12-01"), ""]
        if impact:
            out += [f"**Verdict impact (판정 영향): {impact}.**", ""]
        out += ["### Fixed", "", "- something", ""]
    return "\n".join(out)


def ruleset_with(**changes):
    doc = copy.deepcopy(RULESET)
    doc["versions"][doc["current"]].update(changes)
    return doc


class VersionPolicy(unittest.TestCase):
    def test_this_tree_follows_the_policy(self):
        log = (PROOF / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertEqual(VP.check_tree(V.tool_version(), log, RULESET), [])

    def test_ruleset_record_lists_the_rule_files_that_changed(self):
        # 해시 고정 시험이 실패할 때 어느 파일이 바뀌었는지 바로 보이게: 기록의 files 와 지금 파일을 하나씩 맞춘다
        current, entries = V.ruleset_entries()
        now = {f["path"]: f["sha256"] for f in V.current_ruleset_files()}
        recorded = {f["path"]: f["sha256"] for f in entries[current]["files"]}
        self.assertEqual(sorted(p for p in now if now[p] != recorded.get(p)), [], "rule files changed since ruleset " + current)

    def test_old_ruleset_form_is_still_read(self):
        tmp = tempfile.mkdtemp(prefix="pqproof-rsold-")
        try:
            path = os.path.join(tmp, "ruleset.json")
            sha = RULESET["versions"]["1"]["sha256"]
            pathlib.Path(path).write_text(json.dumps({"current": "1", "versions": {"1": sha}}), encoding="utf-8")
            self.assertEqual(V.ruleset_history(path), ("1", {"1": sha}))
            self.assertEqual(V.ruleset_entries(path)[1]["1"], {"sha256": sha, "since": None, "verdict_impact": None, "files": None})
            self.assertEqual(V.ruleset_label(sha, path), "1")
            self.assertEqual(VP.ruleset_doc(json.dumps({"current": "1", "versions": {"1": sha}}))["versions"]["1"], {"sha256": sha})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만

    def test_tree_mistakes_are_caught(self):
        ok_log = changelog(("Unreleased", "none"), ("0.1.0", "yes"))
        cases = [
            ("verdict ruleset first ships in a PATCH release", "0.1.1", changelog(("0.1.1", "yes"), ("0.1.0", "yes")),
             ruleset_with(since="0.1.1"), "a PATCH release"),
            ("PATCH entry says yes", "0.1.1", changelog(("0.1.1", "yes"), ("0.1.0", "yes")), RULESET, "a PATCH release"),
            ("entry without a verdict-impact line", "0.1.0", changelog(("0.1.0", None)), RULESET, "no '**Verdict impact"),
            ("unreleased without a verdict-impact line", "0.1.0", changelog(("Unreleased", None), ("0.1.0", "yes")), RULESET,
             "[Unreleased] has no"),
            ("ruleset says yes, entry says none", "0.1.0", changelog(("0.1.0", "none")), RULESET, "does not say yes"),
            ("old form", "0.1.0", ok_log, dict(RULESET, versions={"1": RULESET["versions"]["1"]["sha256"]}), "old form"),
            ("files do not give sha256", "0.1.0", ok_log, ruleset_with(sha256="0" * 64), "not sha256"),
            ("verdict_impact missing", "0.1.0", ok_log, ruleset_with(verdict_impact="maybe"), "verdict_impact must be"),
            ("from 1.0 a verdict change bumps MAJOR", "1.1.0", changelog(("1.1.0", "yes")), ruleset_with(since="1.1.0"), "a PATCH release"),
            ("unreleased ruleset, unreleased entry says none", "0.1.0", changelog(("Unreleased", "none"), ("0.1.0", "yes")),
             ruleset_with(since="0.2.0"), "[Unreleased] does not say yes"),
        ]
        for name, version, log, rules, want in cases:
            with self.subTest(name):
                self.assertIn(want, "\n".join(VP.check_tree(version, log, rules)))

    def test_allowed_shapes(self):
        # 주석만 바뀐 묶음(verdict_impact no)은 PATCH 에서 나와도 된다. 아직 안 낸 묶음은 [Unreleased] 가 yes 면 된다
        self.assertEqual(VP.check_tree("0.1.1", changelog(("0.1.1", "none"), ("0.1.0", "yes")),
                                       ruleset_with(since="0.1.1", verdict_impact="no")), [])
        self.assertEqual(VP.check_tree("0.1.0", changelog(("Unreleased", "yes"), ("0.1.0", "yes")), ruleset_with(since="0.2.0")), [])
        self.assertEqual(VP.check_tree("1.0.0", changelog(("1.0.0", "yes")), ruleset_with(since="1.0.0")), [])

    def test_release_comparison(self):
        gold = json.loads((PROOF / "tests" / "golden" / "verdicts.json").read_text(encoding="utf-8"))["runs"]
        moved = copy.deepcopy(gold)
        moved["m01-trust-all"]["verdict"] = "pass"
        relabeled = {k: dict(v, ruleset_version="2") for k, v in gold.items()}
        base = VP.ruleset_doc(json.dumps(RULESET))
        new_no = copy.deepcopy(base)
        new_no["versions"]["2"] = dict(base["versions"]["1"], sha256="1" * 64, since="0.1.1", verdict_impact="no")
        new_no["current"] = "2"
        new_yes = copy.deepcopy(new_no)
        new_yes["versions"]["2"]["verdict_impact"] = "yes"
        rows = [
            ("0.1.1", "0.1.0", base, gold, [], []),
            ("0.1.1", "0.1.0", base, moved, ["PATCH release after 0.1.0", "m01-trust-all"], []),
            ("0.2.0", "0.1.0", base, moved, [], []),
            ("0.1.1", "0.1.0", new_no, relabeled, [], []),
            ("0.1.1", "0.1.0", new_yes, gold, ["ruleset 1 -> 2 with verdict impact yes"], []),
            ("1.1.0", "1.0.0", base, moved, ["from 1.0 a verdict change bumps MAJOR"], []),
            ("2.0.0", "1.0.0", base, moved, [], []),
            ("0.0.9", "0.1.0", base, gold, ["older than 0.1.0"], []),
            ("0.1.0", "0.1.0", base, moved, [], ["the next release must be MINOR"]),
            ("0.1.0", "0.1.0", base, gold, [], ["a PATCH release is allowed"]),
        ]
        for version, base_v, rules_now, gold_now, want_bad, want_notes in rows:
            with self.subTest(version=version, base=base_v, bad=want_bad, notes=want_notes):
                yes = changelog(("Unreleased", "yes"), (version, "yes"), (base_v, "yes"))
                bad, notes = VP.check_release(version, base_v, rules_now, base, gold_now, gold, yes)
                self.assertEqual(bool(bad), bool(want_bad), bad)
                for w in want_bad:
                    self.assertIn(w, "\n".join(bad))
                for w in want_notes:
                    self.assertIn(w, "\n".join(notes))

    def test_moved_verdicts_need_yes_in_the_changelog(self):
        gold = json.loads((PROOF / "tests" / "golden" / "verdicts.json").read_text(encoding="utf-8"))["runs"]
        moved = copy.deepcopy(gold)
        moved["m06-d2-test-file-key"]["checks"]["c-classic"] = "fail"
        base = VP.ruleset_doc(json.dumps(RULESET))
        bad, _ = VP.check_release("0.2.0", "0.1.0", base, base, moved, gold, changelog(("0.2.0", "none"), ("0.1.0", "yes")))
        self.assertIn("CHANGELOG.md [0.2.0] does not say verdict impact yes", "\n".join(bad))
        bad, _ = VP.check_release("0.1.0", "0.1.0", base, base, moved, gold, changelog(("Unreleased", "none"), ("0.1.0", "yes")))
        self.assertIn("CHANGELOG.md [Unreleased] does not say verdict impact yes", "\n".join(bad))
        bad, _ = VP.check_release("0.1.0", "0.1.0", base, base, moved, gold, changelog(("Unreleased", "yes"), ("0.1.0", "yes")))
        self.assertEqual(bad, [])

    def test_workflows_run_the_policy(self):
        wf = PROOF / ".github" / "workflows"
        if not wf.is_dir():
            self.assertEqual(PROOF.name, "_tool")  # 설치본에는 워크플로가 없다
            return
        self.assertIn("python3 -I tests/version_policy.py", (wf / "ci.yml").read_text(encoding="utf-8"))
        rel = (wf / "release.yml").read_text(encoding="utf-8")
        self.assertIn("python3 -I tests/version_policy.py", rel)
        self.assertIn("--base", rel)


if __name__ == "__main__":
    unittest.main()
