#!/usr/bin/env python3
# kpqc_e2e.py: 실제 KpqC 빌드로 pqproof impl 을 끝까지 돌려 기대 판정과 맞춘다(선택 CI .github/workflows/kpqc-e2e.yml, 개발용).
#   python3 -I tests/kpqc_e2e.py --libs <kpqc_targets.sh 의 KPQC_LIBS> --rsp <KPQC_RSP> --out <새 폴더>
#          [--pqproof <설치한 pqproof 실행 파일>] [--nist-good LIB --nist-bad LIB --nist-pqclean LIB] [--json 결과.json]
# 라이브러리는 tests/kpqc_targets.sh 가 만든 것이다. 문제지(pqproof impl prompt) → 예제 하네스(examples/impl/kpqc_harness.py, ctypes 로
# 라이브러리를 실행한다) → 판정(pqproof impl judge) → pqproof --verify 를 경우마다 돌린다. 기대: 최신판 통과, 옛 판 검토 필요,
# derand 없는 답안은 판을 못 가려 검토 필요, 일부러 틀린 빌드 실패, PQCgenKAT .rsp 통과(100/100). --nist-* 를 주면 PQ_VERIFY(또는 PATH)의
# pq-verify 로 i-nist 도 본다: mlkem-native 통과, 결함 심은 판 실패, PQClean ML-KEM-768 clean 실패(FIPS 203 입력 검사를 API 안에서 하지 않음).
# --pqproof 를 안 주면 이 저장소의 bash prove.sh 를 쓴다. 종료: 0 모두 기대와 같음 · 1 하나라도 다름 · 2 사용법 오류.
# PQ-Proof 런타임은 이 파일을 쓰지 않는다(PQ-Proof 는 검사 대상을 실행하지 않고, 실행은 이 시험과 하네스가 한다).
"""End-to-end check of pqproof impl on real KpqC builds (optional CI)."""
import argparse
import glob
import json
import os
import shlex
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "examples", "impl", "kpqc_harness.py")
LATEST = {"smaug-t": "smaug-t-1.2.0", "ntruplus": "ntruplus-2026-01", "aimer": "aimer-3.0"}
FILE = {"smaug-t": "smaugt", "ntruplus": "ntruplus", "haetae": "haetae", "aimer": "aimer"}
PARAMS = {"smaug-t": ["mode1", "mode3", "mode5", "modet"], "ntruplus": ["768", "864", "1152"], "haetae": ["mode2", "mode3", "mode5"],
          "aimer": ["128f", "128s", "192f", "192s", "256f", "256s"]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--libs", required=True)
    ap.add_argument("--rsp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pqproof", default=None)
    ap.add_argument("--nist-good")
    ap.add_argument("--nist-bad")
    ap.add_argument("--nist-pqclean")
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)
    if os.path.exists(a.out):
        print(f"kpqc_e2e: {a.out} already exists", file=sys.stderr)
        return 2
    os.makedirs(a.out)
    cmd = [a.pqproof] if a.pqproof else ["bash", os.path.join(ROOT, "prove.sh")]
    impl = cmd + (["impl"] if a.pqproof else ["--impl"])

    def run(argv, env=None):
        r = subprocess.run(argv, capture_output=True, text=True, env=dict(os.environ, **(env or {})))
        return r.returncode, r.stdout + r.stderr

    def lib(folder, alg, p):
        hit = glob.glob(os.path.join(a.libs, folder, f"lib{FILE[alg]}-{p}.*"))
        if len(hit) != 1:
            raise SystemExit(f"kpqc_e2e: no single library for {folder} {alg}/{p} in {a.libs}")
        return hit[0]

    def prompt(name, pids):
        path = os.path.join(a.out, f"prompt-{name}.json")
        code, log = run(impl + ["prompt", "-o", path] + sum((["--param", p] for p in pids), []))
        if code:
            raise SystemExit(f"kpqc_e2e: prompt {name} exit {code}\n{log}")
        return path

    def harness(name, sheet, libs, extra=()):
        path = os.path.join(a.out, f"answers-{name}.json")
        code, log = run([sys.executable, "-I", HARNESS, sheet, path] + sum((["--lib", f"{p}={x}"] for p, x in libs.items()), [])
                        + ["--name", f"kpqc_targets.sh {name}"] + list(extra))
        if code:
            raise SystemExit(f"kpqc_e2e: harness {name} exit {code}\n{log}")
        return path

    rows = []

    def judge(case, what, args, want, env=None):
        """want: {'exit': n, 'i-kpqc': 상태, 'i-nist': 상태, 'params': {파라미터: 상태}, 'text': {검사: 들어 있어야 할 글}}"""
        out = os.path.join(a.out, f"out-{case}")
        code, log = run(impl + ["judge"] + args, dict(env or {}, OUT=out))
        try:
            with open(os.path.join(out, "receipt.json"), encoding="utf-8") as f:
                r = json.load(f)
        except (OSError, ValueError) as e:
            rows.append({"case": case, "what": what, "ok": False, "problem": f"no receipt ({e}); exit {code}: {log[-600:]}"})
            print(f"{case}: NO RECEIPT exit {code}", flush=True)
            return
        vcode, vlog = run(cmd + ["--verify", out])
        checks = {c["id"]: c for c in r["checks"]}
        got_params = {x["param"]: x["status"] for x in r["impl"].get("results") or []}
        bad = []
        if code != want["exit"]:
            bad.append(f"exit {code}, want {want['exit']}")
        for cid in ("i-kpqc", "i-nist"):
            if cid in want and checks.get(cid, {}).get("status") != want[cid]:
                bad.append(f"{cid} {checks.get(cid, {}).get('status')}, want {want[cid]}")
        for p, st in want.get("params", {}).items():
            if got_params.get(p) != st:
                bad.append(f"{p} {got_params.get(p)}, want {st}")
        for cid, needles in want.get("text", {}).items():
            actual = checks.get(cid, {}).get("actual", "")
            bad += [f"{cid} does not say '{n}'" for n in needles if n not in actual]
        if vcode != 0:
            bad.append(f"--verify exit {vcode}: {vlog[-300:]}")
        rows.append({"case": case, "what": what, "ok": not bad, "problem": "; ".join(bad) or None, "exit": code, "verdict": r["verdict"],
                     "i-kpqc": checks.get("i-kpqc", {}).get("status"), "i-nist": checks.get("i-nist", {}).get("status"),
                     "params": got_params, "verify": vcode == 0,
                     "detail": " | ".join(checks[c]["actual"] for c in ("i-kpqc", "i-nist") if c in checks)[:600]})
        print(f"{case}: {'ok' if not bad else 'MISMATCH ' + '; '.join(bad)}", flush=True)

    latest = [f"{alg}/{p}" for alg in LATEST for p in PARAMS[alg]]
    sheet = prompt("latest", latest)
    ans_latest = harness("latest", sheet, {pid: lib(LATEST[pid.split('/')[0]], *pid.split("/")) for pid in latest})
    judge("k1-latest", "SMAUG-T 1.2.0, NTRU+ 2026-01, AIMer 3.0 builds (13 parameter sets, derand answers)", [ans_latest],
          {"exit": 0, "i-kpqc": "pass", "i-nist": "na", "params": {p: "pass" for p in latest}})
    smaug = [f"smaug-t/{p}" for p in PARAMS["smaug-t"]]
    sheet = prompt("smaug-t", smaug)
    judge("k2-smaug-t-1.1.1", "SMAUG-T 1.1.1 builds: old version", [harness("smaug-t-1.1.1", sheet, {p: lib("smaug-t-1.1.1", *p.split("/")) for p in smaug})],
          {"exit": 0, "i-kpqc": "review", "params": {p: "review" for p in smaug}, "text": {"i-kpqc": ["1.1.1"]}})
    haetae = [f"haetae/{p}" for p in PARAMS["haetae"]]
    sheet = prompt("haetae", haetae)
    ans_haetae = harness("haetae-1.1.2", sheet, {p: lib("haetae-1.1.2", *p.split("/")) for p in haetae})
    judge("k3-haetae-1.1.2", "HAETAE 1.1.2 builds: old version (the one Bouncy Castle ships)", [ans_haetae],
          {"exit": 0, "i-kpqc": "review", "params": {p: "review" for p in haetae}, "text": {"i-kpqc": ["1.1.2"]}})
    judge("k3b-haetae-1.1.2-fail-on-review", "same answers under FAIL_ON_REVIEW=1", [ans_haetae],
          {"exit": 5, "i-kpqc": "review"}, {"FAIL_ON_REVIEW": "1"})
    sheet = prompt("smaug-t-mode3", ["smaug-t/mode3"])
    judge("k4-smaug-t-no-derand", "SMAUG-T 1.2.0 mode3, decaps answers only: versions cannot be told apart",
          [harness("smaug-t-no-derand", sheet, {"smaug-t/mode3": lib("smaug-t-1.2.0", "smaug-t", "mode3")}, ["--no-derand"])],
          {"exit": 0, "i-kpqc": "review", "text": {"i-kpqc": ["1.2.0", "1.1.1"]}})
    judge("k5-wrong-build", "SMAUG-T 1.2.0 mode3 with a planted decaps defect", [harness("wrong", sheet, {"smaug-t/mode3": lib("wrong", "smaug-t", "mode3")})],
          {"exit": 1, "i-kpqc": "fail", "text": {"i-kpqc": ["smaug-t/mode3@1.2.0#"]}})
    judge("k6-rsp", "PQCgenKAT .rsp written by the SMAUG-T 1.2.0 mode3 reference KAT program", [a.rsp],
          {"exit": 0, "i-kpqc": "pass", "params": {"smaug-t/mode3": "pass"}, "text": {"i-kpqc": ["100/100"]}})
    if a.nist_good:
        judge("n1-mlkem-native", "pq-verify on mlkem-native ML-KEM-768, with the latest KpqC answers", [ans_latest, "--pq-verify", f"--audit-kem {shlex.quote(a.nist_good)} ML-KEM-768"],
              {"exit": 0, "i-kpqc": "pass", "i-nist": "pass"})
    if a.nist_bad:
        judge("n2-mlkem-native-bad", "pq-verify on mlkem-native with a planted decaps defect, no answers", ["--pq-verify", f"--audit-kem {shlex.quote(a.nist_bad)} ML-KEM-768"],
              {"exit": 1, "i-kpqc": "na", "i-nist": "fail"})
    if a.nist_pqclean:
        judge("n3-pqclean", "pq-verify on PQClean ML-KEM-768 clean: input-check stages fail", ["--pq-verify", f"--audit-kem {shlex.quote(a.nist_pqclean)} ML-KEM-768"],
              {"exit": 1, "i-kpqc": "na", "i-nist": "fail", "text": {"i-nist": ["FIPS 203"]}})

    ok = sum(r["ok"] for r in rows)
    lines = [f"## KpqC end-to-end: {ok}/{len(rows)} as expected", "", "| case | what | exit | i-kpqc | i-nist | --verify | result |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['case']} | {r['what']} | {r.get('exit', '')} | {r.get('i-kpqc', '')} | {r.get('i-nist', '')} | "
                     f"{'ok' if r.get('verify') else 'FAIL'} | {'ok' if r['ok'] else (r['problem'] or '').replace('|', '/')} |")
    text = "\n".join(lines) + "\n"
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"ok": ok, "total": len(rows), "cases": rows}, f, ensure_ascii=False, indent=1)
    return 0 if rows and ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
