#!/usr/bin/env python3
# run_mutations.py: 심어 둔 결함(mutations.json)을 examples/classic·pqc 사본에 적용하고 PQ-Proof 를 돌려, 항목마다 적힌
# '반드시 잡혀야 하는 결과'와 비교한다. 표준 라이브러리만 쓰고 인터넷을 쓰지 않는다. 작업은 임시 폴더에서만 하고 원본은 읽기만 한다.
#   python3 -I tests/mutations/run_mutations.py                 저장소 루트의 prove.sh 로
#   python3 -I tests/mutations/run_mutations.py --strict        D1·D2 처럼 고치는 중(pending)인 항목도 통과해야 0
#   python3 -I tests/mutations/run_mutations.py --only m01-trust-all,m07-evidence-one-byte --keep
#   PQPROOF_CMD="pqproof" python3 -I tests/mutations/run_mutations.py   깐 패키지 명령으로
#   --root DIR: 도구 루트(prove.sh·examples/ 가 있는 곳). --sarif FILE: sarif.py(기본 <root>/src/pqproof/sarif.py)
#   --spec selfcheck.json: 이 실행기 자체 점검(틀린 기대값은 FAIL, 낡은 고정물은 SKIP 으로 나와 종료 코드 1이어야 한다)
#   --golden tests/golden/verdicts.json: 트리 항목마다 판정·검사 칸·숫자(golden_view)를 고정 기록과 맞춘다. 규칙을 바꿔 하나라도
#     움직이면 FAIL 이다. 일부러 바꾼 것이면 --write-golden 으로 다시 쓰고 CHANGELOG.md 의 '판정 영향' 칸에 같이 적는다
# 상태: PASS · FAIL · SKIP(준비 못 함: 고정물이 낡았거나 의존 도구 없음) · PENDING(고치는 중인 결함, --strict 가 아니면 종료 코드에 안 셈)
# 건너뛴 것은 통과로 세지 않는다: SKIP 이 하나라도 있으면 종료 코드는 1이다.
# 종료: 0 전부 통과 · 1 실패·건너뜀 있음 · 2 사용법 오류
"""Run the planted-defect suite against PQ-Proof and compare each result with the result it must give."""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))


class Skip(Exception):
    """준비를 못 했다(고정물이 낡음, 도구 없음). 통과가 아니다."""


# ---------------------------------------------------------------------------------------------
# JSON 경로: a.b.c, list[0], checks[c-classic](id 로 찾기), checks[*](모두)
SEG = re.compile(r"([^.\[\]]+)|\[([^\]]+)\]")


def _segments(path):
    out = []
    for name, idx in SEG.findall(path):
        out.append(("key", name) if name else ("idx", idx))
    return out


def get_path(doc, path):
    cur = [doc]
    for kind, val in _segments(path):
        nxt = []
        for c in cur:
            if kind == "key":
                if isinstance(c, dict) and val in c:
                    nxt.append(c[val])
            elif isinstance(c, list):
                if val == "*":
                    nxt.extend(c)
                elif re.fullmatch(r"-?[0-9]+", val):
                    i = int(val)
                    if -len(c) <= i < len(c):
                        nxt.append(c[i])
                else:
                    nxt.extend(x for x in c if isinstance(x, dict) and x.get("id") == val)
        cur = nxt
    return cur


def set_path(doc, path, value, where=None):
    segs = _segments(path)
    parents = [doc]
    for kind, val in segs[:-1]:
        nxt = []
        for c in parents:
            if kind == "key" and isinstance(c, dict):
                nxt.append(c.setdefault(val, {}))
            elif kind == "idx" and isinstance(c, list):
                if val == "*":
                    nxt.extend(c)
                elif re.fullmatch(r"-?[0-9]+", val):
                    nxt.append(c[int(val)])
                else:
                    nxt.extend(x for x in c if isinstance(x, dict) and x.get("id") == val)
        parents = nxt
    kind, last = segs[-1]
    n = 0
    for p in parents:
        if where and not all(isinstance(p, dict) and p.get(k) == v for k, v in where.items()):
            continue
        if kind == "key" and isinstance(p, dict):
            p[last] = value
            n += 1
        elif kind == "idx" and isinstance(p, list):
            p[int(last)] = value
            n += 1
    return n


def as_number(values):
    if not values:
        return None
    v = values[0]
    if isinstance(v, (list, dict, str)):
        return len(v)
    if isinstance(v, bool):
        return int(v)
    return v


def flat_text(values):
    return "\n".join(v if isinstance(v, str) else json.dumps(v, ensure_ascii=False) for v in values)


# RFC 8785 정규형(증적의 정수·문자열·배열·객체). 위조 시험에서 receipt_id 를 다시 계산하는 데만 쓴다
def jcs(v):
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(int(v)) if v == int(v) and abs(v) < 1e21 else repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"


def receipt_id(doc):
    return hashlib.sha256(jcs({k: v for k, v in doc.items() if k != "receipt_id"}).encode("utf-8")).hexdigest()


# 판정 고정 기록(golden): 기계·시각·경로와 상관없이 같은 입력이면 같아야 하는 값만 고른다
def golden_view(code, rec):
    if rec is None:
        return {"exit": code, "receipt": None}
    side = lambda c: {k: c.get(k) for k in ("blocking", "allowed", "review", "comment_or_test", "tests")}  # noqa: E731

    def java(j):
        if not j:
            return None
        return {"code": {k: v["code"] for k, v in sorted(j["families"].items())}, "expect": dict(sorted(j["expect"].items())),
                "weak_pqc": j["weak_pqc"], "legacy_write": j["legacy_write"], "tests": (j.get("tests") or {}).get("count")}
    a = rec.get("allowlist") or {}
    return {"exit": code, "verdict": rec["verdict"], "checks": {c["id"]: c["status"] for c in rec["checks"]},
            "cbom": {"orig": side(rec["cbom"]["orig"]), "fixed": side(rec["cbom"]["fixed"])},
            "java": {"orig": java(rec["java"]["orig"]), "fixed": java(rec["java"]["fixed"])},
            "weakening": {"deny": len(rec["weakening"]["deny"]), "review": len(rec["weakening"]["review"])},
            "allowlist": {k: a.get(k) for k in ("unreviewed", "unused", "unused_orig_lines", "write_review")},
            "allow_status": sorted(e["status"] for e in a.get("entries", [])),
            "ruleset_version": rec.get("ruleset_version")}


def golden_diff(want, got, where=""):
    if isinstance(want, dict) and isinstance(got, dict):
        out = []
        for k in sorted(set(want) | set(got)):
            out += golden_diff(want.get(k, "<missing>"), got.get(k, "<missing>"), f"{where}.{k}" if where else k)
        return out
    return [] if want == got else [f"{where}: golden {json.dumps(want, ensure_ascii=False)}, now {json.dumps(got, ensure_ascii=False)}"]


# ---------------------------------------------------------------------------------------------
class Runner:
    def __init__(self, args):
        self.root = os.path.abspath(args.root)
        self.examples = os.path.abspath(args.examples or os.path.join(self.root, "examples"))
        env_cmd = os.environ.get("PQPROOF_CMD")
        self.cmd = shlex.split(args.cmd or env_cmd) if (args.cmd or env_cmd) else ["bash", os.path.join(self.root, "prove.sh")]
        self.sarif = None if args.no_sarif else os.path.abspath(args.sarif or os.path.join(self.root, "src", "pqproof", "sarif.py"))
        self.strict, self.keep, self.verbose = args.strict, args.keep, args.verbose
        self.own_tmp = args.work is None
        self.work = os.path.abspath(args.work) if args.work else tempfile.mkdtemp(prefix="pqproof-mut-")
        os.makedirs(self.work, exist_ok=True)
        self.receipts = {}
        self.views = {}
        self.timeout = args.timeout

    # 트리 준비
    def tree(self, m, mdir):
        for side in ("orig", "base"):
            if not os.path.isdir(os.path.join(self.examples, m[side])):
                raise Skip(f"example {m[side]!r} not found under {self.examples}")
        orig = os.path.join(self.examples, m["orig"])
        fixed = os.path.join(mdir, "fixed")
        shutil.copytree(os.path.join(self.examples, m["base"]), fixed)
        for e in m.get("edits", []):
            self.edit(fixed, e)
        return orig, fixed

    def text_of(self, e):
        if "text_file" in e:
            p = os.path.join(HERE, e["text_file"])
            if not os.path.isfile(p):
                raise Skip(f"fixture {e['text_file']} missing")
            with open(p, encoding="utf-8") as f:
                return f.read()
        return e.get("text", "")

    def edit(self, root, e):
        path = os.path.join(root, *e["file"].split("/"))
        op = e["op"]
        if op == "add":
            if os.path.exists(path):
                raise Skip(f"{e['file']} already exists in the base tree")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.text_of(e))
            return
        if not os.path.isfile(path):
            raise Skip(f"{e['file']} not found in the base tree")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if op == "append":
            text += self.text_of(e)
        else:
            n = text.count(e["find"])
            if n != 1:
                raise Skip(f"anchor found {n} times in {e['file']} (fixture is stale): {e['find'][:60]!r}")
            if op == "replace":
                text = text.replace(e["find"], e["replace"])
            elif op == "insert_before":
                k = text.index(e["find"])
                text = text[:k] + self.text_of(e) + text[k:]
            else:
                raise Skip(f"unknown edit op {op}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def allow_file(self, m, mdir):
        if not m.get("allow"):
            return None
        src = os.path.join(HERE, m["allow"])
        if not os.path.isfile(src):
            raise Skip(f"allow-list fixture {m['allow']} missing")
        with open(src, encoding="utf-8") as f:
            data = json.load(f)
        for key, val in (m.get("allow_set") or {}).items():
            if isinstance(val, str) and val.startswith("@"):
                ref_path, _, ref_id = val[1:].partition(":")
                rec = self.receipts.get(ref_id)
                got = get_path(rec, ref_path) if rec else []
                if not got or not got[0]:
                    raise Skip(f"needs {ref_path} from {ref_id}, which produced no receipt")
                val = got[0]
            if set_path(data, key, val) == 0:
                raise Skip(f"allow_set could not set {key}")
        dst = os.path.join(mdir, "allow.json")
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        return dst

    def prove(self, orig, fixed, out, env_extra):
        env = {k: v for k, v in os.environ.items() if k not in ("ALLOW", "EXCLUDE", "REQUIRE_REVIEW", "TLS_TARGETS", "TLS_TARGETS_ORIG",
                                                                "RECON", "EXPECT", "SCOPE", "CLASSIC", "OUT", "RESIDUE", "EV_NAME")}
        env.update({"OUT": out, "ALLOW": "none", "RECON": "none"})
        env.update(env_extra)
        t = time.time()
        try:
            r = subprocess.run(self.cmd + [orig, fixed], env=env, capture_output=True, text=True, errors="replace",
                               timeout=self.timeout, stdin=subprocess.DEVNULL)
        except FileNotFoundError as e:
            raise Skip(f"cannot start {self.cmd[0]}: {e}") from e
        except subprocess.TimeoutExpired as e:
            raise Skip(f"timed out after {self.timeout}s") from e
        return r.returncode, r.stdout + r.stderr, time.time() - t

    def verify(self, out):
        r = subprocess.run(self.cmd + ["--verify", out], capture_output=True, text=True, errors="replace", timeout=self.timeout,
                           stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr

    def run_sarif(self, out, mdir):
        if not self.sarif:
            return None
        if not os.path.isfile(self.sarif):
            raise Skip(f"sarif.py not found at {self.sarif} (pass --sarif or --no-sarif)")
        dst = os.path.join(mdir, "result.sarif")
        r = subprocess.run([sys.executable, "-I", "-B", self.sarif, out, "-o", dst], capture_output=True, text=True,
                           errors="replace", timeout=120, stdin=subprocess.DEVNULL)
        doc = None
        if r.returncode == 0 and os.path.isfile(dst):
            with open(dst, encoding="utf-8") as f:
                doc = json.load(f)
        return {"exit": r.returncode, "doc": doc, "log": r.stdout + r.stderr}

    # 증적 조작
    def tamper(self, out, ops):
        def load(rel):
            with open(os.path.join(out, rel), encoding="utf-8") as f:
                return json.load(f)

        def save(rel, doc, indent=1):
            with open(os.path.join(out, rel), "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False, indent=indent)

        for op in ops:
            kind, rel = op["op"], op.get("file")
            if kind == "flip_byte":
                p = os.path.join(out, rel)
                if not os.path.isfile(p):
                    raise Skip(f"{rel} not in the evidence folder")
                with open(p, "rb") as f:
                    data = bytearray(f.read())
                data[op.get("offset", -2)] ^= 1
                with open(p, "wb") as f:
                    f.write(bytes(data))
            elif kind == "json_set":
                if not os.path.isfile(os.path.join(out, rel)):
                    raise Skip(f"{rel} not in the evidence folder")
                doc = load(rel)
                if set_path(doc, op["path"], op["value"], op.get("where")) == 0:
                    raise Skip(f"{rel}: nothing at {op['path']}")
                save(rel, doc)
            elif kind == "rehash_artifact":
                p = os.path.join(out, rel)
                with open(p, "rb") as f:
                    data = f.read()
                sha, size = hashlib.sha256(data).hexdigest(), len(data)
                rec = load("receipt.json")
                hit = 0
                for a in rec.get("artifacts", []):
                    if a.get("path") == rel:
                        a["sha256"], a["bytes"] = sha, size
                        hit += 1

                def walk(o):
                    nonlocal hit
                    if isinstance(o, dict):
                        for k in list(o):
                            if isinstance(o[k], str) and o[k] == rel and f"{k}_sha256" in o:
                                o[f"{k}_sha256"] = sha
                                hit += 1
                            walk(o[k])
                    elif isinstance(o, list):
                        for x in o:
                            walk(x)
                walk(rec)
                if not hit:
                    raise Skip(f"{rel} is not listed in receipt.json")
                save("receipt.json", rec)
            elif kind == "rehash_receipt":
                rec = load("receipt.json")
                rec["receipt_id"] = receipt_id(rec)
                save("receipt.json", rec)
            else:
                raise Skip(f"unknown evidence op {kind}")

    # 기대값 비교
    def compare(self, m, code, log, rec, ver, sar):
        exp, bad = m.get("expect", {}), []

        def one_of(v):
            return v if isinstance(v, list) else [v]

        if "exit" in exp and code not in one_of(exp["exit"]):
            bad.append(f"exit {code}, want {exp['exit']}")
        if rec is None and any(k in exp for k in ("verdict", "checks", "checks_not", "min", "max", "eq", "contains")):
            bad.append("no receipt.json")
            return bad
        if rec is not None:
            st = {c.get("id"): c.get("status") for c in rec.get("checks", [])}
            if "verdict" in exp and rec.get("verdict") not in one_of(exp["verdict"]):
                bad.append(f"verdict {rec.get('verdict')}, want {exp['verdict']}")
            if rec.get("verdict") in exp.get("verdict_not", []):
                bad.append(f"verdict {rec.get('verdict')} not allowed")
            for cid, want in exp.get("checks", {}).items():
                if st.get(cid) not in one_of(want):
                    bad.append(f"{cid} {st.get(cid)}, want {want}")
            for cid, deny in exp.get("checks_not", {}).items():
                if st.get(cid) in deny:
                    bad.append(f"{cid} {st.get(cid)} must not be one of {deny}")
            for path, n in exp.get("min", {}).items():
                v = as_number(get_path(rec, path))
                if v is None or v < n:
                    bad.append(f"{path} = {v}, want >= {n}")
            for path, n in exp.get("max", {}).items():
                v = as_number(get_path(rec, path))
                if v is None or v > n:
                    bad.append(f"{path} = {v}, want <= {n}")
            for path, want in exp.get("eq", {}).items():
                got = get_path(rec, path)
                if not got or got[0] != want:
                    bad.append(f"{path} = {got[0] if got else None}, want {want}")
            for path, subs in exp.get("contains", {}).items():
                text = flat_text(get_path(rec, path))
                for s in one_of(subs):
                    if s not in text:
                        bad.append(f"{path} does not mention {s!r}")
        for s in exp.get("stdout_contains", []):
            if s not in log:
                bad.append(f"output does not mention {s!r}")
        for rx in exp.get("stdout_regex", []):
            if not re.search(rx, log):
                bad.append(f"output does not match {rx!r}")
        for rx in exp.get("stdout_regex_not", []):
            if re.search(rx, log):
                bad.append(f"output matches {rx!r} (silent pass)")
        if "verify_exit" in exp:
            vcode, vlog = ver
            if (exp["verify_exit"] == "nonzero" and vcode == 0) or (exp["verify_exit"] != "nonzero" and vcode != exp["verify_exit"]):
                bad.append(f"--verify exit {vcode}, want {exp['verify_exit']}")
            for s in exp.get("verify_contains", []):
                if s not in vlog:
                    bad.append(f"--verify output does not mention {s!r}")
        want_s = m.get("sarif")
        if want_s and sar is not None:
            if "exit" in want_s:
                if sar["exit"] != want_s["exit"]:
                    bad.append(f"sarif exit {sar['exit']}, want {want_s['exit']}")
            elif sar["doc"] is None:
                bad.append(f"sarif failed: {sar['log'][-300:]}")
            else:
                results = sar["doc"]["runs"][0]["results"]
                for rule, level in want_s.get("rules", {}).items():
                    if not any(r["ruleId"] == rule and r["level"] == level for r in results):
                        bad.append(f"sarif has no {level} result for {rule}")
                for rule in want_s.get("absent", []):
                    if any(r["ruleId"] == rule for r in results):
                        bad.append(f"sarif has a result for {rule}, want none")
                if "max_results" in want_s and len(results) > want_s["max_results"]:
                    bad.append(f"sarif has {len(results)} results, want <= {want_s['max_results']}")
        return bad

    def one(self, m):
        mdir = os.path.join(self.work, m["id"])
        os.makedirs(mdir)
        orig, fixed = self.tree(m, mdir)
        env = dict(m.get("env") or {})
        allow = self.allow_file(m, mdir)
        if allow:
            env["ALLOW"] = allow
        out = os.path.join(mdir, "out")
        code, log, secs = self.prove(orig, fixed, out, env)
        with open(os.path.join(mdir, "prove.log"), "w", encoding="utf-8") as f:
            f.write(log)
        rec = None
        rp = os.path.join(out, "receipt.json")
        if os.path.isfile(rp):
            with open(rp, encoding="utf-8") as f:
                rec = json.load(f)
            self.receipts[m["id"]] = rec
        if code == 2:
            raise Skip(f"tool usage error (exit 2): {log.strip().splitlines()[-1] if log.strip() else ''}")
        ver = None
        if m["kind"] == "evidence":
            if rec is None:
                raise Skip("base run produced no receipt.json")
            base_v = self.verify(out)
            if base_v[0] != 0:
                raise Skip(f"untampered evidence already fails --verify: {base_v[1][-200:]}")
            if receipt_id(rec) != rec.get("receipt_id"):
                raise Skip("this runner's RFC 8785 form does not reproduce receipt_id; rehash cases cannot be built")
            self.tamper(out, m.get("evidence_ops", []))
            ver = self.verify(out)
            with open(os.path.join(mdir, "verify.log"), "w", encoding="utf-8") as f:
                f.write(ver[1])
            code_for_compare, rec_for_compare = code, None
        else:
            code_for_compare, rec_for_compare = code, rec
        sar = self.run_sarif(out, mdir) if m.get("sarif") else None
        if m["kind"] == "tree":
            self.views[m["id"]] = golden_view(code, rec)
        return self.compare(m, code_for_compare, log, rec_for_compare, ver, sar), secs


def main(argv=None):
    ap = argparse.ArgumentParser(description="PQ-Proof planted-defect suite")
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(HERE)), help="tool root with prove.sh and examples/")
    ap.add_argument("--examples", default=None, help="folder with classic/ and pqc/ (default <root>/examples)")
    ap.add_argument("--cmd", default=None, help='tool command (default "bash <root>/prove.sh"; env PQPROOF_CMD)')
    ap.add_argument("--sarif", default=None, help="sarif.py to check SARIF output (default <root>/src/pqproof/sarif.py)")
    ap.add_argument("--no-sarif", action="store_true", help="do not check SARIF output (reported in the summary)")
    ap.add_argument("--spec", default=os.path.join(HERE, "mutations.json"), help="mutation list (default: mutations.json next to this file)")
    ap.add_argument("--only", default="", help="comma separated mutation ids")
    ap.add_argument("--strict", action="store_true", help="pending mutations (D1, D2) must pass too")
    ap.add_argument("--work", default=None, help="work folder (default: a new temp folder, removed unless --keep)")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--json", default=None, help="write the results as JSON")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--golden", default=None, help="compare each tree case with this golden file (verdict, checks, counts)")
    ap.add_argument("--write-golden", default=None, help="write the golden file from this run (after an intended rule change)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    golden = None
    if a.golden:
        with open(a.golden, encoding="utf-8") as f:
            golden = json.load(f).get("runs", {})
    with open(a.spec, encoding="utf-8") as f:
        spec = json.load(f)
    muts = spec["mutations"]
    if a.only:
        want = {x.strip() for x in a.only.split(",") if x.strip()}
        unknown = want - {m["id"] for m in muts}
        if unknown:
            print(f"unknown mutation ids: {sorted(unknown)}", file=sys.stderr)
            return 2
        # allow_set 가 다른 항목의 결과(@경로:id)를 쓰면 그 항목도 먼저 돌린다
        for m in muts:
            if m["id"] in want:
                for v in (m.get("allow_set") or {}).values():
                    if isinstance(v, str) and v.startswith("@") and ":" in v:
                        want.add(v.rsplit(":", 1)[1])
        muts = [m for m in muts if m["id"] in want]
    run = Runner(a)
    rows, t0 = [], time.time()
    print(f"PQ-Proof mutations: {len(muts)} · tool {' '.join(run.cmd)} · work {run.work}")
    for m in muts:
        try:
            bad, secs = run.one(m)
            if golden is not None and m["kind"] == "tree":
                if m["id"] not in golden:
                    bad = bad + [f"no golden entry for {m['id']} in {a.golden} (run with --write-golden after checking it)"]
                else:
                    gd = golden_diff(golden[m["id"]], run.views.get(m["id"]))
                    bad = bad + [f"golden {x}" for x in gd[:8]] + ([f"golden: {len(gd) - 8} more differences"] if len(gd) > 8 else [])
            if not bad:
                status = "PASS"
            elif m.get("pending") and not a.strict:
                status = "PENDING"
            else:
                status = "FAIL"
            why = bad
        except Skip as e:
            status, why, secs = "SKIP", [str(e)], 0.0
        rows.append({"id": m["id"], "status": status, "pending": m.get("pending"), "control": bool(m.get("control")),
                     "title": m.get("title"), "title_ko": m.get("title_ko"), "problems": why, "seconds": round(secs, 1)})
        tag = f" [{m['pending']} fix pending]" if m.get("pending") and status != "PASS" else ""
        print(f"{status:<8}{m['id']:<36}{m.get('title_ko') or m.get('title')}{tag}")
        if status != "PASS" or a.verbose:
            for w in why:
                print(f"          - {w}")
    count = {s: sum(1 for r in rows if r["status"] == s) for s in ("PASS", "FAIL", "SKIP", "PENDING")}
    print(f"mutations: PASS {count['PASS']}/{len(rows)} · FAIL {count['FAIL']} · SKIP {count['SKIP']} (not counted as pass) · "
          f"PENDING {count['PENDING']}{' (strict)' if a.strict else ''}" + ("" if run.sarif else " · SARIF not checked (--no-sarif)")
          + f" · {time.time() - t0:.1f}s")
    if golden is not None:
        print(f"golden: compared {sum(1 for m in muts if m['kind'] == 'tree')} tree cases with {a.golden}")
    if a.write_golden:
        with open(a.write_golden, "w", encoding="utf-8") as f:
            f.write(json.dumps({"format": "pqproof golden verdicts 1",
                                "about": "Verdict, check statuses and counts of every tree case in tests/mutations/mutations.json "
                                         "(the two c0x controls are the plain examples). run_mutations.py --golden fails when any "
                                         "of them moves. Rewrite with --write-golden only for an intended rule change, and record "
                                         "it in CHANGELOG.md with its verdict impact.",
                                "runs": dict(sorted(run.views.items()))}, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        print(f"wrote {a.write_golden} ({len(run.views)} tree cases)")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"format": "pqproof mutation results 1", "tool": run.cmd, "strict": a.strict, "sarif_checked": bool(run.sarif),
                       "counts": count, "results": rows}, f, ensure_ascii=False, indent=1)
    if run.own_tmp and not a.keep:
        shutil.rmtree(run.work, ignore_errors=True)  # 이 실행이 mkdtemp 로 만든 자기 폴더만 지운다
    elif a.keep:
        print(f"kept: {run.work}")
    return 0 if count["FAIL"] == 0 and count["SKIP"] == 0 and (count["PENDING"] == 0 or not a.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
