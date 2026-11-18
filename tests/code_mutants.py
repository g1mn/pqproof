#!/usr/bin/env python3
# code_mutants.py: 규칙 코드에 작은 변이를 하나씩 넣은 사본마다 행동·동기 시험(test_rules·test_rule_sync·test_testpaths)을 돌려
# 살아남은 변이 수를 센다. 살아남은 변이는 그 규칙을 지키는 시험이 없다는 뜻이다. 주간 CI(.github/workflows/code-mutants.yml)가 돈다.
#   python3 -I tests/code_mutants.py                 모든 변이(동시에 -j 개)
#   python3 -I tests/code_mutants.py --only m03,m06 --json out.json --keep
# 변이 표(MUTANTS)는 (번호, 파일, 찾을 글, 바꿀 글, 설명). 찾을 글이 파일에 꼭 한 번 있어야 한다. 아니면 표가 낡은 것이라 종료 2.
# 해시 고정 시험(test_versioning)과 golden 은 돌리지 않는다. 규칙 파일이 바뀌면 늘 실패해서 행동 시험이 잡았는지를 가린다.
# 작업은 임시 폴더의 사본에서만 하고 저장소는 읽기만 한다. 표준 라이브러리만 쓴다.
# 종료: 0 모두 잡힘 · 1 살아남은 변이 있음 · 2 표·사용법 오류
"""Plant small code mutations in the rule code and count the ones the behaviour and sync tests miss."""
import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COPY = ("prove.sh", "prove.py", "pqlite", "scan", "src", "tests", "examples", "CHANGELOG.md")
TESTS = ("test_rules", "test_rule_sync", "test_testpaths")  # 모듈 이름(run_unit.py 에는 "이름.*" 로 넘긴다)
MUTANTS = [
    ("m01", "scan/residue.sh", "|[Bb][Rr][Aa][Ii][Nn][Pp][Oo][Oo][Ll]|", "|", "G-CURVE 에서 brainpool 대안 삭제"),
    ("m02", "scan/residue.sh", '|ssh-dss|ElGamal|ECIES@@', '|ssh-dss@@', "G-DH-DSA 에서 ElGamal·ECIES 삭제"),
    ("m03", "pqlite/rules.py", "HYB_WINDOW = 12", "HYB_WINDOW = 40", "하이브리드 창 12줄을 40줄로"),
    ("m04", "pqlite/rules.py", "MIN_COMMON = 0.5", "MIN_COMMON = 0.05", "a-input 공통 파일 50% 를 5% 로"),
    ("m05", "pqlite/verify.py", r'SECLEVEL\s*=\s*0\b', r'SECLEVEL\s*=\s*00\b', "보안 수준 0 규칙이 00 만 보게"),
    ("m06", "pqlite/rules.py", r'publicEncrypt\s*\(|', "", "허용 목록 쓰기 경로에서 publicEncrypt 삭제"),
    ("m07", "scan/test-paths.ere", "|/conftest[.]py$", "", "시험 경로에서 conftest.py 삭제"),
    ("m08", "scan/residue.sh", "RES_WRITEOPS='ENCRYPT_MODE|WRAP_MODE|initSign|", "RES_WRITEOPS='ENCRYPT_MODE|WRAP_MODE|",
     "residue 쓰기 연산에서 initSign 삭제"),
    ("m09", "scan/residue.sh", "같은 줄 ML-KEM 이면 하이브리드 허용)@@[Mm][Ll][-_]?[Kk][Ee][Mm]", "같은 줄 ML-KEM 이면 하이브리드 허용)@@",
     "G-X25519 같은 줄 ML-KEM 허용 삭제"),
    ("m10", "scan/residue.sh", 'if (b ~ /\\.sql$/) return "sql"', 'if (b ~ /\\.sqlx$/) return "sql"', "SQL 주석(--)을 코드로"),
    ("m11", "scan/residue.sh", "if ((ISLEG || CODE ~ ALLOWLINE) && CODE !~ ALLOWWR)", "if (ISLEG && CODE !~ ALLOWWR)", "같은 줄 legacy 허용 삭제"),
    ("m12", "scan/residue.sh", ")(RS|ES|PS)(256|384|512)", ")(RS|ES)(256|384|512)", "G-JWT-ALG 에서 PS 삭제"),
    ("m13", "pqlite/verify.py", '(?:--insecure|-k)', '(?:--insecure)', "curl -k 규칙 삭제"),
    ("m14", "pqlite/verify.py", 'OLD_PROTOCOLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.1"}', 'OLD_PROTOCOLS = {"sslv2", "sslv3", "tlsv1"}',
     "nginx 옛 프로토콜에서 TLSv1.1 삭제"),
    ("m15", "pqlite/verify.py", "GODEBUG_DEFAULT_MIN = 23", "GODEBUG_DEFAULT_MIN = 20", "godebug default 문턱 Go 1.23 을 1.20 으로"),
    ("m16", "pqlite/rules.py", "range(line + 1, line + 4)", "range(line + 1, line + 5)", "허용 목록 쓰기 경로를 아래 4줄까지"),
    ("m17", "pqlite/rules.py", 'LEGACY_FILE = re.compile(r"(?:^|/)Legacy', 'LEGACY_FILE = re.compile(r"Legacy', "Legacy*.java 이름 규칙의 경로 앞 경계 삭제"),
    ("m18", "pqlite/rules.py", '"G-X25519", "G-DH-DSA"]', '"G-X25519"]', "공개키 9계열에서 G-DH-DSA 삭제"),
    ("m19", "src/pqproof/sarif.py", '"G-DH-DSA", "G-WEAK-PQC"}', '"G-DH-DSA"}', "SARIF 가 세는 규칙에서 G-WEAK-PQC 삭제"),
    ("m20", "src/pqproof/deps.py", '"/usr/local/opt/openssl@3/bin/openssl", ', "", "doctor 의 OpenSSL 후보에서 한 곳 삭제"),
    ("m21", "pqlite/verify.py", r'r"\bX509(?:Extended)?TrustManager\b|', r'r"\bX509ExtendedTrustManager\b|', "trust-all 규칙이 X509TrustManager 를 놓치게"),
    ("m22", "scan/residue.sh", "if (ISTEST) { add(r, \"TEST\", FNR, s); continue }", "", "시험 경로 줄을 TEST 로 따로 세지 않게"),
    # 규칙 묶음 2(교차 리뷰 X01·X02·X03·X04·X06·X07·X09)
    ("m23", "pqlite/rules.py", "ALLOWLINE.search(code_part(text))", "ALLOWLINE.search(text)", "이름 규칙이 주석의 legacy 도 세게(X01)"),
    ("m24", "scan/residue.sh", "&& CODE !~ ALLOWWR)", ")", "residue 이름 규칙이 모든 언어 쓰기 연산을 안 보게(X01)"),
    ("m25", "scan/skip-dirs", "main /src/main/\n", "", "운영 소스 표시를 지워 src/main 아래 산출물 이름 폴더도 건너뛰게(X02·X03)"),
    ("m26", "pqlite/rules.py", 'if threat in ("쇼어로 깨짐", CBOM_WEAK_PQC):', 'if threat == "쇼어로 깨짐":', "cbom-scan 의 보안레벨 3 미만 행을 참고로(X07)"),
    ("m27", "pqlite/rules.py", "        if part not in CBOM_FLAGS:\n            break", "        if part not in CBOM_FLAGS:\n            continue",
     "비고 맨 앞이 아닌 '테스트·예제'도 표시로(X06)"),
    ("m28", "pqlite/rules.py", 'if norm == ".." or norm.startswith("../"):', 'if norm == "..":', "상대 경로로 트리 밖을 가리키는 링크를 놓치게(X04)"),
    ("m29", "pqlite/rules.py", "                again += 1\n", "                continue\n", "residue 가 허용한 쓰기 경로 줄을 다시 세지 않게(X01)"),
    ("m30", "pqlite/skipdirs.py", "        if not parent_rel or not self.build_files.isdisjoint(sibling_files):",
     "        if True:", "산출물 이름 폴더를 어디서나 건너뛰게(X02·X03·X09)"),
    # 규칙 묶음 2, 나머지(교차 리뷰 X11·X18·X19·X22·X23·X24·X26·X27·X30)
    ("m31", "pqlite/rules.py", '    if c and c[1] != "44":\n        return COMPOSITE_REASON', "", "복합 서명을 다른 허용 규칙으로 넘기게(X26)"),
    ("m32", "scan/residue.sh", "    if (index(substr(t, 4), d) == 0) INDOC = d\n", "", "여러 줄 독스트링을 첫 줄만 주석으로(X22)"),
    ("m33", "scan/test-paths.ere", "|/tests?[.]py$", "", "시험 경로에서 Django tests.py 삭제(X24)"),
    ("m34", "pqlite/verify.py", "TLS13 = 0x0304", "TLS13 = 0x0303", "TLS 1.2 상한을 약화로 안 보게(X18)"),
    ("m35", "pqlite/rules.py", '    if not re.search(r"\\w", cv):\n        return True', '    if not re.search(r"\\w", cv):\n        return False',
     "cbom 행의 주석·독스트링 판정 끄기(X22)"),
    ("m36", "scan/residue.sh", "ParameterSpec|Curve|[^A-Za-z0-9:]|$)", "ParameterSpec|Curve|[^A-Za-z]|$)", "G-EC 가 EC2·AWS::EC2 를 다시 잡게(X23)"),
    ("m37", "scan/profiles.json", '"kem": ["E-MLKEM1024"],', '"kem": ["E-MLKEM768", "E-MLKEM1024"],', "cnsa2 프로필이 ML-KEM-768 도 세게(X11)"),
    ("m38", "pqlite/rules.py", '(it["tool"] == "cbom-scan" and "일반 패턴" not in it["note"])', '(it["tool"] == "cbom-scan")',
     "EXPECT_FROM=api 가 이름만 맞은 일반 패턴 행도 세게(X30)"),
    ("m39", "pqlite/rules.py", '            status, reason = "review", UNRESOLVED_KEY\n', '            status = "check"\n',
     "열지 못한 키 자료를 다시 '확인'으로(X27)"),
    ("m40", "scan/residue.sh", "|(^|[^A-Za-z0-9])(ed25519|ed448|eddsa|curve25519|ED25519|ED448)@@", "@@",
     "G-EDDSA 가 소문자 ed25519 를 놓치게(X19)"),
]


def apply(root, rel, find, repl):
    path = os.path.join(root, *rel.split("/"))
    with open(path, encoding="utf-8") as f:
        text = f.read()
    n = text.count(find)
    if n != 1:
        return f"{rel}: anchor found {n} times (the mutant table is stale): {find[:60]!r}"
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.replace(find, repl))
    return None


def copy_tree(dst):
    for name in COPY:
        src = os.path.join(ROOT, name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(dst, name), ignore=shutil.ignore_patterns("__pycache__"))
        elif os.path.isfile(src):
            shutil.copy2(src, os.path.join(dst, name))


def run_tests(root, timeout):
    env = {k: v for k, v in os.environ.items() if k not in ("STRICT", "OUT", "ALLOW", "RESIDUE", "CBOM_SCAN")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    t = time.time()
    r = subprocess.run([sys.executable, "-I", "-B", os.path.join(root, "tests", "run_unit.py"), *(f"{t}.*" for t in TESTS)], capture_output=True, text=True,
                       errors="replace", timeout=timeout, env=env, stdin=subprocess.DEVNULL, cwd=root)
    line = next((x for x in reversed(r.stdout.splitlines()) if x.startswith("unit: ")), "")
    return r.returncode, line, r.stdout + r.stderr, time.time() - t


def one(work, m, timeout):
    mid, rel, find, repl, what = m
    d = os.path.join(work, mid)
    os.makedirs(d)
    copy_tree(d)
    bad = apply(d, rel, find, repl)
    if bad:
        return {"id": mid, "file": rel, "what": what, "status": "STALE", "detail": bad, "seconds": 0}
    code, line, log, secs = run_tests(d, timeout)
    with open(os.path.join(d, "unit.log"), "w", encoding="utf-8") as f:
        f.write(log)
    return {"id": mid, "file": rel, "what": what, "status": "KILLED" if code != 0 else "SURVIVED", "detail": line,
            "seconds": round(secs, 1)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="PQ-Proof code mutants")
    ap.add_argument("--only", default="", help="comma separated mutant ids")
    ap.add_argument("-j", "--jobs", type=int, default=min(4, os.cpu_count() or 1))
    ap.add_argument("--json", default=None, help="write the results as JSON")
    ap.add_argument("--keep", action="store_true", help="keep the work folder")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--baseline", action="store_true", help="also run the tests on an unmutated copy (must pass)")
    a = ap.parse_args(argv)
    muts = MUTANTS
    if a.only:
        want = {x.strip() for x in a.only.split(",") if x.strip()}
        unknown = want - {m[0] for m in MUTANTS}
        if unknown:
            print(f"unknown mutant ids: {sorted(unknown)}", file=sys.stderr)
            return 2
        muts = [m for m in MUTANTS if m[0] in want]
    work = tempfile.mkdtemp(prefix="pqproof-codemut-")
    t0 = time.time()
    print(f"PQ-Proof code mutants: {len(muts)} · tests {' '.join(TESTS)} · jobs {a.jobs} · work {work}")
    if a.baseline:
        base = os.path.join(work, "baseline")
        os.makedirs(base)
        copy_tree(base)
        code, line, _, _ = run_tests(base, a.timeout)
        print(f"baseline: exit {code} {line}")
        if code != 0:
            print("the unmutated copy fails its own tests; fix that first", file=sys.stderr)
            return 2
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        rows = list(ex.map(lambda m: one(work, m, a.timeout), muts))
    for r in rows:
        print(f"{r['status']:<9}{r['id']}  {r['file']:<22}{r['what']}  {r['detail']}")
    count = {s: sum(1 for r in rows if r["status"] == s) for s in ("KILLED", "SURVIVED", "STALE")}
    print(f"code mutants: killed {count['KILLED']}/{len(rows)} · survived {count['SURVIVED']} · stale {count['STALE']} · "
          f"{time.time() - t0:.1f}s")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"format": "pqproof code mutants 1", "tests": list(TESTS), "counts": count, "results": rows}, f, ensure_ascii=False,
                      indent=1)
    if a.keep:
        print(f"kept: {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)  # 이 실행이 mkdtemp 로 만든 자기 폴더만 지운다
    return 2 if count["STALE"] else (1 if count["SURVIVED"] else 0)


if __name__ == "__main__":
    sys.exit(main())
