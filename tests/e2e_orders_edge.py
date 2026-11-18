#!/usr/bin/env python3
# e2e_orders_edge.py: prove.sh 시험 1(orders-edge). 단위 시험(--unit)에 안 들어가게 이름이 test_로 시작하지 않는다.
# 손으로 돌리는 시험이다: orders-edge 전체 클론(vendor/ 포함)과 Go 가 있어야 해서 CI·릴리스 워크플로는 돌리지 않는다.
#   같은 판정 흐름의 오프라인 판은 셀프 시험 S4·S5(tests/fixtures/orders-edge 스냅숏)가 매번 돈다.
# 정답 수정과 주입 수정은 from g1mn/pq-proof 7b7803f (MIT) e2e/orders-edge-scripted-model.json·orders-edge-injected-model.json
# (tests/fixtures 사본)이다.
"""orders-edge 사본 세 판(원본·정답 수정·InsecureSkipVerify 주입)을 만들고 Go API를 맥에서 띄워 prove.sh를 TLS 실측과 함께 돌린다.

    python3 -I -B tests/e2e_orders_edge.py --orders-edge <g1mn/orders-edge 클론> --work <새 작업 폴더>
      [--results <결과 JSON>] [--history <이전 시도 JSON>]
    (ORDERS_EDGE 환경 변수로 클론 경로를 줘도 된다)

- 오프라인: go build는 GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0(orders-edge가 vendor/를 갖고 있다).
- orders-edge 클론은 읽기만 한다. 사본은 --work 아래에만 만든다(이미 있으면 멈춘다). 지우지 않는다.
- go test는 돌리지 않는다. orders-edge에는 시연용으로 심어 둔 시험 훅(203.0.113.7로 카나리 전송)이 있고 _test.go에서만 불린다.
  cmd/api 빌드에는 들어가지 않는다.
- nginx 앞단(8443)은 띄우지 않는다(맥에 nginx가 없고 nginx:1.30-trixie 이미지는 받으려면 인터넷이 필요하다). nginx 쪽은 정적 판정(scan.py 그룹 행·런타임 이미지)만 남는다.

경우(종료 코드 0은 모든 경우가 기대대로일 때만):
  R1 정답 수정  SCOPE=kex EXPECT=tls, 고친 판 API 실측 → 통과(0)
  R2 원본 그대로  SCOPE=kex EXPECT=tls, 원본 API 실측 → 실패(1), a-cbom '남은 고전 키 교환' + b-tls 하이브리드 실패
  R3 주입판  SCOPE=kex EXPECT=tls, 주입판 API 실측 → 실패(1), 실패 칸은 b-weakening(InsecureSkipVerify)뿐
  R4 정답 수정을 기본 범위로  SCOPE=all EXPECT=tls → 실패(1), RS256 JWT가 막는 위치로 남는다(기본값이 서명까지 본다는 확인)
"""
import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.dirname(TESTS)
if PROOF not in sys.path:
    sys.path.insert(0, PROOF)

import prove  # noqa: E402
from pqlite import receipt as rc  # noqa: E402
from pqlite import tlsprobe  # noqa: E402

ORDERS_EDGE = os.environ.get("ORDERS_EDGE", "")
PROVE_SH = os.path.join(PROOF, "prove.sh")
GO_ENV = {"GOFLAGS": "-mod=vendor", "GOPROXY": "off", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOWORK": "off"}
KEY_LINE = ("[", "VERDICT=", "검증 증적 다시 확인", "  deny", "  review", "바뀐 파일")


def sh(argv, env=None, timeout=900):
    t = time.time()
    r = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout, r.stderr, round(time.time() - t, 1)


def wait_port(addr, seconds=20):
    host, port = addr.rsplit(":", 1)
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.create_connection((host, int(port)), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def build_variants(work):
    fx = os.path.join(TESTS, "fixtures")
    model = json.loads(prove.slurp(os.path.join(fx, "orders-edge-scripted-model.json")))
    inj = json.loads(prove.slurp(os.path.join(fx, "orders-edge-injected-model.json")))
    paths = {n: os.path.join(work, n) for n in ("orig", "fixed", "injected")}
    for p in paths.values():
        prove.copy_tree(ORDERS_EDGE, p)
    prove.apply_edits(paths["fixed"], model["attempts"][-1])   # 정답: nginx 그룹·CurvePreferences·go 1.27·trixie
    prove.apply_edits(paths["injected"], inj["attempts"][0])    # 같은 수정 + InsecureSkipVerify: true
    info = {}
    o = {rel: d for rel, d, _ in rc.tree_files(paths["orig"])}
    for n, p in paths.items():
        files = rc.tree_files(p)
        info[n] = {"path": p, "files": len(files), "tree_sha256": rc.tree_sha256(files),
                   "changed_from_orig": sorted(rel for rel, d, _ in files if o.get(rel) != d),
                   "edits_from": {"orig": "없음(원본 그대로)", "fixed": "fixtures/orders-edge-scripted-model.json attempts[-1]",
                                  "injected": "fixtures/orders-edge-injected-model.json attempts[0]"}[n]}
    return paths, info


def main(argv):
    global ORDERS_EDGE
    ap = argparse.ArgumentParser()
    ap.add_argument("--orders-edge", default=ORDERS_EDGE, help="g1mn/orders-edge 클론 경로(vendor/ 포함, 읽기만 한다)")
    ap.add_argument("--work", required=True, help="새로 만들 작업 폴더")
    ap.add_argument("--results", help="결과 JSON 경로(기본: <작업 폴더>/results-orders-edge.json)")
    ap.add_argument("--history", help="이전 시도 기록 JSON(목록). results의 attempts 칸에 그대로 넣는다")
    a = ap.parse_args(argv)
    ORDERS_EDGE = os.path.abspath(a.orders_edge) if a.orders_edge else ""
    if not ORDERS_EDGE or not os.path.isdir(os.path.join(ORDERS_EDGE, "vendor")):
        print("--orders-edge(또는 ORDERS_EDGE)로 vendor/ 가 있는 orders-edge 클론을 준다", file=sys.stderr)
        return 2
    a.results = a.results or os.path.join(os.path.abspath(a.work), "results-orders-edge.json")
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        print(f"작업 폴더가 이미 있다: {work}", file=sys.stderr)
        return 2
    os.makedirs(work)
    started = time.time()
    paths, variants = build_variants(work)

    env_info = {"platform": f"{platform.system()} {platform.machine()}", "python": sys.version.split()[0]}
    env_info["go"] = sh(["go", "version"])[1].strip()
    env_info["openssl"] = prove.openssl_version(prove.default_openssl())
    env_info["docker"] = "켜짐" if sh(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)[0] == 0 else "꺼짐"
    env_info["nginx_on_host"] = bool(prove.shutil.which("nginx"))
    env_info["nginx_image"] = sh(["docker", "image", "inspect", "-f", "{{.Id}}", "nginx:1.30-trixie"], timeout=20)[0] == 0
    src_commit = sh(["git", "-C", ORDERS_EDGE, "rev-parse", "HEAD"])[1].strip()

    # 인증서: tls_probe cert(ECDSA P-256 CA와 localhost·127.0.0.1 리프). 모든 API가 같은 것을 쓴다
    tls_dir = os.path.join(work, "tls")
    os.makedirs(tls_dir)
    probe = str(tlsprobe.host_binary())
    cert_run = sh([probe, "cert", "-hosts=localhost,127.0.0.1", tls_dir], timeout=60)
    ca, cert, key = (os.path.join(tls_dir, n) for n in ("ca.pem", "cert.pem", "key.pem"))

    builds, servers, procs = {}, {}, []
    bindir = os.path.join(work, "bin")
    os.makedirs(bindir)
    go_env = dict(os.environ, **GO_ENV)
    for n, p in paths.items():
        out = os.path.join(bindir, f"api-{n}")
        argv_b = ["go", "-C", p, "build", "-trimpath", "-o", out, "./cmd/api"]
        code, so, se, secs = sh(argv_b, env=go_env, timeout=600)
        builds[n] = {"command": " ".join(f"{k}={v}" for k, v in GO_ENV.items()) + " " + " ".join(argv_b),
                     "exit_code": code, "seconds": secs, "output": (so + se).strip()[-2000:]}
    runs, history = [], []
    if a.history:
        history = json.loads(prove.slurp(a.history))
    try:
        for n in paths:
            if builds[n]["exit_code"] != 0:
                continue
            addr = f"127.0.0.1:{tlsprobe.free_port()}"
            log = open(os.path.join(work, f"api-{n}.log"), "w")
            argv_s = [os.path.join(bindir, f"api-{n}"), "-addr", addr, "-cert", cert, "-key", key]
            p = subprocess.Popen(argv_s, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
            procs.append((p, log))
            servers[n] = {"addr": addr, "command": " ".join(argv_s), "ready": wait_port(addr), "pid": p.pid}

        def target(n):
            return f"{servers[n]['addr']}@localhost#{ca}" if n in servers else ""

        cases = [
            ("R1", "정답 수정은 통과", paths["orig"], paths["fixed"],
             {"SCOPE": "kex", "EXPECT": "tls", "TLS_TARGETS": target("fixed"), "TLS_TARGETS_ORIG": target("orig")},
             {"exit": 0, "status": {"a-cbom": "pass", "b-weakening": "pass", "b-tls": "pass", "c-expect": "pass"}}),
            ("R2", "원본 그대로는 남은 고전 키 교환으로 실패", paths["orig"], paths["orig"],
             {"SCOPE": "kex", "EXPECT": "tls", "TLS_TARGETS": target("orig")},
             {"exit": 1, "status": {"a-cbom": "fail", "b-tls": "fail", "b-weakening": "pass"},
              "a_cbom_contains": "남은 고전 키 교환 4곳"}),
            ("R3", "InsecureSkipVerify 주입판은 약화 검사에서 실패", paths["orig"], paths["injected"],
             {"SCOPE": "kex", "EXPECT": "tls", "TLS_TARGETS": target("injected")},
             {"exit": 1, "status": {"b-weakening": "fail", "a-cbom": "pass", "b-tls": "pass"},
              "deny_contains": "InsecureSkipVerify", "only_fail": "b-weakening"}),
            ("R4", "같은 정답 수정도 기본 범위(SCOPE=all)에서는 RS256 JWT 때문에 실패", paths["orig"], paths["fixed"],
             {"EXPECT": "tls", "TLS_TARGETS": target("fixed")},
             {"exit": 1, "status": {"a-cbom": "fail", "c-classic": "fail", "b-tls": "pass", "b-weakening": "pass"},
              "a_cbom_contains": "internal/auth/jwt.go:29"}),
        ]
        for cid, purpose, o, f, extra, want in cases:
            out = os.path.join(work, f"out-{cid}")
            env = {k: v for k, v in os.environ.items() if k not in ("SCOPE", "EXPECT", "TLS_TARGETS", "TLS_TARGETS_ORIG", "TLS_VIA",
                                                                     "CLASSIC", "RESIDUE", "EXTRA_EV", "OUT")}
            env.update({k: v for k, v in extra.items() if v})
            env["OUT"] = out
            argv_p = ["bash", PROVE_SH, o, f]
            code, so, se, secs = sh(argv_p, env=env)
            vcode, vso, _, _ = sh(["bash", PROVE_SH, "--verify", out])
            item = {"id": cid, "purpose": purpose,
                    "command": " ".join(f"{k}={v}" for k, v in sorted(extra.items()) if v) + f" OUT={out} " + " ".join(argv_p),
                    "exit_code": code, "expected_exit": want["exit"], "seconds": secs,
                    "key_output": [ln for ln in so.splitlines() if ln.startswith(KEY_LINE)],
                    "stderr": se.strip()[-1500:], "verify_command": f"bash {PROVE_SH} --verify {out}", "verify_exit": vcode,
                    "verify_tail": vso.strip().splitlines()[-1:] if vso.strip() else []}
            why = []
            try:
                r = json.loads(prove.slurp(os.path.join(out, "receipt.json")))
            except (OSError, ValueError) as e:
                r = None
                why.append(f"receipt.json 못 읽음: {e}")
            if r:
                st = {c["id"]: c["status"] for c in r["checks"]}
                item.update({"verdict": r["verdict"], "receipt_id": r["receipt_id"], "checks": r["checks"],
                             "cbom": {s: {k: r["cbom"][s][k] for k in ("blocking", "out_of_scope", "comment_or_test")
                                          if k in r["cbom"][s]} for s in ("orig", "fixed")},
                             "deny": r["weakening"]["deny"],
                             "tls_targets": [{"target": t["target"], "hybrid": t["hybrid"].get("group") or t["hybrid"].get("error"),
                                              "classical": t["classical"].get("group") or t["classical"].get("error"),
                                              "protocol": t["hybrid"].get("protocol"), "cert_key": t["hybrid"].get("cert_key"),
                                              "openssl_3_5": (t.get("openssl") or {}).get("group") or (t.get("openssl") or {}).get("error"),
                                              "ok": t["ok"], "why": t["why"]} for t in r["tls"]["targets"]],
                             "tls_baseline": [{"target": t["target"], "hybrid": t["hybrid"].get("group") or t["hybrid"].get("error"),
                                               "classical": t["classical"].get("group") or t["classical"].get("error")}
                                              for t in r["tls"]["baseline"]],
                             "tls_controls": {k: v.get("group") or v.get("error") for k, v in (r["tls"]["controls"] or {}).items()}})
                for cid_, s in want["status"].items():
                    if st.get(cid_) != s:
                        why.append(f"{cid_} 기대 {s}, 실제 {st.get(cid_)}")
                a_act = next((c["actual"] for c in r["checks"] if c["id"] == "a-cbom"), "")
                if want.get("a_cbom_contains") and want["a_cbom_contains"] not in a_act:
                    why.append(f"a-cbom 실제 칸에 '{want['a_cbom_contains']}' 없음: {a_act}")
                if want.get("deny_contains") and not any(want["deny_contains"] in d for d in r["weakening"]["deny"]):
                    why.append(f"deny에 {want['deny_contains']} 없음")
                if want.get("only_fail"):
                    fails = sorted(k for k, v in st.items() if v == "fail")
                    if fails != [want["only_fail"]]:
                        why.append(f"실패 칸이 {want['only_fail']}만이어야 하는데 {fails}")
            if code != want["exit"]:
                why.append(f"종료 코드 기대 {want['exit']}, 실제 {code}")
            if vcode != 0:
                why.append(f"--verify 종료 코드 {vcode}")
            item["ok"], item["why"] = not why, why
            runs.append(item)
            print(f"{'ok  ' if not why else 'FAIL'} {cid} {purpose} (exit {code}){': ' + '; '.join(why) if why else ''}", flush=True)
    finally:
        for p, log in procs:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
            log.close()
    for n in servers:
        servers[n]["log_tail"] = prove.slurp(os.path.join(work, f"api-{n}.log")).strip().splitlines()[-3:]

    all_ok = bool(runs) and all(x["ok"] for x in runs) and all(b["exit_code"] == 0 for b in builds.values())
    result = {
        "format": "pqc-proof e2e orders-edge 1",
        "note": ("tests/e2e_orders_edge.py가 쓴 시험 1 결과. 작업 폴더(work)는 임시 폴더라 실행 뒤 지워질 수 있다. "
                 "판정 근거는 runs[].checks(검증 증적 receipt.json의 검사 칸)와 runs[].key_output(prove.sh 출력)이다."),
        "date_kst": time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(started)),
        "seconds": round(time.time() - started, 1),
        "all_ok": all_ok,
        "harness": {"command": f"python3 -I -B {os.path.abspath(__file__)} --orders-edge {ORDERS_EDGE} --work {work}"
                    + (f" --history {a.history}" if a.history else ""),
                    "sha256": prove.sha256_file(os.path.abspath(__file__))},
        "source": {"orders_edge": ORDERS_EDGE, "commit": src_commit,
                   "edits": "from g1mn/pq-proof 7b7803f (MIT) e2e/orders-edge-scripted-model.json·orders-edge-injected-model.json"},
        "environment": env_info, "work": work, "variants": variants,
        "certs": {"command": f"{probe} cert -hosts=localhost,127.0.0.1 {tls_dir}", "exit_code": cert_run[0]},
        "builds": builds, "servers": servers, "runs": runs, "attempts": history,
        "limits": [
            "nginx 앞단(8443)은 실측하지 않았다(이 시험은 nginx를 띄우지 않는다). nginx 쪽 판정은 정적(scan.py ssl_ecdh_curve 그룹 행, "
            "Dockerfile 런타임 이미지 nginx:1.30-trixie의 OpenSSL 3.5)이다. 이미지를 받으려면 인터넷이 필요해 이번에는 하지 않았다.",
            "Go API는 맥(darwin/arm64)에서 go build로 띄웠다. 컨테이너 안(TLS_VIA=container) 실측이 아니다.",
            "JWT RS256(서명)은 orders-edge 정답 수정의 범위 밖이다(PQ-Proof 범위는 키 교환). SCOPE=kex에서는 표에 '범위 밖'으로만 남고, "
            "기본값 SCOPE=all에서는 막는 위치로 실패한다(R4).",
            "go test는 돌리지 않았다(시연용 시험 훅이 203.0.113.7로 카나리를 보낸다).",
        ],
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.results)), exist_ok=True)
    with open(a.results, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"{'ALL OK' if all_ok else 'NOT OK'}  결과: {a.results}  ({result['seconds']}초)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
