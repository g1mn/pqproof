# from g1mn/pq-proof 7b7803f (MIT)
# 수정: 허용 목록·실행 데이터 제외 칸(allowlist·excluded)과 deck.json(render_deck, verify가 다시 만들어 비교).
# 수정: 허용 항목 사람 확인 칸(reviewed_by·reviewed_at, allowlist.unreviewed, params.require_review, 검사 r-allow)과 판정 옆
#       '허용 n건 사람 확인 전' 표시. 이 칸이 없는 옛 증적은 예전 그대로 그린다(옛 receipt.html·deck.json이 그대로 맞게).
#       verify는 항목의 사람 확인 칸을 증적 폴더의 허용 목록 사본에서 다시 풀어 맞춰 본다(allowlist.resolve_reviews).
# 수정(결함 D1·D2 뒤): 허용 항목마다 덮은 줄 수(lines_fixed, 원본 lines_orig·orig), 안 쓰인 항목 수(unused,
#       unused_orig_lines), 허용 범위 쓰기 경로 수(write_review)를 적고 consistency 가 대조한다. 판정 옆 표시에 쓰기 경로·안 쓰인
#       항목 수를 더한다. 시험 경로 목록 사본(test_paths), CBOM·residue 의 시험 줄 수(tests)도 적는다. 이 칸이 없는 옛 증적은
#       예전 그대로 그린다.
# 수정(독립 검토 뒤): 고친 판에서 무효·제외·트리 밖인데 원본 고전 줄을 덮는 항목도 안 쓰인 항목으로 센다(_counts_unused,
#       allowlist.counts_unused 와 같은 식). 새 형식 증적(test_paths 또는 lines_fixed 있음)에서 unused·unused_orig_lines·
#       write_review 칸이 빠지면 실패로 본다(칸을 지워 옛 증적처럼 보이게 하는 위조). verify 는 evidence-fragment.json 과
#       tables/report.md 의 판정이 receipt 판정과 같은지도 본다(새 형식만).
# 수정(0.1.0, 버전 관리): 증적 형식 2. format_version·tool_version·ruleset_version·ruleset_sha256 칸을 더하고 verify 가 규칙 묶음
#       해시를 tools[] 해시로 다시 계산해 맞춘다. format_version 이 없는 증적은 형식 1(0.1.0 이전 공개본)로 읽는다: 첫 공개본의 옛 NOTE 를
#       받고 receipt.html 은 그 판의 낱말(영수증)로 다시 그려 비교한다(tests/golden/evidence 고정물). 형식 2부터 판정 옆 표시에
#       '검증 호출 제거 n건 검토 필요'(r-review)를 더한다. 형식 1 증적은 예전 표시 그대로 그린다.
# 수정(0.1.1): receipt.json 을 엄격하게 읽는다(loads_strict: BOM·중복 키·NaN·Infinity 거부) 그리고 파일 바이트가 도구 직렬화(dumps)와
#       같은지 본다. 정규화는 키를 UTF-16 코드 단위 순서로 정렬하고(RFC 8785 3.2.3) 절댓값 2^53 을 넘는 정수는 거부한다.
#       verify 에서 폴더나 receipt.json 이 없으면 main 이 2(입력 오류)로 끝낸다. 열기는 O_NOFOLLOW·dir_fd 가 없는 플랫폼(Windows)에서
#       경로 조각마다 lstat 으로 링크를 거른 뒤 연다.
# 수정(0.3.0): 증적 형식 4. 구현 검증(pqproof impl, params.mode impl) 증적은 두 트리 칸(inputs·cbom·java·tls 등) 대신 최상위 impl 칸
#       (답안 사본·정답 묶음 사본·문제지 사본, 받아 줄 판, 자기 점검, 파라미터별 결과)과 검사 i-kpqc 하나를 가진다(SCHEMA_IMPL).
#       verify 는 정답 묶음 사본으로 답안 사본을 다시 판정해 결과·검사 행이 같은지 보고(impl_record), 지금 도구의 KAT 목록이 그 증적과
#       같으면 정답 묶음·문제지를 다시 만들어 바이트까지 맞춘다. 두 트리·한 트리 증적은 형식 3과 같은 꼴이다. 형식 1~3을 계속 읽는다.
#       pq-verify 다리(검사 i-nist): impl.nist 에 pq-verify 실행(argv·종료 코드)과 보고서 요약·상태를 적고, 보고서(artifacts/impl/pq-verify/
#       report.json)와 실행 기록(log.json)을 산출물로 둔다. consistency 는 요약으로 상태를 다시 정하고, verify 는 보고서·실행 기록 사본으로
#       요약부터 다시 뽑아 맞춘다. 답안 없이 pq-verify 만 돌린 증적은 impl.input·key 가 null 이고 i-kpqc 가 해당 없음이다.
# 수정: 축소판. RFC 8785 정규화(_number·_jcs·canonical)·compute_id·validate·obj·strict·iso·_Artifacts·_read_nofollow·
#       _hash_refs·_listed_files·verify 뼈대·STYLE·SCRIPT(테마 토글)는 가져오고, microVM 증적용 build·_sandbox·_network·
#       _proofs·_steps·POLICY·consistency·SCHEMA·render_html은 이 오프라인판용으로 새로 썼다. loop._open_nofollow도 옮겨 왔다.
"""한 번 돌린 prove.sh의 검증 증적: receipt.json, receipt.html, 그리고 그것이 이름 붙인 파일들.

    receipt.json     무엇을 어떤 도구(경로·sha256)로 쟀고 판정이 무엇인지
    receipt.html     같은 내용의 자가완결 페이지(외부 참조 0, 기본 다크·라이트 토글)
    artifacts/       CBOM 원문(cbom-scan md·csv, scan.py json), residue 출력, tls_probe·s_client 원문, 약화 수정 결과
    tables/          CSV, 마크다운 표(report.md), HTML 조각
    in/              zip 입력을 푼 트리(inputs.*.tree_sha256로 확인)

receipt.json은 모든 산출물을 바이트 수와 SHA-256으로 적고, 파일을 가리키는 칸(X)마다 X_sha256 짝이 있다.
receipt_id는 receipt_id 칸을 뺀 receipt.json의 JSON 정규형(RFC 8785: 키 정렬, 공백 없음, UTF-8, 숫자는 ECMAScript 표기)
SHA-256이다. `python3 -I -B pqlite/receipt.py verify OUT`(또는 prove.sh --verify OUT)가 전부 다시 계산한다.

이것은 해시 묶음이지 누가 만들었는지의 증명이 아니다. 누구든 파일을 바꾸고 해시를 새로 쓸 수 있다. receipt_id는 믿을 수 있는
곳(실행 출력, 제출 목록)에서 받은 값과 비교할 때만 의미가 있다.
"""
import base64
import hashlib
import html
import json
import os
import posixpath
import re
import stat
import sys
import time

FORMAT = "pqc-proof receipt 1"
NOTE = ("검증 증적: receipt_id는 receipt_id 칸을 뺀 이 JSON의 RFC 8785 정규형(키 정렬, 공백 없음, UTF-8) SHA-256이고, "
        "artifacts·tables의 모든 파일과 evidence-fragment.json이 SHA-256과 함께 적혀 있다. `pqproof --verify DIR`(또는 "
        "`bash prove.sh --verify DIR`)이 다시 계산한다. 해시는 파일이 이 증적이 말하는 그 파일임을 보일 뿐, 누가 만들었는지는 "
        "보이지 않는다. receipt_id를 믿을 수 있는 곳에서 받은 값과 비교할 것.")
# 형식 2(0.1.x)와 형식 1 의 둘째 공개본이 쓰던 NOTE. --verify 는 이 글을 계속 받고 receipt.html 을 그 판의 낱말로 다시 그린다
NOTE_V2 = ("검증 증적: receipt_id는 receipt_id 칸을 뺀 이 JSON의 RFC 8785 정규형(키 정렬, 공백 없음, UTF-8) SHA-256이고, "
           "artifacts·tables의 모든 파일과 evidence-fragment.json이 SHA-256과 함께 적혀 있다. `bash prove.sh --verify DIR`이 다시 계산한다. "
           "해시는 파일이 이 증적이 말하는 그 파일임을 보일 뿐, 누가 만들었는지는 보이지 않는다. "
           "receipt_id를 믿을 수 있는 곳에서 받은 값과 비교할 것.")
# 형식 1(format_version 칸 없음) 증적이 쓰던 NOTE. 첫 공개본(2026-11-17)은 '영수증'이라고 적었다.
# --verify 는 이 글을 계속 받고, receipt.html 은 그 판의 낱말로 다시 그린다(LEGACY_WORDS)
NOTE_PUBLIC1 = ("해시 영수증: receipt_id는 receipt_id 칸을 뺀 이 JSON의 RFC 8785 정규형(키 정렬, 공백 없음, UTF-8) SHA-256이고, "
                "artifacts와 tables의 모든 파일이 SHA-256과 함께 적혀 있다. `bash prove.sh --verify DIR`이 다시 계산한다. "
                "해시는 파일이 이 영수증이 말하는 그 파일임을 보일 뿐, 누가 만들었는지는 보이지 않는다. "
                "receipt_id를 믿을 수 있는 곳에서 받은 값과 비교할 것.")
LEGACY_NOTES = {NOTE_PUBLIC1: "public-1"}
MAX_ARTIFACT = 64 << 20
_SEGMENT = r"(?!\.\.?(?:/|$))[A-Za-z0-9_.-]{1,120}"  # . 이나 .. 은 안 된다: 경로가 증적 폴더 안에 머문다
ARTIFACT_PATH = re.compile(rf"(?:artifacts|tables)/{_SEGMENT}(?:/{_SEGMENT}){{0,4}}|evidence-fragment\.json")
STATUS = ["pass", "fail", "undecided", "na", "review", "check"]
# 증적 형식 1·2 의 트리 목록이 건너뛴 폴더(이름이 같으면 어느 깊이든). --verify 가 옛 증적의 in/ 트리를 이 목록으로 다시 잰다.
# 형식 3부터는 scan/skip-dirs 규칙(pqlite/skipdirs.py, 증적의 skip_dirs 사본)으로 잰다(교차 리뷰 X03·X09)
LEGACY_TREE_SKIP_DIRS = frozenset({".git", "node_modules", "target", "build", "__pycache__", ".gradle", ".idea", "__MACOSX", ".venv",
                                   "venv"})
TREE_SKIP_FILES = {".DS_Store"}
LEGACY = "legacy"  # tree_files(root, LEGACY): 형식 1·2 의 걷기

# ---------------------------------------------------------------------------------------------
# validate()가 아는 JSON Schema 부분집합: type, const, enum, pattern, minimum, required, properties,
# additionalProperties, items, minItems.
SHA = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
SHA_OR_NULL = {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"}
TIME = {"type": "string", "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"}
PATH = {"type": "string", "pattern": "^(?:" + ARTIFACT_PATH.pattern + ")$"}
PATH_OR_NULL = dict(PATH, type=["string", "null"])
STR, INT, BOOL = {"type": "string"}, {"type": "integer", "minimum": 0}, {"type": "boolean"}
INT_OR_NULL = {"type": ["integer", "null"]}
STR_OR_NULL = {"type": ["string", "null"]}
STRS = {"type": "array", "items": STR}
ANY_OBJ = {"type": "object"}


def obj(required, **props):
    """정확히 이 속성만 갖는 객체 스키마. 따로 적지 않으면 전부 필수."""
    return {"type": "object", "additionalProperties": False, "required": sorted(required), "properties": props}


def strict(**props):
    return obj(props, **props)


INPUT = obj(["path", "kind", "zip_sha256", "root", "files", "tree_sha256", "skipped"],
            path=STR, kind={"enum": ["dir", "zip"]}, zip_sha256=SHA_OR_NULL, root=STR, files=INT, tree_sha256=SHA, skipped=STRS,
            oversize=STRS)
TOOL = strict(name=STR, path=STR, sha256=SHA_OR_NULL, version=STR)
CHECK = strict(id=STR, title=STR, status={"enum": STATUS}, expected=STR, actual=STR)
_CBOM_REQ = ["rows", "locations", "blocking", "allowed", "comment_or_test", "check", "info", "cbom_scan_ok", "csv", "csv_sha256"]
# out_of_scope(SCOPE=kex의 '범위 밖' 위치 수)와 params.scope는 나중에 보탰다. 그 전 증적도 읽히게 필수로 두지 않는다.
# review(허용 목록의 쓰기 경로 줄 수)도 나중에 보탰다(필수 아님).
# tests(주석·테스트 중 시험·예제 경로 위치 수)는 결함 D2 뒤에 보탰다(필수 아님).
CBOM_SIDE = obj(_CBOM_REQ, rows=INT, locations=INT, blocking=INT, allowed=INT, comment_or_test=INT, check=INT, info=INT,
                out_of_scope=INT, review=INT, tests=INT, unresolved=INT, cbom_scan_ok=BOOL, csv=PATH, csv_sha256=SHA)
JAVA_SIDE = {"type": ["object", "null"], "additionalProperties": False,
             "required": ["families", "expect", "weak_pqc", "legacy_write", "sites_left", "verdict", "output", "output_sha256"],
             "properties": {"families": {"type": "object",
                                         "additionalProperties": obj(["code", "allow", "comment"], code=INT, allow=INT, comment=INT,
                                                                     test=INT)},
                            "expect": {"type": "object", "additionalProperties": INT}, "weak_pqc": INT, "legacy_write": INT,
                            "sites_left": INT_OR_NULL, "verdict": STR, "output": PATH, "output_sha256": SHA,
                            "listed": {"type": ["object", "null"]}, "tests": strict(count=INT, lines=STRS)}}
HS = {"type": ["object", "null"]}
ALLOW_STATUS = ["allowed", "review", "unused", "invalid", "excluded", "outside"]
# reviewed_by·reviewed_at·reviewed_via(사람 확인 칸과 그 출처), digest(항목 글 해시), unreviewed(확인 전 허용 항목 수),
# top_digest(목록 맨 위 칸이 덮는 항목들의 지금 해시)는 나중에 보탰다. 그 전 증적도 읽히게 필수로 두지 않는다.
REVIEW_AT = {"type": ["string", "null"], "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}"}
DIGEST16 = {"type": ["string", "null"], "pattern": "^[0-9a-f]{16}$"}
# lines_fixed(고친 판에서 덮은 고전 줄 수), lines_orig·orig(같은 목록을 원본 트리로 풀었을 때 덮는 고전 줄), 목록의 unused(고친 판에서
# 안 쓰인 항목 수)·unused_orig_lines(그 항목들이 원본에서 덮는 줄 수)·write_review(허용 범위 쓰기 경로 위치 수)는 결함 D1 뒤에 보탰다.
ALLOW_ENTRY = obj(["n", "where", "what", "why", "kind", "targets", "status", "note", "allowed", "review"],
                  n=INT, where=STR, what=STR, why=STR, kind=STR, targets=STRS, status={"enum": ALLOW_STATUS}, note=STR,
                  allowed=STRS, review=STRS, reviewed_by=STR_OR_NULL, reviewed_at=REVIEW_AT,
                  reviewed_via={"enum": ["entry", "top", None]}, digest=DIGEST16, lines_fixed=INT, lines_orig=INT, orig=STRS,
                  expires_at={"type": ["string", "null"], "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"}, approval_ref=STR_OR_NULL, expired=BOOL)
ALLOWLIST = obj(["source", "auto", "file", "file_sha256", "entries", "warnings", "hybrid", "legacy", "imports"],
                source=STR_OR_NULL, auto=BOOL, file=PATH_OR_NULL, file_sha256=SHA_OR_NULL,
                entries={"type": "array", "items": ALLOW_ENTRY}, warnings=STRS, unreviewed=INT, top_digest=DIGEST16,
                hybrid=STRS, legacy=STRS, imports=STRS, unused=INT, unused_orig_lines=INT, write_review=INT, composite=STRS, expired=INT)
EXCLUDED = strict(items={"type": "array", "items": strict(pattern=STR, **{"from": STR}, why=STR)}, notes=STRS, app_roots=STRS,
                  recon_file=STR_OR_NULL, recon_digest=SHA_OR_NULL, count_orig=INT, count_fixed=INT, files_orig=STRS,
                  files_fixed=STRS)
DECK_META = strict(receipt_file=STR, verify_cmd=STR, ev=STR)
_TOP_REQ = ["format", "receipt_id", "note", "verdict", "started_at", "finished_at", "inputs", "tools", "params", "changed", "cbom",
            "java", "tls", "weakening", "checks", "timeline", "extra", "artifacts"]
# allowlist·excluded·deck_meta·params.allow·exclude·recon·require_review는 나중에 보탰다. 그 전 증적도 읽히게 필수로 두지 않는다.
# format_version·tool_version·ruleset_version·ruleset_sha256 은 증적 형식 2(0.1.0)에서 보탰다. 형식 2에서는 꼭 있어야 한다
# (version_problems). 옛 NOTE 는 형식 1 증적에만 받는다.
SCHEMA = obj(_TOP_REQ,
    format={"const": FORMAT}, receipt_id=SHA, note={"enum": [NOTE, NOTE_V2, NOTE_PUBLIC1]},
    verdict={"enum": ["pass", "fail", "undecided"]},
    format_version={"type": "integer", "minimum": 2}, tool_version={"type": "string", "pattern": r"^[0-9][0-9A-Za-z.+-]*$"},
    ruleset_version={"type": "string", "pattern": r"^[0-9A-Za-z][0-9A-Za-z.+-]*$"}, ruleset_sha256=SHA,
    started_at=TIME, finished_at=TIME,
    inputs=strict(orig=INPUT, fixed=INPUT),
    tools={"type": "array", "minItems": 1, "items": TOOL},
    params=obj(["classic", "expect", "tls_via", "tls_targets", "tls_targets_orig", "residue"],
               classic={"enum": ["allow", "deny"]}, expect=STRS, scope={"enum": ["all", "kex"]}, tls_via=STR, tls_targets=STRS,
               tls_targets_orig=STRS, residue=STR, allow=STR, exclude=STRS, recon=STR, require_review=BOOL, profile=STR,
               fail_on_review=BOOL, require_resolved=BOOL, expect_from={"enum": ["names", "api"]}, review_max_age_days=INT_OR_NULL,
               max_file_bytes=INT, mode={"enum": ["pair", "check"]}),
    changed=strict(added=STRS, removed=STRS, modified=STRS, file=PATH, file_sha256=SHA),
    cbom=strict(orig=CBOM_SIDE, fixed=CBOM_SIDE),
    java=strict(residue_kind={"enum": ["custom", "generic", "none"]}, script=PATH_OR_NULL, script_sha256=SHA_OR_NULL,
                ref=STR_OR_NULL, ref_digest=SHA_OR_NULL, orig=JAVA_SIDE, fixed=JAVA_SIDE, usage=PATH, usage_sha256=SHA),
    tls=obj(["signals", "client_signals", "applicable", "via", "controls", "control_problem", "targets", "baseline", "log", "log_sha256"],
            signals=STRS, client_signals=STRS, applicable=BOOL, via=STR,
               controls={"type": ["object", "null"]}, control_problem=STR_OR_NULL,
               targets={"type": "array", "items": ANY_OBJ}, baseline={"type": "array", "items": ANY_OBJ},
               log=PATH_OR_NULL, log_sha256=SHA_OR_NULL, probe_build={"enum": ["release", "local", "unchecked", None]}),
    weakening=strict(deny=STRS, review={"type": "array", "items": strict(path=STR, rule=STR, before=INT, after=INT,
                                                                           detail=STR, reason=STR)},
                     file=PATH, file_sha256=SHA),
    checks={"type": "array", "minItems": 1, "items": CHECK},
    timeline={"type": "array", "items": strict(name=STR, started_at=TIME, ended_at=TIME)},
    extra={"type": "array", "items": strict(source=STR, path=PATH, path_sha256=SHA)},
    artifacts={"type": "array", "minItems": 1, "items": strict(path=PATH, bytes=INT, sha256=SHA)},
    allowlist=ALLOWLIST, excluded=EXCLUDED, deck_meta=DECK_META, test_paths=strict(file=PATH, file_sha256=SHA),
    skip_dirs=strict(file=PATH, file_sha256=SHA),
)
# 구현 검증 증적(형식 4, params.mode impl). 두 트리 증적과 칸이 달라 따로 읽는다(verify 가 params.mode 로 고른다)
IMPL_STATUS = ["pass", "fail", "undecided", "review"]
IMPL_VERSION = strict(version=STR, role={"enum": ["reference", "known-variant"]}, latest=BOOL, accepted=BOOL, checked=INT, ok=INT,
                      records=STR_OR_NULL, first_mismatch=STR_OR_NULL)
IMPL_RESULT = strict(param=STR, name=STR, status={"enum": IMPL_STATUS}, summary=STR, matched=STRS,
                     versions={"type": "array", "items": IMPL_VERSION})
IMPL_PROMPT = dict(strict(file=PATH, file_sha256=SHA, prompt_sha256=SHA, items=INT), type=["object", "null"])
BOOL_OR_NULL = {"type": ["boolean", "null"]}
# pq-verify 보고서에서 판정에 쓰는 칸(pqlite/impl.py pqverify_summary, SUMMARY_KEYS)
IMPL_PQV_SUMMARY = strict(audit=STR_OR_NULL, problem=STR_OR_NULL, exit_code=INT_OR_NULL, schema=STR_OR_NULL, schema_version=STR_OR_NULL,
                          tool_version=STR_OR_NULL, status=STR_OR_NULL, verified=BOOL_OR_NULL, bound=BOOL_OR_NULL,
                          artifact_sha256=STR_OR_NULL, library_sha256=SHA_OR_NULL, target=STR_OR_NULL, param_set=STR_OR_NULL,
                          checks_passed=INT_OR_NULL, checks_total=INT_OR_NULL, findings=INT_OR_NULL, failed=STRS, missing=STRS,
                          scope=STR_OR_NULL, scope_complete=BOOL_OR_NULL, degraded=BOOL, unavailable=STRS)
IMPL_NIST = dict(strict(engine={"const": "pq-verify"}, args=STRS, argv={"type": ["array", "null"], "items": STR}, executable=STR_OR_NULL,
                        env_removed=STRS, timeout=INT, exit_code=INT_OR_NULL, not_run=STR_OR_NULL,
                        library=strict(path=STR, sha256=SHA_OR_NULL), report=PATH_OR_NULL, report_sha256=SHA_OR_NULL, log=PATH,
                        log_sha256=SHA, summary=IMPL_PQV_SUMMARY, status={"enum": ["pass", "fail", "undecided"]}, detail=STR),
                 type=["object", "null"])
IMPL = strict(engine={"const": "kpqc-kat"}, kat_manifest_sha256=SHA,
              input=dict(strict(path=STR, kind={"enum": ["response", "rsp", None]}, bytes=INT, sha256=SHA, file=PATH_OR_NULL,
                                file_sha256=SHA_OR_NULL, implementation=STR_OR_NULL, header=STR_OR_NULL), type=["object", "null"]),
              prompt=IMPL_PROMPT, key=dict(strict(file=PATH, file_sha256=SHA, params=INT), type=["object", "null"]), accept=STRS,
              control=strict(ok=BOOL, problem=STR_OR_NULL), problem=STR_OR_NULL, results={"type": "array", "items": IMPL_RESULT},
              nist=IMPL_NIST)
_IMPL_REQ = ["format", "format_version", "tool_version", "ruleset_version", "ruleset_sha256", "receipt_id", "note", "verdict",
             "started_at", "finished_at", "tools", "params", "impl", "checks", "timeline", "artifacts", "deck_meta"]
SCHEMA_IMPL = obj(_IMPL_REQ,
    format={"const": FORMAT}, format_version={"type": "integer", "minimum": 4}, tool_version=SCHEMA["properties"]["tool_version"],
    ruleset_version=SCHEMA["properties"]["ruleset_version"], ruleset_sha256=SHA, receipt_id=SHA, note={"const": NOTE},
    verdict={"enum": ["pass", "fail", "undecided"]}, started_at=TIME, finished_at=TIME,
    tools={"type": "array", "minItems": 1, "items": TOOL},
    params=strict(mode={"const": "impl"}, profile=STR, params=STRS, input={"enum": ["response", "rsp", None]}, fail_on_review=BOOL),
    impl=IMPL, checks={"type": "array", "minItems": 1, "items": CHECK},
    timeline={"type": "array", "items": strict(name=STR, started_at=TIME, ended_at=TIME)},
    artifacts={"type": "array", "minItems": 1, "items": strict(path=PATH, bytes=INT, sha256=SHA)}, deck_meta=DECK_META,
)
IMPL_SINCE = 4  # params.mode impl 이 생긴 형식


def is_impl(r):
    """구현 검증 증적인가(params.mode 가 impl)."""
    return isinstance(r, dict) and isinstance(r.get("params"), dict) and r["params"].get("mode") == "impl"


# 형식마다 꼭 있어야 하는 칸과 있으면 안 되는 칸(스키마는 모든 형식을 한 번에 읽는다). skip_dirs 는 형식 3에서 보탰다(두 트리·한 트리 증적만)
FORMAT_ONLY = {"skip_dirs": 3}
# 형식 3에서 보탠 안쪽 칸(선택). 형식 2 스키마(schemas/receipt-v2.schema.json)에는 없다: tests/make_schemas.py 가 뺀다
FORMAT_ONLY_NESTED = {("tls", "probe_build"): 3, ("params", "profile"): 3, ("params", "mode"): 3, ("params", "fail_on_review"): 3, ("params", "require_resolved"): 3,
                      ("params", "expect_from"): 3, ("params", "review_max_age_days"): 3, ("params", "max_file_bytes"): 3,
                      ("allowlist", "composite"): 3, ("allowlist", "expired"): 3, ("allowlist", "entries[]", "expires_at"): 3,
                      ("allowlist", "entries[]", "approval_ref"): 3, ("allowlist", "entries[]", "expired"): 3,
                      ("cbom", "orig", "unresolved"): 3, ("cbom", "fixed", "unresolved"): 3, ("inputs", "orig", "oversize"): 3,
                      ("inputs", "fixed", "oversize"): 3}

TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict,
         "null": type(None)}


def _is(value, name):
    if name in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, TYPES[name])


def validate(value, schema, where="receipt"):
    """value가 schema를 어기는 곳마다 "where: 문제" 한 줄(맞으면 [])."""
    out = []
    if "const" in schema and value != schema["const"]:
        return [f"{where}: must be {schema['const']!r}"]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{where}: must be one of {schema['enum']}"]
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is(value, n) for n in names):
            return [f"{where}: must be {' or '.join(names)}, not {type(value).__name__}"]
    if isinstance(value, str) and "pattern" in schema and not re.search(schema["pattern"], value):
        out.append(f"{where}: does not match {schema['pattern']}")
    if _is(value, "number") and "minimum" in schema and value < schema["minimum"]:
        out.append(f"{where}: below {schema['minimum']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            out.append(f"{where}: needs at least {schema['minItems']} items")
        if "items" in schema:
            for i, item in enumerate(value):
                out += validate(item, schema["items"], f"{where}[{i}]")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                out.append(f"{where}: missing {key}")
        props, extra = schema.get("properties", {}), schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in props:
                out += validate(item, props[key], f"{where}.{key}")
            elif extra is False:
                out.append(f"{where}: unexpected field {key}")
            elif isinstance(extra, dict):
                out += validate(item, extra, f"{where}.{key}")
    return out


# ---------------------------------------------------------------------------------------------
MAX_EXACT_INT = 1 << 53  # IEEE 754 double 이 정확히 나타내는 정수의 끝(I-JSON, RFC 7493 2.2)


def _number(x):
    """ECMAScript Number::toString 표기(RFC 8785, 3.2.2.3). 절댓값 2^53 을 넘는 정수는 다른 언어 검증기가 double 로 읽어 값이
    바뀌므로 거부한다."""
    if isinstance(x, int):
        if abs(x) > MAX_EXACT_INT:
            raise ValueError(f"integer {x} is beyond 2^53: RFC 8785 verifiers read it as a double and get another value")
        return str(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("NaN and infinity have no JSON form")
    if x == 0:
        return "0"
    m = re.fullmatch(r"(-?)([0-9]+)(?:\.([0-9]+))?(?:e([-+][0-9]+))?", repr(x))  # repr: the shortest round trip
    sign, whole, frac = m[1], m[2], m[3] or ""
    digits = (whole + frac).lstrip("0")
    n = len(whole) + int(m[4] or 0) - (len(whole + frac) - len(digits))  # value = 0.DIGITS x 10^n
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + digits
    else:
        e = n - 1
        out = (digits[0] + ("." + digits[1:] if k > 1 else "")) + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return sign + out


def _jcs(value):
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))  # RFC 8785 3.2.3: UTF-16 코드 단위 순서
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(value[k]) for k in keys) + "}"
    raise TypeError(f"{type(value).__name__} has no JSON form")


def canonical(value):
    """value의 JSON 정규형(RFC 8785) UTF-8 바이트. 키는 UTF-16 코드 단위 순서로 정렬한다(BMP 안 문자만 쓴 키는 코드 포인트 순서와 같다.
    지금 증적의 키는 모두 ASCII 다). 절댓값 2^53 을 넘는 정수는 ValueError."""
    return _jcs(value).encode("utf-8")


def dumps(receipt):
    """receipt.json 을 쓰는 단 하나의 꼴(prove.py 가 쓰고 verify 가 바이트로 맞춰 본다)."""
    return json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _unique_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}: parsers that keep the first value and parsers that keep the last see "
                             "different evidence")
        out[key] = value
    return out


def _no_constant(name):
    raise ValueError(f"{name} is not a JSON number (RFC 8259)")


def loads_strict(data):
    """증적 JSON 바이트를 엄격하게 읽는다: UTF-8(BOM 없음), 중복 키·NaN·Infinity 거부, 값 뒤에 다른 바이트가 오면 거부(json 이 막는다).
    너무 깊게 겹친 값(RecursionError)도 traceback 대신 ValueError 로 알린다."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("starts with a UTF-8 byte order mark")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys, parse_constant=_no_constant)
    except RecursionError:
        raise ValueError("values are nested too deeply to read") from None


def compute_id(receipt):
    return hashlib.sha256(canonical({k: v for k, v in receipt.items() if k != "receipt_id"})).hexdigest()


def iso(t):
    """밀리초까지의 UTC 시각(스키마 꼴). None은 None."""
    if t is None:
        return None
    ms = int(float(t) * 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms // 1000)) + f".{ms % 1000:03d}Z"


NOFOLLOW_FD = all(hasattr(os, n) for n in ("O_NOFOLLOW", "O_DIRECTORY")) and os.open in os.supports_dir_fd
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _open_checked(root, rel, flags):
    """O_NOFOLLOW·dir_fd 가 없는 플랫폼(Windows)용: 경로 조각마다 lstat 으로 링크·재분석 지점을 거른 뒤 연다. 거른 뒤 여는 사이에
    바뀌는 경쟁은 막지 못한다(재검증만 하는 쪽이라 받아들인다). fd를 돌려준다."""
    cur = root
    for part in rel.split("/"):
        cur = os.path.join(cur, part)
        st = os.lstat(cur)
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
            raise OSError(f"{rel}: a link inside the receipt directory")
    return os.open(cur, (flags & ~getattr(os, "O_NONBLOCK", 0)) | getattr(os, "O_BINARY", 0))


def _open_nofollow(root, rel, flags):
    """root/rel을 어느 단계에서도 심볼릭 링크를 따라가지 않고 연다(from pq-proof loop.py). fd를 돌려준다."""
    if not NOFOLLOW_FD:
        return _open_checked(root, rel, flags)
    parts = rel.split("/")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return os.open(parts[-1], flags | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)


def _read_nofollow(root, rel, limit=MAX_ARTIFACT):
    if any(part in ("", ".", "..") for part in rel.split("/")):
        raise ValueError(f"{rel}: not a plain path inside the receipt")
    fd = _open_nofollow(os.path.realpath(root), rel, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{rel} is not a regular file")
        if st.st_size > limit:
            raise ValueError(f"{rel} is larger than {limit} bytes")
        return f.read(limit + 1)


class Artifacts:
    """OUT 아래 artifacts/·tables/에 파일을 쓰고 목록을 지킨다(from pq-proof _Artifacts). register는 다른 도구가 이미 쓴 파일을 올린다."""

    def __init__(self, out):
        self.out, self.items = out, {}

    def _check(self, path):
        if not ARTIFACT_PATH.fullmatch(path) or ".." in path.split("/"):
            raise ValueError(f"bad artifact path {path!r}")

    def add(self, path, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._check(path)
        if path in self.items:
            raise ValueError(f"artifact written twice: {path}")
        full = os.path.join(self.out, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "xb") as f:
            f.write(data)
        digest = hashlib.sha256(data).hexdigest()
        self.items[path] = {"path": path, "bytes": len(data), "sha256": digest}
        return path, digest

    def add_json(self, path, value):
        return self.add(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    def register(self, path):
        self._check(path)
        data = _read_nofollow(self.out, path)
        digest = hashlib.sha256(data).hexdigest()
        self.items[path] = {"path": path, "bytes": len(data), "sha256": digest}
        return path, digest

    def register_dir(self, rel_dir):
        """rel_dir(예 artifacts/tls) 아래 일반 파일을 전부 올린다. 이름이 규칙에 안 맞는 파일은 오류."""
        base = os.path.join(self.out, *rel_dir.split("/"))
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            for name in sorted(filenames):
                rel = os.path.relpath(os.path.join(dirpath, name), self.out).replace(os.sep, "/")
                if rel not in self.items:
                    self.register(rel)

    def manifest(self):
        return [self.items[k] for k in sorted(self.items)]


# ---------------------------------------------------------------------------------------------
def tree_files(root, rules=None, skipped=None):
    """root 아래 파일 목록 [(상대 경로, sha256 또는 'symlink:<대상>', 바이트)]. 링크는 따라가지 않는다.
    rules: pqlite/skipdirs.Rules(증적 형식 3, 비우면 scan/skip-dirs). LEGACY 면 형식 1·2 의 걷기(LEGACY_TREE_SKIP_DIRS 이름은 어느
    깊이든 건너뜀). skipped: 리스트를 주면 건너뛴 폴더 (상대 경로, 종류)를 채운다(형식 3 걷기만)."""
    if rules == LEGACY:
        return _tree_files_legacy(root)
    sk = _skipdirs_module()
    entries, skips = sk.walk(root, rules or sk.load())
    if skipped is not None:
        skipped.extend(skips)
    out = []
    for rel, full, kind in entries:
        if kind == "link":
            out.append((rel, "symlink:" + os.readlink(full), 0))
        elif kind == "file":
            st = os.lstat(full)
            if stat.S_ISREG(st.st_mode):
                out.append((rel, _sha256_path(full), st.st_size))
    return sorted(out)


def _sha256_path(full):
    h = hashlib.sha256()
    with open(full, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _tree_files_legacy(root):
    """증적 형식 1·2 의 트리 목록: LEGACY_TREE_SKIP_DIRS 이름 폴더는 어느 깊이든 건너뛴다."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            if d in LEGACY_TREE_SKIP_DIRS:
                continue
            if os.path.islink(full):
                out.append((os.path.relpath(full, root).replace(os.sep, "/"), "symlink:" + os.readlink(full), 0))
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            if name in TREE_SKIP_FILES:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                out.append((rel, "symlink:" + os.readlink(full), 0))
            elif stat.S_ISREG(st.st_mode):
                out.append((rel, _sha256_path(full), st.st_size))
    return sorted(out)


def tree_sha256(files):
    h = hashlib.sha256()
    for rel, digest, _ in files:
        h.update(rel.encode("utf-8") + b"\0" + digest.encode() + b"\n")
    return h.hexdigest()


def _hash_refs(value, where="receipt"):
    """증적 안의 {X: 경로, X_sha256: 해시} 짝마다 (where, 경로, sha256)."""
    out = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key + "_sha256" in value and isinstance(item, str):
                out.append((f"{where}.{key}", item, value[key + "_sha256"]))
            out += _hash_refs(item, f"{where}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            out += _hash_refs(item, f"{where}[{i}]")
    return out


def _listed_files(root):
    """root 아래 모든 파일과 링크(링크는 따라가지 않음). receipt.json·receipt.html과 in/(트리 해시로 따로 확인)은 뺀다."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if os.path.relpath(dirpath, root) == ".":
            dirnames[:] = [d for d in dirnames if d != "in"]
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isdir(full):
                out.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return sorted(p for p in out if p not in ("receipt.json", "receipt.html", "deck.json", "README.txt"))


def derive_verdict(checks):
    statuses = [c["status"] for c in checks]
    if "fail" in statuses:
        return "fail"
    if "undecided" in statuses:
        return "undecided"
    return "pass"


def consistency(r):
    """요약 칸이 그 아래 기록과 어긋나는 곳([] 이면 맞다). 판정은 검사 칸에서, 검사 칸은 숫자에서 나와야 한다."""
    if is_impl(r):
        return _impl_consistency(r)
    out = []
    want = derive_verdict(r["checks"])
    if r["verdict"] != want:
        out.append(f"verdict is {r['verdict']!r}, but the checks give {want!r}")
    ids = [c["id"] for c in r["checks"]]
    if len(ids) != len(set(ids)):
        out.append("check ids repeat")
    by = {c["id"]: c["status"] for c in r["checks"]}
    fixed = r["cbom"]["fixed"]
    resolved_fail = bool(r["params"].get("require_resolved")) and bool(fixed.get("unresolved")) and fixed["blocking"] == 0
    if "a-cbom" in by and by["a-cbom"] != "undecided":
        if (by["a-cbom"] == "fail") != (fixed["blocking"] > 0 or not fixed["cbom_scan_ok"] or resolved_fail):
            out.append(f"a-cbom is {by['a-cbom']}, but cbom.fixed.blocking is {fixed['blocking']}"
                       + (f" and {fixed.get('unresolved')} unresolved locations with require_resolved" if resolved_fail else ""))
        if by["a-cbom"] == "review" and not fixed.get("review"):
            out.append("a-cbom is review, but cbom.fixed.review is 0")
    if format_version(r) >= 2 and "r-review" in by and (by["r-review"] == "review") != bool(r["weakening"]["review"]):
        out.append(f"r-review is {by['r-review']}, but weakening.review has {len(r['weakening']['review'])} items")
    single = r["params"].get("mode") == "check"  # 형식 3 한 트리 점검: 두 트리 대조 검사는 해당 없음
    if single and (by.get("b-weakening"), by.get("r-review")) != ("na", "na"):
        out.append("params.mode is check, but b-weakening or r-review is not na")
    if not single and "b-weakening" in by and (by["b-weakening"] == "pass") != (not r["weakening"]["deny"]):
        out.append(f"b-weakening is {by['b-weakening']}, but weakening.deny has {len(r['weakening']['deny'])} items")
    if "b-tls" in by:
        # review: 서버 신호 0인데 클라이언트 TLS 신호가 있다(prove.py, 반박 검증에서 찾음)
        if not r["tls"]["applicable"] and by["b-tls"] not in ("na", "undecided", "review"):
            out.append(f"b-tls is {by['b-tls']}, but TLS is not applicable")
        if r["tls"]["targets"] and by["b-tls"] == "pass" and not all(t.get("ok") for t in r["tls"]["targets"]):
            out.append("b-tls is pass, but a target failed")
    jf = r["java"]["fixed"]
    if by.get("c-classic") == "na" and r["params"].get("scope") != "kex":
        out.append("c-classic is na, but params.scope is not kex")
    if "c-classic" in by and jf is not None and by["c-classic"] not in ("undecided", "na"):
        lst = jf.get("listed") or {}
        left = (sum(v["code"] for k, v in jf["families"].items()) + lst.get("relisted", 0) - lst.get("allowed", 0) - lst.get("hybrid", 0)
                - lst.get("review", 0))
        sites = lst.get("sites_left", jf["sites_left"])
        if (by["c-classic"] in ("pass", "review")) != (left == 0 and jf["weak_pqc"] == 0 and jf["legacy_write"] == 0
                                                       and not sites):
            out.append(f"c-classic is {by['c-classic']}, but residue counts {left} classical lines")
        if by["c-classic"] == "review" and not lst.get("review") and not lst.get("composite"):
            out.append("c-classic is review, but no allow-list line or composite signature needs review")
    a = r.get("allowlist") or {}
    if "unreviewed" not in a and "r-allow" in by:
        out.append("there is an r-allow check, but allowlist.unreviewed is not recorded")
    if "unreviewed" in a:  # 사람 확인 칸이 있는 증적: 확인 전 수와 r-allow 가 항목 기록과 맞아야 한다
        for e in a["entries"]:
            if "reviewed_via" in e and bool(e["reviewed_via"]) != bool(e.get("reviewed_by") and e.get("reviewed_at")):
                out.append(f"allowlist entry {e['n']}: reviewed_via is {e['reviewed_via']!r}, but reviewed_by and reviewed_at "
                           + ("are missing" if e["reviewed_via"] else "are set"))
        live = [e for e in a["entries"] if e["status"] in ("allowed", "review")]
        n = sum(1 for e in live if not (e.get("reviewed_by") and e.get("reviewed_at")))
        strict_ = bool(r["params"].get("require_review"))
        if a["unreviewed"] != n:
            out.append(f"allowlist.unreviewed is {a['unreviewed']}, but {n} allowing entries have no reviewed_by and reviewed_at")
        unused = [e for e in a["entries"] if _counts_unused(e)]
        u = len(unused) if "unused" in a else 0  # 안 쓰인 항목 칸이 없는 옛 증적은 예전 식 그대로
        nm = len(a.get("legacy") or []) if format_version(r) >= 3 else 0  # 형식 3: 이름 규칙으로만 허용한 곳도 r-allow 가 본다
        ex = [e for e in live if e.get("expired")] if format_version(r) >= 3 else []  # 형식 3: 만료된 허용 항목(교차 리뷰 X31)
        if format_version(r) >= 3:
            day = r["started_at"][:10]
            for e in a["entries"]:
                if bool(e.get("expired")) != bool(e.get("expires_at") and e["expires_at"] < day):
                    out.append(f"allowlist entry {e['n']}: expired is {e.get('expired')}, but expires_at {e.get('expires_at')} and the run "
                               f"date {day} say otherwise")
            if a.get("expired", 0) != len(ex):
                out.append(f"allowlist.expired is {a.get('expired')}, but {len(ex)} allowing entries are expired")
        want = ("fail" if strict_ else "review") if (n or u or nm or ex) else ("pass" if live else "na")
        if "r-allow" not in by:
            out.append("allowlist.unreviewed is recorded, but there is no r-allow check")
        elif by["r-allow"] != want:
            out.append(f"r-allow is {by['r-allow']}, but {n} of {len(live)} allowing entries are not reviewed"
                       + (f" and {u} entries are unused" if u else "") + (f" and {nm} lines pass on the name rule alone" if nm else "")
                       + (f" and {len(ex)} entries are expired" if ex else "")
                       + (" and require_review is on" if strict_ else ""))
        out += _coverage_problems(a, unused)
    if a and _new_format(r):  # 새 형식인데 결함 D1 뒤 칸이 없다: 칸을 지워 옛 증적처럼 보이게 한 것으로 본다
        missing = [k for k in NEW_ALLOW_KEYS if k not in a]
        if missing:
            out.append(f"this receipt has the newer fields (test_paths or lines_fixed), but allowlist.{', allowlist.'.join(missing)} "
                       "is missing")
    # tools[] 의 residue 해시는 증적에 둔 residue 사본(java.script)의 해시와 같아야 한다. 사본 자체는 _hash_refs 가 맞춰 본다
    res = [t for t in r["tools"] if t.get("name") == "residue"]
    if r["java"]["script"] and res and res[0].get("sha256") != r["java"]["script_sha256"]:
        out.append(f"tools[] lists the residue script as {res[0].get('sha256')}, but java.script_sha256 is "
                   f"{r['java']['script_sha256']}")
    return out


# 결함 D1·D2 뒤 증적의 표시: test_paths 칸, 또는 허용 항목의 lines_fixed. 이런 증적에는 아래 목록 칸이 꼭 있어야 한다
NEW_ALLOW_KEYS = ("unreviewed", "unused", "unused_orig_lines", "write_review")
DEAD_STATUS = ("invalid", "excluded", "outside")


def _new_format(r):
    a = r.get("allowlist") or {}
    return "test_paths" in r or any("lines_fixed" in e for e in a.get("entries", []))


def _counts_unused(e):
    """안 쓰인 항목으로 세는가(allowlist.counts_unused 와 같은 식): status unused, 또는 고친 판에서 무효·제외·트리 밖인데 원본 고전
    줄을 덮는 항목(lines_orig > 0)."""
    return e["status"] == "unused" or (e["status"] in DEAD_STATUS and (e.get("lines_orig") or 0) > 0)


def _coverage_problems(a, unused):
    """항목별 덮은 줄 수·안 쓰인 항목 수·쓰기 경로 수가 항목 기록(allowed·review·orig·status)과 맞는가(결함 D1 뒤 칸만)."""
    out = []
    for e in a["entries"]:
        if "lines_fixed" in e:
            got = len(set(e["allowed"]) | set(e["review"]))
            if e["lines_fixed"] != got:
                out.append(f"allowlist entry {e['n']}: lines_fixed is {e['lines_fixed']}, but it lists {got} allowed or review lines")
            if (e["status"] == "unused") != (e["status"] not in ("invalid", "excluded", "outside") and got == 0):
                out.append(f"allowlist entry {e['n']}: status is {e['status']!r}, but it covers {got} lines in the fixed tree")
        if "lines_orig" in e and len(e.get("orig", [])) < 400 and e["lines_orig"] != len(e.get("orig", [])):
            out.append(f"allowlist entry {e['n']}: lines_orig is {e['lines_orig']}, but it lists {len(e.get('orig', []))} lines")
    if "unused" in a and a["unused"] != len(unused):
        out.append(f"allowlist.unused is {a['unused']}, but {len(unused)} entries count as unused (status unused, or invalid, "
                   "excluded or outside while covering original lines)")
    if "unused_orig_lines" in a:
        got = sum(e.get("lines_orig", 0) for e in unused)
        if a["unused_orig_lines"] != got:
            out.append(f"allowlist.unused_orig_lines is {a['unused_orig_lines']}, but the unused entries cover {got} original lines")
    if "write_review" in a:
        got = len({loc for e in a["entries"] for loc in e["review"]})
        if a["write_review"] != got:
            out.append(f"allowlist.write_review is {a['write_review']}, but the entries list {got} review lines")
    return out


def _impl_consistency(r):
    """구현 검증 증적: 판정이 검사에서, 검사 i-kpqc 가 impl 칸(결과·자기 점검·답안 문제)에서, i-nist 가 impl.nist(pq-verify 요약)에서
    나오는가. 결과마다 상태가 판 기록과 맞는가. 답안 없는 증적(pq-verify 만)은 input·key·prompt·결과가 비어 있어야 한다."""
    out = []
    im = _impl_module()
    want = derive_verdict(r["checks"])
    if r["verdict"] != want:
        out.append(f"verdict is {r['verdict']!r}, but the checks give {want!r}")
    ids = [c["id"] for c in r["checks"]]
    if ids != [im.CHECK_ID, im.NIST_CHECK_ID]:
        out.append(f"an impl receipt has exactly two checks, {im.CHECK_ID} and {im.NIST_CHECK_ID}, in that order (it has {ids})")
    x = r["impl"]
    answered = x["input"] is not None
    if x["control"]["ok"] != (x["control"]["problem"] is None):
        out.append("impl.control.ok does not match impl.control.problem")
    row = im.check_row(x["results"], x["control"]["problem"], x["problem"], answered)
    if r["checks"] and r["checks"][0]["status"] != row["status"]:  # 글은 판마다 다를 수 있다. 상태만 본다(글은 impl_record 가 같은 규칙일 때 맞춘다)
        out.append(f"{im.CHECK_ID} is {r['checks'][0]['status']}, but the impl results, self-check and problem give {row['status']}")
    if x["results"] and [res["param"] for res in x["results"]] != r["params"]["params"]:
        out.append("impl.results do not list the parameters in params.params")
    if x["problem"] and x["results"]:
        out.append("impl.problem is set, but there are results")
    if r["params"]["input"] != (x["input"]["kind"] if answered else None):
        out.append("params.input differs from impl.input.kind")
    if (x["prompt"] is not None) != (answered and x["input"]["kind"] == "response" and not x["problem"]):
        out.append("impl.prompt must be recorded for a response that was judged, and only then")
    if answered != (x["key"] is not None) or (x["key"] is not None and x["key"]["params"] != len(r["params"]["params"])):
        out.append("impl.key must be recorded for an answer, with the number of parameters judged")
    if not answered and (r["params"]["params"] or x["results"] or x["accept"] or x["problem"] or not x["control"]["ok"]):
        out.append("impl.input is null (no answer), but parameters, results, accepted versions, a problem or a self-check are recorded")
    if not answered and x["nist"] is None:
        out.append("an impl receipt with no answer must carry a pq-verify run (impl.nist)")
    kat = [t.get("sha256") for t in r["tools"] if t.get("name") == "kat-kpqc"]
    if kat != [x["kat_manifest_sha256"]]:
        out.append("tools[] does not list the KAT list (kat-kpqc) with impl.kat_manifest_sha256")
    for res in x["results"]:
        acc = {v["version"] for v in res["versions"] if v["accepted"]}
        known = {v["version"] for v in res["versions"]}
        st, m = res["status"], set(res["matched"])
        if not m <= known or (st == "pass" and (not m or not m <= acc)) or (st == "review" and not m) or (st in ("fail", "undecided") and m):
            out.append(f"impl result {res['param']}: status {st} does not fit matched versions {sorted(m)} (accepted {sorted(acc)})")
    out += _nist_consistency(r, im)
    return out


def _nist_consistency(r, im):
    """i-nist 가 impl.nist 의 요약에서 나오는가(pqverify_status 로 다시 정한다), 실행 칸이 요약·tools[] 와 맞는가."""
    out, n = [], r["impl"]["nist"]
    nrow = im.nist_check_row(n)
    if len(r["checks"]) > 1 and r["checks"][1]["status"] != nrow["status"]:
        out.append(f"{im.NIST_CHECK_ID} is {r['checks'][1]['status']}, but impl.nist gives {nrow['status']}")
    pqv = [t for t in r["tools"] if t.get("name") == im.PQV_NAME]
    if n is None:
        if pqv:
            out.append("tools[] lists pq-verify, but no pq-verify run is recorded (impl.nist is null)")
        return out
    st, detail = im.pqverify_status(n["summary"])
    if (n["status"], n["detail"]) != (st, detail):
        out.append(f"impl.nist.status is {n['status']}, but its summary gives {st}")
    sm = n["summary"]
    if sm["exit_code"] != n["exit_code"] or sm["library_sha256"] != n["library"]["sha256"]:
        out.append("impl.nist.summary differs from the run it summarises (exit code or library hash)")
    if (n["executable"] is None) != (n["argv"] is None) or (n["executable"] is None) != (n["not_run"] is not None):
        out.append("impl.nist: a run needs an executable and argv, and only a run without an executable has not_run")
    if [t.get("path") for t in pqv] != ([n["executable"]] if n["executable"] else []):
        out.append("tools[] must list the pq-verify executable that ran, and only that one")
    if n["argv"] is not None:
        try:
            spec = im.pqverify_args(" ".join(_shell_quote(a) for a in n["args"]))
        except ValueError as e:
            spec = None
            out.append(f"impl.nist.args are not arguments pqproof accepts: {e}")
        if spec is not None:
            want = im.pqverify_argv(n["executable"], spec, n["library"]["path"], n["argv"][-1])
            if n["argv"] != want or spec["audit"] != sm["audit"] or not n["argv"][-1].replace("\\", "/").endswith("/" + (n["report"] or "artifacts/impl/pq-verify/report.json")):
                out.append("impl.nist.argv is not the command pqproof builds from impl.nist.args")
    return out


def _shell_quote(a):
    import shlex
    return shlex.quote(a)


def _impl_module():
    """pqlite/impl.py(구현 검증의 대조 규칙). 스크립트로 돌 때는 sys.path 를 건드리지 않고 파일로 읽는다."""
    if __package__:
        from . import impl
        return impl
    import importlib.util
    spec = importlib.util.spec_from_file_location("pqlite_impl", os.path.join(os.path.dirname(os.path.abspath(__file__)), "impl.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def impl_record(root, r):
    """구현 검증 증적을 다시 판정한다: [(ok, 무엇)]. 답안이 있으면 KpqC 대조(_kpqc_record), pq-verify 를 돌렸으면 그 보고서(_nist_record)."""
    out = _kpqc_record(root, r) if r["impl"]["key"] is not None else []
    return out + _nist_record(root, r)


def _same_rules(r):
    """증적을 쓴 pqlite/impl.py 가 지금 도구의 것과 같은가."""
    v = _version_module()
    tools = {t.get("name"): t.get("sha256") for t in r["tools"]}
    return tools.get("pqlite/impl.py") == v.path_sha256(os.path.join(v.ROOT, "pqlite", "impl.py"))


def _nist_record(root, r):
    """pq-verify 감사를 증적의 사본으로 다시 판정한다: 실행 기록(log.json)의 감사 기록과 보고서 사본으로 요약을 다시 뽑아 impl.nist 의 요약·
    상태·상세와 검사 행 i-nist 가 같은지 본다. 대조 규칙(pqlite/impl.py)이 그 증적을 쓴 것과 다르면(다른 규칙 묶음, '+modified') 이
    도구의 규칙으로 다시 판정해 상태가 같은지만 본다(글은 판마다 다를 수 있다). 다시 판정하지 않고 넘기는 길은 없다."""
    im, n = _impl_module(), r["impl"]["nist"]
    if n is None:
        return []
    same_rules = _same_rules(r)
    try:
        log = loads_strict(_read_nofollow(root, n["log"]))
        report = _read_nofollow(root, n["report"]) if n["report"] else None
    except (OSError, ValueError) as e:
        return [(False, f"the pq-verify run record cannot be read: {e}")]
    if not isinstance(log, list) or not all(isinstance(e, dict) for e in log):
        return [(False, f"{n['log']} is not a list of runs")]
    audits = [e for e in log if e.get("role") == "audit"]
    if len(audits) > 1 or (n["argv"] is not None) != bool(audits) or (audits and audits[0].get("argv") != n["argv"]):
        return [(False, f"{n['log']} does not hold the one audit run impl.nist.argv names")]
    run = audits[0] if audits else None
    summary = im.pqverify_summary(n["summary"]["audit"], run, report, n["library"]["sha256"], n["not_run"])
    st, detail = im.pqverify_status(summary)
    row = im.nist_check_row(dict(n, summary=summary))
    if not same_rules:
        same = st == n["status"] and len(r["checks"]) > 1 and r["checks"][1]["status"] == st
        return [(same, f"written with another pqlite/impl.py (ruleset {r['ruleset_version']}); the pq-verify report judged again with this "
                       f"tool's rules gives the same {im.NIST_CHECK_ID} status ({STATUS_KO[st]})" if same else
                 f"written with another pqlite/impl.py (ruleset {r['ruleset_version']}); the pq-verify report judged again with this tool's "
                 f"rules gives {im.NIST_CHECK_ID} {st}: {detail[:200]!r}, which differs from the receipt (check it with the pqproof version "
                 "that wrote it)")]
    same = summary == n["summary"] and (st, detail) == (n["status"], n["detail"]) and len(r["checks"]) > 1 and r["checks"][1] == row
    return [(same, f"the pq-verify report judged again gives the same {im.NIST_CHECK_ID} result ({STATUS_KO[st]})" if same else
             f"the pq-verify report judged again gives {im.NIST_CHECK_ID} {st}: {detail[:200]!r}, which differs from the receipt")]


def _kpqc_record(root, r):
    """KpqC 대조를 다시 판정한다: [(ok, 무엇)]. 다시 판정하지 않고 통과로 넘기는 길은 없다(리뷰: '+modified' 로 규칙 해시만 바꿔 결과를 고친
    증적이 다시 판정 없이 ok 로 끝나던 구멍).
    1) 정답 묶음 사본(artifacts/impl/key.json)이 스스로 맞는지 본다.
    2) 사본을 믿을 근거: 이 도구의 KAT 목록이 그 증적의 것과 같으면 이 도구가 만드는 정답 묶음과 바이트까지 같아야 한다. 다르면 그 증적의
       KAT 목록·발췌 해시가 scan/ruleset.json 에 기록된 규칙 묶음의 것이어야 하고, 사본의 판 기록마다 이 도구의 목록과 같아야 한다
       (impl.key_problem). 아니면 사본을 믿지 않고 실패로 적는다.
    3) 받아 줄 판(impl.accept)은 이 도구의 프로필(scan/profiles.json 의 impl_accept)이 주는 것과 같아야 한다.
    4) 문제지 사본이 정답 묶음으로 다시 만든 것과 같은지 보고, 답안 사본을 이 도구의 대조 규칙(pqlite/impl.py)으로 다시 판정한다. 그 증적을
       쓴 규칙과 같으면 결과·자기 점검·검사 행이 글까지 같아야 하고, 다르면(다른 규칙 묶음, '+modified') 파라미터마다 상태·일치한 판과
       검사 행 상태가 같아야 한다(글은 판마다 다를 수 있다)."""
    im, v = _impl_module(), _version_module()
    x, out = r["impl"], []
    try:
        raw_key = _read_nofollow(root, x["key"]["file"])
        key = loads_strict(raw_key)
    except (OSError, ValueError) as e:
        return [(False, f"{x['key']['file']}: cannot be read ({e})")]
    probs = im.check_key(key)
    if probs:
        return [(False, f"{x['key']['file']}: the answer key is not consistent: {probs[0]}")]
    if [P["id"] for P in key["params"]] != r["params"]["params"]:
        return [(False, f"{x['key']['file']} holds other parameters than params.params")]
    tools = {t.get("name"): t.get("sha256") for t in r["tools"]}
    same_rules = tools.get("pqlite/impl.py") == v.path_sha256(os.path.join(v.ROOT, "pqlite", "impl.py"))
    try:
        manifest = im.load_manifest()
    except im.ManifestError as e:
        return [(False, f"this tool's KAT list cannot be read ({e}), so {x['key']['file']} cannot be checked and the answer is not judged again")]
    same_kat = (manifest["sha256"] == x["kat_manifest_sha256"] == tools.get("kat-kpqc")
                and tools.get("kat-excerpts") == v.path_sha256(os.path.join(v.ROOT, "scan", "kat")))
    if same_kat:
        same = im.dumps(im.build_key(manifest, r["params"]["params"])).encode("utf-8") == raw_key
        out.append((same, f"{x['key']['file']} is the answer key this tool's KAT list gives" if same else
                    f"{x['key']['file']} differs from the answer key this tool's KAT list gives"))
    else:
        recorded = _recorded_kat(r)
        if recorded is None:
            return out + [(False, f"{x['key']['file']}: the receipt names a KAT list (kat-kpqc {str(tools.get('kat-kpqc'))[:16]}, kat-excerpts "
                                  f"{str(tools.get('kat-excerpts'))[:16]}) that is neither this tool's nor one recorded in scan/ruleset.json, "
                                  "so the answer key copy cannot be trusted and the answer is not judged again")]
        prob = im.key_problem(manifest, key)
        if prob:
            return out + [(False, f"{x['key']['file']}: the answer key copy disagrees with this tool's KAT list ({prob}), so it cannot be "
                                  "trusted and the answer is not judged again")]
        out.append((True, f"{x['key']['file']}: the receipt used the KAT list of ruleset {recorded}, not this tool's; every version in the "
                          "copied answer key matches this tool's list, so the answer is judged again with the copy"))
    prof = _profiles_accept(r)
    if prof is None:
        out.append((False, f"profile {r['params']['profile']} of this tool has no impl_accept, so the accepted versions in impl.accept "
                           "cannot be confirmed"))
    else:
        try:
            want = im.accept_list(im.resolve_accept(manifest["params"], prof, r["params"]["params"]))
        except ValueError as e:
            want = [f"error: {e}"]
        out.append((want == x["accept"], "impl.accept follows the profile" if want == x["accept"] else
                    f"impl.accept is {x['accept']}, but profile {r['params']['profile']} of this tool gives {want}"))
    if x["prompt"] is not None:
        prompt = im.emit_prompt(key)
        same = (im.dumps(prompt).encode("utf-8") == _read_nofollow(root, x["prompt"]["file"])
                and prompt["prompt_sha256"] == x["prompt"]["prompt_sha256"] and len(prompt["items"]) == x["prompt"]["items"])
        out.append((same, f"{x['prompt']['file']} is the question sheet of the answer key" if same else
                    f"{x['prompt']['file']} differs from the question sheet the answer key gives"))
    accept = im.accept_from_list(x["accept"])
    if x["input"]["file"]:
        parsed = im.parse_input(_read_nofollow(root, x["input"]["file"]))
    else:
        parsed = {"kind": None, "problem": im.oversize_problem(x["input"]["bytes"])}
    hint = r["params"]["params"][0] if parsed["kind"] in ("rsp", None) and r["params"]["params"] else None  # 판정 때 --param 을 썼다
    pids, problem = im.input_params(parsed, im.key_names(key), hint)
    problem = parsed["problem"] or problem
    control, results = (None, []) if problem else (im.control_problem(key, accept, parsed["kind"]), im.match_versions(key, parsed, accept))
    row = im.check_row(results, control, problem)
    if not same_rules:
        def statuses(res, ctrl_ok, prob, check):
            return [(x_["param"], x_["status"], x_["matched"]) for x_ in res], ctrl_ok, bool(prob), check
        got = statuses(results, control is None, problem, row["status"])
        rec = statuses(x["results"], x["control"]["ok"], x["problem"], r["checks"][0]["status"] if r["checks"] else None)
        same = pids == r["params"]["params"] and got == rec
        detail = ", ".join(f"{p} {STATUS_KO[st]}" for p, st, _ in got[0]) or row["actual"][:200]
        out.append((same, f"written with another pqlite/impl.py (ruleset {r['ruleset_version']}); the answer judged again with this tool's "
                          f"rules gives the same statuses ({im.CHECK_ID} {STATUS_KO[row['status']]})" if same else
                    f"written with another pqlite/impl.py (ruleset {r['ruleset_version']}); the answer judged again with this tool's rules "
                    f"gives {im.CHECK_ID} {row['status']} ({detail}), which differs from the receipt (check it with the pqproof version "
                    "that wrote it)"))
        return out
    same = (pids == r["params"]["params"] and problem == x["problem"] and results == x["results"]
            and {"ok": control is None, "problem": control} == x["control"] and r["checks"][:1] == [row])
    out.append((same, f"the answer judged again gives the same {im.CHECK_ID} result ({STATUS_KO[row['status']]})" if same else
                f"the answer judged again gives {im.CHECK_ID} {row['status']}: {row['actual'][:200]!r}, which differs from the receipt"))
    return out


def _recorded_kat(r):
    """증적 tools[] 의 KAT 목록(kat-kpqc)·발췌(kat-excerpts) 해시가 scan/ruleset.json 에 기록된 어느 규칙 묶음의 파일 해시와 같으면 그
    묶음 이름, 아니면 None. 기록된 묶음의 KAT 는 공개한 판이 쓴 것이고, 기록에 없는 해시(직접 고친 목록)는 정답 묶음 사본의 근거가 못 된다."""
    v = _version_module()
    tools = {t.get("name"): t.get("sha256") for t in r["tools"]}
    want = (tools.get("kat-kpqc"), tools.get("kat-excerpts"))
    if None in want:
        return None
    for name, e in v.ruleset_entries()[1].items():
        files = {f.get("path"): f.get("sha256") for f in (e.get("files") or []) if isinstance(f, dict)}
        if (files.get("scan/kat-kpqc.json"), files.get("scan/kat")) == want:
            return name
    return None


def _profiles_accept(r):
    """이 도구의 scan/profiles.json 에서 증적이 쓴 프로필의 impl_accept(없으면 None). 해시가 그 증적의 것과 달라도 내용으로 맞춘다
    (받아 줄 판을 증적에서 고치고 프로필 해시를 바꿔 대조를 건너뛰지 못하게)."""
    v = _version_module()
    path = os.path.join(v.ROOT, "scan", "profiles.json")
    try:
        with open(path, encoding="utf-8") as f:
            return ((json.load(f).get("profiles") or {}).get(r["params"]["profile"]) or {}).get("impl_accept")
    except (OSError, ValueError, AttributeError):
        return None


def _allowlist_module():
    """pqlite/allowlist.py. `python3 -I pqlite/receipt.py verify` 처럼 스크립트로 돌 때는 sys.path 를 건드리지 않고 파일로 읽는다."""
    if __package__:
        from . import allowlist
        return allowlist
    import importlib.util
    spec = importlib.util.spec_from_file_location("pqlite_allowlist", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                                   "allowlist.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _skipdirs_module():
    """pqlite/skipdirs.py(건너뛰는 폴더 규칙과 트리 걷기). 스크립트로 돌 때는 파일로 읽는다."""
    if __package__:
        from . import skipdirs
        return skipdirs
    import importlib.util
    spec = importlib.util.spec_from_file_location("pqlite_skipdirs", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                                  "skipdirs.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _version_module():
    """pqlite/version.py(스크립트로 돌 때도 sys.path 를 건드리지 않게 파일로 읽는다)."""
    if __package__:
        from . import version
        return version
    import importlib.util
    spec = importlib.util.spec_from_file_location("pqlite_version", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                                 "version.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree_rules(root, r):
    """in/ 트리를 다시 잴 걷기 규칙: 형식 3은 증적에 남긴 skip-dirs 사본, 그 전 형식은 LEGACY."""
    if format_version(r) < 3:
        return LEGACY
    return _skipdirs_module().parse(_read_nofollow(root, r["skip_dirs"]["file"]).decode("utf-8"), r["skip_dirs"]["file"])


def format_version(r):
    """format_version 칸이 없으면 형식 1(0.1.0 이전 공개본)."""
    return r.get("format_version", 1)


def version_problems(r):
    """판정 근거 버전 칸이 맞는가([] 이면 맞다). 형식 2: 네 칸이 모두 있고, NOTE 가 지금 글이며, ruleset_sha256 이 tools[] 의 규칙 파일
    해시로 다시 계산한 값과 같고, ruleset_version 이 scan/ruleset.json 기록과 맞아야 한다. 형식 1: 이 칸들이 없어야 한다."""
    v = _version_module()
    fv = format_version(r)
    keys = ("tool_version", "ruleset_version", "ruleset_sha256")
    impl = is_impl(r)
    if fv == 1:
        extra = [k for k in keys + tuple(FORMAT_ONLY) if k in r] + (["params.mode impl"] if impl else [])
        return [f"{', '.join(extra)} without format_version: a format 1 receipt does not carry version fields"] if extra else []
    out = [f"format_version {fv} needs {k}" for k in keys if k not in r]
    if out:
        return out
    want_note = NOTE_V2 if fv == 2 else NOTE
    if r["note"] != want_note:
        out.append(f"a format {fv} receipt must carry the note of format {fv}, not the note of another version")
    if impl and fv < IMPL_SINCE:
        out.append(f"params.mode impl is a field of format {IMPL_SINCE}, but format_version is {fv}")
    for key, since in ({} if impl else FORMAT_ONLY).items():
        if fv >= since and key not in r:
            out.append(f"format_version {fv} needs {key}")
        elif fv < since and key in r:
            out.append(f"{key} is a field of format {since}, but format_version is {fv}")
    got = v.ruleset_from_tools(r["tools"], r["ruleset_version"])  # 그 묶음의 파일 목록으로(묶음 1은 여섯, 2부터 여덟)
    if r["ruleset_sha256"] != got:
        out.append(f"ruleset_sha256 is {r['ruleset_sha256']}, but the rule files listed in tools[] hash to {got}")
    current, history = v.ruleset_history()
    name = r["ruleset_version"]
    if name in history and history[name] != r["ruleset_sha256"]:
        out.append(f"ruleset_version {name} is {history[name]} in scan/ruleset.json, but the receipt says {r['ruleset_sha256']}")
    elif name not in history and not name.endswith("+modified"):
        out.append(f"ruleset_version {name} is not in this tool's ruleset history (it knows {', '.join(sorted(history)) or 'none'}); "
                   "check this receipt with the pqproof version that wrote it, or a newer one")
    elif name.endswith("+modified") and r["ruleset_sha256"] in history.values():
        out.append(f"ruleset_version {name} says modified, but ruleset_sha256 is a recorded ruleset")
    return out


def review_record(root, r):
    """항목의 reviewed_by·reviewed_at·reviewed_via 가 증적 폴더의 허용 목록 사본에서 다시 푼 값과 같은가. (ok, 무엇) 또는 None
    (사람 확인 칸이 없는 옛 증적, 항목 없음). 사본의 바이트는 artifacts 해시 검사가 따로 본다."""
    a = r.get("allowlist") or {}
    if "unreviewed" not in a or not a["entries"]:
        return None
    if not a.get("file"):
        return (False, "allowlist entries are recorded, but there is no copy of the allow list to check the review fields against")
    try:
        data = json.loads(_read_nofollow(root, a["file"]).decode("utf-8"))
    except (OSError, ValueError) as e:
        return (False, f"{a['file']}: cannot be read as JSON ({e})")
    if format_version(r) >= 3:  # 형식 3: REVIEW_MAX_AGE_DAYS 는 실행한 날(started_at, UTC)을 기준으로 다시 본다
        got = _allowlist_module().resolve_reviews(data, r["started_at"][:10], r["params"].get("review_max_age_days"))[0]
    else:
        got = _allowlist_module().resolve_reviews(data)[0]
    if len(got) != len(a["entries"]):
        return (False, f"{a['file']} has {len(got)} entries, but allowlist.entries has {len(a['entries'])}")
    bad = []
    for e, x in zip(a["entries"], got):
        rec = (e.get("reviewed_by"), e.get("reviewed_at"), e.get("reviewed_via", x["via"]))
        if rec != (x["by"], x["at"], x["via"]):
            bad.append(f"entry {e['n']}: receipt says {rec}, the copied list gives {(x['by'], x['at'], x['via'])}")
    if bad:
        return (False, "allowlist review fields disagree with the copied allow list:\n  " + "\n  ".join(bad[:10]))
    return (True, f"allowlist review fields match {a['file']} ({len(got)} entries)")


def _copies_agree(root, r, listed):
    """evidence-fragment.json·tables/report.md 에 옮겨 적은 판정이 receipt 판정과 같은가(새 형식 증적만). 두 파일은 verify 가 다시
    만들지 않으므로, receipt 만 고쳐 판정을 바꾸면 여기서 어긋난다. 둘 다 다시 써서 해시까지 맞춘 위조는 소스로 다시 돌려야 잡힌다."""
    out = []
    want_checks = {c["id"]: c["status"] for c in r["checks"]}
    if "evidence-fragment.json" in listed:
        try:
            frag = loads_strict(_read_nofollow(root, "evidence-fragment.json")).get("proof") or {}
            same = (frag.get("verdict"), frag.get("checks"), frag.get("verdict_text")) == (r["verdict"], want_checks, verdict_text(r))
            out.append((same, "evidence-fragment.json gives the same verdict and checks" if same else
                        f"evidence-fragment.json says {frag.get('verdict_text')!r} with checks {frag.get('checks')}, "
                        f"but the receipt says {verdict_text(r)!r}"))
        except (OSError, ValueError, AttributeError) as e:
            out.append((False, f"evidence-fragment.json cannot be read: {e}"))
    if "tables/report.md" in listed:
        try:
            md = _read_nofollow(root, "tables/report.md").decode("utf-8")
            line = f"판정 **{verdict_text(r)}**"
            out.append((line in md, "tables/report.md gives the same verdict" if line in md else
                        f"tables/report.md does not say {line!r}"))
        except (OSError, ValueError) as e:
            out.append((False, f"tables/report.md cannot be read: {e}"))
    return out


def verify(root):
    """증적 폴더의 [(ok, 무엇)]: 스키마, receipt_id, 산출물 바이트·SHA-256, 목록에 없는 파일, *_sha256 짝,
    in/ 트리 해시, 판정과 검사 칸의 일치, receipt.html 재생성 비교."""
    out = []
    try:
        raw = _read_nofollow(root, "receipt.json")
        receipt = loads_strict(raw)
    except (OSError, ValueError) as e:
        return [(False, f"receipt.json cannot be read: {e}")]
    if not isinstance(receipt, dict):
        return [(False, "receipt.json is not a JSON object")]
    same = raw == dumps(receipt).encode("utf-8")
    out.append((same, "receipt.json is byte for byte the tool's own serialization of its values" if same else
                "receipt.json bytes differ from the tool's own serialization of the same values (spacing, key order, escapes or "
                "bytes after the object), so another parser could read other values"))
    reads = _version_module().FORMAT_READS
    fv = receipt.get("format_version", 1) if isinstance(receipt, dict) else None
    if fv not in reads:
        return out + [(False, f"receipt.json has format_version {fv!r}; this tool reads {', '.join(map(str, reads))}. "
                              "Check it with the pqproof version that wrote it, or a newer one")]
    impl = is_impl(receipt)
    problems = validate(receipt, SCHEMA_IMPL if impl else SCHEMA)
    out.append((not problems, "receipt.json fits the schema" if not problems else
                "receipt.json does not fit the schema:\n  " + "\n  ".join(problems[:20])))
    if problems:
        return out
    vp = version_problems(receipt)
    if fv == 1:
        kind = LEGACY_NOTES.get(receipt["note"], "public-2")
        msg = (f"evidence format 1 ({ {'public-1': 'first public copy'}.get(kind, 'public copy before 0.1.0') }):"
               " no tool or ruleset version recorded; read with the old wording")
    else:
        msg = (f"evidence format {fv}: pqproof {receipt.get('tool_version')}, ruleset {receipt.get('ruleset_version')} "
               f"(ruleset_sha256 matches the rule files in tools[])")
    out.append((not vp, msg if not vp else "version fields disagree with the record:\n  " + "\n  ".join(vp)))
    try:
        got = compute_id(receipt)
    except ValueError as e:
        got = None
        out.append((False, f"receipt_id cannot be recomputed: {e}"))
    if got is not None:
        out.append((got == receipt["receipt_id"], f"receipt_id {receipt['receipt_id']}" if got == receipt["receipt_id"]
                    else f"receipt_id is {receipt['receipt_id']}, but the receipt hashes to {got}"))
    listed = {}
    for item in receipt["artifacts"]:
        path = item["path"]
        try:
            data = _read_nofollow(root, path)
        except (OSError, ValueError) as e:
            out.append((False, f"{path}: cannot be read ({e})"))
            continue
        digest = hashlib.sha256(data).hexdigest()
        ok = digest == item["sha256"] and len(data) == item["bytes"]
        listed[path] = item["sha256"]
        out.append((ok, f"{path}: sha256 {digest}" if ok else
                    f"{path}: {len(data)} bytes, sha256 {digest}; the receipt says {item['bytes']} bytes, {item['sha256']}"))
    for path in _listed_files(root):
        if path not in listed:
            out.append((False, f"{path}: in the receipt directory but not in the receipt"))
    refs = [(w, p, d) for w, p, d in _hash_refs(receipt) if not (p is None and d is None)]
    bad = [(w, p, d) for w, p, d in refs if listed.get(p) != d]
    for where, path, digest in bad:
        out.append((False, f"{where}: {path} with sha256 {digest} is not an artifact with that hash"))
    if not bad:
        out.append((True, f"all {len(refs)} file references in the receipt name an artifact with the same SHA-256"))
    for side in () if impl else ("orig", "fixed"):
        inp = receipt["inputs"][side]
        if inp["kind"] == "zip":
            tree = os.path.join(root, *inp["root"].split("/"))
            if not inp["root"].startswith("in/") or not os.path.isdir(tree) or os.path.islink(tree):
                out.append((False, f"inputs.{side}: unpacked tree {inp['root']} is missing"))
                continue
            try:
                rules = _tree_rules(root, receipt)
            except (OSError, ValueError, KeyError, TypeError) as e:
                out.append((False, f"inputs.{side}: the skip-dirs copy cannot be read ({e})"))
                continue
            got = tree_sha256(tree_files(tree, rules))
            out.append((got == inp["tree_sha256"], f"inputs.{side}: tree {inp['root']} sha256 {got}"
                        if got == inp["tree_sha256"] else f"inputs.{side}: tree hashes to {got}, receipt says {inp['tree_sha256']}"))
    problems = consistency(receipt)
    out.append((not problems, "the verdict and the checks agree with the numbers below them" if not problems
                else "the verdict or the checks disagree with the record:\n  " + "\n  ".join(problems[:20])))
    rv = None if impl else review_record(root, receipt)
    if rv:
        out.append(rv)
    if impl:
        try:
            out += impl_record(root, receipt)
        except (OSError, ValueError, KeyError, TypeError) as e:
            out.append((False, f"the implementation check cannot be judged again: {e}"))
        out += _copies_agree(root, receipt, listed)
    elif _new_format(receipt):
        out += _copies_agree(root, receipt, listed)
    try:
        page = _read_nofollow(root, "receipt.html").decode("utf-8")
        same = page == render_html(receipt)
        out.append((same, "receipt.html is this receipt" if same else "receipt.html differs from this receipt"))
    except (OSError, ValueError) as e:
        out.append((False, f"receipt.html cannot be read: {e}"))
    if "deck_meta" in receipt:
        try:
            deck = _read_nofollow(root, "deck.json").decode("utf-8")
            same = deck == render_deck(receipt)
            out.append((same, "deck.json is this receipt" if same else "deck.json differs from this receipt"))
        except (OSError, ValueError) as e:
            out.append((False, f"deck.json cannot be read: {e}"))
    elif os.path.lexists(os.path.join(root, "deck.json")):
        out.append((False, "deck.json is there, but the receipt has no deck_meta"))
    if format_version(receipt) >= 3:  # 형식 3: 결과 폴더 안내 파일도 receipt 에서 결정적으로 나온다
        try:
            same = _read_nofollow(root, "README.txt").decode("utf-8") == render_readme(receipt)
            out.append((same, "README.txt is this receipt" if same else "README.txt differs from this receipt"))
        except (OSError, ValueError) as e:
            out.append((False, f"README.txt cannot be read: {e}"))
    elif os.path.lexists(os.path.join(root, "README.txt")):
        out.append((False, "README.txt is there, but formats before 3 do not write one"))
    return out


def render_readme(r):
    """결과 폴더 안내(README.txt, 형식 3). 먼저 볼 파일, 다시 확인하는 법, 폴더를 넘기기 전에 볼 것. receipt.json 에서만 만든다."""
    meta = r.get("deck_meta") or {}
    verify_cmd = meta.get("verify_cmd") or "pqproof --verify <this folder>"
    if is_impl(r):
        return _impl_readme(r, verify_cmd)
    lines = [
        f"PQ-Proof {r.get('tool_version', '')} result folder. Verdict: {verdict_text(r, en=True)}",
        f"판정: {verdict_text(r)} · 증적 해시(receipt_id): {r['receipt_id']}",
        "",
        "Open first / 먼저 볼 것",
        "  receipt.html          the verification evidence as one page (사람이 볼 것)",
        "  receipt.json          the verification evidence for programs (기계가 읽을 것, schemas/receipt-v3.schema.json)",
        "  tables/report.md      a summary to paste into a document (문서에 붙일 표)",
        "  tables/cbom-fixed.csv every cryptographic location in the fixed tree with its status",
        "",
        "Check again / 다시 확인",
        f"  {verify_cmd}",
        "  Adding, removing or editing any file in this folder makes the check fail (README.txt included).",
        "  폴더 안 파일을 더하거나 지우거나 고치면 다시 확인이 실패한다.",
        "",
        "Before sharing / 넘기기 전에",
        "  artifacts/ holds the raw scanner output with source lines, and in/ holds unpacked zip inputs.",
        "  Paths on this machine are recorded in receipt.json. Read guide/outputs.md before handing the folder over.",
        "  artifacts/ 에는 소스 줄이 든 스캐너 원문이, in/ 에는 푼 zip 입력이 있다. 넘기기 전에 확인한다.",
        "",
    ]
    return "\n".join(lines)


def _impl_readme(r, verify_cmd):
    """구현 검증 결과 폴더의 README.txt(형식 4)."""
    x = r["impl"]
    what = " and ".join(w for w, on in (("KpqC KAT", x["input"] is not None), ("pq-verify audit", x.get("nist") is not None)) if on)
    lines = [
        f"PQ-Proof {r.get('tool_version', '')} implementation check ({what}). Verdict: {verdict_text(r, en=True)}",
        f"판정: {verdict_text(r)} · 증적 해시(receipt_id): {r['receipt_id']}",
        "",
        "Open first / 먼저 볼 것",
        "  receipt.html             the evidence as one page (사람이 볼 것)",
        "  receipt.json             the evidence for programs (기계가 읽을 것, schemas/receipt-v4.schema.json)",
        "  tables/report.md         a summary to paste into a document (문서에 붙일 표)",
        "  tables/impl.csv          every parameter set and reference version with its count",
        "  artifacts/impl/          the answer file, the answer key and the question sheet that were compared",
    ]
    if x.get("nist") is not None:
        lines += ["  artifacts/impl/pq-verify/ the pq-verify report (report.json) and its run record (log.json: argv, exit code, output)"]
    lines += [
        "",
        "What this is / 이것은",
        "  A match with pinned reference KAT versions (scan/kat-kpqc.json). PQ-Proof did not build or run the implementation;",
        "  your harness wrote the answers. It is not a conformance test or a certification (not KCMVP).",
        "  참조판 KAT 와 일치하는지 본 것이다. 표준 준수 시험이나 공인 시험(KCMVP)이 아니다.",
        "  The KAT records in artifacts/impl/ come from the KpqC reference packages (MIT); see scan/kat/NOTICE in PQ-Proof.",
        "  artifacts/impl/ 의 KAT 레코드는 KpqC 참조 구현 묶음(MIT)에서 왔다. 고지는 PQ-Proof 의 scan/kat/NOTICE 에 있다.",
    ]
    if x.get("nist") is not None:
        lines += [
            "  The NIST audit (i-nist) was run by pq-verify, an external tool you turned on; pq-verify loaded and ran the library.",
            "  PQ-Proof read its report and exit code. pq-verify is not a sandbox: audit untrusted libraries in a container or VM.",
            "  NIST 감사는 사용자가 켠 pq-verify 가 라이브러리를 불러 실행했고, PQ-Proof 는 그 보고서만 읽었다.",
        ]
    lines += [
        "",
        "Check again / 다시 확인",
        f"  {verify_cmd}",
        "  The check judges the copied answer again. Adding, removing or editing any file here makes it fail.",
        "  폴더 안 파일을 더하거나 지우거나 고치면 다시 확인이 실패한다.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------
# 페이지: receipt.json만으로 결정적으로 그린다(verify가 다시 그려 비교한다).
SCRIPT = """(function(){var r=document.documentElement,b=document.getElementById('theme');
function set(t){r.setAttribute('data-theme',t);b.textContent=t==='dark'?'라이트':'다크';}
var t='dark';try{t=localStorage.getItem('pqcproof-theme')||'dark'}catch(e){}
if(location.hash==='#light')t='light';set(t);
b.addEventListener('click',function(){var n=r.getAttribute('data-theme')==='dark'?'light':'dark';set(n);
try{localStorage.setItem('pqcproof-theme',n)}catch(e){}});})();"""
SCRIPT_CSP = "'sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode() + "'"
TOKENS_DARK = ("--bg:#0f1115;--panel:#171a21;--line:#2a2f3a;--text:#e6e8ee;--muted:#9aa3b2;--ok:#3fb950;--bad:#f85149;"
               "--warn:#d29922;--accent:#58a6ff;--code:#0b0d11;--badge-pass:#238636;--badge-fail:#da3633;--badge-und:#9e6a03")
TOKENS_LIGHT = ("--bg:#f6f7f9;--panel:#fff;--line:#d8dce3;--text:#1b1f27;--muted:#5b6474;--ok:#1a7f37;--bad:#cf222e;"
                "--warn:#9a6700;--accent:#0969da;--code:#f0f2f5;--badge-pass:#1a7f37;--badge-fail:#cf222e;--badge-und:#9a6700")
STYLE = (":root{color-scheme:dark;" + TOKENS_DARK + "}"
         ":root[data-theme=light]{color-scheme:light;" + TOKENS_LIGHT + "}"
         """*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Segoe UI",Roboto,sans-serif;overflow-wrap:break-word;word-break:keep-all}
main{padding:20px 24px 48px}header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
h1{font-size:22px;margin:0;text-wrap:balance}h2{font-size:17px;margin:28px 0 10px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;font-size:13px;color:#fff;white-space:nowrap}
.pass{background:var(--badge-pass)}.fail{background:var(--badge-fail)}.undecided{background:var(--badge-und)}
.s-pass{color:var(--ok);font-weight:600}.s-fail{color:var(--bad);font-weight:600}.s-undecided,.s-review,.s-check{color:var(--warn);font-weight:600}
.s-na{color:var(--muted)}.muted{color:var(--muted)}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-top:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px 24px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}code,.hash{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.hash{word-break:break-all;color:var(--muted)}pre{background:var(--code);padding:10px;border-radius:8px;
overflow-x:auto;white-space:pre-wrap;word-break:break-all;font-size:12.5px;margin:0}
a{color:var(--accent)}button{background:var(--panel);color:var(--text);border:1px solid var(--line);
border-radius:8px;padding:6px 12px;font:inherit;cursor:pointer}
.num,.nowrap{white-space:nowrap;font-variant-numeric:tabular-nums}
@media (max-width:600px){main{padding:16px 16px 40px}}""")
STATUS_KO = {"pass": "통과", "fail": "실패", "undecided": "미판정", "na": "해당 없음", "review": "검토 필요", "check": "확인"}
VERDICT_KO = {"pass": "통과", "fail": "실패", "undecided": "미판정"}


def pending_note(r, en=False):
    """통과인데 사람이 볼 것이 남았을 때 판정 옆에 붙일 말(없으면 빈 글): 검증 호출 제거 흔적(r-review, 형식 2부터), 사람 확인 전
    허용 항목, 허용 범위 안 쓰기 경로(검토 필요), 고친 판에서 안 쓰인 항목. 옛 증적(unreviewed 칸 없음)은 허용 몫이 빈 글,
    write_review·unused 칸이 없으면 첫 몫만(옛 표시 그대로). 형식 1 증적에는 검증 호출 몫을 붙이지 않는다(옛 receipt.html 이 그대로 맞게)."""
    a = r.get("allowlist") or {}
    n, w, u = a.get("unreviewed") or 0, a.get("write_review") or 0, a.get("unused") or 0
    v = len((r.get("weakening") or {}).get("review") or []) if format_version(r) >= 2 else 0
    m = len(a.get("legacy") or []) if format_version(r) >= 3 else 0  # 이름 규칙으로만 허용한 곳(형식 3부터)
    c = len(a.get("composite") or []) if format_version(r) >= 3 else 0  # 복합 서명 위치(형식 3부터, 교차 리뷰 X26)
    x = (a.get("expired") or 0) if format_version(r) >= 3 else 0  # 만료된 허용 항목(형식 3부터, 교차 리뷰 X31)
    k = ((r.get("cbom") or {}).get("fixed") or {}).get("unresolved") or 0 if format_version(r) >= 3 else 0  # 열지 못한 키 자료(X27)
    # 형식 3: 검토 필요인 검사 이름을 적는다(교차 리뷰 X30: a-input·b-tls 의 검토 필요가 판정 줄에 안 보였다). r-review·r-allow·a-cbom·
    # c-classic 의 검토 필요는 앞의 수(검증 호출 제거, 허용 항목, 쓰기 경로, 복합 서명)가 이미 말한다
    rv = ([x["id"] for x in r.get("checks") or [] if x["status"] == "review" and x["id"] not in ("r-review", "r-allow", "a-cbom", "c-classic")]
          if format_version(r) >= 3 else [])
    if r["verdict"] != "pass" or not (v or n or w or u or m or c or x or k or rv):
        return ""
    if en:
        parts = ([f"{v} removed {'verification needs' if v == 1 else 'verifications need'} review"] if v else []) \
            + ([f"{n} allowed {'entry' if n == 1 else 'entries'} not yet reviewed by a person"] if n else []) \
            + ([f"{w} write {'path' if w == 1 else 'paths'} in allowed ranges {'needs' if w == 1 else 'need'} review"] if w else []) \
            + ([f"{u} allowlist {'entry' if u == 1 else 'entries'} unused in the fixed tree"] if u else []) \
            + ([f"{m} {'line' if m == 1 else 'lines'} allowed by the name rule alone"] if m else []) \
            + ([f"{c} composite {'signature needs' if c == 1 else 'signatures need'} review"] if c else []) \
            + ([f"{x} allowlist {'entry' if x == 1 else 'entries'} expired"] if x else []) \
            + ([f"{k} unresolved key or algorithm {'name' if k == 1 else 'names'}"] if k else []) \
            + ([f"needs review: {', '.join(rv)}"] if rv else [])
        return "; ".join(parts)
    parts = ([f"검증 호출 제거 {v}건 검토 필요"] if v else []) + ([f"허용 {n}건 사람 확인 전"] if n else []) \
        + ([f"허용 범위 쓰기 경로 {w}곳 검토 필요"] if w else []) + ([f"안 쓰인 항목 {u}건"] if u else []) \
        + ([f"이름 규칙으로만 허용 {m}곳"] if m else []) + ([f"복합 서명 {c}곳 검토 필요"] if c else []) \
        + ([f"만료된 허용 항목 {x}건"] if x else []) + ([f"열지 못한 키 자료·못 읽은 알고리즘 {k}곳"] if k else []) \
        + ([f"검토 필요 검사 {', '.join(rv)}"] if rv else [])
    return " · ".join(parts)


def verdict_text(r, en=False):
    """'통과(허용 2건 사람 확인 전)' · 'pass (2 allowed entries not yet reviewed by a person)'. 종료 코드는 판정(verdict)만 따른다."""
    note = pending_note(r, en)
    base = r["verdict"] if en else VERDICT_KO[r["verdict"]]
    return base + (f" ({note})" if en else f"({note})") if note else base


def _e(value):
    return html.escape("" if value is None else str(value), quote=True)


def _short(digest):
    return f'<span class="hash" title="{_e(digest)}">{_e(digest)}</span>' if digest else '<span class="muted">없음</span>'


def _link(path, label=None):
    return f'<a href="{_e(path)}">{_e(label or path)}</a>' if path else '<span class="muted">없음</span>'


def _table(head, rows):
    out = ['<div class="wrap"><table><thead><tr>'] + [f"<th>{_e(h)}</th>" for h in head] + ["</tr></thead><tbody>"]
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>")
    if not rows:
        out.append(f'<tr><td colspan="{len(head)}" class="muted">없음</td></tr>')
    return "".join(out) + "</tbody></table></div>"


def _status(s):
    return f'<span class="s-{_e(s)} nowrap">{_e(STATUS_KO.get(s, s))}</span>'


def _num(n):
    return f'<span class="num">{_e(n)}</span>'


def _hs(h):
    if not h:
        return '<span class="muted">안 돌림</span>'
    if h.get("kind") == "failed":
        return f"접속 실패 ({_e(h.get('error') or '')})"
    return f"<code>{_e(h.get('group'))}</code> ({_e(h.get('protocol'))})"


ALLOW_KO = {"allowed": "허용", "review": "검토 필요(쓰기 경로)", "unused": "고전 줄 없음", "invalid": "무효(허용 안 함)",
            "excluded": "검사 범위 밖(실행 데이터)", "outside": "제출 트리 밖(허용할 줄 없음)"}
ALLOW_CLS = {"allowed": "pass", "review": "review", "unused": "na", "invalid": "fail", "excluded": "na", "outside": "na"}


def _few(items, n):
    items = list(items)
    return ", ".join(items[:n]) + (f" 외 {len(items) - n}" if len(items) > n else "")


def _reviewed(e):
    """허용 항목의 사람 확인 칸: 이름과 시각(목록 맨 위 칸을 물려받았으면 그렇게 적는다), 줄을 허용했는데 없으면 '확인 전'."""
    if e.get("reviewed_by") and e.get("reviewed_at"):
        return (f'{_e(e["reviewed_by"])}<br><span class="muted nowrap">{_e(e["reviewed_at"])}</span>'
                + ('<br><span class="muted nowrap">목록 맨 위 칸</span>' if e.get("reviewed_via") == "top" else ""))
    if e["status"] in ("allowed", "review"):
        return '<span class="s-review nowrap">확인 전</span>'
    return '<span class="muted">없음</span>'


def allow_sections(r):
    """허용 목록·실행 데이터 제외 표. 이 칸이 없는 옛 증적은 아무것도 그리지 않는다(옛 receipt.html이 그대로 맞게)."""
    a, x = r.get("allowlist"), r.get("excluded")
    parts = []
    if a is not None:
        rv = "unreviewed" in a  # 사람 확인 칸이 있는 증적만 '사람 확인' 열을 그린다
        cov = "unused" in a  # 결함 D1 뒤 증적만 '원본에서 덮는 줄' 열과 안 쓰인 항목 문단을 그린다
        rows, imps = [], set(a.get("imports") or [])
        for e in a["entries"]:
            where = f"<code>{_e(e['where'])}</code>" + "".join(f'<br><span class="muted">{_e(t)}</span>' for t in e["targets"][:3]) \
                + (f'<br><span class="muted">외 {len(e["targets"]) - 3}개</span>' if len(e["targets"]) > 3 else "")
            st = f'<span class="s-{ALLOW_CLS[e["status"]]} nowrap">{_e(ALLOW_KO[e["status"]])}</span>' \
                + (f'<br><span class="muted">{_e(e["note"])}</span>' if e["note"] else "")
            mark = lambda locs: [x + " (import)" if x in imps else x for x in locs]  # noqa: E731
            hit = _e(_few(mark(e["allowed"]), 6)) + (f"<br>검토: {_e(_few(mark(e['review']), 4))}" if e["review"] else "")
            orig = ""
            if cov:
                k = e.get("lines_orig")
                orig = ('<span class="muted">안 봄</span>' if k is None else
                        (f'<span class="s-review">{_num(k)}</span>' if _counts_unused(e) and k else _num(k))
                        + (f'<br><span class="muted">{_e(_few(e.get("orig", []), 3))}</span>' if k and _counts_unused(e) else ""))
            rows.append([_num(e["n"]), where, _e(e["kind"]), _e(e["why"]), st, hit or '<span class="muted">없음</span>']
                        + ([orig] if cov else []) + ([_reviewed(e)] if rv else []))
        head = (f"<p>목록 <code>{_e(a['source'] or '없음')}</code>" + (" (작업 폴더에서 자동으로 찾음)" if a.get("auto") else "")
                + (f" · 사본 {_link(a['file'], a['file'].rsplit('/', 1)[-1])} {_short(a['file_sha256'])}" if a.get("file") else "")
                + "</p><p class=\"muted\">목록이 가리킨 줄만 사유와 함께 허용으로 센다. 그 줄에서만 쓰는 import 줄도 같은 항목으로 센다. "
                "고전 줄이나 바로 아래 3줄에 새 키·새 서명·새 암호화가 있으면 허용으로 세지 않고 검토 필요로 남긴다. 목록 밖의 고전 줄은 "
                "그대로 실패다. 없는 파일이나 파일 길이를 넘는 줄을 가리킨 항목은 무효로 두고 아무것도 허용하지 않는다. "
                "제출 트리 밖이라고 적힌 자리는 허용할 줄이 없다."
                + (" 줄을 허용한 항목에 reviewed_by·reviewed_at 이 없으면 사람 확인 전으로 적고 판정 옆에 건수를 붙인다"
                   "(REQUIRE_REVIEW=1 이면 실패). 목록 맨 위 칸은 reviewed_digest 가 지금 목록과 맞을 때만 자기 칸이 없는 항목에 "
                   "물려준다. 이 칸은 사람이 남긴 기록이고, 실제로 확인했는지는 도구가 알 수 없다." if rv else "")
                + "</p>"
                + (f'<p class="muted">맨 위 칸이 덮는 항목의 지금 reviewed_digest <code>{_e(a["top_digest"])}</code></p>'
                   if rv and a.get("top_digest") else "")
                + (f'<p class="s-review">사람 확인 전 허용 항목 {_num(a["unreviewed"])}건</p>' if rv and a["unreviewed"] else "")
                + (f'<p class="s-review">고친 판에서 안 쓰인 항목 {_num(a["unused"])}건: 원본에서 덮는 고전 {_num(a.get("unused_orig_lines", 0))}줄은 '
                   "사람 확인 전이다. 목록은 어느 트리에 대든 걸리므로, 이 항목은 원본 같은 다른 트리에 대면 그 줄을 가린다. 쓰지 않으면 "
                   "목록에서 지운다(REQUIRE_REVIEW=1 이면 실패).</p>" if cov and a["unused"] else "")
                + (f'<p class="s-review">허용 범위 안 쓰기 경로(새 키·서명·암호화) {_num(a["write_review"])}곳은 검토 필요로 남았다. '
                   "판정을 바꾸지 않으니 사람이 보고 고치거나 사유를 확인한다.</p>" if cov and a.get("write_review") else ""))
        hyb = a.get("hybrid") or []
        tail = (f"<p>하이브리드 결합 허용 {_num(len(hyb))}줄(같은 함수 안 주석이 아닌 ML-KEM 코드와 묶인 키 교환 고전 성분): "
                f"<code>{_e(_few(hyb, 8))}</code></p>" if hyb else "")
        leg = a.get("legacy") or []
        if format_version(r) >= 3:
            tail += (f'<p class="s-review">이름 규칙으로만 허용 {_num(len(leg))}곳(허용 목록 항목 없음, Legacy*.java 파일이거나 코드에 legacy, '
                     "그 줄과 아래 3줄에 새 키·서명·암호화 없음). 사람이 확인하지 않은 허용이라 r-allow 가 검토 필요로 본다"
                     f"(REQUIRE_REVIEW=1 이면 실패): <code>{_e(_few(leg, 8))}</code></p>" if leg else "")
        else:
            tail += (f"<p>이름 규칙 허용 {_num(len(leg))}곳(허용 목록 밖, Legacy*.java 파일이거나 같은 줄에 legacy, 그 줄에 쓰기 연산 없음. "
                     f"{_words(r)['legacy_rule']}): <code>{_e(_few(leg, 8))}</code></p>" if leg else "")
        tail += "".join(f'<p class="s-review">{_e(w)}</p>' for w in a["warnings"])
        parts.append("<h2>허용 목록(남긴 고전과 사유)</h2><section>" + head
                     + _table(["#", "위치", "종류", "사유", "판정", "걸린 고전 줄"] + (["원본에서 덮는 줄"] if cov else [])
                              + (["사람 확인"] if rv else []), rows) + tail
                     + "</section>")
    if x is not None and (x["items"] or x["notes"]):
        rows = [[f"<code>{_e(i['pattern'])}</code>", _e(i["from"]), _e(i["why"])] for i in x["items"]]
        files = x["files_fixed"] or x["files_orig"]
        body = (f"<p>원본 {_num(x['count_orig'])}개 · 고친 판 {_num(x['count_fixed'])}개 파일을 CBOM·residue·약화 수정 검사에서 뺐다. "
                "입력 트리 해시에는 뺀 파일도 들어 있다.</p>"
                + (f'<p class="muted">고친 판에서 뺀 파일: <code>{_e(_few(files, 12))}</code></p>' if files else "")
                + "".join(f'<p class="muted">{_e(n)}</p>' for n in x["notes"]))
        parts.append("<h2>검사에서 뺀 실행 데이터</h2><section>" + _table(["글롭", "출처", "근거"], rows) + body + "</section>")
    return parts


def body_sections(r):
    """요약·허용 목록·Java·TLS·약화 수정 표(receipt.html과 tables/fragment.html이 같이 쓴다). 스크립트 없음."""
    parts = ["<h2>검사</h2><section>" + _table(["검사", "판정", "기준", "실제"], [
        [f"<b>{_e(c['id'])}</b> {_e(c['title'])}", _status(c["status"]), _e(c["expected"]), _e(c["actual"])]
        for c in r["checks"]]) + "</section>"]
    parts += allow_sections(r)
    co, cf = r["cbom"]["orig"], r["cbom"]["fixed"]
    new = "allowlist" in r
    head = ["판", "행", "위치", "막는 위치"] + (["검토 필요"] if new else []) + [
        "허용(목록·레거시·하이브리드)" if new else "허용(레거시·하이브리드)", "주석·테스트", "확인", "범위 밖", "참고", "표"]
    parts.append("<h2>(a) CBOM</h2><section>" + _table(
        head,
        [[name, _num(s["rows"]), _num(s["locations"]), _num(s["blocking"])] + ([_num(s.get("review", 0))] if new else [])
         + [_num(s["allowed"]), _num(s["comment_or_test"]),
            _num(s["check"]), _num(s.get("out_of_scope", "")), _num(s["info"]), _link(s["csv"], s["csv"].rsplit("/", 1)[-1])]
         for name, s in (("원본", co), ("고친 판", cf))]) +
        '<p class="muted">막는 위치 = 양자 컴퓨터로 깨지는 공개키 사용처(cbom-scan "쇼어로 깨짐" 또는 scan.py shor·weak-pqc·TLS 고정) 중 '
        "주석·테스트가 아니고 허용 규칙(Legacy*.java 또는 같은 줄 legacy, 쓰기 연산 없음, 같은 줄 ML-KEM 하이브리드)에 안 걸리는 곳. "
        "범위 밖 = SCOPE=kex일 때 키 교환이 아닌 서명·암호화 사용처(표에 남기고 막는 위치로 세지 않음)."
        + (" 허용에는 허용 목록이 가리킨 줄과 같은 함수 안 ML-KEM 하이브리드 결합 줄도 들어간다. 검토 필요 = 허용 목록에 있으나 쓰기 경로인 줄."
           if new else "")
        + (f" 주석·테스트 중 시험·예제 경로(<code>scan/test-paths.ere</code>) 위치: 원본 {_num(co['tests'])} · 고친 판 {_num(cf['tests'])}."
           if "tests" in cf else "") + "</p></section>")
    j = r["java"]
    if j["fixed"] is not None:
        fams = sorted(set(j["fixed"]["families"]) | set((j["orig"] or {}).get("families", {})))
        lst = j["fixed"].get("listed")
        rows = []
        for fam in fams:
            o = (j["orig"] or {}).get("families", {}).get(fam, {})
            f = j["fixed"]["families"].get(fam, {})
            row = [f"<code>{_e(fam)}</code>", _num(o.get("code", "")), _num(o.get("allow", "")), _num(o.get("comment", "")),
                   _num(f.get("code", "")), _num(f.get("allow", "")), _num(f.get("comment", ""))]
            if lst is not None:
                by = lst.get("by_family", {})
                moved = by.get("allowed", {}).get(fam, 0) + by.get("hybrid", {}).get(fam, 0)
                rev = by.get("review", {}).get(fam, 0)
                row += [_num(moved), _num(rev), _num(f.get("code", 0) - moved - rev) if f else _num("")]
            rows.append(row)
        exp = j["fixed"]["expect"]
        # 옛 증적(사람 확인 칸 이전)은 예전 낱말 그대로 그린다(옛 receipt.html이 그대로 맞게). 새 증적은 NIST 보안레벨
        level = "보안레벨 3 미만 PQC" if "unreviewed" in (r.get("allowlist") or {}) else "범주 3 미만 PQC"
        parts.append("<h2>(c) 고전 공개키·PQC 집계(residue)</h2><section>" + _table(
            ["계열", "원본 code", "원본 allow", "원본 comment", "고친 판 code", "고친 판 allow", "고친 판 comment"]
            + (["목록·하이브리드 허용", "검토 필요", "남은 code"] if lst is not None else []), rows) +
            "<p>" + " · ".join(f"<code>{_e(k)}</code> {_num(v)}" for k, v in sorted(exp.items())) +
            f" · {level} {_num(j['fixed']['weak_pqc'])} · 레거시 쓰기 {_num(j['fixed']['legacy_write'])}"
            f" · residue {_e(j['residue_kind'])} {_e(j['fixed']['verdict'])}</p>"
            + (f"<p>시험 경로 코드 줄(판정에 안 넣고 따로 셈, <code>scan/test-paths.ere</code>): 원본 "
               f"{_num(((j['orig'] or {}).get('tests') or {}).get('count', 0))} · 고친 판 {_num(j['fixed']['tests']['count'])}"
               + (f" · <code>{_e(_few(j['fixed']['tests']['lines'], 8))}</code>" if j["fixed"]["tests"]["lines"] else "") + "</p>"
               if "tests" in j["fixed"] else "") + "</section>")
    t = r["tls"]
    tls_rows = [[f"<code>{_e(x['target'])}</code>", _e(x.get("trust")), _hs(x.get("hybrid")), _hs(x.get("classical")),
                 _e((x.get("hybrid") or {}).get("cert_sig")), _e((x.get("hybrid") or {}).get("cert_key")),
                 _hs(x.get("openssl")), _status("pass" if x.get("ok") else "fail"), _e("; ".join(x.get("why", [])))]
                for x in t["targets"]]
    parts.append("<h2>(b) TLS</h2><section>" +
                 (f"<p>TLS 서버 신호 {len(t['signals'])}곳" + (": " + ", ".join(f"<code>{_e(s)}</code>" for s in t["signals"][:12]) if t["signals"] else "") +
                  f" · 실행 위치 {_e(t['via'])}" + (f" · 대조 문제: {_e(t['control_problem'])}" if t["control_problem"] else "") + "</p>")
                 + _table(["대상", "신뢰", "하이브리드 전용 제시", "옛 클라이언트(X25519,P-256)", "cert_sig", "cert_key",
                           "OpenSSL 3.5 교차", "판정", "이유"], tls_rows) + "</section>")
    w = r["weakening"]
    parts.append("<h2>TLS 약화 수정</h2><section>" + _table(["거부(deny)"], [[_e(d)] for d in w["deny"]]) +
                 _table(["검토(review)", "규칙", "전", "후", "근거", "사유"],
                        [[f"<code>{_e(x['path'])}</code>", _e(x["rule"]), _num(x["before"]), _num(x["after"]), _e(x["detail"]),
                          _e(x["reason"]) or _status("review")] for x in w["review"]]) + "</section>")
    return parts


# 형식 1 증적을 다시 그릴 때 쓰는 그 판의 낱말(옛 receipt.html 이 바이트까지 그대로 맞게). 고르는 기준은 증적의 note 다
WORDS = {"title": "PQC 전환 검증 증적", "h1": "PQC 전환 검증 증적", "verify": "pqproof --verify 이_폴더",
         "app": "앱 계층 서명·래핑이 실제로 도는지는 앱 기능 시험이 따로 본다.", "legacy_rule": "오래된 이름 규칙"}
WORDS_V2 = dict(WORDS, verify="bash prove.sh --verify 이_폴더")  # 형식 2 와 형식 1 둘째 공개본(NOTE_V2)의 낱말
LEGACY_WORDS = {"public-1": dict(WORDS_V2, title="PQC 전환 영수증", h1="PQC 전환 검증 영수증"), "v2": WORDS_V2}


def _words(r):
    """증적의 note 로 그 판의 낱말을 고른다(형식 1 의 첫 공개본은 LEGACY_WORDS, 나머지는 지금 낱말)."""
    return LEGACY_WORDS.get(LEGACY_NOTES.get(r["note"]) or ("v2" if r["note"] == NOTE_V2 else None), WORDS)


def render_html(r):
    """receipt.html. 증적에서 온 값은 모두 이스케이프한다. 아무것도 불러오지 않고 자기 산출물에만 링크한다."""
    if is_impl(r):
        return render_impl_html(r)
    w = _words(r)
    basis = (f"<div><div class=\"muted\">판정 근거</div>pqproof {_e(r.get('tool_version'))} · 규칙 묶음 {_e(r.get('ruleset_version'))} · "
             f"증적 형식 {_num(r['format_version'])}<br>{_short(r.get('ruleset_sha256'))}</div>" if format_version(r) >= 2 else "")
    # 통과인데 사람 확인 전 허용이 있으면 노란 배지에 '통과(허용 n건 사람 확인 전)'
    verdict = f'<span class="badge {_e("undecided" if pending_note(r) else r["verdict"])}">{_e(verdict_text(r))}</span>'
    inputs = "".join(
        f"<div><div class=\"muted\">{_e(label)}</div><code>{_e(i['path'])}</code><br>"
        f"<span class=\"muted\">{_e(i['kind'])} · 파일 {_num(i['files'])}개 · 트리</span> {_short(i['tree_sha256'])}"
        + (f"<br><span class=\"muted\">zip</span> {_short(i['zip_sha256'])}" if i["zip_sha256"] else "") + "</div>"
        for label, i in (("원본", r["inputs"]["orig"]), ("고친 판", r["inputs"]["fixed"])))
    parts = [f"""<!doctype html><html lang="ko" data-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src {SCRIPT_CSP}; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>{w['title']}</title><style>{STYLE}</style></head><body><main>
<header><h1>{w['h1']} {verdict}</h1><button id="theme" type="button">라이트</button></header>
<section><div class="grid">{inputs}
<div><div class="muted">시작, 끝(UTC)</div><span class="nowrap">{_e(r['started_at'])}</span><br><span class="nowrap">{_e(r['finished_at'])}</span></div>
<div><div class="muted">매개변수</div>CLASSIC={_e(r['params']['classic'])} · EXPECT={_e(','.join(r['params']['expect']) or '없음')} · SCOPE={_e(r['params'].get('scope', 'all'))} · TLS={_e(r['params']['tls_via'])}</div>
{basis}</div><p><span class="muted">receipt_id</span><br>{_short(r['receipt_id'])}</p>
<p class="muted">{_e(r['note'])}</p><pre>{w['verify']}</pre>
<p class="muted">판정은 아래 도구 출력과 종료 코드에서만 나온다. {w['app']}</p></section>"""]
    parts += body_sections(r)
    ch = r["changed"]
    parts.append(f"<h2>바뀐 파일</h2><section><p>추가 {_num(len(ch['added']))} · 삭제 {_num(len(ch['removed']))} · 수정 {_num(len(ch['modified']))} · "
                 f"{_link(ch['file'])} {_short(ch['file_sha256'])}</p></section>")
    parts.append("<h2>도구</h2><section>" + _table(["이름", "경로", "버전", "SHA-256"], [
        [_e(t["name"]), f"<code>{_e(t['path'])}</code>", _e(t["version"]), _short(t["sha256"])] for t in r["tools"]]) + "</section>")
    parts.append("<h2>시간</h2><section>" + _table(["단계", "시작(UTC)", "끝(UTC)"], [
        [_e(t["name"]), f'<span class="nowrap">{_e(t["started_at"])}</span>', f'<span class="nowrap">{_e(t["ended_at"])}</span>']
        for t in r["timeline"]]) + "</section>")
    parts.append("<h2>산출물</h2><section>" + _table(["파일", "바이트", "SHA-256"], [
        [_link(a["path"]), _num(a["bytes"]), _short(a["sha256"])] for a in r["artifacts"]]) + "</section>")
    parts.append(f"</main><script>{SCRIPT}</script></body></html>\n")
    return "".join(parts)


IMPL_NOTE = ("참조판 KAT 와 일치하는지 본 것이다(scan/kat-kpqc.json 의 판 이름과 .rsp SHA-256). PQ-Proof 는 구현을 빌드하거나 실행하지 "
             "않았고 답안은 사용자 하네스가 만들었다. 표준 준수 시험이나 공인 시험(KCMVP)이 아니다.")
IMPL_PQV_NOTE = ("NIST 구현 감사는 사용자가 켠 바깥 도구 pq-verify 가 대상 라이브러리를 불러 실행했고, PQ-Proof 는 그 JSON 보고서와 종료 "
                 "코드만 읽었다(셸 없이 부름, --require-full-coverage). pq-verify 는 샌드박스가 아니라서 믿지 못할 라이브러리는 컨테이너나 VM "
                 "안에서 돌린다. 표준 준수 인증이나 공인 시험이 아니고, 결과는 pq-verify 판과 그 고정 벡터에 따른다.")
ROLE_KO = {"reference": "참조판", "known-variant": "알려진 변형"}


def impl_rows(r):
    """파라미터 × 판 표의 칸(receipt.html·tables/impl.csv 가 같이 쓴다): (파라미터, 판, 역할, 받아 줌, 대조, 첫 불일치, 결과, 요약)."""
    rows = []
    for res in r["impl"]["results"]:
        for i, v in enumerate(res["versions"]):
            role = ROLE_KO.get(v["role"], v["role"]) + (" 최신" if v["latest"] else "")
            count = v["records"] if v["records"] is not None else (f"문항 {v['ok']}/{v['checked']}" if v["checked"] else "발췌 없음")
            rows.append((res["param"], v["version"], role, "예" if v["accepted"] else "", count, v["first_mismatch"] or "",
                         res["status"] if i == 0 else "", res["summary"] if i == 0 else ""))
    return rows


def nist_extra_args(n):
    """--pq-verify 인자에서 감사 옵션과 그 두 값(경로, 파라미터)을 뺀 나머지(--accumulated 1 처럼 표본 수·범위를 바꾸는 옵션이 보이게)."""
    args = list(n.get("args") or [])
    i = next((k for k, a in enumerate(args) if a.startswith("--audit-")), None)
    return args if i is None else args[:i] + args[i + 3:]


def nist_rows(r):
    """pq-verify 감사 표의 (항목, 값)(receipt.html·tables/report.md 가 같이 쓴다). impl.nist 가 없으면 []."""
    n = r["impl"].get("nist")
    if n is None:
        return []
    s = n["summary"]
    extra = nist_extra_args(n)
    tool = next((t for t in r["tools"] if t.get("name") == "pq-verify"), None)
    rows = [("결과", f"{STATUS_KO[n['status']]}: {n['detail']}"),
            ("pq-verify", (f"{n['executable']} ({(tool or {}).get('version') or '판 모름'})" if n["executable"] else f"없음: {n['not_run']}")),
            ("감사", (f"{s['audit'] or ''} {s['param_set'] or ''}".strip() or "모름")
             + (f" · 더 준 옵션 {' '.join(_impl_module().shown(a, 200) for a in extra)}" if extra else
                " · 더 준 옵션 없음(표본 수 등은 pq-verify 기본값)")),
            ("대상", f"{n['library']['path']} (sha256 {n['library']['sha256'] or '못 잼'})"),
            ("종료 코드", str(n["exit_code"]) if n["exit_code"] is not None else "없음"),
            ("보고서", f"{s['status'] or '없음'}, verified {s['verified']}, 검사 {s['checks_passed']}/{s['checks_total']}, "
                     f"schema {s['schema'] or '없음'} {s['schema_version'] or ''}".rstrip()),
            ("검사 범위", s["scope"] or "모름"),
            ("통과 못 한 단계", ", ".join(s["failed"]) or "없음")]
    if s["unavailable"] or s["degraded"]:
        rows.append(("돌지 못한 검사", "; ".join(s["unavailable"] + (["DEGRADED RUN"] if s["degraded"] else []))))
    rows.append(("뺀 환경 변수", ", ".join(n["env_removed"]) or "없음"))
    return rows


def render_impl_html(r):
    """구현 검증 증적의 receipt.html."""
    x = r["impl"]
    inp = x["input"]
    verdict = f'<span class="badge {_e("undecided" if pending_note(r) else r["verdict"])}">{_e(verdict_text(r))}</span>'
    basis = (f"<div><div class=\"muted\">판정 근거</div>pqproof {_e(r.get('tool_version'))} · 규칙 묶음 {_e(r.get('ruleset_version'))} · "
             f"증적 형식 {_num(r['format_version'])}<br>{_short(r.get('ruleset_sha256'))}</div>")
    answer = ("<div><div class=\"muted\">답안</div>없음(KpqC KAT 대조를 하지 않음)</div>" if inp is None else
              f"<div><div class=\"muted\">답안</div><code>{_e(inp['path'])}</code><br><span class=\"muted\">"
              f"{_e({'response': '답안 JSON', 'rsp': 'PQCgenKAT .rsp'}.get(inp['kind'], '읽지 않음'))} · {_num(inp['bytes'])}바이트</span> "
              f"{_short(inp['sha256'])}" + (f"<br><span class=\"muted\">구현</span> {_e(inp['implementation'])}" if inp["implementation"] else "")
              + (f"<br><span class=\"muted\">머리 줄</span> <code>{_e(inp['header'])}</code>" if inp["header"] else "") + "</div>")
    params = (f"<div><div class=\"muted\">매개변수</div>PROFILE={_e(r['params']['profile'])} · 파라미터 "
              f"{_e(', '.join(r['params']['params']) or '없음')}<br><span class=\"muted\">받아 줄 판</span> {_e(', '.join(x['accept']) or '없음')}</div>")
    rows = [[f"<code>{_e(a)}</code>", _e(b), _e(c), _e(d), f'<span class="num">{_e(e)}</span>', _e(f), _status(g) if g else "", _e(h)]
            for a, b, c, d, e, f, g, h in impl_rows(r)]
    title = " · ".join(t for t, on in (("KpqC 구현 KAT 대조", inp is not None), ("NIST 구현 감사", x.get("nist") is not None)) if on)
    ctrl = ("답안이 없어 자기 점검을 하지 않았다" if inp is None else "자기 점검 통과: 받아 줄 판의 정답 답안은 통과, 한 바이트 바꾼 답안은 실패"
            if x["control"]["ok"] else f"자기 점검 실패: {x['control']['problem']}")
    files = " · ".join(f"{_link(f['file'], label)} {_short(f['file_sha256'])}" for f, label in
                       ((inp, "답안 사본"), (x["key"], "정답 묶음"), (x["prompt"], "문제지")) if f and f.get("file"))
    n = x.get("nist")
    nist = "" if n is None else (
        "<h2>NIST 구현 감사(pq-verify)</h2><section>" + _table(["항목", "값"], [[_e(a), _e(b)] for a, b in nist_rows(r)])
        + "<p>" + " · ".join(f"{_link(path, label)} {_short(digest)}" for path, digest, label in
                             ((n["report"], n["report_sha256"], "보고서"), (n["log"], n["log_sha256"], "실행 기록")) if path) + "</p>"
        + f"<p class=\"muted\">{_e(IMPL_PQV_NOTE)}</p></section>")
    parts = [f"""<!doctype html><html lang="ko" data-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src {SCRIPT_CSP}; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>{_e(title)}</title><style>{STYLE}</style></head><body><main>
<header><h1>{_e(title)} 증적 {verdict}</h1><button id="theme" type="button">라이트</button></header>
<section><div class="grid">{answer}
<div><div class="muted">시작, 끝(UTC)</div><span class="nowrap">{_e(r['started_at'])}</span><br><span class="nowrap">{_e(r['finished_at'])}</span></div>
{params}
{basis}</div><p><span class="muted">receipt_id</span><br>{_short(r['receipt_id'])}</p>
<p class="muted">{_e(r['note'])}</p><pre>{WORDS['verify']}</pre>
<p>{_e(IMPL_NOTE if inp is not None else IMPL_PQV_NOTE)}</p></section>"""]
    parts.append("<h2>검사</h2><section>" + _table(["검사", "판정", "기준", "실제"], [
        [f"<b>{_e(c['id'])}</b> {_e(c['title'])}", _status(c["status"]), _e(c["expected"]), _e(c["actual"])] for c in r["checks"]])
        + "</section>")
    if inp is not None:
        parts.append("<h2>파라미터별 참조판 대조</h2><section>" + (f'<p class="s-undecided">{_e(x["problem"])}</p>' if x["problem"] else "")
                     + _table(["파라미터", "판", "역할", "받아 줌", "대조", "첫 불일치", "결과", "요약"], rows)
                     + f'<p class="{"muted" if x["control"]["ok"] else "s-undecided"}">{_e(ctrl)}</p>'
                     + f"<p>{files}</p></section>")
    if nist:
        parts.append(nist)
    parts.append("<h2>도구</h2><section>" + _table(["이름", "경로", "버전", "SHA-256"], [
        [_e(t["name"]), f"<code>{_e(t['path'])}</code>", _e(t["version"]), _short(t["sha256"])] for t in r["tools"]]) + "</section>")
    parts.append("<h2>시간</h2><section>" + _table(["단계", "시작(UTC)", "끝(UTC)"], [
        [_e(t["name"]), f'<span class="nowrap">{_e(t["started_at"])}</span>', f'<span class="nowrap">{_e(t["ended_at"])}</span>']
        for t in r["timeline"]]) + "</section>")
    parts.append("<h2>산출물</h2><section>" + _table(["파일", "바이트", "SHA-256"], [
        [_link(a["path"]), _num(a["bytes"]), _short(a["sha256"])] for a in r["artifacts"]]) + "</section>")
    parts.append(f"</main><script>{SCRIPT}</script></body></html>\n")
    return "".join(parts)


# ---------------------------------------------------------------------------------------------
# deck.json: 발표 자료·대시보드에 옮기기 쉬운 요약. receipt.json만으로 결정적으로 만든다(verify가 다시 만들어 비교).
CHECK_LABEL = {"a-input": "입력 대조", "a-cbom": "막는 고전 위치 0", "b-weakening": "TLS 약화 없음", "b-tls": "TLS 하이브리드 협상",
               "c-classic": "사유 없는 고전 줄 0", "c-expect": "ML-KEM·ML-DSA 사용", "r-review": "검증 호출 유지",
               "r-allow": "허용 항목 사람 확인", "i-kpqc": "KpqC 참조판 KAT 일치", "i-nist": "NIST PQC 구현 감사(pq-verify)"}
HYBRID_WHY = "같은 함수 안 ML-KEM 결합(하이브리드 고전 성분)"
LEGACY_WHY = "이름 규칙: Legacy*.java 파일이거나 같은 줄에 legacy, 그 줄에 쓰기 연산 없음(옛 자료 읽기·검증)"


def _ranges(nums):
    nums, out = sorted(set(nums)), []
    for n in nums:
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return ",".join(f"{a}-{b}" if a != b else str(a) for a, b in out)


def _short_where(e):
    """허용 항목의 짧은 위치: 줄 범위면 '파일이름:시작-끝', 파일이면 경로(여럿이면 '폴더/ 파일 n개')."""
    lines = [t for t in e["targets"] if re.search(r":[0-9][0-9,-]*$", t)]
    files = [t for t in e["targets"] if t not in lines]
    out = [t.rsplit("/", 1)[-1] for t in lines]
    if len(files) == 1:
        out.append(files[0])
    elif files:
        top = posixpath.commonpath(files) if len(files) > 1 else files[0]  # 증적 경로는 늘 '/'(Windows 에서도 같은 deck.json)
        out.append(f"{top}/ 파일 {len(files)}개")
    return ", ".join(out) or e["where"]


def _deck_nist(n):
    """deck.json 의 pq-verify 감사 요약(없으면 None)."""
    if n is None:
        return None
    s = n["summary"]
    return {"status": n["status"], "detail": n["detail"], "audit": s["audit"], "param_set": s["param_set"], "tool_version": s["tool_version"],
            "checks_passed": s["checks_passed"], "checks_total": s["checks_total"]}


def deck_view(r):
    """deck.json(요약). 전후 숫자의 뜻:
    cbom.before·after = 고전 공개키 자산 위치(막는 위치 + 허용 + 검토 필요), blocking_* = 그중 막는 위치(판정을 정하는 수).
    classic_lines.before·after = residue 공개키 9계열 code 줄 합(허용 줄 포함), allowed = 사유가 기록된 허용(허용 목록 + 하이브리드 결합),
    hybrid·review = 그중 하이브리드·검토 필요, left = 허용 안 된 남은 줄(판정을 정하는 수). legacy_rule = residue 가 이름 규칙
    (Legacy*.java·같은 줄 legacy)으로 code 밖 allow 칸에 센 줄(after 에 안 들어간다). allowed[] 의 kind hybrid·legacy-name 은
    허용 목록 밖에서 규칙으로 빠진 위치라 따로 적는다(숨기지 않는다). ev 는 실행 기록 파일 이름 목록.
    사람 확인 칸이 있는 증적은 verdict_text·verdict_text_en('통과(허용 2건 사람 확인 전)'), allow_unreviewed(확인 전 허용 항목 수),
    허용 목록 항목의 reviewed_by·reviewed_at(없으면 null)을 더 적는다. hybrid·legacy-name 은 규칙이라 이 칸이 없다."""
    m = r["deck_meta"]
    if is_impl(r):  # 구현 검증(형식 4): 파라미터마다 맞은 판과 상태
        return {"verdict": r["verdict"], "verdict_text": verdict_text(r), "verdict_text_en": verdict_text(r, en=True),
                "receipt": r["receipt_id"][:12], "receipt_file": m["receipt_file"], "mode": "impl",
                "impl": [{"param": x["param"], "name": x["name"], "status": x["status"], "matched": x["matched"], "summary": x["summary"]}
                         for x in r["impl"]["results"]],
                "accept": r["impl"]["accept"], "control_ok": r["impl"]["control"]["ok"],
                "nist": _deck_nist(r["impl"]["nist"]),
                "checks": [{"id": c["id"], "status": c["status"], "label": CHECK_LABEL.get(c["id"], c["title"])} for c in r["checks"]],
                "verify_cmd": m["verify_cmd"], "ev": [m["ev"]], "tool_version": r["tool_version"],
                "ruleset_version": r["ruleset_version"], "format_version": r["format_version"]}
    co, cf = r["cbom"]["orig"], r["cbom"]["fixed"]
    jo, jf = r["java"]["orig"], r["java"]["fixed"]
    lst = (jf or {}).get("listed") or {}
    raw = lambda j: sum(v["code"] for v in j["families"].values()) if j else None  # noqa: E731
    left = None if jf is None else raw(jf) - lst.get("allowed", 0) - lst.get("hybrid", 0) - lst.get("review", 0)
    a = r.get("allowlist") or {}
    rv = "unreviewed" in a  # 사람 확인 칸이 있는 증적만 새 칸을 적는다(옛 deck.json이 그대로 맞게)
    allowed = [{"where": _short_where(e), "kind": e["kind"], "why": e["why"], "what": e["what"], "status": e["status"],
                "lines": len(e["allowed"]) + len(e["review"]),
                **({"reviewed_by": e.get("reviewed_by"), "reviewed_at": e.get("reviewed_at")} if rv else {})}
               for e in a.get("entries", []) if e["status"] in ("allowed", "review", "excluded")]
    for key, kind, why in (("hybrid", "hybrid", HYBRID_WHY), ("legacy", "legacy-name", LEGACY_WHY)):
        by_file = {}
        for loc in a.get(key, []):
            f, _, n = loc.rpartition(":")
            if n.isdigit():
                by_file.setdefault(f, []).append(int(n))
        allowed += [{"where": f"{f.rsplit('/', 1)[-1]}:{_ranges(ns)}", "kind": kind, "why": why, "what": "", "status": "allowed",
                     "lines": len(ns)} for f, ns in sorted(by_file.items())]
    tls = None
    ts = r["tls"]["targets"]
    if ts:
        groups = [t["hybrid"].get("group") for t in ts if t["hybrid"].get("group")]
        tls = {"hybrid": all(t["hybrid"].get("group") == "X25519MLKEM768" for t in ts), "group": groups[0] if groups else None,
               "classic_client": "accept" if any(t["classical"].get("group") for t in ts) else "reject"}
    exp = (jf or {}).get("expect", {})
    x = r.get("excluded") or {}
    side = lambda c: c["blocking"] + c["allowed"] + c.get("review", 0)  # noqa: E731
    d = {"verdict": r["verdict"],
         **({"verdict_text": verdict_text(r), "verdict_text_en": verdict_text(r, en=True), "allow_unreviewed": a["unreviewed"]}
            if rv else {}),
         "receipt": r["receipt_id"][:12], "receipt_file": m["receipt_file"],
         "cbom": {"before": side(co), "after": side(cf), "blocking_before": co["blocking"], "blocking_after": cf["blocking"],
                  "allowed_after": cf["allowed"], "review_after": cf.get("review", 0)},
         "classic_lines": {"before": raw(jo), "after": raw(jf),
                           "allowed": None if jf is None else lst.get("allowed", 0) + lst.get("hybrid", 0),
                           "hybrid": None if jf is None else lst.get("hybrid", 0),
                           "review": None if jf is None else lst.get("review", 0), "left": left,
                           "legacy_rule": None if jf is None else sum(v["allow"] for v in jf["families"].values())},
         "pqc_lines": {"mlkem": exp.get("E-MLKEM768"), "mldsa": exp.get("E-MLDSA65")},
         "allowed": allowed,
         "allow_invalid": sum(1 for e in a.get("entries", []) if e["status"] == "invalid"),
         **({"allow_unused": a["unused"], "allow_unused_orig_lines": a.get("unused_orig_lines", 0),
             "allow_write_review": a.get("write_review", 0)} if "unused" in a else {}),
         "checks": [{"id": c["id"], "status": "skip" if c["status"] == "na" else c["status"],
                     "label": CHECK_LABEL.get(c["id"], c["title"])} for c in r["checks"]],
         "excluded": [i["pattern"] for i in x.get("items", [])],
         "excluded_files": {"orig": x.get("count_orig", 0), "fixed": x.get("count_fixed", 0)},
         "tls": tls, "verify_cmd": m["verify_cmd"], "ev": [m["ev"]],
         **({"tool_version": r.get("tool_version"), "ruleset_version": r.get("ruleset_version"), "format_version": r["format_version"]}
            if format_version(r) >= 2 else {})}
    return d


def render_deck(r):
    return json.dumps(deck_view(r), indent=1, ensure_ascii=False) + "\n"


FRAGMENT_STYLE = (".pqcproof{font:14px/1.5 -apple-system,BlinkMacSystemFont,'Apple SD Gothic Neo',sans-serif;word-break:keep-all;"
                  "overflow-wrap:break-word}.pqcproof table{border-collapse:collapse;width:100%;font-size:13px}"
                  ".pqcproof th,.pqcproof td{border-bottom:1px solid #8884;padding:4px 6px;text-align:left;vertical-align:top}"
                  ".pqcproof th{white-space:nowrap}.pqcproof .num,.pqcproof .nowrap{white-space:nowrap;font-variant-numeric:tabular-nums}"
                  ".pqcproof .s-pass{color:#1a7f37;font-weight:600}.pqcproof .s-fail{color:#cf222e;font-weight:600}"
                  ".pqcproof .s-undecided,.pqcproof .s-review,.pqcproof .s-check{color:#9a6700;font-weight:600}"
                  ".pqcproof .muted,.pqcproof .s-na{color:#6e7781}.pqcproof .wrap{overflow-x:auto}"
                  ".pqcproof code{font-family:ui-monospace,Menlo,monospace;font-size:12px}")


def render_fragment(r):
    """다른 HTML 문서에 붙일 <section class="pqcproof"> 하나. 스타일은 클래스 아래로 한정, 스크립트 없음."""
    return (f'<section class="pqcproof"><style>{FRAGMENT_STYLE}</style>'
            f"<p><b>PQC 전환 검증(prove.sh)</b> 판정 <b>{_e(verdict_text(r))}</b> · 고친 판 트리 sha256 "
            f"<code>{_e(r['inputs']['fixed']['tree_sha256'])}</code>"
            + (f" · zip sha256 <code>{_e(r['inputs']['fixed']['zip_sha256'])}</code>" if r['inputs']['fixed']['zip_sha256'] else "")
            + " · receipt_id는 같은 폴더 receipt.json</p>"
            + "".join(body_sections(r)) + "</section>\n")


def main(argv):
    """verify DIR: 검사마다 한 줄, 모두 통과일 때만 0."""
    if len(argv) != 2 or argv[0] != "verify":
        print("usage: python3 -I -B pqlite/receipt.py verify RECEIPT_DIR")
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # 한국어를 못 찍는 콘솔(Windows cp1252 등)에서도 죽지 않게
    if not os.path.isdir(argv[1]):
        print(f"verify: no such folder: {argv[1]} (usage or input error, exit 2)", file=sys.stderr)
        return 2
    if not os.path.lexists(os.path.join(argv[1], "receipt.json")):
        print(f"verify: {argv[1]} has no receipt.json; give the folder a PQ-Proof run wrote (usage or input error, exit 2)",
              file=sys.stderr)
        return 2
    try:
        results = verify(argv[1])
    except Exception as e:  # noqa: BLE001  도구 오류는 변조(1)와 가른다(교차 리뷰 X62)
        import traceback
        traceback.print_exc()
        print(f"verify: tool error ({type(e).__name__}: {str(e)[:200]}), not a verdict on the evidence (exit 4)", file=sys.stderr)
        return 4
    for ok, what in results:
        print(f"{'ok  ' if ok else 'FAIL'} {what}")
    bad = sum(1 for ok, _ in results if not ok)
    print(f"{'all checks pass' if not bad else f'{bad} check(s) failed'} ({len(results)} checks)")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
