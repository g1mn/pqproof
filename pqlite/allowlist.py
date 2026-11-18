# 허용 목록(전환 에이전트의 notes/unconverted.json)과 실행 데이터 제외(EXCLUDE 글롭, notes/recon.json 의 DATA_DIR)를 읽는다.
# 호환 때문에 일부러 남긴 옛 코드 경로(옛 키 로더·옛 서명 검증)와 앱 폴더 안 실행 데이터(키 파일·DB)가 '남은 고전'으로 세여,
# 전환이 끝났는데도 prove.sh 가 실패하던 꼴을 고치려고 만들었다. 판정 규칙은 DESIGN.md 'Allow rules'.
# 표준 라이브러리만 쓴다. 받은 소스의 코드는 실행하지 않는다(파일 줄 수만 센다).
"""허용 목록과 제외 글롭.

허용 목록 항목: {"where": "Sealer.java:78-84", "what": ..., "why": ..., "kind": "fallback|boundary|kept|..."}
  where 꼴: '파일:줄', '파일:시작-끝', '파일:15,24-40,50', 경로·글롭('/app/data/keys/<user>.pem, service.log.pem'),
           ' · '·';'로 여러 자리. 끝 괄호 설명('(저장소 밖)')은 뗀다. <user>·{user} 는 * 로 읽는다.
  파일 이름만 쓰면 고친 판에서 그 이름으로 끝나는 파일 하나를 찾는다(둘 이상이면 무효).
  컨테이너 절대 경로는 recon.json 의 앱 루트(cd /app && …)를 떼고, 모르면 가장 긴 꼬리 경로로 찾는다.
무효(허용하지 않고 경고로 남김): where·why 없음, 파일 없음, 파일 이름이 여러 파일에 걸림, 파일 줄 수를 넘는 범위,
  코드 파일을 글롭으로 여러 개 잡음. 한 자리라도 무효면 그 항목 전체를 허용하지 않는다(줄 번호가 밀린 항목을 믿지 않는다).
트리 밖(outside, 허용할 것 없음·경고 아님): 못 찾은 자리가 스스로 트리 밖이라고 적혔거나('(저장소 밖)'·'앱 폴더 밖'),
  recon.json 앱 루트 밖 절대 경로(/var/lib/svc/… 처럼 앱 /opt/svc 밖)일 때. 그 자리는 아무것도 허용하지 않는다.
사람 확인(선택): 항목에 reviewed_by(사람 이름·계정)와 reviewed_at(ISO 8601 날짜 또는 날짜·시각)을 함께 적는다. 목록이
  {"unconverted": [...]} 꼴이면 맨 위에 한 번 적어 자기 칸이 없는 항목 모두에 물려줄 수 있다(항목에 둘 중 하나라도 있으면 항목 값).
  맨 위 칸은 reviewed_digest(물려받는 항목들의 where·what·why·kind 해시 앞 16자리, 실행할 때 지금 값을 찍어 준다)가 맞을 때만
  물려준다. 확인 뒤 항목을 더하거나 고치면 값이 달라져 물려받던 항목이 모두 '사람 확인 전'으로 돌아간다. 항목 자기 칸에도
  reviewed_digest 를 적을 수 있고(선택), 적었으면 맞아야 한다. 두 칸이 없거나 null 이면 '사람 확인 전'이다. 빈 글자, 한 칸만 있음,
  제어 문자, 날짜가 아닌 reviewed_at, 맞지 않는 reviewed_digest 는 경고를 남기고 '사람 확인 전'으로 센다(항목은 무효가 아니다:
  허용 판정과 사람 확인 기록을 섞지 않는다). 확인 전 허용 항목은 판정 옆에 '허용 n건 사람 확인 전'으로 적고, REQUIRE_REVIEW=1 이면
  실패다(prove.py r-allow).
안 쓰인 항목(unused): 고친 판에서 덮은 고전 줄이 0인 유효 항목. 목록은 고친 판 기준으로 쓰지만 어느 트리에 대든 그대로 걸린다.
  그래서 고친 판에서 안 쓰인 항목은 원본 같은 다른 트리에 대면 그 범위의 고전 줄을 가린다(결함 D1).
  note_other()가 같은 목록을 원본 트리로도 풀어 항목마다 원본에서 덮는 고전 줄을 세고(판정에는 안 쓴다), 안 쓰인 항목이 덮는
  원본 줄은 '사람 확인 전'으로 경고에 남긴다. 판정은 바꾸지 않고 r-allow 를 검토 필요로, REQUIRE_REVIEW=1 이면 실패로 만든다.
  고친 판에서 무효·제외·트리 밖이라 아무것도 덮지 않는데 원본에서는 고전 줄을 덮는 항목(고친 판에서 지운 파일, 줄어든 파일을
  가리킨 항목)도 안 쓰인 항목으로 센다(counts_unused). 원본 트리에서는 그 항목이 유효해서 그 줄을 가리기 때문이다.
"""
import datetime
import fnmatch
import hashlib
import json
import os
import re

CODE_FILE = re.compile(r"\.(?:java|kt|kts|scala|groovy|go|py|js|mjs|cjs|jsx|ts|tsx|rs|c|h|cc|cpp|hpp|cs|rb|php|swift|sh)$", re.I)
LINES = re.compile(r"^(?P<path>.*\S)\s*:\s*(?P<lines>[0-9]+(?:\s*-\s*[0-9]+)?(?:\s*,\s*[0-9]+(?:\s*-\s*[0-9]+)?)*)$")
PLACEHOLDER = re.compile(r"<[^<>/]{1,40}>|\{[^{}/]{1,40}\}")
SEGMENTS = re.compile(r"\s+·\s+|\s*;\s*|\s+및\s+")
GLOB = re.compile(r"[*?\[]")
WIDE = 80  # 코드 파일 범위가 이보다 길면 경고(허용은 한다)
# 자리가 스스로 제출 트리 밖이라고 적은 말(괄호 설명 포함). 이런 자리를 못 찾으면 무효가 아니라 '트리 밖'(허용할 것 없음)
OUTSIDE_NOTE = re.compile(r"컨테이너\s*밖|앱\s*폴더\s*밖|트리\s*밖|저장소\s*밖|\(\s*맥\b|맥\s*(?:에|쪽)|outside", re.I)
# 실행 데이터 제외에서 빼지 않는 파일: 코드와 동작을 정하는 설정·빌드 파일(EXCLUDE='src/**' 로 고전 코드를 감추는 거짓 통과를 막는다)
KEEP_FILE = re.compile(CODE_FILE.pattern + r"|\.(?:ya?ml|properties|conf|cnf|toml|ini|gradle|xml|env)$|(?:^|/)(?:Dockerfile[^/]*|"
                       r"Makefile|go\.mod|go\.sum|package\.json|requirements[^/]*\.txt|pyproject\.toml|setup\.cfg|nginx[^/]*)$", re.I)


# 사람 확인 칸. reviewed_at: 2026-11-18, 2026-11-18T10:30, 2026-11-18T10:30:00+09:00, 2026-11-18 10:30:00.5Z 같은 꼴
REVIEW_KEYS = ("reviewed_by", "reviewed_at")
REVIEW_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[T ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.[0-9]{1,9})?)?"
                         r"(Z|[+-]([0-9]{2}):?([0-9]{2}))?)?")
# 이름에 넣으면 안 되는 글자: C0·DEL·C1, 폭 없는 글자, 줄·문단 구분자, 양방향 제어(U+202A~202E, U+2066~2069), BOM
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁠-⁩﻿]")
IN_EFFECT = ("allowed", "review")  # 줄을 실제로 판정에서 뺀 항목(사람 확인 전을 세는 대상)
OTHER_MAX = 400  # 항목마다 증적에 적는 원본 덮은 줄 목록 길이(수는 따로 다 센다)
DIGEST_FIELDS = ("where", "what", "why", "kind")  # reviewed_digest 가 덮는 칸(사람이 읽은 글)
DIGEST_LEN = 16
DEAD = ("invalid", "excluded", "outside")  # 고친 판에서 아무 줄도 판정에서 빼지 않는 상태


def counts_unused(status, orig_lines):
    """안 쓰인 항목으로 세는가. 고친 판에서 덮은 고전 줄 0인 유효 항목(unused)이거나, 고친 판에서는 무효·제외·트리 밖이라 아무것도
    덮지 않는데 원본에서는 고전 줄을 덮는 항목(orig_lines > 0). 뒤의 것은 원본 같은 다른 트리에 대면 유효해져 그 줄을 가린다.
    receipt.consistency 가 증적의 status·lines_orig 로 같은 식을 다시 센다."""
    return status == "unused" or (status in DEAD and orig_lines > 0)


def review_time_ok(text):
    m = REVIEW_TIME.fullmatch(text)
    if not m:
        return False
    try:
        datetime.datetime(*(int(m[i] or 0) for i in range(1, 7)))
    except ValueError:  # 2026-02-30, 25:00 같은 값
        return False
    return not m[7] or m[7] == "Z" or (int(m[8]) < 24 and int(m[9]) < 60)


def review_stamp(src):
    """항목(또는 목록 맨 위) dict → (reviewed_by, reviewed_at, 오류). 두 칸이 다 없거나 null 이면 (None, None, None)."""
    if not isinstance(src, dict) or all(src.get(k) is None for k in REVIEW_KEYS):
        return None, None, None
    by, at = src.get("reviewed_by"), src.get("reviewed_at")
    if not isinstance(by, str) or not by.strip():
        return None, None, "reviewed_by 가 없거나 비었음(사람 이름·계정을 reviewed_at 과 함께 적는다)"
    if CONTROL.search(by):
        return None, None, "reviewed_by 에 줄바꿈·제어 문자"
    if at is None:
        return None, None, "reviewed_at 없음(reviewed_by 와 함께 적는다)"
    if not isinstance(at, str) or not review_time_ok(at.strip()):
        return None, None, f"reviewed_at 이 ISO 8601 날짜·시각이 아님: {CONTROL.sub(' ', str(at))[:40]!r}"
    return by.strip(), at.strip(), None


def review_digest(items):
    """항목들 → 사람 확인 칸이 덮는 글(where·what·why·kind)의 SHA-256 앞 16자리. reviewed_digest 에 옮겨 적는 값이다.
    칸마다 앞뒤 공백을 떼고(글이 아니면 빈 글) 키 정렬·공백 없는 JSON 배열로 만들어 잰다. 가리킨 코드 줄의 내용은 들어가지 않는다."""
    rows = [{k: (x[k].strip() if isinstance(x, dict) and isinstance(x.get(k), str) else "") for k in DIGEST_FIELDS} for x in items]
    text = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:DIGEST_LEN]


def entries_of(data):
    """허용 목록 JSON → 항목 배열(못 찾으면 None). 배열 그대로이거나 {"unconverted"|"items"|"entries": [...]}."""
    if isinstance(data, dict):
        data = next((data[k] for k in ("unconverted", "items", "entries") if isinstance(data.get(k), list)), None)
    return data if isinstance(data, list) else None


def resolve_reviews(data):
    """허용 목록 JSON(통째) → (항목별 {"by", "at", "via"}, 경고 목록, 맨 위 칸 상태, 자기 칸 없는 항목 번호, 그 항목들의 지금 digest).
    via: 'entry'(항목 자기 칸), 'top'(목록 맨 위 칸, reviewed_digest 가 지금 내용과 맞을 때), None(사람 확인 전).
    맨 위 칸 상태: 'none'(맨 위 칸 없음), 'ok'(물려줌), 'bad'(꼴이 틀리거나 digest 가 없거나 다름).
    고친 판 트리를 보지 않으므로 --verify 가 증적 폴더의 목록 사본(artifacts/allow-list.json)으로 같은 결과를 다시 낸다."""
    items = entries_of(data) or []
    out, warns, inherit = [], [], []
    for i, raw in enumerate(items, 1):
        x = {"by": None, "at": None, "via": None}
        out.append(x)
        if not isinstance(raw, dict) or all(raw.get(k) is None for k in REVIEW_KEYS):
            inherit.append(i)
            continue
        by, at, err = review_stamp(raw)
        if err:
            warns.append(f"#{i} 사람 확인 칸을 받지 않음({err}): 사람 확인 전으로 셈")
            continue
        given = raw.get("reviewed_digest")
        if given is not None:
            want = review_digest([raw])
            if not (isinstance(given, str) and given.strip().lower() == want):
                warns.append(f"#{i} reviewed_digest 가 지금 항목과 다름(확인 뒤 where·what·why·kind 가 바뀜): 사람 확인 전으로 셈. "
                             f"지금 값 {want}")
                continue
        x.update(by=by, at=at, via="entry")
    top_digest = review_digest([items[i - 1] for i in inherit]) if inherit else None
    by, at, err = review_stamp(data)
    if not (by or err):
        return out, warns, "none", inherit, top_digest
    given = data.get("reviewed_digest")
    if err:
        why = f"목록 맨 위 사람 확인 칸을 받지 않음({err})"
    elif not inherit:
        return out, warns, "ok", inherit, top_digest  # 모든 항목이 자기 칸을 써서 맨 위 칸이 덮는 것이 없다
    elif given is None:
        why = "목록 맨 위 사람 확인 칸에 reviewed_digest 가 없음(어느 항목을 확인했는지 묶이지 않음)"
    elif not (isinstance(given, str) and given.strip().lower() == top_digest):
        why = "목록 맨 위 reviewed_digest 가 지금 목록과 다름(확인 뒤 항목을 더하거나 고침)"
    else:
        for i in inherit:
            out[i - 1].update(by=by, at=at, via="top")
        return out, warns, "ok", inherit, top_digest
    if inherit:
        warns.append(f"{why}: 자기 칸이 없는 항목 {len(inherit)}건을 사람 확인 전으로 셈. 지금 값 reviewed_digest={top_digest}")
    else:
        warns.append(why)
    return out, warns, "bad", inherit, top_digest


def strip_note(s):
    """끝에 붙은 괄호 설명을 뗀다('a.tgz (저장소 밖)' → 'a.tgz'). 괄호가 짝이 안 맞으면 그대로."""
    s = s.strip()
    while s.endswith(")") or s.endswith("）"):
        depth, cut = 0, None
        for i in range(len(s) - 1, -1, -1):
            c = s[i]
            if c in ")）":
                depth += 1
            elif c in "(（":
                depth -= 1
                if depth == 0:
                    cut = i
                    break
        if cut is None or cut == 0:
            break
        s = s[:cut].rstrip()
    return s


def parse_ranges(text):
    out = []
    for part in text.split(","):
        part = part.strip()
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = b = int(part)
        out.append([min(a, b), max(a, b)])
    return out


def _note(s):
    """끝 괄호 설명만(없으면 빈 글)."""
    t = s.strip()
    return t[len(strip_note(t)):]


def parse_where(where):
    """where 글 → [(경로 후보 목록, 범위 목록 또는 None, 트리 밖이라고 적혔나)]. 경로 후보는 앞의 것부터 찾는다(디렉터리 물려받기 → 그대로).
    트리 밖 표시는 그 자리(또는 마지막 자리면 where 끝)의 괄호 설명에 '저장소 밖'·'앱 폴더 밖' 같은 말이 있을 때다."""
    out = []
    body = strip_note(where)
    tail_out = bool(OUTSIDE_NOTE.search(_note(where)))
    segs = SEGMENTS.split(body)
    for si, seg_raw in enumerate(segs):
        seg = strip_note(seg_raw).strip(" `'\"")
        if not seg:
            continue
        seg_out = bool(OUTSIDE_NOTE.search(_note(seg_raw))) or (si == len(segs) - 1 and tail_out)
        m = LINES.match(seg)
        if m and "," not in m["path"]:
            out.append(([m["path"].strip(" `'\"")], parse_ranges(m["lines"]), seg_out))
            continue
        base = ""
        for item_raw in seg.split(","):
            item = strip_note(item_raw).strip(" `'\"")
            if not item:
                continue
            m = LINES.match(item)
            path, ranges = (m["path"].strip(" `'\""), parse_ranges(m["lines"])) if m else (item, None)
            if ":" in path and not m:  # 'data/x.sqlite3:records.blob' 처럼 줄 번호가 아닌 꼬리
                path = path.split(":", 1)[0]
            cands = [path]
            if "/" in path:
                base = path.rsplit("/", 1)[0] + "/"
            elif base:
                cands = [base + path, path]
            out.append((cands, ranges, seg_out or bool(OUTSIDE_NOTE.search(_note(item_raw)))))
    return out


def outside_roots(spec, app_roots):
    """절대 경로가 알려진 앱 루트 밖인가(앱 루트를 모르면 False: 판단하지 않는다)."""
    spec = _norm(spec)
    roots = [r.rstrip("/") for r in app_roots if r]
    return bool(spec.startswith("/") and roots and not any(spec == r or spec.startswith(r + "/") for r in roots))


def _globify(p):
    return PLACEHOLDER.sub("*", p)


def _norm(p):
    p = p.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def find(spec, files, app_roots=()):
    """경로·글롭 하나 → 고친 판 상대 경로 목록(정렬). 절대 경로는 앱 루트를 떼고, 모르면 가장 긴 꼬리로."""
    spec = _globify(_norm(spec))
    if not spec:
        return []
    if spec.startswith("/"):
        tried = []
        for root in sorted({r.rstrip("/") for r in app_roots if r}, key=len, reverse=True):
            if spec == root or spec.startswith(root + "/"):
                tried.append(spec[len(root) + 1:])
        parts = [x for x in spec.strip("/").split("/") if x]
        tried += ["/".join(parts[k:]) for k in range(len(parts)) if len(parts) - k >= min(2, len(parts))]
        for t in tried:
            got = _match(t, files)
            if got:
                return got
        return []
    return _match(spec, files)


def _match(spec, files):
    if not spec:
        return []
    if spec.endswith("/"):
        spec += "**"
    if GLOB.search(spec):
        pat = spec.replace("**", "*")
        hits = [f for f in files if fnmatch.fnmatchcase(f, pat) or fnmatch.fnmatchcase(f, "*/" + pat)]
        if "/" not in spec:
            hits += [f for f in files if fnmatch.fnmatchcase(f.rsplit("/", 1)[-1], pat)]
        return sorted(set(hits))
    exact = [f for f in files if f == spec]
    if exact:
        return exact
    under = [f for f in files if f.startswith(spec + "/")]  # 폴더 이름
    if under:
        return sorted(under)
    return sorted(f for f in files if f.endswith("/" + spec))


class AllowList:
    """resolve()가 끝난 허용 목록. match(path, line)는 그 줄을 덮는 첫 유효 항목을 돌려준다."""

    def __init__(self, source=None):
        self.source = source
        self.entries = []
        self.warnings = []
        self.index = {}  # 상대 경로 → [(항목, 범위 목록 또는 None)]
        self.top_state, self.inherit, self.top_digest = "none", [], None  # 목록 맨 위 사람 확인 칸(resolve_reviews)
        self.other_checked = False  # note_other()로 원본 트리에서도 풀어 봤나

    @classmethod
    def load(cls, path, files, line_count, app_roots=(), excluded=frozenset()):
        """path(JSON) → AllowList. files: 고친 판 전체 상대 경로, line_count(rel) → 줄 수(못 읽으면 None),
        excluded: 검사에서 뺀 상대 경로(그 파일만 가리키는 항목은 '검사 범위 밖')."""
        al = cls(path)
        if not path:
            return al
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            al.warnings.append(f"허용 목록 파일 없음: {path}")
            return al
        except (OSError, ValueError) as e:
            al.warnings.append(f"허용 목록을 못 읽음({type(e).__name__}): {str(e)[:160]}")
            return al
        items = entries_of(data)
        if items is None:
            al.warnings.append("허용 목록이 배열이 아님(항목 배열 또는 {\"unconverted\": [...]})")
            return al
        reviews, review_warns, al.top_state, al.inherit, al.top_digest = resolve_reviews(data)
        fileset = sorted(files)
        soon = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
        for i, raw in enumerate(items, 1):
            e = al._resolve(i, raw, fileset, line_count, app_roots, excluded)
            x = reviews[i - 1]
            e["reviewed_by"], e["reviewed_at"], e["reviewed_via"] = x["by"], x["at"], x["via"]
            e["digest"] = review_digest([raw])
            if x["at"] and x["at"][:10] > soon:  # 받기는 하되 알린다(시계·오타 확인)
                review_warns.append(f"#{i} reviewed_at 이 미래 날짜({x['at'][:10]})")
            al.entries.append(e)
        al.warnings += review_warns
        for e in al.entries:
            if e["status"] in ("pending",):
                for t in e["targets"]:
                    al.index.setdefault(t["path"], []).append((e, t["ranges"]))
        return al

    def _resolve(self, n, raw, files, line_count, app_roots, excluded):
        e = {"n": n, "where": "", "what": "", "why": "", "kind": "", "targets": [], "status": "pending", "note": "",
             "allowed": [], "review": [], "reviewed_by": None, "reviewed_at": None, "reviewed_via": None, "digest": None}
        if not isinstance(raw, dict):
            return self._invalid(e, "항목이 객체가 아님")
        for k in ("where", "what", "why", "kind"):
            v = raw.get(k)
            e[k] = v.strip() if isinstance(v, str) else ""
        if not e["where"]:
            return self._invalid(e, "where 없음")
        if not e["why"]:
            return self._invalid(e, "why(사유) 없음")
        segs = parse_where(e["where"])
        if not segs:
            return self._invalid(e, "where 를 못 읽음")
        notes, outside = [], []
        for cands, ranges, declared_out in segs:
            got, used = [], cands[0]
            for c in cands:
                got = find(c, files, app_roots)
                if got:
                    used = c
                    break
            if not got:
                if declared_out or outside_roots(cands[-1], app_roots):
                    outside.append(cands[-1])  # 트리 밖이라고 적었거나 앱 루트 밖: 허용할 것 없음(무효 아님)
                    continue
                return self._invalid(e, f"파일 없음: {cands[-1]}")
            if ranges is not None:
                if len(got) > 1:
                    return self._invalid(e, f"'{used}'가 파일 {len(got)}개에 걸림({', '.join(got[:3])}): 경로를 더 적는다")
                n_lines = line_count(got[0])
                if n_lines is None:
                    return self._invalid(e, f"줄 범위를 줬지만 글 파일이 아님: {got[0]}")
                over = [r for r in ranges if r[0] < 1 or r[1] > n_lines]
                if over:
                    return self._invalid(e, f"범위 밖 줄: {got[0]}:{over[0][0]}-{over[0][1]} (파일 {n_lines}줄)")
                width = sum(b - a + 1 for a, b in ranges)
                if width > WIDE and CODE_FILE.search(got[0]):
                    notes.append(f"넓은 범위 {width}줄")
                e["targets"].append({"path": got[0], "ranges": ranges})
            else:
                code = [g for g in got if CODE_FILE.search(g)]
                if code and (GLOB.search(_globify(used)) or len(got) > 1):
                    return self._invalid(e, f"코드 파일을 글롭으로 허용하지 않는다({', '.join(code[:3])}): '파일:시작-끝'으로 적는다")
                if code:
                    notes.append("코드 파일 전체")
                e["targets"] += [{"path": g, "ranges": None} for g in got]
        if not e["targets"]:
            e["status"] = "outside"
            e["note"] = "제출 트리 밖 자리(허용할 줄 없음): " + ", ".join(outside[:3])
            return e
        if outside:
            notes.append("트리 밖 자리는 건너뜀: " + ", ".join(outside[:3]))
        live = [t for t in e["targets"] if t["path"] not in excluded]
        if not live:
            e["status"] = "excluded"
            e["note"] = "가리킨 파일이 모두 실행 데이터로 검사에서 빠짐"
        if notes:
            e["note"] = "; ".join(([e["note"]] if e["note"] else []) + notes)
            self.warnings.append(f"#{n} {e['where'][:80]}: " + ", ".join(notes))
        e["targets"] = live or e["targets"]
        return e

    def _invalid(self, e, why):
        e["status"], e["note"] = "invalid", why
        self.warnings.append(f"허용 무효 #{e['n']} {e['where'][:80] or '(where 없음)'}: {why}")
        return e

    def match(self, path, line):
        for e, ranges in self.index.get(path, ()):
            if ranges is None or (line is not None and any(a <= line <= b for a, b in ranges)):
                return e
        return None

    def finish(self):
        """줄이 다 걸린 뒤 항목 상태를 정한다: allowed·review·unused(고전 줄 없음)·invalid·excluded·outside."""
        for e in self.entries:
            if e["status"] != "pending":
                continue
            e["allowed"] = sorted(set(e["allowed"]), key=_loc_key)
            e["review"] = sorted(set(e["review"]), key=_loc_key)
            if e["review"]:
                e["status"] = "review"
            elif e["allowed"]:
                e["status"] = "allowed"
            else:
                e["status"] = "unused"
                e["note"] = "; ".join(x for x in (e["note"], "범위 안에 고전 공개키 줄 없음(공개키 암호가 아니거나 줄 번호가 밀림)") if x)
        return self

    def note_other(self, other, locs):
        """다른 트리(원본)에서 항목마다 덮는 고전 줄을 센다. other: 같은 목록을 그 트리로 푼 AllowList(finish() 전), locs: 그 트리의
        고전 줄 위치('파일:줄'). 판정에는 쓰지 않는다(원본은 판정 대상이 아니다). finish() 뒤에 부른다.
        고친 판에서 안 쓰인 항목이 원본 고전 줄을 덮으면, 이 목록을 원본 같은 다른 트리에 댈 때 그 줄을 가린다는 뜻이라 경고한다."""
        hits = {}
        if other is not None:
            for loc in locs:
                m = re.fullmatch(r"(.+):([0-9]+)", loc)
                e = other.match(m[1], int(m[2])) if m else None
                if e is not None:
                    hits.setdefault(e["n"], set()).add(loc)
        self.other_checked = other is not None
        for e in self.entries:
            e["orig"] = sorted(hits.get(e["n"], ()), key=_loc_key)
        dead_ko = {"invalid": "무효", "excluded": "검사 범위 밖(제외 파일)", "outside": "트리 밖"}
        for e in self.unused():
            k = len(e["orig"])
            head = ("고친 판에서 덮은 고전 줄 0(안 쓰인 항목)" if e["status"] == "unused" else
                    f"고친 판에서는 {dead_ko[e['status']]}라 아무것도 허용하지 않는다(안 쓰인 항목으로 셈)")
            self.warnings.append(f"#{e['n']} {CONTROL.sub(' ', e['where'])[:80]}: {head}"
                                 + (f". 원본에서는 고전 {k}줄을 덮는다({', '.join(e['orig'][:3])}{' 외' if k > 3 else ''}): 이 목록을 "
                                    "원본 같은 다른 트리에 대면 그 줄을 가린다. 사람 확인 전으로 센다" if k else "")
                                 + ". 쓰지 않는 항목이면 목록에서 지운다(REQUIRE_REVIEW=1 이면 실패)")
        return self

    def unused(self):
        """안 쓰인 항목(counts_unused): 고친 판에서 덮은 고전 줄이 0인 유효 항목과, 고친 판에서 무효·제외·트리 밖인데 원본 고전 줄을
        덮는 항목. finish() 뒤에 부른다(뒤의 것은 note_other() 뒤에만 잡힌다)."""
        return [e for e in self.entries if counts_unused(e["status"], len(e.get("orig", ())))]

    def write_review(self):
        """허용 범위 안 쓰기 경로라 검토 필요로 남은 위치(항목 전체에서 겹치지 않게). finish() 뒤에 부른다."""
        return sorted({loc for e in self.entries for loc in e["review"]}, key=_loc_key)

    def record(self):
        out = []
        for e in self.entries:
            x = {"n": e["n"], "where": e["where"], "what": e["what"], "why": e["why"], "kind": e["kind"],
                 "targets": [t["path"] + (":" + ",".join(f"{a}-{b}" if a != b else str(a) for a, b in t["ranges"])
                                          if t["ranges"] else "") for t in e["targets"]],
                 "status": e["status"], "note": e["note"], "allowed": e["allowed"], "review": e["review"],
                 "reviewed_by": e["reviewed_by"], "reviewed_at": e["reviewed_at"], "reviewed_via": e["reviewed_via"],
                 "digest": e["digest"], "lines_fixed": len(set(e["allowed"]) | set(e["review"]))}
            if self.other_checked:
                x["lines_orig"], x["orig"] = len(e.get("orig", [])), e.get("orig", [])[:OTHER_MAX]
            out.append(x)
        return out

    def unreviewed(self):
        """줄을 판정에서 뺀 항목(허용·검토 필요) 중 받아들인 사람 확인 칸이 없는 것. finish() 뒤에 부른다."""
        return [e for e in self.entries if e["status"] in IN_EFFECT and not e["reviewed_via"]]


def _loc_key(loc):
    m = re.fullmatch(r"(.+):([0-9]+)", loc)
    return (m[1], int(m[2])) if m else (loc, 0)


# ---------------------------------------------------------------------------------------------
# 실행 데이터 제외
DATA_ENV = re.compile(r"\b[A-Z0-9_]*DATA_DIR\s*=\s*['\"]?(/[\w./-]+)")
DATA_KO = re.compile(r"데이터(?:\s*폴더)?\s*[:=]?\s*(/[\w./-]+)")
APP_CD = re.compile(r"\bcd\s+['\"]?(/[\w./-]+?)['\"]?\s*(?:&&|;)")
APP_KO = re.compile(r"컨테이너\s+(/[\w./-]+)")


def recon_paths(recon):
    """recon.json(dict) → (앱 루트 목록, 데이터 폴더 목록). 명시 칸(app_dir·app_path·data_dirs·data_dir)을 먼저, 글에서 찾은 것을 뒤에."""
    roots, data = [], []
    if not isinstance(recon, dict):
        return roots, data
    for k in ("app_dir", "app_path", "app_root"):
        if isinstance(recon.get(k), str) and recon[k].startswith("/"):
            roots.append(recon[k])
    for k in ("data_dirs", "data_dir", "runtime_data"):
        v = recon.get(k)
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str) and x.startswith("/"):
                data.append(x)
    text = json.dumps(recon, ensure_ascii=False)
    roots += APP_CD.findall(text) + APP_KO.findall(text)
    data += DATA_ENV.findall(text) + DATA_KO.findall(text)
    norm = lambda xs: list(dict.fromkeys(x.rstrip("/.") or "/" for x in xs))  # noqa: E731
    return norm(roots), norm(data)


class Exclusions:
    """검사에서 뺄 글롭. 상대 경로 기준. 'data/**'·'data/'·'data' 는 폴더째, '*.db' 처럼 / 가 없으면 파일 이름으로도 본다."""

    def __init__(self):
        self.items = []  # {"pattern", "from", "why"}

    @staticmethod
    def norm(pattern):
        p = _norm(pattern)
        return p + "**" if p.endswith("/") else p

    def add(self, pattern, source, why=""):
        p = self.norm(pattern)
        if not p or p in ("/**", "*", "**", "**/*"):
            return False  # 전부 빼는 글롭은 받지 않는다(빈 트리로 통과하는 꼴)
        if any(x["pattern"] == p for x in self.items):
            return False
        self.items.append({"pattern": p, "from": source, "why": why})
        return True

    @property
    def patterns(self):
        return [x["pattern"] for x in self.items]

    def match(self, rel):
        for x in self.items:
            p = x["pattern"]
            if "/" not in p:
                if fnmatch.fnmatchcase(rel.rsplit("/", 1)[-1], p) or fnmatch.fnmatchcase(rel, p):
                    return True
                if not GLOB.search(p) and rel.startswith(p + "/"):  # 'data' = 맨 위 data 폴더
                    return True
                continue
            if p.endswith("/**") and (rel.startswith(p[:-3] + "/") or rel == p[:-3]):
                return True
            if fnmatch.fnmatchcase(rel, p.replace("**", "*")) or rel == p or rel.startswith(p + "/"):
                return True
        return False


def from_recon(excl, recon, recon_label):
    """recon 의 데이터 폴더 중 앱 루트 안에 있는 것을 상대 글롭으로 더한다. (앱 루트 목록, 메모 목록)"""
    roots, data = recon_paths(recon)
    notes = []
    for d in data:
        inside = [r for r in sorted(roots, key=len, reverse=True) if d == r or d.startswith(r.rstrip("/") + "/")]
        if not inside:
            notes.append(f"{d}: 앱 폴더({', '.join(roots) or '모름'}) 밖이라 뺄 것 없음")
            continue
        rel = d[len(inside[0].rstrip("/")) + 1:]
        if not rel:
            notes.append(f"{d}: 앱 폴더 자체라 빼지 않음")
            continue
        if excl.add(rel + "/**", recon_label, f"DATA_DIR {d} (앱 {inside[0]})"):
            notes.append(f"{d} → {rel}/**")
    return roots, notes
