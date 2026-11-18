#!/usr/bin/env python3
# sarif.py: PQ-Proof 결과 폴더(receipt.json, tables/*, artifacts/*)를 SARIF 2.1.0으로 바꾼다. 표준 라이브러리만 쓴다.
#   python3 -I sarif.py <결과 폴더> [-o pqproof.sarif] [--uri-prefix services/app/] [--anchor 파일] [--lang en|ko] [--include-notes]
#   pqproof sarif <결과 폴더> ...                (패키지로 깔았을 때 같은 동작)
# 결과(result)는 고친 판에 남은 위치다. 규칙 id는 검사 id(a-cbom, c-classic, b-weakening, r-review, r-allow …)이고,
# 수준은 그 검사가 실패면 error, 검토 필요·미판정이면 warning이다. 위치가 없는 검사(c-expect, b-tls, a-input)는
# --anchor 를 주면 그 파일 1행의 결과로, 아니면 invocations[0].toolExecutionNotifications 로 남긴다.
# 건너뛴 검사는 통과로 세지 않는다: 해당 없음(na)·미판정(undecided) 검사는 알림으로 남기고 run.properties.notCountedAsPass 에 적는다.
# 읽는 파일은 receipt.json 에 적힌 SHA-256과 맞춰 보고, receipt_id(RFC 8785 + SHA-256)도 다시 계산한다. 다르면 쓰지 않고 2로 끝낸다.
# 종료: 0 씀 · 2 사용법·증적 오류
"""Convert a PQ-Proof evidence folder to SARIF 2.1.0.

Results are the positions that remain in the converted tree. The rule id is the check id and the level follows the check:
fail -> error, review or undecided -> warning. Checks that are skipped (na) or undecided are never reported as passed.
"""
import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import sys


def _tool_version():
    """버전은 바로 옆 __init__.py 의 __version__ 한 곳에서 읽는다. prove.sh sarif 와 action.yml 은 이 파일을 -I 로 따로
    돌리므로 import 대신 파일을 읽는다(저장소 src/pqproof/, 설치본 pqproof/ 모두 옆에 있다). 못 읽으면 0+unknown."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "__init__.py"), encoding="utf-8") as f:
            m = re.search(r'^__version__\s*=\s*"([^"]+)"', f.read(), re.M)
    except OSError:
        m = None
    return m[1] if m else "0+unknown"


VERSION = _tool_version()

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/g1mn/pqproof"
HELP_URI = "https://g1mn.github.io/pqproof/#sec-checks"
FINGERPRINT = "pqproof/v1"
LEVEL = {"fail": "error", "review": "warning", "undecided": "warning", "check": "note"}
NOT_PASSED = ("na", "undecided", "skip", "skipped")  # 통과로 세지 않는 상태
BLOCK_LABELS = {"막음", "block", "blocking"}
REVIEW_LABELS = {"검토 필요", "review"}
FAMILY_EN = {
    "G-RSA": "RSA", "G-EC": "elliptic-curve keys (EC, ECDSA, ECDH)", "G-CURVE": "named classical curve (P-256, secp256r1 and similar)",
    "G-OAEP-PKCS1": "RSA OAEP or PKCS#1 padding", "G-CLASSIC-SIG": "classical signature name (SHA256withRSA, SHA256withECDSA and similar)",
    "G-JWT-ALG": "JWT RS/ES/PS algorithm", "G-EDDSA": "EdDSA (Ed25519, Ed448)", "G-X25519": "X25519 or X448 key exchange",
    "G-DH-DSA": "DH or DSA", "G-WEAK-PQC": "post-quantum parameter below NIST level 3 (ML-KEM-512, ML-DSA-44)",
    "LW-legacy-write": "write path inside a Legacy* file (must stay read or verify only)",
}

RULES = {
    "a-input": ("InputPair", "The two inputs look like the same service before and after migration",
                "두 입력이 같은 서비스의 전환 전·후로 보인다"),
    "a-cbom": ("BlockingClassicPublicKey", "Classical public-key use that blocks the migration remains in the converted tree",
               "고친 판 CBOM에 전환을 막는 고전 공개키 위치가 남았다"),
    "b-weakening": ("TlsCheckWeakened", "A changed file turns off or weakens a TLS check",
                    "바뀐 파일이 TLS 검증을 끄거나 약하게 만들었다"),
    "b-tls": ("TlsHybridNegotiation", "Live TLS endpoints do not negotiate hybrid ML-KEM as expected",
              "실제 TLS 주소가 기대한 하이브리드 ML-KEM 협상을 하지 않는다"),
    "c-classic": ("ClassicPublicKeyLine", "Classical public-key code lines remain without a recorded reason",
                  "사유 없이 남은 고전 공개키 코드 줄"),
    "c-expect": ("ExpectedPqcMissing", "Expected post-quantum algorithms (ML-KEM-768, ML-DSA-65) are not used",
                 "기대한 PQC 알고리즘(ML-KEM-768, ML-DSA-65)을 쓰지 않는다"),
    "r-review": ("VerificationRemoved", "Signature verification or decryption calls were removed or stubbed out",
                 "서명 검증·복호 호출이 줄었거나 늘 성공만 돌려준다"),
    "r-allow": ("AllowListReview", "Allow-list entry without human review, unused in the converted tree, or covering a write path",
                "허용 항목이 사람 확인 전이거나, 고친 판에서 안 쓰였거나, 쓰기 경로를 덮는다"),
}
NO_LOCATION = ("a-input", "b-tls", "c-expect")
# c-classic 이 세는 residue 규칙: 공개키 9계열, 보안레벨 3 미만 PQC, 레거시 쓰기(LWRITE), 서비스별 SITE.
# G-AES128 같은 다른 GEN 규칙은 표에만 나오고 판정에 안 들어가므로 결과로 내지 않는다
COUNTED_GEN = {"G-RSA", "G-EC", "G-CURVE", "G-OAEP-PKCS1", "G-CLASSIC-SIG", "G-JWT-ALG", "G-EDDSA", "G-X25519", "G-DH-DSA", "G-WEAK-PQC"}


class EvidenceError(Exception):
    pass


# ---------------------------------------------------------------------------------------------
# RFC 8785 정규형(이 증적에 나오는 값: 문자열·정수·참거짓·null·배열·객체, 드물게 실수)
def _es_number(x):
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        if abs(x) > 1 << 53:
            raise EvidenceError(f"receipt.json has an integer beyond 2^53 ({x}); RFC 8785 cannot hash it exactly")
        return str(x)
    if not math.isfinite(x):
        raise EvidenceError("receipt.json has a non-finite number")
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    if "e" in r:
        mant, exp = r.split("e")
        return f"{mant}e{'+' if not exp.startswith('-') else ''}{int(exp)}"
    return r


def jcs(v):
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, (int, float)):
        return _es_number(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"
    raise EvidenceError(f"unexpected JSON value {type(v).__name__}")


def _unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise EvidenceError(f"receipt.json has the key {k!r} twice; parsers would disagree on its value")
        out[k] = v
    return out


def _constant(name):
    raise EvidenceError(f"receipt.json has {name}, which is not a JSON number")


def load_receipt(raw):
    """receipt.json 바이트를 엄격하게 읽는다(pqlite/receipt.py loads_strict·dumps 와 같은 규칙): BOM·중복 키·NaN 을 거부하고,
    바이트가 도구 직렬화와 같아야 한다."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raise EvidenceError("receipt.json starts with a byte order mark")
    try:
        r = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise EvidenceError(f"receipt.json is not valid JSON: {e}") from e
    if not isinstance(r, dict):
        raise EvidenceError("receipt.json is not a JSON object")
    if raw != (json.dumps(r, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"):
        raise EvidenceError("receipt.json is not byte for byte what PQ-Proof writes (spacing, key order or bytes after the object)")
    return r


def receipt_id(receipt):
    body = {k: v for k, v in receipt.items() if k != "receipt_id"}
    return hashlib.sha256(jcs(body).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------------------------
class Evidence:
    """결과 폴더를 읽는다. 파일은 receipt.json 에 적힌 SHA-256과 맞을 때만 내준다."""

    def __init__(self, out_dir):
        self.dir = os.path.abspath(out_dir)
        path = os.path.join(self.dir, "receipt.json")
        if not os.path.isfile(path):
            raise EvidenceError(f"no receipt.json in {self.dir}")
        with open(path, "rb") as f:
            raw = f.read()
        self.r = load_receipt(raw)
        fmt = str(self.r.get("format", ""))
        if not (fmt.startswith("pqc-proof receipt") or fmt.startswith("pqproof receipt")):
            raise EvidenceError(f"not a PQ-Proof receipt (format {fmt!r})")
        given = self.r.get("receipt_id")
        if given != receipt_id(self.r):
            raise EvidenceError("receipt.json changed after the run (receipt_id does not match). Run: pqproof --verify " + self.dir)
        self.sha = {a.get("path"): a.get("sha256") for a in self.r.get("artifacts", []) if isinstance(a, dict)}

    def read(self, rel, sha=None):
        if not rel:
            return None
        if rel.startswith("/") or ".." in rel.split("/"):
            raise EvidenceError(f"path outside the evidence folder: {rel}")
        want = sha or self.sha.get(rel)
        if not want:
            raise EvidenceError(f"{rel} has no SHA-256 in receipt.json")
        p = os.path.join(self.dir, rel)
        if os.path.islink(p) or not os.path.isfile(p):
            raise EvidenceError(f"{rel} is missing or not a regular file")
        with open(p, "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != want:
            raise EvidenceError(f"{rel} does not match its SHA-256 in receipt.json. Run: pqproof --verify {self.dir}")
        return data.decode("utf-8", errors="replace")


def norm_prefix(p):
    """'./services/app' -> 'services/app/', '.' or '' -> ''."""
    p = (p or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    if p in ("", "."):
        return ""
    return p if p.endswith("/") else p + "/"


def split_loc(loc):
    m = re.match(r"^(.*?):([0-9]+)(?:-([0-9]+))?$", loc or "")
    if not m:
        return loc, None, None
    return m[1], int(m[2]), int(m[3]) if m[3] else None


# ---------------------------------------------------------------------------------------------
class Builder:
    def __init__(self, ev, uri_prefix="", anchor=None, lang="en", include_notes=False):
        self.ev, self.r = ev, ev.r
        self.prefix = norm_prefix(uri_prefix)
        self.anchor, self.lang, self.include_notes = anchor, lang, include_notes
        self.status = {c["id"]: c.get("status") for c in self.r.get("checks", []) if isinstance(c, dict)}
        self.checks = {c["id"]: c for c in self.r.get("checks", []) if isinstance(c, dict)}
        self.results, self.notes, self.seen = [], [], {}
        self.located = set()

    def t(self, en, ko):
        return ko if self.lang == "ko" else en

    def level(self, check_id, default=None):
        st = self.status.get(check_id)
        if st in LEVEL:
            return LEVEL[st]
        if st == "pass" or st in NOT_PASSED:
            return "note" if self.include_notes else None
        return default

    def loc(self, path, line=None, end=None, snippet=None):
        region = {"startLine": line or 1}
        if end and line and end >= line:
            region["endLine"] = end
        if snippet:
            region["snippet"] = {"text": snippet[:400]}
        return {"physicalLocation": {"artifactLocation": {"uri": self.prefix + path, "uriBaseId": "%SRCROOT%"}, "region": region}}

    def add(self, rule, level, text, path, line=None, end=None, snippet=None, key="", props=None):
        if level is None:
            return
        norm = re.sub(r"[ \t]+", " ", key or snippet or text).strip()
        base = f"{rule}|{path}|{norm}"
        n = self.seen.get(base, 0)
        self.seen[base] = n + 1
        res = {"ruleId": rule, "level": level, "message": {"text": text}, "locations": [self.loc(path, line, end, snippet)],
               "partialFingerprints": {FINGERPRINT: hashlib.sha256(f"{base}#{n}".encode()).hexdigest()[:32]}}
        if line is None:
            res.setdefault("properties", {})["fileLevel"] = True
        if props:
            res.setdefault("properties", {}).update(props)
        self.results.append(res)
        self.located.add(rule)

    def note(self, check_id, level, text):
        self.notes.append({"level": level, "message": {"text": text}, "descriptor": {"id": check_id}})

    # (a) CBOM 막는 위치·허용 범위 쓰기 경로
    def cbom(self):
        c = (self.r.get("cbom") or {}).get("fixed") or {}
        text = self.ev.read(c.get("csv"), c.get("csv_sha256"))
        if text is None:
            return
        rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
        by_loc = {}
        for row in rows:
            label = (row.get("판정") or row.get("status") or "").strip()
            kind = "block" if label in BLOCK_LABELS else "review" if label in REVIEW_LABELS else None
            if kind:
                by_loc.setdefault((kind, row.get("위치") or row.get("location") or ""), []).append(row)
        blocks = sum(1 for k, _ in by_loc if k == "block")
        if c.get("blocking") is not None and blocks != c.get("blocking"):
            self.note("a-cbom", "warning", self.t(f"CBOM table lists {blocks} blocking positions but receipt.json counts {c.get('blocking')}",
                                                  f"CBOM 표의 막는 위치 {blocks}곳과 receipt.json 수 {c.get('blocking')}가 다르다"))
        lv = self.level("a-cbom", "error")
        for (kind, loc), rs in sorted(by_loc.items(), key=lambda x: (x[0][1], x[0][0])):
            path, line, _ = split_loc(loc)
            algs = sorted({(r.get("알고리즘") or r.get("algorithm") or "").strip() for r in rs} - {""})
            uses = sorted({(r.get("용도·종류") or r.get("use") or "").strip() for r in rs} - {""})
            snippet = next((m[1] for r in rs for m in [re.search(r"`(.+)`", r.get("비고") or "")] if m), None)
            why = next(((r.get("허용·참고 사유") or "").strip() for r in rs if (r.get("허용·참고 사유") or "").strip()), "")
            if kind == "block":
                text = self.t(f"Classical public key still used here: {', '.join(algs) or 'unknown algorithm'} ({', '.join(uses)}). "
                              "Quantum computers break it (Shor).",
                              f"고전 공개키가 남았다: {', '.join(algs) or '알고리즘 미상'} ({', '.join(uses)}). 쇼어 알고리즘으로 깨진다.")
                self.add("a-cbom", lv, text, path, line, snippet=snippet, key=",".join(algs) + "|" + (snippet or ""))
            else:
                text = self.t(f"Allowed range, but this line writes (new key, signature or encryption): {', '.join(algs)}. "
                              f"A person must confirm it. {why}",
                              f"허용 범위 안 쓰기 경로(새 키·서명·암호화): {', '.join(algs)}. 사람이 확인해야 한다. {why}")
                self.add("a-cbom", "warning", text.strip(), path, line,
                         snippet=snippet, key="review|" + ",".join(algs) + "|" + (snippet or ""))

    # (c) residue 공개키 9계열·보안레벨 3 미만 PQC·레거시 쓰기
    def classic(self):
        j = (self.r.get("java") or {}).get("fixed") or {}
        text = self.ev.read(j.get("output"), j.get("output_sha256"))
        if text is None:
            return
        listed = j.get("listed") or {}
        moved = {x.get("loc"): x.get("as") for x in listed.get("lines", []) if isinstance(x, dict)}
        rule_re = re.compile(r"^(GEN|SITE|LWRITE)\s+(\S+)\s")
        det_re = re.compile(r"^      LEFT (.+?):([0-9]+): (.*)$")
        cur, seen_left = None, 0
        lv = self.level("c-classic", "error")
        for line in text.split("\n"):
            m = rule_re.match(line)
            if m:
                cur = m[2] if (m[1] in ("SITE", "LWRITE") or m[2] in COUNTED_GEN) else None
                continue
            if line.startswith("EXPECT ") or line.startswith("SUMMARY "):
                cur = None
                continue
            d = det_re.match(line)
            if not (d and cur):
                continue
            loc = f"{d[1]}:{d[2]}"
            as_ = moved.get(loc)
            if as_ in ("allowed", "hybrid"):
                continue
            seen_left += 1
            name = FAMILY_EN.get(cur, cur)
            if as_ == "review":
                msg = self.t(f"{cur} ({name}) inside an allowed range, but on a write path. A person must confirm it.",
                             f"{cur}: 허용 범위 안이지만 쓰기 경로라 사람이 확인해야 한다.")
                self.add("c-classic", "warning", msg, d[1], int(d[2]), snippet=d[3].strip(), key=f"review|{cur}|{d[3]}")
            else:
                msg = self.t(f"{cur}: {name} remains without a recorded reason.", f"{cur}: 사유 없이 남은 고전 공개키 코드 줄.")
                self.add("c-classic", lv, msg, d[1], int(d[2]), snippet=d[3].strip(), key=f"{cur}|{d[3]}")
        if not seen_left and self.status.get("c-classic") == "fail":
            self.note("c-classic", "warning", self.t("c-classic failed but the residue output lists no line (list may be cut short)",
                                                     "c-classic 실패인데 residue 출력에 줄 목록이 없다(목록이 잘렸을 수 있다)"))

    # (b) TLS 약화 수정
    def weakening(self):
        w = self.r.get("weakening") or {}
        lv = self.level("b-weakening", "error")
        for d in w.get("deny", []):
            path, _, rule = str(d).partition(": ")
            self.add("b-weakening", lv, self.t(f"TLS check weakened: {rule} (file-level)", f"TLS 검증 약화: {rule} (파일 단위)"),
                     path, None, key=rule.split(" (")[0])
        lv = self.level("r-review", "warning")
        for x in w.get("review", []):
            rule, path = x.get("rule", ""), x.get("path", "")
            txt = self.t(f"Review: {rule} (before {x.get('before')}, after {x.get('after')}). Write the reason next to it or restore the call.",
                         f"검토 필요: {rule} (전 {x.get('before')}, 후 {x.get('after')}). 사유를 적거나 호출을 되살린다.")
            if path and path != "(patch)":
                self.add("r-review", lv, txt, path, None, key=rule)
                continue
            files = re.findall(r"(\S+) ([0-9]+)->([0-9]+)", x.get("detail", ""))
            for f, b, a in files:
                if int(a) < int(b):
                    self.add("r-review", lv, txt + f" [{f} {b}->{a}]", f, None, key=f"{rule}|{f}")
            if not files and lv:
                self.note("r-review", lv, txt)

    # r-allow: 사람 확인 전·안 쓰인 항목
    def allow(self):
        a = self.r.get("allowlist") or {}
        lv = self.level("r-allow", "warning")
        for e in a.get("entries", []):
            st = e.get("status")
            problems = []
            if st in ("allowed", "review") and not e.get("reviewed_via"):
                problems.append(self.t("allowed without a human review (reviewed_by, reviewed_at)", "사람 확인 전 허용(reviewed_by·reviewed_at 없음)"))
            if st == "unused":
                problems.append(self.t(f"covers no classical line in the converted tree, but covers {e.get('lines_orig', 0)} in the original "
                                       "(it can hide reverted code)",
                                       f"고친 판에서 덮은 고전 줄 0, 원본에서는 {e.get('lines_orig', 0)}줄(되돌린 코드를 가릴 수 있다)"))
            if e.get("review"):
                problems.append(self.t(f"{len(e['review'])} write paths inside the range need review", f"범위 안 쓰기 경로 {len(e['review'])}곳 검토 필요"))
            if not problems:
                continue
            text = self.t(f"Allow-list #{e.get('n')} ({e.get('kind') or 'no kind'}): ", f"허용 목록 #{e.get('n')}({e.get('kind') or '종류 없음'}): ") \
                + "; ".join(problems) + f". why: {str(e.get('why', ''))[:160]}"
            targets = e.get("targets") or [e.get("where", "")]
            for tgt in targets:
                path, line, end = split_loc(tgt)
                if path:
                    self.add("r-allow", lv, text, path, line, end, key=f"#{e.get('n')}|{e.get('where')}")
        for wtxt in a.get("warnings", []):
            self.note("r-allow", "warning", str(wtxt)[:500])

    # 위치 없는 검사와 통과로 세지 않는 검사
    def checks_without_location(self):
        for cid, c in self.checks.items():
            st = c.get("status")
            actual = str(c.get("actual", ""))[:400]
            if st in NOT_PASSED:
                lvl = "warning" if st == "undecided" else "note"
                self.note(cid, lvl, self.t(f"{cid} {st}: not counted as passed. {actual}", f"{cid} {st}: 통과로 세지 않는다. {actual}"))
                continue
            lvl = LEVEL.get(st)
            if lvl in ("error", "warning") and cid not in self.located:
                text = self.t(f"{cid} {st}: {c.get('title', '')}. {actual}", f"{cid} {st}: {c.get('title', '')}. {actual}")
                if self.anchor:
                    self.add(cid, lvl, text, self.anchor, 1, key=f"check|{cid}")
                else:
                    self.note(cid, lvl, text)

    def build(self):
        self.cbom()
        self.classic()
        self.weakening()
        self.allow()
        self.checks_without_location()
        used = sorted({r["ruleId"] for r in self.results} | {n["descriptor"]["id"] for n in self.notes} | set(self.status))
        rules = []
        for rid in used:
            name, en, ko = RULES.get(rid, (rid, rid, rid))
            rules.append({"id": rid, "name": name, "shortDescription": {"text": self.t(en, ko)},
                          "fullDescription": {"text": en if self.lang != "ko" else ko},
                          "helpUri": HELP_URI, "defaultConfiguration": {"level": "error" if rid in ("a-cbom", "b-weakening", "c-classic") else "warning"},
                          "properties": {"tags": ["security", "cryptography", "post-quantum"]}})
        counts = {}
        for st in self.status.values():
            counts[st] = counts.get(st, 0) + 1
        run = {
            "tool": {"driver": {"name": "PQ-Proof", "informationUri": INFO_URI, "version": VERSION, "semanticVersion": VERSION,
                                "rules": rules}},
            "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": self.notes}],
            "results": self.results,
            "columnKind": "unicodeCodePoints",
            "properties": {
                "verdict": self.r.get("verdict"), "receiptId": self.r.get("receipt_id"), "receiptFormat": self.r.get("format"),
                "checks": self.status, "checkCounts": counts,
                "notCountedAsPass": sorted(k for k, v in self.status.items() if v in NOT_PASSED),
            },
        }
        return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def convert(out_dir, uri_prefix="", anchor=None, lang="en", include_notes=False):
    return Builder(Evidence(out_dir), uri_prefix, anchor, lang, include_notes).build()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pqproof sarif", description="PQ-Proof evidence folder -> SARIF 2.1.0")
    ap.add_argument("out_dir", help="result folder that holds receipt.json")
    ap.add_argument("-o", "--output", default="-", help="SARIF file to write (default: stdout)")
    ap.add_argument("--uri-prefix", default="", help="path of the converted tree inside the repository, e.g. services/app/")
    ap.add_argument("--anchor", default=None, help="repository file for checks that have no file position (c-expect, b-tls, a-input)")
    ap.add_argument("--lang", choices=("en", "ko"), default="en")
    ap.add_argument("--include-notes", action="store_true", help="also emit note-level results for checks that passed")
    a = ap.parse_args(argv)
    try:
        doc = convert(a.out_dir, a.uri_prefix, a.anchor, a.lang, a.include_notes)
    except EvidenceError as e:
        print(f"pqproof sarif: {e}", file=sys.stderr)
        return 2
    text = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
    if a.output == "-":
        sys.stdout.write(text)
    else:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text)
        run = doc["runs"][0]
        lv = {}
        for r in run["results"]:
            lv[r["level"]] = lv.get(r["level"], 0) + 1
        print(f"SARIF 2.1.0: {len(run['results'])} results {json.dumps(lv)}, {len(run['invocations'][0]['toolExecutionNotifications'])} "
              f"notifications, verdict {run['properties']['verdict']} -> {a.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
