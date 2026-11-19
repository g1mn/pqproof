# impl.py: 구현 검증(pqproof impl)의 순수 함수(표준 라이브러리만). 지금은 NIST PQCgenKAT 응답 파일(.rsp)을 읽어 정규화하고
#   digest 를 만드는 세 함수(parse_rsp, record_digest, rsp_digest)만 있다. 다음 단계가 문제지·답안 대조를 이 파일에 더한다.
# 참조판 목록(scan/kat-kpqc.json)과 발췌(scan/kat/)는 tools/make_kat_manifest.py 가 이 함수들로 만든다.
# 받는 .rsp 는 남이 만든 데이터다. 글자로만 읽고, 그 안의 무엇도 실행하지 않는다.
"""Read NIST PQCgenKAT response files (.rsp) and give normalized per-record and per-file digests."""
from __future__ import annotations  # 맥 기본 python3 3.9

import hashlib
import re

# 10진 정수 칸. PQCgenKAT 가 길이와 번호를 10진으로 쓴다(KEM 은 count 만, 서명은 mlen 과 smlen 또는 siglen)
DEC_FIELDS = frozenset({"count", "mlen", "smlen", "siglen"})
_KEY_RE = re.compile(r"[a-z][a-z0-9_]*")
_HEX_RE = re.compile(r"[0-9A-Fa-f]*")
_DEC_RE = re.compile(r"[0-9]+")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


def _norm_field(key, value, where=""):
    """칸 하나를 정규화한 (키, 값). 키는 앞뒤 공백을 지운 소문자, 10진 칸은 앞의 0 을 뗀 10진 문자열, 그 밖은 대문자 16진수.
    규칙에 안 맞으면 ValueError."""
    if not isinstance(key, str) or not isinstance(value, str):
        raise ValueError(f"{where}키와 값은 문자열이어야 한다({key!r})")
    key, value = key.strip().lower(), value.strip()
    if not _KEY_RE.fullmatch(key):
        raise ValueError(f"{where}키 이름이 아니다: {key!r}")
    if key in DEC_FIELDS:
        if not _DEC_RE.fullmatch(value):
            raise ValueError(f"{where}{key} 는 10진 정수여야 한다: {value[:40]!r}")
        return key, str(int(value))
    if not _HEX_RE.fullmatch(value):
        raise ValueError(f"{where}{key} 가 16진수가 아니다: {value[:40]!r}")
    if len(value) % 2:
        raise ValueError(f"{where}{key} 의 16진수 자릿수가 홀수다({len(value)}자)")
    return key, value.upper()


def parse_rsp(text):
    """.rsp 텍스트(str, 또는 ASCII bytes) → 레코드 목록 [{키: 값}]. 레코드와 칸은 파일에 나온 순서 그대로다.

    정규화 규칙(KpqC 참조판 4종 7판의 .rsp 33개를 보고 정했다. KEM 은 count·seed·pk·sk·ct·ss, HAETAE 는
    count·seed·mlen·msg·pk·sk·siglen·sig, AIMer 는 count·seed·mlen·msg·pk·sk·smlen·sm 이고, 모두 LF 줄 끝, 대문자 16진수,
    맨 위에 '# 알고리즘 이름' 한 줄이 있다):
    - 줄 끝은 LF, CRLF, CR 모두 받는다. 맨 앞 BOM(U+FEFF)은 지운다. ASCII 밖의 글자가 있으면 ValueError.
    - 빈 줄과 '#' 로 시작하는 줄(맨 위 '# smaugt_mode1' 같은 이름 줄)은 버린다. 빈 줄은 값이 아니고, 레코드 경계는 count 줄이 정한다.
    - 나머지 줄은 '키 = 값' 꼴이어야 한다(첫 '=' 에서 나눈다). 키는 앞뒤 공백을 지우고 소문자로, 값은 앞뒤 공백을 지운다.
    - 10진 칸(count, mlen, smlen, siglen)은 10진 정수여야 하고 앞의 0 을 뗀 문자열로 둔다('033' 은 '33').
    - 그 밖의 칸은 16진수여야 하고(빈 값 허용) 대문자로 바꾼다. 16진수가 아닌 글자나 홀수 자릿수는 ValueError.
    - count 줄이 새 레코드를 연다(PQCgenKAT 는 count 를 맨 앞에 쓴다). 첫 count 앞에 다른 칸이 있거나, 한 레코드에 같은 키가
      두 번 나오면 ValueError.
    - 레코드 수, count 가 0 부터 이어지는지, 칸 이름과 길이가 맞는지는 여기서 보지 않는다(부르는 쪽이 본다).
    """
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("ascii")
        except UnicodeDecodeError as e:
            raise ValueError(f".rsp 에 ASCII 밖의 바이트가 있다(위치 {e.start})") from None
    if not isinstance(text, str):
        raise ValueError(".rsp 는 str 이나 bytes 여야 한다")
    if text.startswith("﻿"):
        text = text[1:]
    if not text.isascii():
        raise ValueError(".rsp 에 ASCII 밖의 글자가 있다")
    records, cur = [], None
    for n, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError(f"{n}행: '키 = 값' 꼴이 아니다: {line[:40]!r}")
        key, value = _norm_field(key, value, f"{n}행: ")
        if key == "count":
            cur = {}
            records.append(cur)
        elif cur is None:
            raise ValueError(f"{n}행: 첫 count 줄 앞에 {key} 가 있다")
        if key in cur:
            raise ValueError(f"{n}행: 한 레코드에 {key} 가 두 번 있다")
        cur[key] = value
    return records


def record_digest(record):
    """레코드 하나({키: 값})의 SHA-256(소문자 16진수 64자).

    값을 parse_rsp 와 같은 규칙으로 정규화한 뒤 키를 사전순으로 놓고, 칸마다 '키=값' 과 LF 를 이어 붙인 ASCII 바이트를 해시한다.
    그래서 칸 순서, 키 대소문자, 16진수 대소문자, 앞뒤 공백, 앞의 0 은 digest 를 바꾸지 않고, 값이 한 바이트라도 다르거나 칸이
    빠지거나 늘면 바뀐다. 정규화할 수 없는 값이나 정규화 뒤 겹치는 키는 ValueError.
    """
    if not isinstance(record, dict):
        raise ValueError("레코드는 dict 여야 한다")
    norm = {}
    for k, v in record.items():
        k, v = _norm_field(k, v)
        if k in norm:
            raise ValueError(f"정규화 뒤 키 {k} 가 겹친다")
        norm[k] = v
    body = "".join(f"{k}={norm[k]}\n" for k in sorted(norm))
    return hashlib.sha256(body.encode("ascii")).hexdigest()


def rsp_digest(records):
    """레코드 목록 전체의 SHA-256(소문자 16진수 64자).

    레코드마다 record_digest 를 파일 순서대로 구해 'digest' 와 LF 를 이어 붙인 ASCII 바이트를 해시한다. 순서가 바뀌거나 레코드가
    빠지거나 늘면 달라진다. 항목은 레코드(dict)이거나 이미 구한 record_digest(소문자 16진수 64자)여도 된다. 그래서
    scan/kat-kpqc.json 의 record_digests 만으로 원문 없이 같은 값을 다시 계산할 수 있다.
    """
    h = hashlib.sha256()
    for r in records:
        if isinstance(r, str):
            if not _DIGEST_RE.fullmatch(r):
                raise ValueError(f"record_digest 꼴이 아니다: {r[:20]!r}")
            d = r
        else:
            d = record_digest(r)
        h.update(d.encode("ascii") + b"\n")
    return h.hexdigest()
