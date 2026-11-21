# impl.py: 구현 검증(pqproof impl)의 순수 함수(표준 라이브러리만, tlsprobe.py 와 같은 꼴). 이 파일은 규칙 묶음 해시에 든다.
#   KpqC 네 알고리즘(SMAUG-T, NTRU+, HAETAE, AIMer)의 구현이 어느 참조판(판 이름 + .rsp SHA-256)의 KAT 와 일치하는지 본다.
#   PQ-Proof 는 검사 대상 구현을 빌드하거나 실행하지 않는다. 문제지(emit_prompt)를 내고, 사용자가 자기 하네스로 만든 답안
#   (답안 JSON 또는 PQCgenKAT .rsp)을 참조 KAT 와 대조만 한다(match_versions). 표준 준수나 공인 시험(KCMVP)이 아니다.
#   - .rsp 읽기와 digest: parse_rsp, record_digest, rsp_digest(참조판 목록을 만드는 tools/make_kat_manifest.py 도 쓴다)
#   - 참조판 목록 읽기: load_manifest(scan/kat-kpqc.json + scan/kat/ 발췌, 깨졌으면 ManifestError), build_key(판정할 파라미터만 담은
#     정답 묶음, 증적에 사본으로 남아 --verify 가 다시 판정한다), check_key, key_problem(사본을 이 도구의 목록과 판 기록마다 맞춘다)
#   - 문제지와 답안: emit_prompt, parse_input(답안 JSON 또는 .rsp, 64 MiB 상한), example_answers(어느 판 구현이라면 낼 답안. 자기
#     점검과 시험이 쓴다)
#   - 판정: match_versions(판마다 문항이 모두 맞으면 후보, 받아 줄 판이면 통과, 옛 판·알려진 변형이면 검토 필요), control_problem
#     (정답 답안은 통과, 한 바이트 바꾼 답안은 실패가 나오는지 먼저 확인), check_row(검사 행 i-kpqc, rules.judge_impl 이 쓴다)
#   - HAETAE KAT 서명은 .rsp 에 없는 ctx 로 만들어졌다. NIST PQCgenKAT 의 AES-256-CTR DRBG(NistDrbg)를 순수 파이썬으로 따라
#     seed 에서 ctx 를 다시 뽑아 문제지에 넣는다.
#   - NIST PQC 는 pq-verify 다리(검사 i-nist, 맨 아래 절): 사용자가 --pq-verify 로 켤 때만 prove.py 가 바깥 도구 pq-verify 를 부르고,
#     여기 순수 함수가 인자를 검사하고(pqverify_args) 보고서를 읽어 판정한다(pqverify_summary, pqverify_status, nist_check_row).
# 받는 답안과 .rsp 는 남이 만든 데이터다. 글자로만 읽고, 그 안의 무엇도 실행하지 않는다. 이 파일은 다른 pqlite 모듈을 가져오지 않는다
# (pqlite/receipt.py 가 --verify 에서 파일 경로로 읽는다).
"""Implementation check: KpqC question sheet, answers and matching against pinned reference KAT versions; the pq-verify bridge."""
from __future__ import annotations  # 맥 기본 python3 3.9

import hashlib
import io
import json
import os
import re

# 10진 정수 칸. PQCgenKAT 가 길이와 번호를 10진으로 쓴다(KEM 은 count 만, 서명은 mlen 과 smlen 또는 siglen)
DEC_FIELDS = frozenset({"count", "mlen", "smlen", "siglen"})
DEC_DIGITS = 18  # 10진 칸의 자릿수 상한(앞의 0 을 뗀 뒤). 맥 기본 python 3.9 의 int() 는 긴 숫자에 자릿수 제곱 시간이 걸린다
JSON_NUMBER_CHARS = 40  # JSON 숫자 글의 길이 상한(같은 까닭. 3.11 부터는 int 가 4300자리에서 스스로 멈춘다)
KEY_CHARS = 32  # .rsp 칸 이름의 길이 상한(참조판은 count·seed·pk·sk·ct·ss·mlen·msg·siglen·sig·smlen·sm 뿐이다)
MAX_RSP_RECORDS = 1000  # .rsp 레코드 수 상한(참조 KAT 는 100건). 'count = 0' 줄만 이어 붙인 파일이 메모리를 입력의 백 배 넘게 쓰지 않게
_KEY_RE = re.compile(r"[a-z][a-z0-9_]*")
_HEX_RE = re.compile(r"[0-9A-Fa-f]*")
_DEC_RE = re.compile(r"[0-9]+")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


# 판정 글에 그대로 넣지 않는 글자: C0·DEL·C1 제어 문자, 줄·문단 나눔(U+2028·2029), 양방향 제어(U+061C, U+200E·200F, U+202A~202E,
# U+2066~2069), 폭 없는 글자(U+200B~200D, U+2060~2064, U+FEFF), 서로게이트. str.isprintable() 은 파이썬에 든 유니코드 판을 따라
# (3.9 는 13.0, 3.15 는 17.0) 새 글자를 판마다 다르게 보므로 쓰지 않는다: 같은 입력이면 어느 파이썬에서도 같은 판정 글이 나와야 한다
_UNSAFE_RANGES = ((0x00, 0x1F), (0x7F, 0x9F), (0x061C, 0x061C), (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x2064),
                  (0x2066, 0x2069), (0xD800, 0xDFFF), (0xFEFF, 0xFEFF))
_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def unsafe_char(c):
    """판정 글에 그대로 넣지 않는 글자인가(_UNSAFE_RANGES, 파이썬 판과 무관한 고정 규칙)."""
    o = ord(c)
    return any(a <= o <= b for a, b in _UNSAFE_RANGES)


def _escape(c):
    o = ord(c)
    return _ESCAPES.get(c) or (f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}")


def _q(v):
    """판정 글에 값을 따옴표로 넣는 꼴. ASCII 글과 글이 아닌 값은 repr 그대로(파이썬 판마다 같다), 그 밖의 글은 repr 대신 작은따옴표로
    싼다(repr 은 isprintable 을 따라 파이썬 판마다 다르게 적는다). 넣기 전에 shown 으로 제어 문자를 적어 바꾼다."""
    if not isinstance(v, str) or v.isascii():
        return repr(v)
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"


def shown(text, n=80):
    """남이 준 글(답안의 문항 id·칸 이름·파라미터 이름, .rsp 머리 줄, pq-verify 출력)을 판정 글에 넣는 꼴: 제어 문자·줄바꿈·ESC·양방향
    제어 같은 글자(unsafe_char)는 \\x1b 처럼 적고 n 자에서 자른다. 콘솔·receipt·report.md·csv 로 터미널 제어 문자가 새지 않게 한다."""
    s = str(text)
    body = "".join(_escape(c) if unsafe_char(c) else c for c in s[:n])
    return body + ("..." if len(s) > n else "")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 저장소 루트, 또는 설치본의 pqproof/_tool
KAT_FILE = os.path.join(ROOT, "scan", "kat-kpqc.json")
MAX_INPUT = 64 << 20  # 답안 파일 상한(바이트). 넘으면 읽지 않고 미판정
PROMPT_FORMAT = "pqproof impl prompt 1"
RESPONSE_FORMAT = "pqproof impl response 1"
KEY_FORMAT = "pqproof impl key 1"
ENGINE = "kpqc-kat"
CHECK_ID = "i-kpqc"


def _norm_field(key, value, where=""):
    """칸 하나를 정규화한 (키, 값). 키는 앞뒤 공백을 지운 소문자, 10진 칸은 앞의 0 을 뗀 10진 문자열, 그 밖은 대문자 16진수.
    규칙에 안 맞으면 ValueError."""
    if not isinstance(key, str) or not isinstance(value, str):
        raise ValueError(f"{where}키와 값은 문자열이어야 한다({key!r})")
    key, value = key.strip().lower(), value.strip()
    if len(key) > KEY_CHARS:
        raise ValueError(f"{where}키 이름이 {len(key):,}자로 상한 {KEY_CHARS}자를 넘는다: {_q(shown(key, 40))}")
    if not _KEY_RE.fullmatch(key):
        raise ValueError(f"{where}키 이름이 아니다: {_q(shown(key, 40))}")
    if key in DEC_FIELDS:
        if not _DEC_RE.fullmatch(value):
            raise ValueError(f"{where}{key} 는 10진 정수여야 한다: {value[:40]!r}")
        digits = value.lstrip("0") or "0"  # int() 를 쓰지 않는다(긴 숫자에 제곱 시간). 앞의 0 을 뗀 글이 곧 정규형이다
        if len(digits) > DEC_DIGITS:
            raise ValueError(f"{where}{key} 가 {len(digits):,}자리로 상한 {DEC_DIGITS}자리를 넘는다")
        return key, digits
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
    - 줄 끝은 LF, CRLF, CR 모두 받는다. 맨 앞 BOM(U+FEFF, bytes 로 주면 EF BB BF)은 지운다. ASCII 밖의 글자가 있으면 ValueError.
    - 빈 줄과 '#' 로 시작하는 줄(맨 위 '# smaugt_mode1' 같은 이름 줄)은 버린다. 빈 줄은 값이 아니고, 레코드 경계는 count 줄이 정한다.
    - 나머지 줄은 '키 = 값' 꼴이어야 한다(첫 '=' 에서 나눈다). 키는 앞뒤 공백을 지우고 소문자로, 값은 앞뒤 공백을 지운다.
    - 10진 칸(count, mlen, smlen, siglen)은 10진 정수여야 하고 앞의 0 을 뗀 문자열로 둔다('033' 은 '33'). 18자리를 넘으면 ValueError.
    - 그 밖의 칸은 16진수여야 하고(빈 값 허용) 대문자로 바꾼다. 16진수가 아닌 글자나 홀수 자릿수는 ValueError.
    - count 줄이 새 레코드를 연다(PQCgenKAT 는 count 를 맨 앞에 쓴다). 첫 count 앞에 다른 칸이 있거나, 한 레코드에 같은 키가
      두 번 나오면 ValueError. 레코드가 MAX_RSP_RECORDS 건을 넘거나 키 이름이 KEY_CHARS 자를 넘어도 ValueError.
    - 레코드 수, count 가 0 부터 이어지는지, 칸 이름과 길이가 맞는지는 여기서 보지 않는다(부르는 쪽이 본다).
    """
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text)
        if text.startswith(b"\xef\xbb\xbf"):
            text = text[3:]
        try:
            text = text.decode("ascii")
        except UnicodeDecodeError as e:
            raise ValueError(f".rsp 에 ASCII 밖의 바이트가 있다(위치 {e.start})") from None
    if not isinstance(text, str):
        raise ValueError(".rsp 는 str 이나 bytes 여야 한다")
    if text.startswith("﻿"):
        text = text[1:]
    if not text.isascii():
        raise ValueError(".rsp 에 ASCII 밖의 글자가 있다")
    records, cur = [], None
    for n, raw in enumerate(io.StringIO(text.replace("\r\n", "\n").replace("\r", "\n"), newline="\n"), 1):  # 줄 목록을 한꺼번에 만들지 않는다
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError(f"{n}행: '키 = 값' 꼴이 아니다: {line[:40]!r}")
        key, value = _norm_field(key, value, f"{n}행: ")
        if key == "count":
            if len(records) >= MAX_RSP_RECORDS:
                raise ValueError(f"{n}행: 레코드가 상한 {MAX_RSP_RECORDS:,}건을 넘는다(참조 KAT 는 100건)")
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


def dumps(obj):
    """문제지·정답 묶음·답안 파일을 쓰는 꼴(키 정렬, 들여쓰기 1). 같은 값이면 바이트까지 같다."""
    return json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def _digest(body):
    """문제지 본문(format, params, sizes, items)의 SHA-256. 키 정렬·공백 없는 JSON 이다. 값이 문자열·참거짓·목록·객체뿐이고 키가 ASCII 라
    RFC 8785 정규형과 같다."""
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _loads_strict(data, where):
    """JSON 을 엄격하게 읽는다: UTF-8(BOM 없음), 중복 키·NaN·Infinity 거부, 숫자 글은 JSON_NUMBER_CHARS 자까지, 너무 깊게 겹친 값
    (RecursionError)도 거부. 틀리면 예외 대신 ValueError(까닭에 where 를 붙인다). 부르는 쪽은 이것을 미판정 까닭으로 적는다."""
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"{where}: 키 {_q(shown(k))} 가 두 번 있다")
            out[k] = v
        return out

    def constant(name):
        raise ValueError(f"{where}: {name} 는 JSON 숫자가 아니다")

    def number(kind):
        def parse(text):
            if len(text) > JSON_NUMBER_CHARS:
                raise ValueError(f"{where}: 숫자가 {len(text):,}자로 상한 {JSON_NUMBER_CHARS}자를 넘는다")
            return kind(text)
        return parse
    if isinstance(data, (bytes, bytearray)):
        if bytes(data[:3]) == b"\xef\xbb\xbf":
            raise ValueError(f"{where}: UTF-8 BOM 으로 시작한다")
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"{where}: UTF-8 이 아니다(위치 {e.start})") from None
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant, parse_int=number(int), parse_float=number(float))
    except json.JSONDecodeError:  # 파이썬 json 의 오류 글과 위치는 판마다 다르다(끝 쉼표: 3.13 부터 'Illegal trailing comma'). 판정 글에 넣지 않는다
        raise ValueError(f"{where}: JSON 이 아니다(문법 오류. 위치는 python3 -m json.tool 로 본다)") from None
    except RecursionError:
        raise ValueError(f"{where}: 값이 너무 깊게 겹쳐 있다(파이썬 재귀 한도)") from None
    except MemoryError:
        raise ValueError(f"{where}: 읽다가 메모리가 모자랐다") from None


# ---------------------------------------------------------------------------------------------
# NIST PQCgenKAT 의 DRBG(kat/rng.c 의 randombytes_init, randombytes, AES256_CTR_DRBG_Update). AES-256 은 FIPS 197 을 그대로 짠
# 순수 파이썬이다(블록 하나 암호화만, 상수 시간이 아니다: 공개 KAT seed 에만 쓴다). tests/test_impl.py 가 FIPS 197 C.3 벡터와
# 참조 라이브러리로 다시 뽑은 HAETAE ctx 로 확인한다.
def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _make_sbox():
    """AES S-box(FIPS 197 5.1.1): 3 의 거듭제곱 p 와 그 역원 q 를 함께 돌며 q 에 아핀 변환을 한다. 0 의 값은 0x63."""
    sbox = [0x63] * 256
    p = q = 1
    while True:
        p ^= _xtime(p)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            return sbox


_SBOX = _make_sbox()


def _aes256_round_keys(key):
    """AES-256 키 확장(FIPS 197 5.2): 라운드 키 15개, 각 16바이트 목록."""
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - 8], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(15)]


def _aes256_encrypt(round_keys, block):
    """블록 하나(16바이트) 암호화. 상태는 열 우선(바이트 i 가 열 i//4, 행 i%4)."""
    s = [b ^ k for b, k in zip(block, round_keys[0])]
    for r in range(1, 15):
        s = [_SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows: 행 c 를 c 칸 왼쪽으로
        if r != 14:
            mixed = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed += [a[j] ^ t ^ _xtime(a[j] ^ a[(j + 1) % 4]) for j in range(4)]
            s = mixed
        s = [b ^ k for b, k in zip(s, round_keys[r])]
    return bytes(s)


class NistDrbg:
    """NIST PQCgenKAT 의 AES-256-CTR DRBG. NistDrbg(seed 48바이트)가 randombytes_init(seed, NULL, 256), take(n) 이
    randombytes(x, n) 한 번이다(끝에 Update 를 한 번 하므로 몇 바이트씩 나눠 뽑는지가 결과를 바꾼다)."""

    def __init__(self, seed):
        seed = bytes(seed)
        if len(seed) != 48:
            raise ValueError("DRBG seed 는 48바이트다")
        self._key, self._v = bytes(32), bytes(16)
        self._update(seed)

    def _block(self, round_keys):
        self._v = ((int.from_bytes(self._v, "big") + 1) & ((1 << 128) - 1)).to_bytes(16, "big")
        return _aes256_encrypt(round_keys, self._v)

    def _update(self, data):
        rk = _aes256_round_keys(self._key)
        t = b"".join([self._block(rk) for _ in range(3)])
        if data is not None:
            t = bytes(a ^ b for a, b in zip(t, data))
        self._key, self._v = t[:32], t[32:]

    def take(self, n):
        rk = _aes256_round_keys(self._key)
        out = b"".join([self._block(rk) for _ in range((n + 15) // 16)])
        self._update(None)
        return out[:n]


def haetae_context(seed_hex):
    """HAETAE PQCgenKAT 가 그 레코드를 서명할 때 쓴 ctx(대문자 16진수). randombytes_init(seed) 뒤 키 seed 32바이트, rnd 32바이트,
    ctxlen 1바이트, ctx ctxlen 바이트를 한 번씩 뽑는다(kat/PQCgenKAT_sign.c). 서명은 pre = ctxlen || ctx 로 만들어졌고 .rsp 에는
    ctx 가 없다."""
    d = NistDrbg(bytes.fromhex(seed_hex))
    d.take(32)
    d.take(32)
    return d.take(d.take(1)[0]).hex().upper()


CONTEXT = {"haetae": haetae_context}  # 알고리즘 → seed 에서 ctx 를 뽑는 함수. 없는 서명 알고리즘(AIMer)은 빈 ctx 로 서명했다


def context_of(alg, seed_hex):
    f = CONTEXT.get(alg)
    return f(seed_hex) if f else ""


# ---------------------------------------------------------------------------------------------
# 참조판 목록과 정답 묶음
class ManifestError(ValueError):
    """참조판 목록(scan/kat-kpqc.json), 발췌(scan/kat/), 또는 증적에 남은 정답 묶음 사본이 깨졌다."""


KEM_FIELDS = ["count", "seed", "pk", "sk", "ct", "ss"]
SIG_BASE = ["count", "seed", "mlen", "msg", "pk", "sk"]
SIG_FIELDS = (SIG_BASE + ["siglen", "sig"], SIG_BASE + ["smlen", "sm"])  # HAETAE 꼴, AIMer 꼴(sm = msg || sig)
ROLES = ("reference", "known-variant")
VERSION_KEYS = ("version", "latest", "role", "source", "rsp_sha256", "digest", "records", "record_digests", "sizes")
_PID_RE = re.compile(r"[a-z0-9][a-z0-9+_-]*/[a-z0-9][a-z0-9_-]*")
_VER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_EXCERPT_RE = re.compile(r"scan/kat/[a-z0-9+_-]+/[a-z0-9_-]+/[A-Za-z0-9][A-Za-z0-9._-]*\.json")


def signature_of(rec):
    """레코드의 서명만(HAETAE 는 sig 칸, AIMer 는 sm = msg || sig 에서 msg 를 뗀 것)."""
    if "sig" in rec:
        return rec["sig"]
    return rec["sm"][2 * int(rec["mlen"]):]


def signed_message_of(rec):
    """레코드의 sm(AIMer 는 sm 칸, HAETAE 는 참조 crypto_sign 이 쓰는 꼴 sig || msg)."""
    if "sm" in rec:
        return rec["sm"]
    return rec["sig"] + rec["msg"]


def _size_problem(P, V, rec):
    """레코드 칸 길이가 판의 sizes·길이 칸과 맞는가(틀린 칸 이름, 맞으면 None)."""
    sizes = V["sizes"]

    def n(f):
        return len(rec[f]) // 2
    if P["kind"] == "kem":
        return next((f for f in ("pk", "sk", "ct", "ss") if f in sizes and n(f) != sizes[f]), None)
    bad = next((f for f in ("pk", "sk") if f in sizes and n(f) != sizes[f]), None)
    if bad:
        return bad
    if n("msg") != int(rec["mlen"]):
        return "mlen"
    if "sig" in rec:
        if int(rec["siglen"]) != n("sig"):
            return "siglen"
    elif int(rec["smlen"]) != n("sm") or not rec["sm"].startswith(rec["msg"]):
        return "smlen"
    return "sig" if "sig" in sizes and len(signature_of(rec)) // 2 != sizes["sig"] else None


def _check_param(P, where):
    """정답 묶음 꼴의 파라미터 하나를 검사한다(틀리면 ManifestError). 판마다 record_digests 로 digest 를 다시 계산하고, 발췌 레코드는
    정규화된 값인지, count 가 0 부터 이어지는지, record_digest 가 그 자리의 record_digests 와 같은지, 길이가 sizes 와 맞는지 본다."""
    if not isinstance(P, dict):
        raise ManifestError(f"{where}: 파라미터가 객체가 아니다")
    pid = P.get("id")
    if not isinstance(pid, str) or not _PID_RE.fullmatch(pid):
        raise ManifestError(f"{where}: 파라미터 이름이 아니다: {pid!r}")
    w = f"{where} {pid}"
    kind, fields = P.get("kind"), P.get("fields")
    if (kind, fields) not in [("kem", KEM_FIELDS)] + [("sig", f) for f in SIG_FIELDS]:
        raise ManifestError(f"{w}: kind {kind!r} 와 fields {fields!r} 가 아는 꼴이 아니다")
    if P.get("alg") != pid.split("/", 1)[0] or not isinstance(P.get("name"), str):
        raise ManifestError(f"{w}: alg 는 이름 앞부분, name 은 글이어야 한다")
    if not isinstance(P.get("aliases"), list) or not all(isinstance(a, str) and a for a in P["aliases"]):
        raise ManifestError(f"{w}: aliases 는 글 목록이어야 한다")
    versions = P.get("versions")
    if not isinstance(versions, list) or not versions:
        raise ManifestError(f"{w}: 판이 없다")
    names = []
    for V in versions:
        if not isinstance(V, dict) or set(V) != set(VERSION_KEYS) | {"excerpt"}:
            raise ManifestError(f"{w}: 판 기록의 칸이 {sorted(VERSION_KEYS) + ['excerpt']} 가 아니다")
        name = V["version"]
        wv = f"{w}@{name}"
        if not isinstance(name, str) or not _VER_RE.fullmatch(name) or name in names:
            raise ManifestError(f"{wv}: 판 이름이 틀렸거나 두 번 있다")
        names.append(name)
        if not isinstance(V["latest"], bool) or V["role"] not in ROLES or not isinstance(V["source"], str):
            raise ManifestError(f"{wv}: latest·role·source 가 틀렸다")
        if not isinstance(V["rsp_sha256"], str) or not _DIGEST_RE.fullmatch(V["rsp_sha256"]):
            raise ManifestError(f"{wv}: rsp_sha256 이 SHA-256 이 아니다")
        rd = V["record_digests"]
        if (not isinstance(V["records"], int) or isinstance(V["records"], bool) or V["records"] < 1 or not isinstance(rd, list)
                or len(rd) != V["records"] or not all(isinstance(d, str) and _DIGEST_RE.fullmatch(d) for d in rd)):
            raise ManifestError(f"{wv}: records 와 record_digests 가 맞지 않는다")
        if rsp_digest(rd) != V["digest"]:
            raise ManifestError(f"{wv}: record_digests 로 다시 계산한 digest 가 {V['digest']!r} 가 아니다")
        if not isinstance(V["sizes"], dict) or not all(isinstance(k, str) and isinstance(v, int) for k, v in V["sizes"].items()):
            raise ManifestError(f"{wv}: sizes 가 틀렸다")
        ex = V["excerpt"]
        if ex is None:
            continue
        if not isinstance(ex, list) or not ex or len(ex) > len(rd):
            raise ManifestError(f"{wv}: 발췌 레코드 목록이 틀렸다")
        for i, rec in enumerate(ex):
            if not isinstance(rec, dict) or set(rec) != set(fields):
                raise ManifestError(f"{wv}: 발췌 {i} 의 칸이 {fields} 가 아니다")
            for k, v in rec.items():
                if _norm_field(k, v, f"{wv} 발췌 {i}: ") != (k, v):
                    raise ManifestError(f"{wv}: 발췌 {i} 의 {k} 가 정규화된 값이 아니다")
            if rec["count"] != str(i):
                raise ManifestError(f"{wv}: 발췌 {i} 의 count 가 {rec['count']} 다")
            if record_digest(rec) != rd[i]:
                raise ManifestError(f"{wv}: 발췌 {i} 의 record_digest 가 record_digests[{i}] 와 다르다")
            bad = _size_problem(P, V, rec)
            if bad:
                raise ManifestError(f"{wv}: 발췌 {i} 의 {bad} 길이가 sizes 와 맞지 않는다")
    if sum(1 for V in versions if V["latest"]) != 1:
        raise ManifestError(f"{w}: latest 판이 정확히 하나여야 한다")


def _names(params):
    """{소문자 이름: 파라미터}. 정식 이름과 별칭 모두. 다른 파라미터와 겹치면 ManifestError."""
    out = {}
    for P in params:
        for a in [P["id"]] + P["aliases"]:
            k = a.lower()
            if out.get(k, P["id"]) != P["id"]:
                raise ManifestError(f"별칭 {a!r} 가 {out[k]} 와 {P['id']} 에 함께 있다")
            out[k] = P["id"]
    return out


def _source_note(S):
    """출처 기록 → 한 줄 설명: 제목, 그리고 공식 페이지가 낸 SHA-256 이 맞은 출처(official.match true)면 그 페이지와 페이지의 말."""
    if not isinstance(S, dict) or not isinstance(S.get("title"), str):
        return None
    o = S.get("official") if isinstance(S.get("official"), dict) else {}
    said = o.get("match") is True and isinstance(o.get("page"), str) and isinstance(o.get("says"), str)
    return S["title"] + (f" ({o['page']}: \"{o['says']}\")" if said else "")


def load_manifest(path=KAT_FILE):
    """scan/kat-kpqc.json 과 그것이 가리키는 scan/kat/ 발췌를 읽어 검사한다(rules.load_profiles 처럼, 틀리면 ManifestError).
    반환: {"sha256": 목록 파일의 SHA-256, "params": {파라미터: 정답 묶음 꼴}, "order": [파라미터](목록 순서), "names": {소문자 이름:
    파라미터}, "sources": {출처 id: 제목(공식 페이지 해시가 맞으면 그 페이지의 말)}(콘솔 안내용, 판정에 쓰지 않는다)}. 정답 묶음 꼴은 {id, alg, name, kind, fields, aliases, versions: [{version, latest, role, source, rsp_sha256, digest,
    records, record_digests, sizes, excerpt(레코드 목록 또는 None)}]}."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(path)))
    rel = "scan/kat-kpqc.json"
    try:
        with open(path, "rb") as f:
            raw = f.read()
        doc = _loads_strict(raw, rel)
    except (OSError, ValueError) as e:
        raise ManifestError(f"{rel}: 읽을 수 없다({e})") from None
    if not isinstance(doc, dict) or doc.get("format") != 1 or not isinstance(doc.get("algorithms"), dict) \
            or not isinstance(doc.get("sources"), dict):
        raise ManifestError(f"{rel}: format 1 의 algorithms·sources 가 없다")
    params, order = {}, []
    for alg, A in doc["algorithms"].items():
        if not isinstance(A, dict) or not isinstance(A.get("params"), dict):
            raise ManifestError(f"{rel}: 알고리즘 {alg} 에 params 가 없다")
        for pid, src in A["params"].items():
            if not isinstance(src, dict) or not isinstance(src.get("variants"), list):
                raise ManifestError(f"{rel}: {pid} 에 variants 가 없다")
            P = {"id": pid, "alg": alg, "name": A.get("name"), "kind": A.get("kind"), "fields": A.get("fields"),
                 "aliases": src.get("aliases"), "versions": []}
            for v in src["variants"]:
                if not isinstance(v, dict):
                    raise ManifestError(f"{rel}: {pid} 의 판 기록이 객체가 아니다")
                if v.get("source") not in doc["sources"]:
                    raise ManifestError(f"{rel}: {pid}@{v.get('version')} 의 source {v.get('source')!r} 가 sources 에 없다")
                excerpt = None
                if v.get("excerpt") is not None:
                    ep = v["excerpt"]
                    if not isinstance(ep, str) or not _EXCERPT_RE.fullmatch(ep) or ".." in ep.split("/"):
                        raise ManifestError(f"{rel}: {pid}@{v.get('version')} 의 발췌 경로가 scan/kat/ 안 파일이 아니다: {ep!r}")
                    try:
                        with open(os.path.join(root, *ep.split("/")), "rb") as f:
                            ex = _loads_strict(f.read(), ep)
                    except (OSError, ValueError) as e:
                        raise ManifestError(f"{ep}: 읽을 수 없다({e})") from None
                    meta = (ex.get("param"), ex.get("version"), ex.get("digest"), ex.get("rsp_sha256")) if isinstance(ex, dict) else None
                    if meta != (pid, v.get("version"), v.get("digest"), v.get("rsp_sha256")):
                        raise ManifestError(f"{ep}: param·version·digest·rsp_sha256 이 목록의 {pid}@{v.get('version')} 과 다르다")
                    excerpt = ex.get("records")
                P["versions"].append(dict({k: v.get(k) for k in VERSION_KEYS}, excerpt=excerpt))
            _check_param(P, rel)
            if pid in params:
                raise ManifestError(f"{rel}: {pid} 가 두 번 있다")
            params[pid] = P
            order.append(pid)
    if not params:
        raise ManifestError(f"{rel}: 파라미터가 없다")
    sources = {sid: _source_note(S) for sid, S in doc["sources"].items()}
    return {"sha256": hashlib.sha256(raw).hexdigest(), "params": params, "order": order, "names": _names(params.values()),
            "sources": sources}


def build_key(manifest, pids):
    """판정할 파라미터만 담은 정답 묶음(목록 순서). 증적에 artifacts/impl/key.json 으로 남아 --verify 가 이것으로 다시 판정한다."""
    want = set(pids)
    return {"format": KEY_FORMAT, "params": [manifest["params"][p] for p in manifest["order"] if p in want]}


def check_key(key):
    """정답 묶음(증적의 사본)이 스스로 맞는가: 문제 목록([] 이면 맞다)."""
    if not isinstance(key, dict) or set(key) != {"format", "params"} or key.get("format") != KEY_FORMAT \
            or not isinstance(key.get("params"), list):
        return [f"정답 묶음이 {KEY_FORMAT!r} 꼴이 아니다"]
    try:
        for P in key["params"]:
            _check_param(P, "정답 묶음")
        _names(key["params"])
    except ManifestError as e:
        return [str(e)]
    ids = [P["id"] for P in key["params"]]
    return ["정답 묶음에 같은 파라미터가 두 번 있다"] if len(ids) != len(set(ids)) else []


def key_problem(manifest, key):
    """증적의 정답 묶음 사본을 이 도구의 참조판 목록(load_manifest)과 맞춘다(--verify 가, 목록이 그 증적을 쓸 때와 다를 때 쓴다).
    사본의 판 기록마다 목록에 같은 파라미터·판 이름·rsp_sha256 의 기록이 있고 digest·records·record_digests·sizes·excerpt 가 같아야
    한다(고정한 .rsp 의 KAT 는 바뀌지 않는다). latest·role·source·aliases 는 목록이 바뀌며 달라질 수 있고 상태를 정하지 않아 보지 않는다.
    맞으면 None, 아니면 까닭."""
    for P in key["params"]:
        M = manifest["params"].get(P["id"])
        if M is None:
            return f"{P['id']} 가 이 도구의 KAT 목록에 없다"
        if (P["alg"], P["kind"], P["fields"]) != (M["alg"], M["kind"], M["fields"]):
            return f"{P['id']} 의 alg·kind·fields 가 이 도구의 KAT 목록과 다르다"
        known = {(V["version"], V["rsp_sha256"]): V for V in M["versions"]}
        for V in P["versions"]:
            W = known.get((V["version"], V["rsp_sha256"]))
            if W is None:
                return f"{P['id']}@{V['version']}(rsp_sha256 {V['rsp_sha256'][:16]}) 이 이 도구의 KAT 목록에 없다"
            bad = next((k for k in ("digest", "records", "record_digests", "sizes", "excerpt") if V[k] != W[k]), None)
            if bad:
                return f"{P['id']}@{V['version']} 의 {bad} 가 이 도구의 KAT 목록과 다르다"
    return None


def key_names(key):
    """정답 묶음에 든 파라미터의 {소문자 이름: 파라미터}(--verify 가 판정 때와 같은 범위로 이름을 푼다)."""
    return _names(key["params"])


def resolve_accept(params, spec, pids):
    """받아 줄 판 {파라미터: [판 이름](목록 순서)}. params: {파라미터: 정답 묶음 꼴}(목록 전체), spec: 프로필의 impl_accept 목록.
    'latest' 는 파라미터마다 latest 판, '<파라미터>@<판>' 은 그 판, '<알고리즘>@<판>' 은 그 알고리즘 모든 파라미터의 그 판.
    아무 판도 가리키지 않는 항목은 ValueError(오타가 조용히 '받아 줄 판 없음'이 되지 않게)."""
    if not isinstance(spec, list) or not spec or not all(isinstance(x, str) for x in spec):
        raise ValueError("impl_accept 는 비지 않은 글 목록이어야 한다")
    hits = {pid: set() for pid in params}
    for item in spec:
        hit = False
        for pid, P in params.items():
            for V in P["versions"]:
                if (item == "latest" and V["latest"]) or item in (f"{pid}@{V['version']}", f"{P['alg']}@{V['version']}"):
                    hits[pid].add(V["version"])
                    hit = True
        if not hit:
            raise ValueError(f"impl_accept 의 {item!r} 가 가리키는 판이 없다")
    return {pid: [V["version"] for V in params[pid]["versions"] if V["version"] in hits[pid]] for pid in pids if pid in params}


def accept_list(accept):
    """{파라미터: [판]} → ['파라미터@판'](증적 impl.accept)."""
    return [f"{pid}@{v}" for pid in accept for v in accept[pid]]


def accept_from_list(items):
    out = {}
    for x in items:
        pid, _, v = x.rpartition("@")
        out.setdefault(pid, []).append(v)
    return out


# ---------------------------------------------------------------------------------------------
# 문제지
PROMPT_ABOUT = (
    "PQ-Proof KpqC question sheet. Run each item through your own implementation and write a response JSON: "
    "{\"format\": \"pqproof impl response 1\", \"prompt_sha256\": <prompt_sha256 of this sheet>, \"params\": <params of this sheet>, "
    "\"implementation\": <free text or null>, \"answers\": {<item id>: {<field>: <value>}}}, then run "
    "`pqproof impl judge <response.json>`. Values are hexadecimal in any case; ok is true or false. PQ-Proof compares the answers "
    "with pinned reference KAT versions (scan/kat-kpqc.json). It does not build or run your code, and the result is a match "
    "with a reference version's KAT, not a conformance test or a certification.")
ANSWER_GUIDE = {
    "decaps": "decapsulate ct with sk and give ss (answer: ss). Required.",
    "verify": "verify sig on msg under pk with the context string ctx (hex, empty for none) and give ok: true or false (answer: ok). "
              "Required. Some items carry a changed signature on purpose; do not read meaning into item ids.",
    "sizes": "byte lengths for buffers per parameter set: pk, sk, ct, ss of the latest reference version, and the longest sig.",
    "derand": "optional: call randombytes_init(seed, NULL, 256) of the NIST KAT DRBG that your build links, then keypair and encaps "
              "(KEM: pk, sk, ct, ss) or keypair and sign msg with ctx (signature: pk, sk, sig, or sm). sm is msg || sig for AIMer and "
              "sig || msg for HAETAE, as their reference crypto_sign writes it (msg || sig is also taken for HAETAE). Give any of these "
              "fields, or leave the item out. These answers tell reference versions apart when decaps and verify answers cannot.",
}
DERAND_FIELDS = {"kem": ["pk", "sk", "ct", "ss"], "sig": ["pk", "sk", "sig", "sm"]}


def _flip_hex(h):
    """16진수 글의 첫 바이트 마지막 비트를 바꾼다(변조 서명 문항, 한 바이트 바꾼 답안)."""
    return f"{int(h[:2], 16) ^ 1:02X}" + h[2:]


def _item_base(P, V, rec):
    return f"{P['id']}@{V['version']}#{rec['count']}"


def _expected(P, V, rec):
    """레코드 하나에서 나오는 문항의 기대 답 {문항 id: {칸: 값}}."""
    base = _item_base(P, V, rec)
    if P["kind"] == "kem":
        return {base + ":decaps": {"ss": rec["ss"]},
                base + ":derand": {"pk": rec["pk"], "sk": rec["sk"], "ct": rec["ct"], "ss": rec["ss"]}}
    return {base + ":verify": {"ok": True}, base + ":verify-tampered": {"ok": False},
            base + ":derand": {"pk": rec["pk"], "sk": rec["sk"], "sig": signature_of(rec), "sm": signed_message_of(rec)}}


def emit_prompt(key):
    """정답 묶음 → 문제지(결정적). 파라미터마다, 발췌가 있는 판마다, 레코드마다
    KEM: decaps(sk, ct → ss, 필수), derand(seed → pk·sk·ct·ss, 선택)
    서명: verify(pk, msg, sig, ctx → ok, 필수, 기대 true), verify-tampered(서명 첫 바이트를 바꾼 것, 기대 false), derand(seed, msg, ctx
    → pk·sk·sig·sm, 선택). sizes 는 하네스 버퍼 크기. prompt_sha256 은 format·params·sizes·items 의 해시라 설명 글이 바뀌어도
    그대로다."""
    items = []
    for P in key["params"]:
        for V in P["versions"]:
            for rec in V["excerpt"] or ():
                base = _item_base(P, V, rec)
                if P["kind"] == "kem":
                    items.append({"id": base + ":decaps", "param": P["id"], "op": "decaps", "sk": rec["sk"], "ct": rec["ct"],
                                  "answer": ["ss"], "optional": []})
                    items.append({"id": base + ":derand", "param": P["id"], "op": "derand", "seed": rec["seed"], "answer": [],
                                  "optional": DERAND_FIELDS["kem"]})
                    continue
                ctx, sig = context_of(P["alg"], rec["seed"]), signature_of(rec)
                for suffix, s in ((":verify", sig), (":verify-tampered", _flip_hex(sig))):
                    items.append({"id": base + suffix, "param": P["id"], "op": "verify", "pk": rec["pk"], "msg": rec["msg"], "sig": s,
                                  "ctx": ctx, "answer": ["ok"], "optional": []})
                items.append({"id": base + ":derand", "param": P["id"], "op": "derand", "seed": rec["seed"], "msg": rec["msg"],
                              "ctx": ctx, "answer": [], "optional": DERAND_FIELDS["sig"]})
    body = {"format": PROMPT_FORMAT, "params": [P["id"] for P in key["params"]], "sizes": {P["id"]: _buffer_sizes(P) for P in key["params"]},
            "items": items}
    return dict(body, about=PROMPT_ABOUT, guide=ANSWER_GUIDE, prompt_sha256=_digest(body))


def _buffer_sizes(P):
    """하네스의 버퍼 크기(바이트): 최신판의 pk·sk·ct·ss, 서명은 판 가운데 가장 긴 sig(서명 함수가 실제 길이를 돌려준다)."""
    latest = next(V for V in P["versions"] if V["latest"])
    out = {f: latest["sizes"][f] for f in ("pk", "sk", "ct", "ss") if f in latest["sizes"]}
    if P["kind"] == "sig":
        out["sig"] = max(V["sizes"].get("sig", 0) for V in P["versions"])
    return out


def example_answers(key, pick, implementation="example answers built from the reference KAT excerpts"):
    """pick({파라미터: 판}) 판의 구현이라면 낼 답안. 그 판 문항은 기대 답 그대로, 다른 판 문항은 decaps 가 그 문항 기대 ss 의 첫 바이트를
    바꾼 값, verify 는 false, derand 는 같은 count 의 고른 판 값(seed 가 판마다 같다)이다. 자기 점검(control_problem)과 시험이 쓴다."""
    prompt = emit_prompt(key)
    exp, own = {}, {}
    for P in key["params"]:
        for V in P["versions"]:
            for rec in V["excerpt"] or ():
                e = _expected(P, V, rec)
                for iid, val in e.items():
                    exp[iid] = (P["id"], V["version"], rec["count"], val)
                if pick.get(P["id"]) == V["version"]:
                    own[(P["id"], rec["count"])] = e[_item_base(P, V, rec) + ":derand"]
    answers = {}
    for it in prompt["items"]:
        pid, ver, count, val = exp[it["id"]]
        if pick.get(pid) == ver:
            answers[it["id"]] = dict(val)
        elif it["op"] == "decaps":
            answers[it["id"]] = {"ss": _flip_hex(val["ss"])}
        elif it["op"] == "verify":
            answers[it["id"]] = {"ok": False}
        elif (pid, count) in own:
            answers[it["id"]] = dict(own[(pid, count)])
    return {"format": RESPONSE_FORMAT, "prompt_sha256": prompt["prompt_sha256"], "params": prompt["params"],
            "implementation": implementation, "answers": answers}


# ---------------------------------------------------------------------------------------------
# 답안 읽기
RESPONSE_KEYS = {"format", "prompt_sha256", "params", "implementation", "answers"}
HEX_ANSWERS = {"ss", "pk", "sk", "ct", "sig", "sm"}


def oversize_problem(n):
    """상한을 넘는 답안의 까닭(파일은 읽지 않고 증적에 사본도 남기지 않는다)."""
    return f"답안이 {n:,}바이트로 상한 {MAX_INPUT:,}바이트(64 MiB)를 넘는다"


def parse_input(data):
    """답안 바이트 → {"kind": "response"|"rsp"|None, "problem": 까닭 또는 None, ...}. 꼴이 틀렸으면 예외 대신 problem 에 적는다
    (판정은 미판정). 맨 앞(공백 뒤) 글자가 '{' 면 답안 JSON, 아니면 PQCgenKAT .rsp 로 읽는다.
    답안 JSON: params, prompt_sha256, implementation, answers({문항 id: {칸: 값}}, 16진수는 대문자로).
    .rsp: header(맨 앞 '#' 줄의 이름 또는 None), records(parse_rsp)."""
    if len(data) > MAX_INPUT:
        return {"kind": None, "problem": oversize_problem(len(data))}
    head = bytes(data).lstrip()
    if head[:1] == b"{" or head.startswith(b"\xef\xbb\xbf{"):  # BOM 붙은 JSON 은 JSON 으로 읽고 BOM 을 까닭으로 적는다
        return _parse_response(data)
    return _parse_rsp_input(data)


def _parse_response(data):
    out = {"kind": "response", "problem": None, "params": [], "prompt_sha256": None, "implementation": None, "answers": {}}

    def bad(msg):
        return dict(out, problem=msg)
    try:
        doc = _loads_strict(data, "답안")
    except ValueError as e:
        return bad(f"답안 JSON 을 읽을 수 없다: {e}")
    if not isinstance(doc, dict):
        return bad("답안 JSON 이 객체가 아니다")
    if doc.get("format") != RESPONSE_FORMAT:
        return bad(f"답안 format 이 {RESPONSE_FORMAT!r} 가 아니다")
    extra = sorted(set(doc) - RESPONSE_KEYS)
    if extra:
        return bad(f"답안에 모르는 칸이 있다: {', '.join(shown(x) for x in extra[:4])}" + (f" 외 {len(extra) - 4}개" if len(extra) > 4 else ""))
    ps, params, impl, answers = doc.get("prompt_sha256"), doc.get("params"), doc.get("implementation"), doc.get("answers")
    if not isinstance(ps, str) or not _DIGEST_RE.fullmatch(ps):
        return bad("prompt_sha256 이 소문자 16진수 64자가 아니다")
    if not isinstance(params, list) or not params or not all(isinstance(p, str) for p in params) or len(set(params)) != len(params):
        return bad("params 가 겹치지 않는 파라미터 이름 목록이 아니다")
    if impl is not None and (not isinstance(impl, str) or len(impl) > 500):
        return bad("implementation 은 500자 이하 글이거나 null 이어야 한다")
    if impl is not None and any(unsafe_char(c) for c in impl):
        return bad("implementation 에 인쇄할 수 없는 글자(줄바꿈·제어 문자·양방향 제어)가 있다")
    if not isinstance(answers, dict):
        return bad("answers 가 객체가 아니다")
    norm = {}
    for iid, a in answers.items():
        w = shown(iid)
        if not isinstance(a, dict):
            return bad(f"답 {w}: 객체가 아니다")
        got = {}
        for k, v in a.items():
            if k == "ok":
                if not isinstance(v, bool):
                    return bad(f"답 {w}: ok 는 true 나 false 여야 한다")
                got[k] = v
            elif k in HEX_ANSWERS:
                if not isinstance(v, str) or not _HEX_RE.fullmatch(v.strip()) or len(v.strip()) % 2:
                    return bad(f"답 {w}: {k} 가 짝수 자리 16진수가 아니다")
                got[k] = v.strip().upper()
            else:
                return bad(f"답 {w}: 모르는 칸 {_q(shown(k, 40))}")
        norm[iid] = got
    return dict(out, params=params, prompt_sha256=ps, implementation=impl, answers=norm)


def _parse_rsp_input(data):
    out = {"kind": "rsp", "problem": None, "header": None, "records": []}
    data = bytes(data)
    skip = 3 if data.startswith(b"\xef\xbb\xbf") else 0  # UTF-8 BOM 은 떼고 읽는다(parse_rsp 와 같은 규칙)
    try:
        text = data[skip:].decode("ascii")
    except UnicodeDecodeError as e:
        return dict(out, problem=f".rsp 에 ASCII 밖의 바이트가 있다(위치 {e.start + skip})")
    s = re.match(r"[^\r\n]*", text.lstrip())[0].strip()  # 첫 비지 않은 줄(줄 목록을 만들지 않는다)
    if s.startswith("#"):
        out["header"] = shown(s[1:].strip(), 200) or None
    try:
        out["records"] = parse_rsp(text)
    except ValueError as e:
        return dict(out, problem=f".rsp 를 읽을 수 없다: {e}")
    return out


def input_params(parsed, names, hint=None):
    """판정할 파라미터와 입력 문제: ([파라미터], 까닭 또는 None). names: {소문자 이름: 파라미터}(목록 전체 또는 정답 묶음).
    답안 JSON 은 params 칸을 정식 이름으로 읽어 names 의 순서(목록 순서)로 돌려주고(답안이 params 를 다른 순서로 써도 증적의 params·
    impl.accept 는 목록 순서다), .rsp 는 hint(--param, 정식 이름) 또는 머리 줄 이름을 쓴다. hint 를 주면 머리 줄이
    다른 파라미터의 알려진 이름일 때만 막고, 모르는 이름(자체 빌드 이름 등)이면 hint 를 따른다(머리 줄은 증적 impl.input.header 에 남는다)."""
    if parsed["kind"] == "response":
        order = list(dict.fromkeys(names.values()))  # 목록(정답 묶음) 순서. 답안 params 순서와 상관없이 증적은 이 순서로 적는다
        known = sorted((p for p in parsed["params"] if names.get(p.lower()) == p), key=order.index)
        unknown = [p for p in parsed["params"] if p not in known]
        if unknown:
            return known, (f"모르는 파라미터 {', '.join(shown(p, 60) for p in unknown[:4])}"
                           + (f" 외 {len(unknown) - 4}개" if len(unknown) > 4 else "") + "(문제지는 pqproof impl prompt 가 낸 정식 이름을 쓴다)")
        return known, None
    if parsed["kind"] != "rsp":
        return ([hint] if hint else []), None
    header = parsed.get("header")
    if hint:
        other = names.get(header.lower()) if header else None
        if other is not None and other != hint:
            return [hint], f"머리 줄 '# {header}' 은 {other} 의 이름이다(--param {hint} 와 다르다: 다른 파라미터의 .rsp 이거나 --param 이 틀렸다)"
        return [hint], None
    pid = names.get(header.lower()) if header else None
    if pid is None:
        return [], ("파라미터를 정할 수 없다: " + (f"머리 줄 '# {header}' 이 아는 이름이 아니다" if header else ".rsp 에 머리 줄이 없다")
                    + ". --param 으로 준다")
    return [pid], None


# ---------------------------------------------------------------------------------------------
# 판정
STATUS_KO = {"pass": "통과", "fail": "실패", "undecided": "미판정", "review": "검토 필요"}


def combine(statuses):
    """파라미터 결과를 하나로: 실패 > 미판정 > 검토 필요 > 통과. 결과가 없으면 미판정(건너뜀은 통과가 아니다)."""
    statuses = list(statuses)
    return next((s for s in ("fail", "undecided", "review") if s in statuses), "pass" if statuses else "undecided")


def _label(V):
    if V["role"] == "known-variant":
        return f"알려진 변형 {V['version']}"
    return f"{'최신판' if V['latest'] else '옛 판'} {V['version']}"


def _row(V, acc, stat):
    return {"version": V["version"], "role": V["role"], "latest": V["latest"], "accepted": V["version"] in acc,
            "checked": stat["checked"], "ok": stat["ok"], "records": stat.get("records"), "first_mismatch": stat["first"]}


def _result(P, status, summary, rows, matched=()):
    return {"param": P["id"], "name": P["name"], "status": status, "summary": summary, "matched": list(matched), "versions": rows}


def _decide(P, cands, acc, rows, unit):
    """후보 판 목록으로 상태를 정한다. unit: 'items'(문항 n/m) 또는 'records'(레코드 n/100)."""
    def count(r):
        return r["records"] if unit == "records" else f"문항 {r['ok']}/{r['checked']}"
    by = {r["version"]: r for r in rows}
    if not cands:
        shown = [r for r in rows if r["checked"]]
        lead = next((r for r in rows if r["accepted"] and r["first_mismatch"]), None) or next((r for r in rows if r["first_mismatch"]), None)
        return _result(P, "fail", "맞는 판 없음(" + ", ".join(f"{r['version']} {count(r)}" for r in shown) + ")"
                       + (f", 첫 불일치 {lead['version']}: {lead['first_mismatch']}" if lead else ""), rows)
    good = [V for V in cands if V["version"] in acc]
    other = [V for V in cands if V["version"] not in acc]
    names = [V["version"] for V in cands]
    if good and not other:
        return _result(P, "pass", ", ".join(f"{V['version']} 일치({count(by[V['version']])})" for V in good), rows, names)
    if good:
        return _result(P, "review", f"{', '.join(V['version'] for V in good)} 와 {', '.join(_label(V) for V in other)} 모두 일치: 이 답안으로는 "
                       "판을 가를 수 없다(derand 문항 결과를 함께 내거나 .rsp 를 낸다)", rows, names)
    hint = next((f"{P['id']}@{V['version']}" for V in other if V["role"] == "reference"), None)
    return _result(P, "review", ", ".join(f"{_label(V)} 일치({count(by[V['version']])})" for V in other)
                   + f": 받아 줄 판({', '.join(acc) or '없음'})이 아니다"
                   + (f"(받아 줄 판은 프로필의 impl_accept 가 정한다. 이 판도 받으려면 {hint} 항목을 더한다)" if hint else ""), rows, names)


def _sm_other_form(P, it, f, got, val):
    """HAETAE 꼴(siglen·sig) 파라미터의 derand sm 은 참조 crypto_sign 의 sig || msg 와 함께 msg || sig 도 맞는 답으로 본다(.rsp 길의
    canonical_record 와 같은 규칙. AIMer 는 sm = msg || sig 하나다)."""
    return f == "sm" and "sig" in P["fields"] and "msg" in it and got == it["msg"] + val["sig"]


def _judge_items(P, items, answers, acc):
    exp = {}
    for V in P["versions"]:
        for rec in V["excerpt"] or ():
            for iid, val in _expected(P, V, rec).items():
                exp[iid] = (V["version"], val)
    stats = {V["version"]: {"checked": 0, "ok": 0, "first": None} for V in P["versions"]}
    rows = [_row(V, acc, stats[V["version"]]) for V in P["versions"]]
    shape = [it["id"] for it in items if it["id"] in answers
             and (set(answers[it["id"]]) - set(it["answer"]) - set(it["optional"]) or not set(it["answer"]) <= set(answers[it["id"]]))]
    if shape:
        it = next(x for x in items if x["id"] == shape[0])
        return _result(P, "undecided", f"문항과 맞지 않는 답 {len(shape)}개: {shape[0]}(받는 칸 {', '.join(it['answer'] + it['optional'])})",
                       rows)
    missing = [it["id"] for it in items if it["answer"] and it["id"] not in answers]
    if missing:
        return _result(P, "undecided", f"답 없는 문항 {len(missing)}개: {missing[0]}" + (" 외" if len(missing) > 1 else ""), rows)
    for it in items:
        a = answers.get(it["id"])
        if not a:
            continue
        ver, val = exp[it["id"]]
        s = stats[ver]
        s["checked"] += 1
        bad = next((f for f in it["answer"] + it["optional"] if f in a and a[f] != val[f] and not _sm_other_form(P, it, f, a[f], val)), None)
        if bad is None:
            s["ok"] += 1
        elif s["first"] is None:
            s["first"] = f"{it['id']} {bad}"
    rows = [_row(V, acc, stats[V["version"]]) for V in P["versions"]]
    tampered = [it["id"] for it in items if it["id"].endswith(":verify-tampered") and answers[it["id"]].get("ok") is True]
    if tampered:
        return _result(P, "fail", f"변조 서명을 받아들임: {tampered[0]}" + (f" 외 {len(tampered) - 1}개" if len(tampered) > 1 else ""), rows)
    cands = [V for V in P["versions"] if stats[V["version"]]["checked"] and stats[V["version"]]["ok"] == stats[V["version"]]["checked"]]
    return _decide(P, cands, acc, rows, "items")


def canonical_record(P, rec):
    """.rsp 레코드를 참조판의 칸 꼴로: HAETAE 꼴(siglen·sig)인데 smlen·sm 으로 쓴 것은 sig 로(참조 crypto_sign 의 sig || msg 를 먼저,
    아니면 AIMer 처럼 msg || sig 로 본다), AIMer 꼴(smlen·sm = msg || sig)인데 siglen·sig 로 쓴 것은 sm 으로 바꾼다. 길이 칸(smlen,
    siglen)이 있으면 실제 길이와 같을 때만 바꾼다. 꼴이 맞지 않으면 그대로 둔다(대조에서 다르게 나온다)."""
    r = dict(rec)
    if P["kind"] != "sig" or not {"mlen", "msg"} <= set(r):
        return r
    m = 2 * int(r["mlen"])
    if "sig" in P["fields"] and "sig" not in r and "sm" in r and len(r["sm"]) >= m and r.get("smlen", str(len(r["sm"]) // 2)) == str(len(r["sm"]) // 2):
        sm = r["sm"]
        if sm[len(sm) - m:] == r["msg"]:
            sig = sm[:len(sm) - m]
        elif sm[:m] == r["msg"]:
            sig = sm[m:]
        else:
            return r
        r.pop("sm")
        r.pop("smlen", None)
        r["sig"], r["siglen"] = sig, str(len(sig) // 2)
    elif "sm" in P["fields"] and "sm" not in r and "sig" in r and r.get("siglen", str(len(r["sig"]) // 2)) == str(len(r["sig"]) // 2):
        sig = r.pop("sig")
        r.pop("siglen", None)
        r["sm"], r["smlen"] = r["msg"] + sig, str(int(r["mlen"]) + len(sig) // 2)
    return r


def match_rsp_digests(P, digests, acc, records=None):
    """.rsp 레코드 digest 목록을 판마다 같은 자리의 record_digests 와 대조한다. 레코드 수가 같고 모두 같으면 후보. records(정규화한 레코드)를
    주면 첫 불일치 레코드에서 처음 다른 칸을 발췌와 비교해 적는다."""
    n = len(digests)
    stats = {}
    for V in P["versions"]:
        rd = V["record_digests"]
        ok = sum(1 for i, d in enumerate(digests[:len(rd)]) if d == rd[i])
        first = next((i for i, d in enumerate(digests[:len(rd)]) if d != rd[i]), None)
        where = None
        if first is not None:
            ex = (V["excerpt"] or [])[first] if V["excerpt"] and first < len(V["excerpt"]) else None
            field = next((f for f in P["fields"] if ex is not None and records is not None and records[first].get(f) != ex[f]), None)
            where = f"count {first}" + (f" {field}" if field else "")
        elif n != len(rd):
            where = f"레코드 {n}건(참조 {len(rd)}건)"
        stats[V["version"]] = {"checked": n, "ok": ok, "records": f"{ok}/{len(rd)}", "first": where}
    rows = [_row(V, acc, stats[V["version"]]) for V in P["versions"]]
    if n == 0:
        return _result(P, "undecided", ".rsp 에 레코드가 0건이다", rows)
    cands = [V for V in P["versions"] if n == V["records"] and stats[V["version"]]["ok"] == n]
    if not cands:
        prefix = [V for V in P["versions"] if n < V["records"] and stats[V["version"]]["ok"] == n]
        if prefix:
            return _result(P, "undecided", f"레코드 {n}건뿐({prefix[0]['records']}건 필요). 있는 {n}건은 "
                           + ", ".join(V["version"] for V in prefix) + " 와 일치", rows)
    return _decide(P, cands, acc, rows, "records")


def _judge_rsp(P, records, acc):
    try:
        canon = [canonical_record(P, r) for r in records]
        digests = [record_digest(r) for r in canon]
    except (ValueError, KeyError) as e:
        return _result(P, "undecided", f".rsp 레코드를 정규화할 수 없다: {e}", [_row(V, acc, {"checked": 0, "ok": 0, "first": None})
                                                                            for V in P["versions"]])
    return match_rsp_digests(P, digests, acc, canon)


def match_versions(key, parsed, accept):
    """정답 묶음과 읽은 답안으로 파라미터마다 판정한다(정답 묶음 순서). accept: {파라미터: [받아 줄 판]}.
    답안 JSON: 정답 묶음으로 다시 만든 문제지의 prompt_sha256 과 같아야 하고(아니면 모두 미판정), 문제지에 없는 문항 id 가 있으면
    미판정이다. 파라미터마다 필수 문항(decaps, verify)이 다 있어야 하고(없으면 미판정), 변조 서명 문항을 true 로 답하면 실패다.
    판마다 그 판 문항이 모두 맞으면 후보다. 후보가 받아 줄 판뿐이면 통과, 받아 줄 판과 다른 판이 함께 후보면 검토 필요(판을 가르지
    못함), 옛 판·알려진 변형만이면 검토 필요, 후보가 없으면 실패(첫 불일치 문항·칸).
    .rsp: 파라미터 하나, 레코드 digest 를 판마다 record_digests 와 대조해 'n/100' 을 적는다."""
    if parsed["kind"] == "rsp":
        return [_judge_rsp(P, parsed["records"], accept.get(P["id"], [])) for P in key["params"]]
    prompt = emit_prompt(key)
    blank = {"checked": 0, "ok": 0, "first": None}

    def all_undecided(why):
        return [_result(P, "undecided", why, [_row(V, accept.get(P["id"], []), blank) for V in P["versions"]]) for P in key["params"]]
    if parsed["prompt_sha256"] != prompt["prompt_sha256"]:
        return all_undecided("prompt_sha256 이 이 도구의 KAT 목록으로 만든 문제지와 다르다(pqproof impl prompt 로 다시 받아 답한다)")
    ids = {it["id"] for it in prompt["items"]}
    extra = sorted(set(parsed["answers"]) - ids)
    if extra:
        return all_undecided(f"문제지에 없는 문항 id {len(extra)}개: {shown(extra[0])}")
    return [_judge_items(P, [it for it in prompt["items"] if it["param"] == P["id"]], parsed["answers"], accept.get(P["id"], []))
            for P in key["params"]]


def _flip_digest(d):
    return ("0" if d[0] != "0" else "1") + d[1:]


def control_problem(key, accept, kind):
    """자기 점검: 판정 전에, 받아 줄 판의 정답 답안은 통과하고 한 바이트 바꾼 답안은 실패하는지 본다. 아니면 까닭(전체를 미판정으로
    둔다), 맞으면 None. kind 'response' 는 발췌로 만든 답안(KEM 은 decaps ss, 서명은 derand sig 한 바이트를 바꾼다), 'rsp' 는 받아 줄
    판의 record_digests(첫 레코드를 바꾼다)로 본다."""
    if not key["params"]:
        return None
    if kind == "rsp":
        for P in key["params"]:
            acc = accept.get(P["id"], [])
            V = next((V for V in P["versions"] if V["version"] in acc), None)
            if V is None:
                return f"{P['id']}: 받아 줄 판이 없다"
            r = match_rsp_digests(P, list(V["record_digests"]), acc)
            if (r["status"], r["matched"]) != ("pass", [V["version"]]):
                return f"{P['id']}: 받아 줄 판 {V['version']} 의 record_digests 가 통과하지 않았다({r['summary']})"
            bad = list(V["record_digests"])
            bad[0] = _flip_digest(bad[0])
            r = match_rsp_digests(P, bad, acc)
            if r["status"] != "fail":
                return f"{P['id']}: 한 레코드를 바꾼 답안이 실패하지 않았다({STATUS_KO[r['status']]}: {r['summary']})"
        return None
    pick = {}
    for P in key["params"]:
        V = next((V for V in P["versions"] if V["version"] in accept.get(P["id"], []) and V["excerpt"]), None)
        if V is None:
            return f"{P['id']}: 받아 줄 판에 발췌가 없어 정답 답안을 만들 수 없다"
        pick[P["id"]] = V["version"]
    good = example_answers(key, pick)

    def judge(resp):
        return match_versions(key, {"kind": "response", "problem": None, "params": resp["params"], "prompt_sha256": resp["prompt_sha256"],
                                    "implementation": None, "answers": resp["answers"]}, accept)
    for r in judge(good):
        if (r["status"], r["matched"]) != ("pass", [pick[r["param"]]]):
            return f"{r['param']}: 받아 줄 판 {pick[r['param']]} 의 정답 답안이 통과하지 않았다({STATUS_KO[r['status']]}: {r['summary']})"
    bad = json.loads(json.dumps(good))
    for P in key["params"]:
        V = next(V for V in P["versions"] if V["version"] == pick[P["id"]])
        base = _item_base(P, V, V["excerpt"][0])
        if P["kind"] == "kem":
            bad["answers"][base + ":decaps"]["ss"] = _flip_hex(bad["answers"][base + ":decaps"]["ss"])
        else:
            bad["answers"][base + ":derand"]["sig"] = _flip_hex(bad["answers"][base + ":derand"]["sig"])
    for r in judge(bad):
        if r["status"] != "fail":
            return f"{r['param']}: 한 바이트 바꾼 답안이 실패하지 않았다({STATUS_KO[r['status']]}: {r['summary']})"
    return None


CHECK_TITLE = "KpqC 구현의 KAT 대조(받아 줄 참조판과 일치하는가, 공인 시험 아님)"
CHECK_EXPECTED = "파라미터마다 받아 줄 판(프로필의 impl_accept, 기본 최신판)의 KAT 와 일치, 변조 서명 거부, 자기 점검 통과"


def check_row(results, control=None, problem=None, answered=True):
    """검사 행 i-kpqc(rules.judge_impl 이 쓰고 --verify 가 다시 만들어 맞춘다). control: 자기 점검 까닭(있으면 미판정),
    problem: 답안 전체의 문제(읽지 못함, 모르는 파라미터, 있으면 미판정). answered: 답안을 줬는가(안 줬으면 해당 없음, pq-verify 감사만
    한 실행)."""
    if not answered:
        status, actual = "na", "답안을 주지 않았다(KpqC KAT 대조를 하지 않음)"
    elif control:
        status, actual = "undecided", f"자기 점검 실패: {control}"
    elif problem:
        status, actual = "undecided", problem
    elif not results:
        status, actual = "undecided", "판정할 파라미터가 없다"
    else:
        status = combine(r["status"] for r in results)
        actual = " · ".join(f"{r['param']} {STATUS_KO[r['status']]}: {r['summary']}" for r in results)
    return {"id": CHECK_ID, "title": CHECK_TITLE, "status": status, "expected": CHECK_EXPECTED, "actual": actual}


# ---------------------------------------------------------------------------------------------
# pq-verify 다리(검사 i-nist). NIST PQC(FIPS 203·204·205) 구현 감사는 사용자가 켤 때만(pqproof impl judge --pq-verify "<인자>")
# 바깥 도구 pq-verify(MIT, PyPI)가 한다. 대상 라이브러리를 불러 실행하는 것은 pq-verify 이고 PQ-Proof 는 대상을 빌드하거나 실행하지
# 않는다. PQ-Proof 는 pq-verify 를 하위 프로세스로 부르고(prove.py, shell 없음, --require-full-coverage 와 --json 을 붙인다) 그 JSON
# 보고서·종료 코드·출력만 읽는다. 아래는 그 순수 함수다(인자 검사 pqverify_args, 실행 argv pqverify_argv, 넘길 환경 pqverify_env,
# 보고서 읽기 pqverify_summary, 판정 pqverify_status, 검사 행 nist_check_row). --verify 가 증적의 보고서 사본으로 다시 판정한다.
# 받은 보고서는 남이 만든 데이터다. JSON 으로 읽고 칸의 꼴을 확인할 뿐 그 안의 무엇도 실행하지 않는다.
NIST_CHECK_ID = "i-nist"
PQV_NAME = "pq-verify"  # PATH 에서 찾는 실행 파일 이름(PQ_VERIFY 로 바꾼다)
PQV_TESTED = "2.19.0"  # 실제 출력 고정물(tests/fixtures/pqverify/)로 시험한 판. 다른 판도 읽지만 보고서 꼴(schema 주 버전)이 같아야 한다
PQV_SCHEMA_MAJOR = "1"
PQV_MAX_REPORT = 16 << 20  # 보고서 상한(바이트). 넘으면 읽지 않고 미판정
PQV_MAX_TEXT = 1 << 20  # 실행 기록에 남기는 stdout·stderr 상한(바이트). 넘으면 앞 256 KiB 와 뒤를 남긴다(DEGRADED 줄은 끝에 나온다)
# 받는 감사(대상 라이브러리를 NIST 벡터와 대조하는 것): 옵션 → 그 감사가 쓰는 보고서 schema. 모두 PATH PARAM_SET 두 값을 받는다
PQV_AUDITS = {"--audit-kem": "pq-verify/kem-audit-result", "--audit-dsa": "pq-verify/dsa-audit-result",
              "--audit-slhdsa": "pq-verify/slhdsa-audit-result", "--audit-contained": "pq-verify/contained-audit-result"}
# 감사와 함께 받는 옵션(값 하나를 받는 것, 값 없는 것). 그 밖의 옵션은 받지 않는다(줄임말도 받지 않는다: pq-verify 의 argparse 는
# 줄임말을 받아서 '--liv' 가 '--live' 로 읽힌다)
PQV_VALUE_OPTS = ("--symbol-prefix", "--kem-keypair", "--kem-encaps", "--kem-decaps", "--dsa-abi", "--dsa-symbol", "--slhdsa-symbol",
                  "--accumulated", "--audit-timeout", "--fresh-seed", "--fresh-count")
PQV_FLAG_OPTS = ("--constant-time", "--require-full-coverage", "--fail-on-finding")
# 따로 까닭을 들어 막는 옵션(줄임말 포함)
PQV_REFUSED = {
    "--live": "네트워크에서 NIST 벡터를 새로 받는다(결과가 실행마다 달라질 수 있다). 고정 벡터로만 감사한다",
    "--vector-dir": "고정 벡터 대신 다른 폴더의 벡터로 감사한다",
    "--json": "보고서 경로는 PQ-Proof 가 증적 폴더 안으로 정해 붙인다",
    "--sarif": "증적 폴더 밖에 파일을 쓴다(SARIF 는 pqproof sarif 로 증적에서 만든다)",
    "--prompt-out": "증적 폴더 밖에 파일을 쓴다",
    "--no-fail": "종료 코드로 문제를 알리지 않게 바꾼다",
    "--audit-harness": "사용자 명령을 그대로 실행한다",
    "--audit-source": "소스를 컴파일해 검사한다(CBMC)",
    "--version": "감사가 아니다",
    "--help": "감사가 아니다",
}
KEM_STAGES = ("keyGen", "encaps", "decaps", "ekCheck", "dkCheck", "edgeValid", "edgeEk", "edgeDk", "accumulated")  # scope 칸이 없는 KEM 감사의 완전성
INPUT_CHECK_STAGES = frozenset({"ekCheck", "dkCheck", "edgeEk", "edgeDk"})  # FIPS 203 7.2·7.3 입력 검사(API 밖에서 해도 된다)
_ENV_DROP_PREFIX = ("PQV_", "LD_", "DYLD_")
_ENV_DROP = frozenset({"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT"})


def pqverify_args(text):
    """--pq-verify 에 준 인자 글 → {"args": [인자], "audit": 감사 옵션, "target": 대상 경로(준 그대로), "target_index": args 안 자리,
    "param_set": 파라미터 이름}. 셸 없이 shlex(POSIX 규칙)로 나눈다. 감사 옵션이 정확히 하나여야 하고, 막는 옵션·모르는 옵션·줄임말·
    짧은 옵션·자리 인자는 ValueError(까닭)."""
    import shlex
    if not isinstance(text, str) or not text.strip():
        raise ValueError("--pq-verify 에 pq-verify 인자를 준다(예: --pq-verify \"--audit-kem ./libmlkem.so ML-KEM-768\")")
    try:
        args = shlex.split(text, posix=True)
    except ValueError as e:
        raise ValueError(f"--pq-verify 인자를 나눌 수 없다({e}): 따옴표 짝을 맞춘다") from None
    known = tuple(PQV_REFUSED) + tuple(PQV_AUDITS) + PQV_VALUE_OPTS + PQV_FLAG_OPTS
    audit, target, i = None, None, 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-") or a == "-":
            raise ValueError(f"pq-verify 인자 {a!r}: 옵션 값이 아닌 자리 인자는 받지 않는다")
        if a == "--":
            raise ValueError("pq-verify 인자에 '--' 는 받지 않는다")
        if not a.startswith("--"):
            raise ValueError(f"pq-verify 옵션 {a!r}: 짧은 옵션은 받지 않는다")
        name, eq, value = a.partition("=")
        refused = next((r for r in PQV_REFUSED if r == name or (len(name) > 2 and r.startswith(name))), None)
        if refused:
            raise ValueError(f"pq-verify 옵션 {name}" + (f"({refused} 의 줄임말)" if name != refused else "")
                             + f" 는 받지 않는다: {PQV_REFUSED[refused]}")
        if name not in known:
            near = [k for k in known if k.startswith(name)]
            if near:
                raise ValueError(f"pq-verify 옵션 {name}: 줄여 쓰지 말고 전체 이름을 쓴다({', '.join(near[:3])})")
            raise ValueError(f"pq-verify 옵션 {name} 는 받지 않는다. 받는 감사: {', '.join(PQV_AUDITS)}. 함께 받는 옵션: "
                             f"{', '.join(PQV_VALUE_OPTS + PQV_FLAG_OPTS)}")
        if name in PQV_AUDITS:
            if eq:
                raise ValueError(f"{name} 는 '{name} 경로 파라미터' 꼴로 준다")
            if audit:
                raise ValueError(f"감사는 하나만 준다({audit}, {name})")
            vals = args[i + 1:i + 3]
            if len(vals) != 2 or any(v.startswith("-") or not v for v in vals):
                raise ValueError(f"{name} 뒤에 라이브러리 경로와 파라미터 이름(예: ML-KEM-768) 두 값을 준다")
            audit, target = name, i + 1
            i += 3
        elif name in PQV_VALUE_OPTS:
            if eq:
                i += 1
            elif i + 1 < len(args) and args[i + 1] and not args[i + 1].startswith("-"):
                i += 2
            else:
                raise ValueError(f"{name} 뒤에 값을 준다('-' 로 시작하는 값은 {name}=값 꼴로 준다)")
        else:  # 값 없는 옵션
            if eq:
                raise ValueError(f"{name} 는 값을 받지 않는다")
            i += 1
    if audit is None:
        raise ValueError(f"감사 옵션이 없다. 하나를 준다: {', '.join(PQV_AUDITS)} (경로 파라미터)")
    return {"args": args, "audit": audit, "target": args[target], "target_index": target, "param_set": args[target + 1]}


def pqverify_argv(exe, spec, target_abs, report):
    """실제로 부를 argv(셸 없음): [실행 파일, 사용자 인자(대상 경로는 절대 경로로), --require-full-coverage(없으면), --json 보고서]."""
    args = list(spec["args"])
    args[spec["target_index"]] = target_abs
    if "--require-full-coverage" not in args:
        args.append("--require-full-coverage")
    return [exe] + args + ["--json", report]


def pqverify_env(env):
    """pq-verify 에 넘길 환경과 뺀 이름 목록. PQV_*(pq-verify 동작을 바꾼다: PQV_IN_PROCESS, PQV_CFL_SO 는 dlopen 된다), LD_*·DYLD_*
    (불러올 라이브러리를 바꾼다), PYTHONPATH·PYTHONHOME·PYTHONSTARTUP·PYTHONINSPECT(pq-verify 는 파이썬 프로그램이다)를 뺀다."""
    drop = sorted(k for k in env if k.startswith(_ENV_DROP_PREFIX) or k in _ENV_DROP)
    return {k: v for k, v in env.items() if k not in drop}, drop


def clip_text(text, limit=PQV_MAX_TEXT):
    """실행 기록에 남길 글: 상한을 넘으면 앞 256 KiB 와 끝을 남기고 가운데를 줄였다고 적는다."""
    if len(text) <= limit:
        return text
    head = 256 << 10
    tail = limit - head
    return text[:head] + f"\n[pqproof: {len(text) - head - tail:,} characters cut]\n" + text[-tail:]


def clip_stream(head, tail, total, limit=PQV_MAX_TEXT):
    """하위 프로세스 출력을 읽으며 앞(head)·뒤(tail) 바이트만 남긴 것 → 실행 기록에 남길 글. 가운데를 버리지 않았으면(total 이 둘의 합)
    clip_text 와 같다. 버렸으면 앞 256 KiB 와 끝을 남기고 전체 바이트 수를 적는다(prove.py run_logged 가 출력 전체를 메모리에 두지 않는다)."""
    if total == len(head) + len(tail):
        return clip_text((head + tail).decode("utf-8", "replace"), limit)
    keep = 256 << 10
    return (head.decode("utf-8", "replace")[:keep] + f"\n[pqproof: {total:,} bytes in all, the middle was not kept]\n"
            + tail.decode("utf-8", "replace")[-(limit - keep):])


def pqverify_version(stdout):
    """'pq-verify 2.19.0' → '2.19.0'(못 읽으면 '')."""
    m = re.search(r"\bpq-verify\s+([0-9][0-9A-Za-z.+-]*)", stdout or "")
    return m[1] if m else ""


def _str(v, n=200):
    """보고서의 글 칸(남이 쓴 글): 인쇄할 수 없는 글자를 적어 바꾸고 n 자에서 자른 글, 글이 아니면 None."""
    return shown(v, n) if isinstance(v, str) else None


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _bool(v):
    return v if isinstance(v, bool) else None


SUMMARY_KEYS = ("audit", "problem", "exit_code", "schema", "schema_version", "tool_version", "status", "verified", "bound",
                "artifact_sha256", "library_sha256", "target", "param_set", "checks_passed", "checks_total", "findings", "failed",
                "missing", "scope", "scope_complete", "degraded", "unavailable")


def pqverify_summary(audit, run, report, library_sha256=None, not_run=None):
    """pq-verify 한 번의 결과에서 판정에 쓰는 칸만 뽑는다(dict, SUMMARY_KEYS). 증적 impl.nist.summary 에 남고 --verify 가 같은 입력으로
    다시 뽑아 맞춘다.
    audit: 감사 옵션(--audit-kem 등, 모르면 None). run: 감사 실행 기록 {exit_code, stdout, timed_out, error} 또는 None(돌리지 못함,
    not_run 이 까닭). report: 보고서 바이트(쓰지 않았으면 None). library_sha256: PQ-Proof 가 잰 대상 파일 SHA-256(없으면 None)."""
    s = dict.fromkeys(SUMMARY_KEYS)
    s.update(audit=audit, library_sha256=library_sha256, failed=[], missing=[], unavailable=[], degraded=False)
    if run is None:
        s["problem"] = not_run or "pq-verify 를 돌리지 않았다"
        return s
    s["exit_code"] = run.get("exit_code")
    stdout = run.get("stdout") or ""
    s["degraded"] = bool(re.search(r"(?m)^\s*DEGRADED RUN\b", stdout))
    if run.get("timed_out"):
        s["problem"] = f"시간 초과({run.get('timeout')}초 안에 끝나지 않아 멈췄다)"
        return s
    if s["exit_code"] is None:
        s["problem"] = f"pq-verify 를 띄우지 못했다({(run.get('error') or '').strip()[:200]})"
        return s
    if report is None:
        last = next((x.strip() for x in reversed(stdout.splitlines()) if x.strip()), "")
        s["problem"] = (f"pq-verify 입력 오류(종료 2): {shown(last, 200)}" if s["exit_code"] == 2 else
                        f"pq-verify 가 보고서를 쓰지 않았다(종료 {s['exit_code']})")
        return s
    if len(report) > PQV_MAX_REPORT:
        s["problem"] = f"보고서가 {len(report):,}바이트로 상한 {PQV_MAX_REPORT:,}바이트를 넘는다(읽지 않음)"
        return s
    try:
        doc = _loads_strict(report, "pq-verify 보고서")
    except ValueError as e:
        s["problem"] = str(e)[:300]
        return s
    if not isinstance(doc, dict):
        s["problem"] = "pq-verify 보고서가 JSON 객체가 아니다"
        return s
    tool, art, summ = doc.get("tool"), doc.get("artifact"), doc.get("summary")
    tool, art, summ = (x if isinstance(x, dict) else {} for x in (tool, art, summ))
    s.update(schema=_str(doc.get("schema")), schema_version=_str(doc.get("schema_version")), tool_version=_str(tool.get("version")),
             status=_str(doc.get("status")), verified=_bool(doc.get("verified")), bound=_bool(art.get("bound")),
             artifact_sha256=_str(art.get("sha256"), 64), target=_str(art.get("path") or doc.get("library"), 500),
             param_set=_str(doc.get("parameter_set")), checks_passed=_int(summ.get("checks_passed")),
             checks_total=_int(summ.get("checks_total")), findings=_int(summ.get("findings")))
    stages = doc.get("stages") if isinstance(doc.get("stages"), dict) else {}
    for name, st in stages.items():
        if not isinstance(st, dict) or _int(st.get("passed")) is None or _int(st.get("total")) is None:
            s["failed"].append(f"{shown(name, 60)} (칸이 틀림)")
        elif "unavailable" in str(name).lower():  # 'ct:unavailable' 처럼 돌지 못한 검사를 적는 단계: 통과 못 한 단계로 세지 않는다
            s["unavailable"].append(f"{shown(name, 60)} (돌지 못함)")
        elif st["passed"] < st["total"]:
            s["failed"].append(f"{shown(name, 60)} {st['passed']}/{st['total']}")
    s["failed"] = s["failed"][:40]
    scope = doc.get("scope")
    if isinstance(scope, dict):
        s["scope_complete"] = _bool(scope.get("complete"))
        s["scope"] = _str(scope.get("statement")) or ("complete" if s["scope_complete"] else "partial")
    elif s["schema"] == PQV_AUDITS["--audit-kem"]:  # KEM 보고서에는 scope 칸이 없다: 필수 단계 아홉이 모두 돌았는지(total > 0)로 본다
        s["missing"] = [n for n in KEM_STAGES if not (isinstance(stages.get(n), dict) and (_int(stages[n].get("total")) or 0) > 0)]
        s["scope_complete"] = not s["missing"]
        s["scope"] = "KEM 필수 단계 9개 모두 돎" if not s["missing"] else f"돌지 않은 KEM 필수 단계: {', '.join(s['missing'])}"
    ct = doc.get("constant_time")
    if isinstance(ct, dict) and ct.get("unavailable"):
        why = ct["unavailable"]
        s["unavailable"].insert(0, f"constant-time: {shown(why, 160) if isinstance(why, str) else '돌지 못함'}")
    s["unavailable"] = s["unavailable"][:10]
    return s


def _target_text(s):
    t = s.get("target") or ""
    name = t.replace("\\", "/").rsplit("/", 1)[-1] if t else "대상 모름"
    return f"{name} {s.get('param_set') or ''}".strip()


def pqverify_status(s):
    """요약(pqverify_summary) → (상태, 상세 글). 통과: 종료 0, VERIFIED, verified true, 감사 옵션에 맞는 보고서 꼴(schema 주 버전 1),
    대상 파일에 묶임(artifact.bound, PQ-Proof 가 잰 SHA-256 이 있고 그것과 같음: 대상이 일반 파일이 아니라 잴 수 없었으면 통과가 아니다),
    검사 범위 완전(scope.complete, KEM 은 필수 단계 9개), 모든 검사 통과.
    실패: 종료 1, FINDINGS PRESENT, verified false, 통과 못 한 검사 단계가 있음(DEGRADED 가 아니고 대상 파일에 묶였을 때. 돌지 못한
    검사가 함께 있어도 통과 못 한 단계는 실패다). 그 밖은 미판정(건너뛴 검사는 통과가 아니다)."""
    if s.get("problem"):
        return "undecided", s["problem"]
    head = f"{_target_text(s)}: pq-verify {s.get('tool_version') or '판 모름'}"
    counts = f"검사 {s.get('checks_passed')}/{s.get('checks_total')}"
    want = PQV_AUDITS.get(s.get("audit"))
    if want is None:
        return "undecided", f"{head}, 받는 감사 옵션({', '.join(PQV_AUDITS)})으로 돈 결과가 아니다"
    if s.get("schema") != want:
        return "undecided", f"{head}, 보고서 꼴 {_q(s.get('schema'))} 이 {s['audit']} 의 {want} 가 아니다"
    if (s.get("schema_version") or "").split(".")[0] != PQV_SCHEMA_MAJOR:
        return "undecided", f"{head}, 보고서 schema_version {_q(s.get('schema_version'))} 의 주 버전이 {PQV_SCHEMA_MAJOR} 이 아니다(이 판의 PQ-Proof 가 읽는 꼴이 아니다)"
    if s.get("degraded"):
        return "undecided", f"{head}, DEGRADED RUN(빠진 엔진·의존 때문에 돌지 않은 검사가 있다), {counts}"
    if s.get("exit_code") not in (0, 1):
        return "undecided", f"{head}, 종료 {s.get('exit_code')}(0 검증됨, 1 문제 있음이 아니다)"
    if s.get("bound") is not True:
        return "undecided", f"{head}, 보고서가 대상 파일에 묶이지 않았다(artifact.bound {s.get('bound')}): 대상을 불러 검사하지 못했다"
    if s.get("library_sha256") and s.get("artifact_sha256") != s["library_sha256"]:
        return "undecided", (f"{head}, pq-verify 가 감사한 파일(sha256 {str(s.get('artifact_sha256'))[:16]})이 PQ-Proof 가 잰 대상 "
                             f"(sha256 {s['library_sha256'][:16]})과 다르다")
    total, passed = s.get("checks_total"), s.get("checks_passed")
    unavailable = s.get("unavailable") or []
    if (s["exit_code"] == 0 and s.get("status") == "VERIFIED" and s.get("verified") is True and s.get("scope_complete") is True
            and not s["failed"] and not unavailable and isinstance(total, int) and total > 0 and passed == total):
        if not s.get("library_sha256"):
            return "undecided", (f"{head}, VERIFIED 지만 PQ-Proof 가 대상 파일의 SHA-256 을 재지 못했다(일반 파일이 아님): 보고서가 어느 "
                                 f"파일의 것인지 맞춰 볼 수 없다, {counts}")
        return "pass", f"{head}, VERIFIED, {counts}, 범위 완전({s.get('scope')})"
    if s["exit_code"] == 1 and s.get("status") == "FINDINGS PRESENT" and s.get("verified") is False and s["failed"]:
        names = {f.split(" ")[0] for f in s["failed"]}
        note = (" (입력 검사 단계만 실패: FIPS 203 7.2·7.3 의 키 검사를 API 안에서 하지 않는다. 표준은 이 검사를 API 밖에서 해도 되지만 "
                "그때는 호출자가 반드시 해야 한다)" if names <= INPUT_CHECK_STAGES else "")
        also = f", 돌지 못한 검사도 있다: {'; '.join(unavailable[:3])}" if unavailable else ""
        return "fail", f"{head}, FINDINGS PRESENT, {counts}, 통과 못 한 단계: {', '.join(s['failed'][:8])}{note}{also}"
    if unavailable:
        return "undecided", f"{head}, 돌지 못한 검사: {'; '.join(unavailable[:3])} ({counts})"
    if s.get("status") == "VERIFIED" and s.get("scope_complete") is not True:
        return "undecided", f"{head}, VERIFIED 지만 검사 범위가 완전하지 않다({s.get('scope') or '범위 칸 없음'}), {counts}"
    if s.get("status") == "CANNOT VERIFY":
        return "undecided", f"{head}, CANNOT VERIFY(pq-verify 가 검증하지 못했다), {counts}"
    return "undecided", (f"{head}, 종료 {s['exit_code']} 와 보고서 status {_q(s.get('status'))}·verified {s.get('verified')} 가 통과나 실패 꼴이 "
                         f"아니다, {counts}" + (f", 통과 못 한 단계: {', '.join(s['failed'][:8])}" if s["failed"] else ""))


NIST_TITLE = "NIST PQC 구현 감사(pq-verify, 사용자가 켠 바깥 도구)"
NIST_EXPECTED = ("pq-verify 감사(--require-full-coverage)가 종료 0·VERIFIED·검사 범위 완전이고 PQ-Proof 가 잰 대상 파일에 묶이면 통과, "
                 "통과 못 한 검사 단계가 있으면 실패(pq-verify 판단을 따른다: API 안에서 FIPS 203 입력 검사를 하지 않아도 실패), "
                 "그 밖(입력 오류, DEGRADED, 범위 불완전, 돌지 못한 검사, 실행 파일 없음, 보고서 깨짐)은 미판정")


def nist_check_row(nist):
    """검사 행 i-nist. nist: 증적 impl.nist(없으면 None: --pq-verify 를 주지 않아 해당 없음)."""
    if nist is None:
        status, actual = "na", "--pq-verify 를 주지 않았다(NIST 구현 감사를 하지 않음)"
    else:
        status, actual = pqverify_status(nist["summary"])
    return {"id": NIST_CHECK_ID, "title": NIST_TITLE, "status": status, "expected": NIST_EXPECTED, "actual": actual}
