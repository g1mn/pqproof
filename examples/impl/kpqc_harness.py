#!/usr/bin/env python3
# kpqc_harness.py: PQ-Proof 구현 검증(pqproof impl)의 예제 하네스. 사용자가 자기 KpqC 빌드로 돌린다(표준 라이브러리 ctypes 만).
#   python3 -I kpqc_harness.py <문제지.json> <답안.json> --lib <파라미터>=<공유 라이브러리> [--lib ...] [--no-derand] [--name 글]
#   예) pqproof impl prompt --param smaug-t/mode3 -o prompt.json
#       python3 -I kpqc_harness.py prompt.json answers.json --lib smaug-t/mode3=./libsmaugt-mode3.dylib
#       pqproof impl judge answers.json
# 공유 라이브러리는 NIST API 이름을 내보내야 한다:
#   KEM   crypto_kem_keypair(pk, sk), crypto_kem_enc(ct, ss, pk), crypto_kem_dec(ss, ct, sk)
#   서명  crypto_sign_keypair(pk, sk), crypto_sign_signature(sig, &siglen, m, mlen, ctx, ctxlen, sk),
#         crypto_sign_verify(sig, siglen, m, mlen, ctx, ctxlen, pk)   (길이는 size_t, 0 이 성공)
#   derand 문항(선택)은 KAT DRBG 의 randombytes_init(seed, NULL, 256) 도 있어야 한다(KAT 용 rng.c 를 넣어 빌드한 라이브러리).
#   없으면 derand 문항을 비우고 decaps·verify 만 답한다(--no-derand 와 같다). 그러면 판을 가르지 못할 때가 있다(검토 필요).
# 이 하네스는 라이브러리를 불러 실행한다(라이브러리의 초기화 코드도 돈다). 믿을 수 있는 자기 빌드에만 쓰고, 남이 준 바이너리는
# 격리된 환경(컨테이너, VM)에서 돌린다. PQ-Proof 는 이 하네스나 라이브러리를 실행하지 않고 답안 파일만 읽는다.
# 종료: 0 답안을 씀 · 2 사용법·입력 오류(라이브러리가 없는 파라미터, 이미 있는 답안 파일)
"""Example harness for `pqproof impl`: answer a KpqC question sheet with your own shared libraries through ctypes."""
import argparse
import ctypes
import json
import os
import sys

RESPONSE_FORMAT = "pqproof impl response 1"
KEM_FUNCS = ("crypto_kem_keypair", "crypto_kem_enc", "crypto_kem_dec")
SIG_FUNCS = ("crypto_sign_keypair", "crypto_sign_signature", "crypto_sign_verify")


def buf(hex_text):
    data = bytes.fromhex(hex_text)
    return ctypes.create_string_buffer(data, len(data)), len(data)


class Lib:
    """공유 라이브러리 하나(파라미터 하나)."""

    def __init__(self, path, kind, sizes):
        self.path, self.kind, self.sizes = path, kind, sizes
        self.dll = ctypes.CDLL(os.path.abspath(path))
        need = KEM_FUNCS if kind == "kem" else SIG_FUNCS
        missing = [n for n in need if not hasattr(self.dll, n)]
        if missing:
            raise SystemExit(f"kpqc_harness: {path} does not export {', '.join(missing)}")
        self.drbg = getattr(self.dll, "randombytes_init", None)
        if self.drbg is not None:
            self.drbg.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            self.drbg.restype = None
        size_t, p = ctypes.c_size_t, ctypes.c_char_p
        if kind == "sig":
            self.dll.crypto_sign_signature.argtypes = [p, ctypes.POINTER(size_t), p, size_t, p, size_t, p]
            self.dll.crypto_sign_verify.argtypes = [p, size_t, p, size_t, p, size_t, p]

    def decaps(self, sk, ct):
        ss = ctypes.create_string_buffer(self.sizes["ss"])
        self.dll.crypto_kem_dec(ss, buf(ct)[0], buf(sk)[0])
        return {"ss": ss.raw.hex()}

    def verify(self, pk, msg, sig, ctx):
        (s, slen), (m, mlen), (c, clen) = buf(sig), buf(msg), buf(ctx)
        return {"ok": self.dll.crypto_sign_verify(s, slen, m, mlen, c, clen, buf(pk)[0]) == 0}

    def derand(self, item):
        if self.drbg is None:
            return None
        self.drbg(bytes.fromhex(item["seed"]), None, 256)
        pk, sk = ctypes.create_string_buffer(self.sizes["pk"]), ctypes.create_string_buffer(self.sizes["sk"])
        if self.kind == "kem":
            ct, ss = ctypes.create_string_buffer(self.sizes["ct"]), ctypes.create_string_buffer(self.sizes["ss"])
            if self.dll.crypto_kem_keypair(pk, sk) or self.dll.crypto_kem_enc(ct, ss, pk):
                return None
            return {"pk": pk.raw.hex(), "sk": sk.raw.hex(), "ct": ct.raw.hex(), "ss": ss.raw.hex()}
        if self.dll.crypto_sign_keypair(pk, sk):
            return None
        sig, siglen = ctypes.create_string_buffer(self.sizes["sig"]), ctypes.c_size_t(0)
        (m, mlen), (c, clen) = buf(item["msg"]), buf(item["ctx"])
        if self.dll.crypto_sign_signature(sig, ctypes.byref(siglen), m, mlen, c, clen, sk):
            return None
        return {"pk": pk.raw.hex(), "sk": sk.raw.hex(), "sig": sig.raw[:siglen.value].hex()}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Answer a PQ-Proof KpqC question sheet with your own shared libraries (ctypes).")
    ap.add_argument("prompt", help="question sheet written by pqproof impl prompt")
    ap.add_argument("answers", help="response JSON to write (must not exist)")
    ap.add_argument("--lib", action="append", default=[], metavar="PARAM=PATH", help="shared library for one parameter set")
    ap.add_argument("--no-derand", action="store_true", help="answer decaps and verify only")
    ap.add_argument("--name", default=None, help="free text that names the implementation (recorded in the evidence)")
    a = ap.parse_args(argv)
    with open(a.prompt, encoding="utf-8") as f:
        prompt = json.load(f)
    libs = dict(x.split("=", 1) for x in a.lib if "=" in x)
    missing = [p for p in prompt["params"] if p not in libs]
    if missing:
        print(f"kpqc_harness: no --lib for {', '.join(missing)}", file=sys.stderr)
        return 2
    if os.path.lexists(a.answers):
        print(f"kpqc_harness: {a.answers} exists", file=sys.stderr)
        return 2
    kinds = {it["param"]: ("kem" if it["op"] == "decaps" else "sig") for it in prompt["items"] if it["op"] != "derand"}
    loaded = {p: Lib(libs[p], kinds[p], prompt["sizes"][p]) for p in prompt["params"]}
    answers = {}
    for it in prompt["items"]:
        lib = loaded[it["param"]]
        if it["op"] == "decaps":
            answers[it["id"]] = lib.decaps(it["sk"], it["ct"])
        elif it["op"] == "verify":
            answers[it["id"]] = lib.verify(it["pk"], it["msg"], it["sig"], it["ctx"])
        elif not a.no_derand:
            got = lib.derand(it)
            if got is not None:
                answers[it["id"]] = got
    name = a.name or ", ".join(f"{p}: {os.path.basename(libs[p])}" for p in prompt["params"])
    doc = {"format": RESPONSE_FORMAT, "prompt_sha256": prompt["prompt_sha256"], "params": prompt["params"], "implementation": name[:500],
           "answers": answers}
    with open(a.answers, "x", encoding="utf-8") as f:
        f.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"kpqc_harness: {len(answers)} answers for {len(prompt['items'])} items -> {a.answers}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
