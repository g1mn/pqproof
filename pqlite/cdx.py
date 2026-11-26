# cdx.py: 병합한 CBOM 항목(pqlite/rules.py merge_cbom)을 CycloneDX 1.6 CBOM JSON 으로 쓴다(표준 라이브러리만, 0.7.0).
# 판정은 하지 않는다. status·threat·reason 은 CSV(tables/cbom-*.csv)에 적힌 그대로 옮기고, 판정의 기록은 receipt.json 과 CSV 다.
# 같은 입력이면 바이트가 같다: timestamp 를 넣지 않고 serialNumber 는 내용 해시에서 만든다(CycloneDX 의 SHOULD '매번 새 serial'을
# 일부러 따르지 않는다, DESIGN.md). 1.7 전용 필드(algorithmFamily, ellipticCurve)는 1.6 검증에 걸려 쓰지 않는다.
"""Write merged CBOM items as a CycloneDX 1.6 CBOM. No verdict logic: status, threat and reason are copied as written."""
import hashlib
import json
import re
import uuid

SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
# nistQuantumSecurityLevel: FIPS 203(ML-KEM 512·768·1024 = 범주 1·3·5), FIPS 204(ML-DSA 44·65·87 = 2·3·5), FIPS 205(SLH-DSA 128·192·256 = 1·3·5)
MLKEM = {"512": (1, "2.16.840.1.101.3.4.4.1"), "768": (3, "2.16.840.1.101.3.4.4.2"), "1024": (5, "2.16.840.1.101.3.4.4.3")}
MLDSA = {"44": (2, "2.16.840.1.101.3.4.3.17"), "65": (3, "2.16.840.1.101.3.4.3.18"), "87": (5, "2.16.840.1.101.3.4.3.19")}
SLH_LEVEL = {"128": 1, "192": 3, "256": 5}
HYBRID_GROUPS = {"x25519mlkem768": "X25519MLKEM768", "secp256r1mlkem768": "SecP256r1MLKEM768", "secp384r1mlkem1024": "SecP384r1MLKEM1024"}
CURVES = {"256": "secp256r1", "384": "secp384r1", "521": "secp521r1"}
# loc 가 host:port 인 행(TLS 실측)은 줄 번호로 자르지 않는다
HOSTPORT_USES = ("TLS 엔드포인트", "키교환(TLS 협상)", "암호화(협상 스위트)")

_F = re.IGNORECASE
RX = [  # (정규식, 함수(match) -> (name, algorithmProperties, oid)). alg 전체가 맞을 때만(fullmatch)
    (re.compile(r"ml[-_]?kem[-_]?(512|768|1024)", _F),
     lambda m: (f"ML-KEM-{m[1]}", {"primitive": "kem", "parameterSetIdentifier": m[1], "nistQuantumSecurityLevel": MLKEM[m[1]][0]}, MLKEM[m[1]][1])),
    (re.compile(r"ml[-_]?dsa[-_]?(44|65|87)", _F),
     lambda m: (f"ML-DSA-{m[1]}", {"primitive": "signature", "parameterSetIdentifier": m[1], "nistQuantumSecurityLevel": MLDSA[m[1]][0]}, MLDSA[m[1]][1])),
    (re.compile(r"slh[-_]?dsa[-_]?(sha2|shake)[-_]?(128|192|256)([sf])?", _F),
     lambda m: (f"SLH-DSA-{m[1].upper()}-{m[2]}{(m[3] or '').lower()}",
                {"primitive": "signature", "parameterSetIdentifier": f"{m[1].upper()}-{m[2]}{(m[3] or '').lower()}",
                 "nistQuantumSecurityLevel": SLH_LEVEL[m[2]]}, None)),
    (re.compile(r"ml[-_]?kem", _F), lambda m: ("ML-KEM", {"primitive": "kem"}, None)),
    (re.compile(r"ml[-_]?dsa", _F), lambda m: ("ML-DSA", {"primitive": "signature"}, None)),
    (re.compile(r"slh[-_]?dsa", _F), lambda m: ("SLH-DSA", {"primitive": "signature"}, None)),
    (re.compile(r"x25519mlkem768|secp256r1mlkem768|secp384r1mlkem1024", _F),
     lambda m: (HYBRID_GROUPS[m[0].lower()], {"primitive": "combiner"}, None)),
    (re.compile(r"(?:mlkem768x25519-sha256|sntrup761x25519-sha512(?:@openssh\.com)?)", _F),
     lambda m: (m[0].lower(), {"primitive": "combiner"}, None)),
    (re.compile(r"(?:smaug|ntru\+|ntru_?plus|hqc|frodo|mceliece|kyber)\S*", _F), lambda m: (m[0], {"primitive": "kem"}, None)),
    (re.compile(r"(?:haetae|aimer|fn[-_]?dsa|falcon|dilithium|sphincs)\S*", _F), lambda m: (m[0], {"primitive": "signature"}, None)),
    (re.compile(r"rsa[-_ :]?([0-9]{3,5})", _F), lambda m: (f"RSA-{m[1]}", {"parameterSetIdentifier": m[1]}, None)),
    (re.compile(r"rsa", _F), lambda m: ("RSA", {}, None)),
    (re.compile(r"(?:ec[-_ ]?(?:256|384|521)?[-_ ]+)?(?:secp(256|384|521)r1|prime(256)v1|p-?(256|384|521))", _F),
     lambda m: (f"EC-{CURVES[m[1] or m[2] or m[3]]}", {"curve": CURVES[m[1] or m[2] or m[3]]}, None)),
    (re.compile(r"(?:aes\S*(?:gcm|ccm)\S*|chacha20[-_]?poly1305)", _F), lambda m: (m[0], {"primitive": "ae"}, None)),
    (re.compile(r"aes\S*", _F), lambda m: (m[0], {"primitive": "block-cipher"}, None)),
    (re.compile(r"(?:sha[-_]?(?:1|224|256|384|512)|sha3[-_]?\S*|md5)", _F), lambda m: (m[0], {"primitive": "hash"}, None)),
    (re.compile(r"(?:\S*with(?:ec)?dsa|ecdsa\S*|ed25519\S*|ed448\S*|(?:ec[-_]?)?kc[-_]?dsa\S*|dsa\S*)", _F), lambda m: (m[0], {"primitive": "signature"}, None)),
    (re.compile(r"(?:x25519|x448|ecdh\S*|dhe?\S*|ffdhe\S*)", _F), lambda m: (m[0], {"primitive": "key-agree"}, None)),
]
USE_PRIMITIVE = {"서명": "signature", "signature": "signature", "key-encapsulation": "kem", "키교환": "key-agree", "key-exchange": "key-agree"}


def classify(alg, use):
    """(component name, algorithmProperties, oid or None). 정해 둔 꼴에 alg 전체가 맞을 때만 정식 이름으로 바꾸고 아니면 원문 그대로."""
    a = (alg or "").strip()
    for rx, f in RX:
        m = rx.fullmatch(a)
        if m:
            name, props, oid = f(m)
            props = dict(props)
            break
    else:
        name, props, oid = (a or "unknown"), {}, None
    if "primitive" not in props:
        u = (use or "").strip()
        prim = USE_PRIMITIVE.get(u)
        if prim is None and name.upper().startswith("RSA") and u in ("암호화", "key-encryption"):
            prim = "pke"
        props["primitive"] = prim or "unknown"
    return name, props, oid


def kind(use):
    """use → (component type, cryptoProperties 의 assetType 쪽 dict 또는 None)."""
    u = (use or "").strip()
    if u.startswith("인증서"):
        return "cryptographic-asset", {"assetType": "certificate"}
    if u.startswith("개인키"):
        return "cryptographic-asset", {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "private-key"}}
    if u == "프로토콜":
        return "cryptographic-asset", {"assetType": "protocol"}
    if u in ("라이브러리", "toolchain", "provider"):
        return "library", None
    if u == "base-image":
        return "container", None
    return "cryptographic-asset", {"assetType": "algorithm"}


def split_loc(loc, use):
    """loc → (location, line 또는 None). host:port(TLS 실측)와 줄 번호 없는 위치는 그대로 둔다."""
    m = re.fullmatch(r"(.+):([0-9]+)", loc or "")
    if m and (use or "").strip() not in HOSTPORT_USES:
        return m[1], int(m[2])
    return (loc or ""), None


def _ref(ctype, name):
    slug = re.sub(r"[^a-z0-9.+-]+", "-", name.lower()).strip("-")[:40] or "x"
    return f"{ctype}/{slug}-{hashlib.sha256((ctype + chr(0) + name).encode('utf-8')).hexdigest()[:8]}"


def _context(it):
    parts = [(k, (it.get(k) or "").strip()) for k in ("status", "tool", "use", "threat", "reason", "note")]
    return "; ".join(f"{k}={v}" for k, v in parts if v)


def _props(pairs):
    return [{"name": n, "value": v} for n, v in sorted(set(pairs))]


def build(items, meta):
    """CycloneDX 1.6 문서(dict). items: merge_cbom 항목(note 는 이미 가린 것). meta: mode, tree, tree_sha256, tool_version,
    ruleset_version, ruleset_sha256, scope. 행마다 occurrence 하나(합치지 않음), 컴포넌트는 (type, name) 마다 하나."""
    comps = {}
    for it in items:
        name, props, oid = classify(it.get("alg"), it.get("use"))
        ctype, crypto = kind(it.get("use"))
        key = (ctype, name if ctype != "cryptographic-asset" else f"{crypto['assetType']}:{name}")
        c = comps.setdefault(key, {"type": ctype, "name": name, "occ": [], "props": set(), "aprops": props, "oid": oid,
                                   "crypto": crypto, "shor": False})
        loc, line = split_loc(it.get("loc"), it.get("use"))
        occ = {"location": loc or "unknown"}
        if line is not None:
            occ["line"] = line
        ctx = _context(it)
        if ctx:
            occ["additionalContext"] = ctx
        c["occ"].append(occ)
        raw = (it.get("alg") or "").strip()
        if raw and raw != name:
            c["props"].add(("pqproof:alg_raw", raw))
        for k in ("status", "threat", "use"):
            v = (it.get(k) or "").strip()
            if v:
                c["props"].add((f"pqproof:{k}", v))
        t = (it.get("threat") or "").strip()
        if t == "shor" or t.startswith("쇼어"):
            c["shor"] = True
    out = []
    for (ctype, keyname), c in comps.items():
        ref = _ref(ctype, keyname)
        comp = {"type": ctype, "bom-ref": ref, "name": c["name"]}
        if c["crypto"] is not None:
            crypto = json.loads(json.dumps(c["crypto"]))
            if crypto["assetType"] == "algorithm":
                ap = dict(c["aprops"])
                if "nistQuantumSecurityLevel" not in ap and c["shor"]:
                    ap["nistQuantumSecurityLevel"] = 0
                crypto["algorithmProperties"] = ap
            if c["oid"]:
                crypto["oid"] = c["oid"]
            comp["cryptoProperties"] = crypto
        comp["evidence"] = {"occurrences": sorted(c["occ"], key=lambda o: (o["location"], o.get("line", -1), o.get("additionalContext", "")))}
        if c["props"]:
            comp["properties"] = _props(c["props"])
        out.append(comp)
    out.sort(key=lambda x: x["bom-ref"])
    doc = {"$schema": SCHEMA, "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"tools": {"components": [{"type": "application", "name": "pqproof", "version": str(meta.get("tool_version") or "")}]},
                        "component": {"type": "application", "bom-ref": "tree", "name": str(meta.get("tree") or "tree")},
                        "properties": _props([("cdx:reproducible", "true")]
                                             + [(f"pqproof:{k}", str(meta[k])) for k in ("mode", "tree", "tree_sha256", "ruleset_version",
                                                                                          "ruleset_sha256", "scope") if meta.get(k) not in (None, "")])},
           "components": out}
    body = json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    doc["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()))
    return doc
