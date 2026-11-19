# make_kat_manifest.py: KpqC 참조판 KAT 목록(scan/kat-kpqc.json)과 발췌(scan/kat/)를 고정 판 원본에서 다시 만든다(개발용, 표준 라이브러리만).
#   python3 -I tools/make_kat_manifest.py <내려받은 파일> ...          scan/kat-kpqc.json, scan/kat/ 를 쓴다
#   python3 -I tools/make_kat_manifest.py --check <내려받은 파일> ...  다시 만든 결과가 저장소 파일과 바이트까지 같은지만 본다(다르면 종료 1)
# 내려받은 파일: 아래 SOURCES 의 zip 일곱 개와 BouncyCastle 시험 데이터의 AIMer .rsp 여섯 개(url 칸에서 받는다). 파일 이름은 상관없고
#   SHA-256 으로 어느 원본인지 가린다. 표에 없는 파일이나 빠진 원본이 있으면 멈춘다(종료 2). 같은 입력이면 출력이 바이트까지 같다
#   (시각·입력 경로를 적지 않고, 표의 순서대로 쓴다).
# 받은 zip 은 남이 만든 데이터다. 풀지 않고 zipfile 로 필요한 멤버(.rsp, LICENSE, rng.c)만 글자로 읽는다. 무엇도 실행하지 않는다.
# 판이 바뀌면 SOURCES·VARIANTS 를 고치고 이 도구를 다시 돌린 뒤, 규칙 묶음을 올린다(scan/ruleset.json, CHANGELOG '판정 영향').
"""Rebuild scan/kat-kpqc.json and scan/kat/ (KpqC reference KAT list and excerpts) from pinned source archives."""
import argparse
import hashlib
import json
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from pqlite import impl  # noqa: E402  (저장소 루트를 경로에 넣은 뒤 가져온다)

MANIFEST = "scan/kat-kpqc.json"
KAT_DIR = "scan/kat"
CHECKED = "2026-11-19"  # 출처·해시를 직접 대조한 날
EXCERPT_LIMIT = 3_000_000  # 발췌 전체가 이 바이트를 넘으면 레코드 수를 줄인다
EXCERPT_TRY = (10, 5)

# 고정 판 원본. official: 공식 사이트에 적힌 SHA-256(없으면 None 과 이유). license: zip 안 라이선스 파일
SOURCES = {
    "smaug-t-1.1.1": {
        "title": "SMAUG-T reference implementation 1.1.1",
        "url": "https://raw.githubusercontent.com/CryptoLabInc/SMAUG-T/bbc463cd788eae36c6d155cef667ac9dbd9054cd/SMAUG-T.zip",
        "repo": "https://github.com/CryptoLabInc/SMAUG-T", "ref": "tag v1.1.1",
        "commit": "bbc463cd788eae36c6d155cef667ac9dbd9054cd",
        "sha256": "d7213f1618282cbcb4090abe808a164f9689062f2b65b34fd86496b9923200d7", "bytes": 1096337,
        "official": {"page": "https://www.kpqc.cryptolab.co.kr/smaug-t",
                     "sha256": "d7213f1618282cbcb4090abe808a164f9689062f2b65b34fd86496b9923200d7",
                     "download": "https://drive.google.com/uc?export=download&id=10Wil4yKO-Pj5MIftpBoNVlb8CVRnGjT-",
                     "says": "Previous 1.1.1 contains some bugs in the implementation."},
        "license": "SMAUG-T-1.1.1/LICENSE",
    },
    "smaug-t-1.2.0": {
        "title": "SMAUG-T reference implementation 1.2.0",
        "url": "https://raw.githubusercontent.com/CryptoLabInc/SMAUG-T/ae7197960f5097c96e3218013f5c28d33dc271d1/SMAUG-T.zip",
        "repo": "https://github.com/CryptoLabInc/SMAUG-T", "ref": "tag v1.2.0",
        "commit": "ae7197960f5097c96e3218013f5c28d33dc271d1",
        "sha256": "ccb58f42043296174e10fc7af520f0a49076d8c2245bd8e66d1b88bcae568c90", "bytes": 1135283,
        "official": {"page": "https://www.kpqc.cryptolab.co.kr/smaug-t",
                     "sha256": "ccb58f42043296174e10fc7af520f0a49076d8c2245bd8e66d1b88bcae568c90",
                     "download": "https://drive.google.com/uc?export=download&id=1L6wLwZu65OHFDz2iPqZdEQOwcqJ-9xxX",
                     "says": "Please use the reference implementation of version 1.2.0 below."},
        "license": "SMAUG-T-1.2.0/LICENSE",
    },
    "haetae-1.1.2": {
        "title": "HAETAE reference implementation 1.1.2",
        "url": "https://raw.githubusercontent.com/CryptoLabInc/HAETAE/743c31df48183fc8c8a39a4f50a634da1c4af03a/HAETAE.zip",
        "repo": "https://github.com/CryptoLabInc/HAETAE", "ref": "commit (no tag)",
        "commit": "743c31df48183fc8c8a39a4f50a634da1c4af03a",
        "sha256": "9b69afb55ed96a20d9626b3ea729c291f9e4bfd8d880b740fcb30f6955c4ca72", "bytes": 2774831,
        "official": {"page": "https://www.kpqc.cryptolab.co.kr/haetae",
                     "sha256": "9b69afb55ed96a20d9626b3ea729c291f9e4bfd8d880b740fcb30f6955c4ca72",
                     "download": "https://drive.google.com/uc?export=download&id=1rgVckJYPws-dJSDSDC3jxK299p3FLHeI",
                     "says": "Original version announced in the KpqC homepage."},
        "license": "HAETAE-1.1.2/LICENSE",
    },
    "haetae-1.2.0": {
        "title": "HAETAE reference implementation 1.2.0",
        "url": "https://drive.google.com/open?id=1pW6YS1wZ1gm8Neb8pY5EyYTkkdRIDmJ6",
        "repo": None, "ref": "Google Drive file linked from the official page (not on GitHub)", "commit": None,
        "sha256": "e54f8f962eefadbb2929bca292797bc7ca18769fb9a273c10204f3887fd83e84", "bytes": 2824949,
        "official": {"page": "https://www.kpqc.cryptolab.co.kr/haetae",
                     "sha256": "e54f8f962eefadbb2929bca292797bc7ca18769fb9a273c10204f3887fd83e84",
                     "download": "https://drive.google.com/open?id=1pW6YS1wZ1gm8Neb8pY5EyYTkkdRIDmJ6",
                     "says": "Hyperball sampler modified."},
        "license": "HAETAE-1.2.0/LICENSE",
    },
    "ntruplus-2026-01": {
        "title": "NTRU+ reference implementation (KpqC final, files dated 2026-01-21)",
        "url": "https://raw.githubusercontent.com/ntruplus/reference/7166f57807899de407458fa46ce8929ac6491903/NTRU+.zip",
        "repo": "https://github.com/ntruplus/reference", "ref": "commit (no tag)",
        "commit": "7166f57807899de407458fa46ce8929ac6491903",
        "sha256": "44fa5b5b6edbb2849322f41e6b0e808874caa9f6efcaa83ba72dce0d47512615", "bytes": 2056278,
        "official": {"page": "https://www.ntruplus.org/", "sha256": None,
                     "says": "No SHA-256 published; the page links to github.com/ntruplus/ntruplus."},
        "license": "LICENSE",
    },
    "aimer-3.0": {
        "title": "AIMer reference implementation V3.0 (AIM3)",
        "url": "https://raw.githubusercontent.com/samsungsds-opensource/AIMer/734cc76fa4695ca8c8eaa070508db8ff62205e68/AIMer.zip",
        "repo": "https://github.com/samsungsds-opensource/AIMer", "ref": "commit 'update AIMer V3.0 reference implementation'",
        "commit": "734cc76fa4695ca8c8eaa070508db8ff62205e68",
        "sha256": "4b67f9bd41005de6789bc24b86279f1c0ecf685b9de80397d8cb459bcd1bee81", "bytes": 12406043,
        "official": {"page": "https://aimer-signature.org/", "sha256": None,
                     "says": "No SHA-256 published; the page links to the GitHub repository."},
        "license": "LICENSE",
        "nist_notice": "Reference_Implementation/common/rng.c",
    },
    "aimer-aim2-2026-01": {
        "title": "AIMer reference implementation, KpqC final package of 2026-01-30 (AIM2)",
        "url": "https://raw.githubusercontent.com/samsungsds-opensource/AIMer/e47c497f3552c234e0ca8368df9bb629af9608ce/AIMer-package.zip",
        "repo": "https://github.com/samsungsds-opensource/AIMer", "ref": "commit 'upload reference implementation'",
        "commit": "e47c497f3552c234e0ca8368df9bb629af9608ce",
        "sha256": "d7bbdb28e70dad021da2057bc0b4802585770cbc2d7449acfcd770d8bc624521", "bytes": 11056066,
        "official": {"page": "https://aimer-signature.org/", "sha256": None,
                     "says": "No SHA-256 published; the page links to the GitHub repository."},
        "license": "AIMer-package/LICENSE",
    },
    "bc-test-data-aimer": {
        "title": "Bouncy Castle test data, AIMer KAT files ('Round 2' implementation)",
        "url": "https://raw.githubusercontent.com/bcgit/bc-test-data/ee3d9c103d11b72840231b736755d6d38bafc7df/",
        "repo": "https://github.com/bcgit/bc-test-data", "ref": "commit 'Add AIMer test vectors' (unchanged up to 1905b926, 2026-11-18)",
        "commit": "ee3d9c103d11b72840231b736755d6d38bafc7df",
        "official": None,
        "license": None,
        "license_note": "The bc-test-data repository has no license file, so these KAT records are not redistributed: only digests are listed.",
        # zip 이 아니라 .rsp 파일을 따로 받는다: zip 안 경로 대신 저장소 경로 → (sha256, 바이트)
        "files": {
            "pqc/crypto/aimer/aimer128f/PQCsignKAT_48.rsp": ("bd2bf0e826d7f80a3110ea436437b425be521ef0724322e53543566f32a58291", 1876770),
            "pqc/crypto/aimer/aimer128s/PQCsignKAT_48.rsp": ("8959b24dfa59a84f21e822db37bc89012319814478ab30be0471ef1b7924bfef", 1531170),
            "pqc/crypto/aimer/aimer192f/PQCsignKAT_72.rsp": ("d54a9225e37bec1c21f398ba0f6fd2d3400d0a4e7e42578b5b1ac892d5824e7b", 3318470),
            "pqc/crypto/aimer/aimer192s/PQCsignKAT_72.rsp": ("826ac0f6e10c6ac30fe50b1048ecf4d5f6c7ecbf9a15a20755cf109d61783f17", 2531244),
            "pqc/crypto/aimer/aimer256f/PQCsignKAT_96.rsp": ("dff42effc0d43985f3e763c03ba442fe04aa7d5e5341c15e0cb94e0b0b6456e4", 5739270),
            "pqc/crypto/aimer/aimer256s/PQCsignKAT_96.rsp": ("ca00d1362544b5555343a5927cc12f1aee90489c6b734ce7ff80a5027fd0f916", 4126470),
        },
    },
}

# 같은 .rsp 바이트가 다른 곳에도 올라 있다(git blob SHA-1 로 대조, 2026-11-19 gh api). 판 구별의 보조 근거이고, 출처는 위 SOURCES 다
ALSO_AT = (
    {"where": "https://github.com/KpqC/kpqc-test-vectors", "commit": "d75490bf824faa4b148cd0b901a2eb13198fe0da",
     "note": "unofficial mirror", "blobs": {
         "195c51d4cf32fa217311a5c026fc10c57604231c": "smaugt/mode1/kat.rsp", "b58b346a41d0916880a7aadb8db9f214ba830f15": "smaugt/mode3/kat.rsp",
         "ee76c321d17009c725e82d3cb4b5a2e9c8071fad": "smaugt/mode5/kat.rsp", "0afeabce7e04e064ba5b2e6d036410b9e6db9ee8": "smaugt/modet/kat.rsp",
         "aadb37a775f8300cc0b30d8c5a8df5b9298bcdf9": "ntruplus/768/kat.rsp", "5e6e663c3de11ccdd3fd1c08748536c9ce070fea": "ntruplus/864/kat.rsp",
         "71cbcc16b85bc2a159a3240d5b7268f868c7759a": "ntruplus/1152/kat.rsp",
         "ef9956ce618df2a4952f5fc5a7c7c06885d93a15": "haetae/mode2/kat.rsp", "7ae03288249768dacf18a390db866bdb42033b97": "haetae/mode3/kat.rsp",
         "630090a31bdc127fb98758225d802713a012e724": "haetae/mode5/kat.rsp",
         "76651187af80e4887f1b2195edcafb116be2c204": "aimer/128f/kat.rsp", "492b2831c256e52e6a957a5a6712dcb3aaf783ef": "aimer/128s/kat.rsp",
         "4955856eae321530c30d9081a96519cff04c6662": "aimer/192f/kat.rsp", "ed0c9745ea410e68297c46f8d256b774fdb6d9ac": "aimer/192s/kat.rsp",
         "0c9717986339e141333b63cf5e525766b5ff14bd": "aimer/256f/kat.rsp", "3ebc720ea871632dd34473ffc28fa853a93a165d": "aimer/256s/kat.rsp"}},
    {"where": "https://github.com/ntruplus/ntruplus", "commit": "0c648674f33c962bd067db0715cf2111f37916ea",
     "note": "NTRU+ team repository linked from ntruplus.org", "blobs": {
         "aadb37a775f8300cc0b30d8c5a8df5b9298bcdf9": "KAT/NTRU+768/PQCkemKAT_2336.rsp",
         "5e6e663c3de11ccdd3fd1c08748536c9ce070fea": "KAT/NTRU+864/PQCkemKAT_2624.rsp",
         "71cbcc16b85bc2a159a3240d5b7268f868c7759a": "KAT/NTRU+1152/PQCkemKAT_3488.rsp"}},
    {"where": "https://github.com/bcgit/bc-test-data", "commit": "1905b9263166a51f68d2c33bc30f32a31c3e15f7",
     "note": "Bouncy Castle test data", "blobs": {
         "195c51d4cf32fa217311a5c026fc10c57604231c": "pqc/crypto/smaug_t/PQCkemKAT_smaugt_mode1.rsp",
         "b58b346a41d0916880a7aadb8db9f214ba830f15": "pqc/crypto/smaug_t/PQCkemKAT_smaugt_mode3.rsp",
         "ee76c321d17009c725e82d3cb4b5a2e9c8071fad": "pqc/crypto/smaug_t/PQCkemKAT_smaugt_mode5.rsp",
         "0afeabce7e04e064ba5b2e6d036410b9e6db9ee8": "pqc/crypto/smaug_t/PQCkemKAT_smaugt_modet.rsp",
         "aadb37a775f8300cc0b30d8c5a8df5b9298bcdf9": "pqc/crypto/ntruplus/PQCkemKAT_2336.rsp",
         "5e6e663c3de11ccdd3fd1c08748536c9ce070fea": "pqc/crypto/ntruplus/PQCkemKAT_2624.rsp",
         "71cbcc16b85bc2a159a3240d5b7268f868c7759a": "pqc/crypto/ntruplus/PQCkemKAT_3488.rsp",
         "091c32e563e0f214a6d8c0c5664e1164db5175e1": "pqc/crypto/haetae/PQCsignKAT_haetae_mode2.rsp",
         "a3835d8c77ca94f235a973142ca5898ce922f804": "pqc/crypto/haetae/PQCsignKAT_haetae_mode3.rsp",
         "cdd210fadab5526526356a5eee86c78c74d5f8ea": "pqc/crypto/haetae/PQCsignKAT_haetae_mode5.rsp"}},
)

KEM_FIELDS = ["count", "seed", "pk", "sk", "ct", "ss"]
HAETAE_FIELDS = ["count", "seed", "mlen", "msg", "pk", "sk", "siglen", "sig"]
AIMER_FIELDS = ["count", "seed", "mlen", "msg", "pk", "sk", "smlen", "sm"]

# 알고리즘: 이름, 종류, .rsp 칸, 형식 메모(확인한 사실만)
ALGORITHMS = {
    "smaug-t": {"name": "SMAUG-T", "kind": "kem", "fields": KEM_FIELDS, "notes": [
        "The official page asks for 1.2.0 and says 1.1.1 has implementation bugs. Every pk, sk, ct and ss differs between the two.",
        "modet is TiMER (Tiny sMaug using Error Reconciliation), a security level 1 set with a shorter ciphertext.",
        "The KAT program calls crypto_kem_keypair_internal(d, seed) and crypto_kem_enc_internal(mu) with d, seed and mu drawn "
        "from the NIST DRBG, in the same order as crypto_kem_keypair and crypto_kem_enc draw them."]},
    "ntruplus": {"name": "NTRU+", "kind": "kem", "fields": KEM_FIELDS, "notes": [
        "Parameter sets 768, 864 and 1152 only. 576 is a round 2 leftover and is not listed.",
        "crypto_kem_dec returns 1 and sets ss to all zero bytes when decapsulation fails (no implicit rejection), "
        "as the reference kem.c says."]},
    "haetae": {"name": "HAETAE", "kind": "sig", "fields": HAETAE_FIELDS, "notes": [
        "Fields are siglen and sig (the signature alone), not the NIST smlen and sm.",
        "1.1.2 and 1.2.0 give the same seed, msg, pk and sk. Only sig differs (1.2.0 changed the hyperball sampler).",
        "The KAT program signs with a context string that the .rsp does not print: after the key seed it draws rnd (32 bytes), "
        "then ctxlen (1 byte) and ctx (ctxlen bytes) from the NIST DRBG and signs with pre = ctxlen || ctx. "
        "Checking a KAT signature with crypto_sign_verify needs that ctx."]},
    "aimer": {"name": "AIMer", "kind": "sig", "fields": AIMER_FIELDS, "notes": [
        "Fields are smlen and sm, where sm = msg || sig.",
        "The f and s sets use the same .rsp file names (PQCsignKAT_48.rsp, _72, _96), so the folder decides the set.",
        "V3.0 (AIM3) changed pk, sk and the signature size from the 2026-01 package (AIM2).",
        "The Bouncy Castle 'Round 2' KAT has the same pk and sk as the 2026-01 package (AIM2) but every signature differs. "
        "It matches no reference version and is listed as a known variant.",
        "The KAT program signs with an empty context (ctx NULL, length 0). The reference implementation is little-endian only."]},
}

# 파라미터: 정규 id → 별칭(실제 쓰이는 표기와 쓰인 곳), .rsp 크기 기대값(바이트)
_SEEN_REF = "reference implementation (CRYPTO_ALGNAME, .rsp header line)"
PARAMS = {}


def _param(pid, aliases, sizes):
    PARAMS[pid] = {"aliases": aliases, "sizes": sizes}


for _m, _pk, _sk, _ct in (("mode1", 672, 832, 672), ("mode3", 1088, 1312, 992), ("mode5", 1440, 1728, 1376), ("modet", 672, 832, 608)):
    _a = {f"smaugt_{_m}": f"{_SEEN_REF}; Bouncy Castle SmaugTParameters field",
          f"smaugt-{_m}": "Bouncy Castle parameter name; reference CMake library name",
          f"cryptolab_smaugt_{_m}": "reference symbol prefix (cryptolab_smaugt_<mode>_keypair)"}
    if _m == "modet":
        _a["TiMER"] = "official page name of the extra level 1 set"
    else:
        _a[f"SMAUG-T{_m[-1]}"] = "KpqClean_ver2 folder (crypto_kem/SMAUG-T<n>)"
    _param(f"smaug-t/{_m}", _a, {"pk": _pk, "sk": _sk, "ct": _ct, "ss": 32})
for _n, _pk, _sk, _ct in (("768", 1152, 2336, 1152), ("864", 1296, 2624, 1296), ("1152", 1728, 3488, 1728)):
    _param(f"ntruplus/{_n}", {
        f"NTRU+{_n}": f"{_SEEN_REF}; reference and KpqClean_ver2 folder",
        f"NTRU+KEM{_n}": "Bouncy Castle parameter name",
        f"ntruplus_kem_{_n}": "Bouncy Castle NTRUPlusParameters field"}, {"pk": _pk, "sk": _sk, "ct": _ct, "ss": 32})
for _m, _pk, _sk, _sig in (("mode2", 992, 1408, 1474), ("mode3", 1472, 2112, 2349), ("mode5", 2080, 2752, 2948)):
    _d = _m[-1]
    _param(f"haetae/{_m}", {
        f"haetae_{_m}": _SEEN_REF,
        f"haetae-{_m}": "reference CMake library name",
        f"cryptolab_haetae_{_m}": "reference symbol prefix (cryptolab_haetae_<mode>_keypair)",
        f"HAETAE-{_d}": "Bouncy Castle parameter name",
        f"haetae{_d}": "Bouncy Castle HAETAEParameters field",
        f"HAETAE{_d}": "KpqClean_ver2 folder (crypto_sign/HAETAE<n>)"}, {"pk": _pk, "sk": _sk, "sig": _sig})
_AIMER_SIG = {"3.0": {"128f": 6944, "128s": 4704, "192f": 15408, "192s": 10320, "256f": 31360, "256s": 20224},
              "aim2": {"128f": 5888, "128s": 4160, "192f": 13056, "192s": 9120, "256f": 25120, "256s": 17056}}
for _p, _pk, _sk in (("128f", 32, 48), ("128s", 32, 48), ("192f", 48, 72), ("192s", 48, 72), ("256f", 64, 96), ("256s", 64, 96)):
    _param(f"aimer/{_p}", {
        f"aimer-{_p}": f"{_SEEN_REF}; reference KAT folder",
        f"aimer{_p}": "Bouncy Castle parameter name and AIMerParameters field; bc-test-data folder",
        f"AIMer{_p}": "KpqClean_ver2 folder (crypto_sign/AIMer<set>)",
        f"samsungsds_aimer_{_p}_ref": "reference symbol prefix (samsungsds_aimer_<set>_ref_crypto_sign_keypair)"}, {"pk": _pk, "sk": _sk})

# 판: 파라미터마다 (판 이름, 원본, zip 안 경로, 최신 여부, 역할). 역할 reference = 참조판, known-variant = 참조판이 아닌 알려진 변형
VARIANTS = {}
for _m in ("mode1", "mode3", "mode5", "modet"):
    VARIANTS[f"smaug-t/{_m}"] = [
        ("1.2.0", "smaug-t-1.2.0", f"SMAUG-T-1.2.0/kat/PQCkemKAT_smaugt_{_m}.rsp", True, "reference"),
        ("1.1.1", "smaug-t-1.1.1", f"SMAUG-T-1.1.1/kat/PQCkemKAT_smaugt_{_m}.rsp", False, "reference")]
for _n, _sk in (("768", 2336), ("864", 2624), ("1152", 3488)):
    VARIANTS[f"ntruplus/{_n}"] = [("2026-01", "ntruplus-2026-01", f"KAT/NTRU+{_n}/PQCkemKAT_{_sk}.rsp", True, "reference")]
for _m in ("mode2", "mode3", "mode5"):
    VARIANTS[f"haetae/{_m}"] = [
        ("1.2.0", "haetae-1.2.0", f"HAETAE-1.2.0/kat/PQCsignKAT_haetae_{_m}.rsp", True, "reference"),
        ("1.1.2", "haetae-1.1.2", f"HAETAE-1.1.2/kat/PQCsignKAT_haetae_{_m}.rsp", False, "reference")]
for _p in ("128f", "128s", "192f", "192s", "256f", "256s"):
    _f = f"PQCsignKAT_{PARAMS[f'aimer/{_p}']['sizes']['sk']}.rsp"
    VARIANTS[f"aimer/{_p}"] = [
        ("3.0", "aimer-3.0", f"KAT/aimer-{_p}/{_f}", True, "reference"),
        ("aim2-2026-01", "aimer-aim2-2026-01", f"AIMer-package/KAT/aimer-{_p}/{_f}", False, "reference"),
        ("bc-round2", "bc-test-data-aimer", f"pqc/crypto/aimer/aimer{_p}/{_f}", False, "known-variant")]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def fail(msg, code=2):
    print(f"make_kat_manifest: {msg}", file=sys.stderr)
    sys.exit(code)


def load_inputs(paths):
    """입력 파일을 SHA-256 으로 SOURCES 에 짝짓는다 → {원본 id: zip 경로 또는 {저장소 경로: 파일 경로}}."""
    by_sha = {s["sha256"]: sid for sid, s in SOURCES.items() if "sha256" in s}
    by_file = {v[0]: (sid, p) for sid, s in SOURCES.items() for p, v in s.get("files", {}).items()}
    found = {}
    for path in paths:
        with open(path, "rb") as f:
            h = sha256(f.read())
        if h in by_sha:
            found[by_sha[h]] = path
        elif h in by_file:
            sid, member = by_file[h]
            found.setdefault(sid, {})[member] = path
        else:
            fail(f"표에 없는 파일이다(sha256 {h}): {os.path.basename(path)}")
    missing = [sid for sid in SOURCES if sid not in found]
    missing += [f"{sid}:{m}" for sid, s in SOURCES.items() for m in s.get("files", {}) if m not in found.get(sid, {})]
    if missing:
        fail("빠진 원본: " + ", ".join(missing))
    return found


def read_member(found, sid, member):
    """원본에서 멤버 하나의 바이트. zip 은 풀지 않고 그 멤버만 읽는다."""
    src = found[sid]
    if isinstance(src, dict):
        with open(src[member], "rb") as f:
            return f.read()
    with zipfile.ZipFile(src) as z:
        return z.read(member)


def check_records(pid, version, recs, alg, sizes_expected):
    """레코드 100건의 칸·번호·길이를 본다. 판에서 실제로 잰 크기({칸: 바이트})를 돌려준다."""
    a = ALGORITHMS[alg]
    where = f"{pid} {version}"
    if len(recs) != 100:
        fail(f"{where}: 레코드가 100건이 아니다({len(recs)})")
    sizes = {}
    for i, r in enumerate(recs):
        if list(r) != a["fields"]:
            fail(f"{where}: count {i} 칸이 다르다 {list(r)}")
        if r["count"] != str(i):
            fail(f"{where}: count 가 0 부터 이어지지 않는다({r['count']})")
        if len(r["seed"]) != 96:
            fail(f"{where}: count {i} seed 가 48바이트가 아니다")
        got = {k: len(r[k]) // 2 for k in a["fields"] if k not in impl.DEC_FIELDS and k not in ("seed", "msg", "sm")}
        if "mlen" in r and int(r["mlen"]) != len(r["msg"]) // 2:
            fail(f"{where}: count {i} mlen 이 msg 길이와 다르다")
        if alg == "haetae" and int(r["siglen"]) != got["sig"]:
            fail(f"{where}: count {i} siglen 이 sig 길이와 다르다")
        if alg == "aimer":
            if int(r["smlen"]) != len(r["sm"]) // 2 or not r["sm"].startswith(r["msg"]):
                fail(f"{where}: count {i} sm 이 msg || sig 가 아니다")
            got["sig"] = int(r["smlen"]) - int(r["mlen"])
        if i == 0:
            sizes = got
        elif got != sizes:
            fail(f"{where}: count {i} 크기가 count 0 과 다르다 {got} {sizes}")
    for k, v in sizes_expected.items():
        if sizes.get(k) != v:
            fail(f"{where}: {k} 가 {v}바이트여야 하는데 {sizes.get(k)}")
    return sizes


def build(found):
    """{저장소 상대 경로: 바이트}."""
    blobs_seen = {}
    for ref in ALSO_AT:
        for blob, path in ref["blobs"].items():
            blobs_seen.setdefault(blob, []).append({"where": ref["where"], "commit": ref["commit"], "path": path, "note": ref["note"]})
    sources_out = {}
    for sid, s in SOURCES.items():
        o = {k: s[k] for k in ("title", "url", "repo", "ref", "commit") if k in s}
        if "sha256" in s:
            o["zip_sha256"], o["zip_bytes"] = s["sha256"], s["bytes"]
        if s.get("official"):
            off = dict(s["official"])
            off["match"] = (off["sha256"] == s["sha256"]) if off.get("sha256") else None
            o["official"] = off
        else:
            o["official"] = None
        o["license"] = ({"spdx": "MIT", "file_in_source": s["license"], "file_sha256": sha256(read_member(found, sid, s["license"]))}
                        if s.get("license") else {"spdx": None, "note": s.get("license_note")})
        sources_out[sid] = o

    parsed = {}  # (pid, version) → (레코드, 원문 바이트)
    for pid, vs in VARIANTS.items():
        for version, sid, member, _latest, _role in vs:
            data = read_member(found, sid, member)
            if isinstance(found[sid], dict) and (sha256(data), len(data)) != SOURCES[sid]["files"][member]:
                fail(f"{pid} {version}: .rsp 해시가 표와 다르다")
            parsed[(pid, version)] = (impl.parse_rsp(data), data)

    # 발췌 레코드 수: 10건 전체가 한도를 넘으면 5건
    def excerpt_bytes(n):
        out = {}
        for pid, vs in VARIANTS.items():
            for version, sid, member, _latest, role in vs:
                if role != "reference":
                    continue
                recs, data = parsed[(pid, version)]
                body = {"format": 1, "param": pid, "version": version, "source": sid, "rsp_path": member,
                        "rsp_sha256": sha256(data), "digest": impl.rsp_digest(recs), "records_in_file": len(recs),
                        "excerpt_records": n, "license": "MIT (scan/kat/NOTICE)", "records": recs[:n]}
                out[f"{KAT_DIR}/{pid}/{version}.json"] = (json.dumps(body, indent=1) + "\n").encode("ascii")
        return out
    sizes_try = {}
    for n in EXCERPT_TRY:
        files = excerpt_bytes(n)
        sizes_try[n] = sum(len(b) for b in files.values())
        if sizes_try[n] <= EXCERPT_LIMIT:
            break
    else:
        fail(f"발췌가 {EXCERPT_TRY[-1]}건으로도 {EXCERPT_LIMIT}바이트를 넘는다")
    out = dict(files)

    algos_out = {}
    for alg, a in ALGORITHMS.items():
        params_out = {}
        for pid, p in PARAMS.items():
            if not pid.startswith(alg + "/"):
                continue
            variants_out = []
            for version, sid, member, latest, role in VARIANTS[pid]:
                recs, data = parsed[(pid, version)]
                expected = dict(p["sizes"])
                if alg == "aimer":
                    expected["sig"] = _AIMER_SIG["3.0" if version == "3.0" else "aim2"][pid.split("/")[1]]
                sizes = check_records(pid, version, recs, alg, expected)
                rds = [impl.record_digest(r) for r in recs]
                header = next((ln.strip()[1:].strip() for ln in data.decode("ascii").splitlines() if ln.strip().startswith("#")), None)
                diffs = {}
                for v2, *_ in VARIANTS[pid]:
                    if v2 == version:
                        continue
                    r2 = parsed[(pid, v2)][0]
                    d = {k: sum(x[k] != y[k] for x, y in zip(recs, r2)) for k in a["fields"]}
                    diffs[v2] = {k: c for k, c in d.items() if c}
                blob = git_blob(data)
                excerpt = f"{KAT_DIR}/{pid}/{version}.json"
                variants_out.append({
                    "version": version, "latest": latest, "role": role, "source": sid, "rsp_path": member,
                    "rsp_header": header, "rsp_sha256": sha256(data), "rsp_bytes": len(data), "git_blob_sha1": blob,
                    "also_at": blobs_seen.get(blob, []), "digest": impl.rsp_digest(rds), "records": len(recs),
                    "fields": a["fields"], "sizes": sizes, "differs_from": diffs,
                    "excerpt": excerpt if excerpt in out else None, "record_digests": rds})
            params_out[pid] = {"aliases": list(p["aliases"]), "alias_seen_in": p["aliases"], "variants": variants_out}
        algos_out[alg] = {"name": a["name"], "kind": a["kind"], "fields": a["fields"], "notes": a["notes"], "params": params_out}

    nused = next(n for n in EXCERPT_TRY if n in sizes_try and sizes_try[n] <= EXCERPT_LIMIT)
    decision = (f"First {nused} records (count 0 to {nused - 1}) of every reference version and parameter set, all fields. "
                + "; ".join(f"{n} records would be {sizes_try[n]} bytes" for n in sizes_try)
                + f"; the limit is {EXCERPT_LIMIT} bytes. Plain JSON, not gzip: the wheel, the sdist and git compress it anyway. "
                  "Known variants without a license (Bouncy Castle) have digests only.")
    manifest = {
        "format": 1,
        "about": ("Reference KAT list for the Korean KpqC algorithms SMAUG-T, NTRU+, HAETAE and AIMer. For each parameter set it lists "
                  "the pinned reference versions (and known variants) with the SHA-256 of the source archive and of the .rsp file, "
                  "a normalized digest of the whole file and one digest per record. A .rsp that matches tells which reference "
                  "version's KAT it agrees with. This is not a certification: there is no official KpqC test programme, and it is "
                  "not a substitute for KCMVP."),
        "generated_by": "tools/make_kat_manifest.py",
        "checked": CHECKED,
        "normalization": {
            "code": "pqlite/impl.py (parse_rsp, record_digest, rsp_digest)",
            "parse": ("Lines may end in LF, CRLF or CR. Blank lines and lines starting with '#' are skipped. Other lines are "
                      "'key = value'. Keys are trimmed and lower-cased. count, mlen, smlen and siglen are decimal integers written "
                      "without leading zeros; every other value is hex, upper-cased. A count line starts a new record. Records keep "
                      "file order."),
            "record_digest": "SHA-256 of the lines 'key=value\\n' of one normalized record, keys sorted.",
            "rsp_digest": "SHA-256 of the lines 'record_digest\\n' in file order, so it can be recomputed from record_digests alone.",
        },
        "keys": {
            "id": "algorithms.<alg>.params.<id>: canonical parameter id, e.g. smaug-t/mode3. aliases are spellings seen in the "
                  "reference code, Bouncy Castle and KpqClean_ver2; alias_seen_in says where.",
            "role": "reference: a published reference version. known-variant: seen in a third-party library, matches no "
                    "reference version.",
            "latest": "true for the newest reference version of that parameter set.",
            "rsp_path": "path of the .rsp inside the source zip, or inside the repository for a source without a zip.",
            "sizes": "bytes of pk, sk and ct, ss (KEM) or sig (signature; for AIMer sig = smlen - mlen).",
            "differs_from": "for each other version of the same parameter set, how many of the 100 records differ in each field.",
            "also_at": "other places that publish the same .rsp bytes (same git blob SHA-1).",
            "excerpt": "file under scan/kat/ with the first records, or null when the source may not be redistributed.",
        },
        "excerpt": {"dir": KAT_DIR, "records": nused, "bytes": sizes_try[nused], "limit_bytes": EXCERPT_LIMIT,
                    "decision": decision, "notice": f"{KAT_DIR}/NOTICE"},
        "sources": sources_out,
        "algorithms": algos_out,
    }
    out[MANIFEST] = (json.dumps(manifest, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    out[f"{KAT_DIR}/NOTICE"] = notice(found)
    return out


def notice(found):
    """scan/kat/NOTICE: 재배포하는 KAT 의 라이선스 원문(같은 글은 한 번)과 NIST 고지."""
    texts = {}
    for sid, s in SOURCES.items():
        if s.get("license"):
            texts.setdefault(read_member(found, sid, s["license"]).decode("utf-8"), []).append(sid)
    parts = ["Third-party notices for the files in scan/kat/\n"
             "=============================================\n\n"
             "scan/kat/ holds excerpts of the known-answer test (KAT) files published with the KpqC reference\n"
             "implementations listed in scan/kat-kpqc.json (sources): the first records of each file, copied into\n"
             "JSON with only normalization applied (key case, hex case, whitespace). Each source is under the MIT\n"
             "license below. The KAT files were produced by the NIST PQCgenKAT programs and the NIST AES-256-CTR\n"
             "DRBG (rng.c) shipped with each reference implementation, whose NIST notice follows the licenses.\n"]
    for text, sids in texts.items():
        names = ", ".join(f"{sid} ({SOURCES[sid]['license']})" for sid in sids)
        parts.append(f"\n----------------------------------------------------------------------\n"
                     f"MIT license of: {names}\n"
                     f"----------------------------------------------------------------------\n\n{text.rstrip()}\n")
    for sid, s in SOURCES.items():
        if s.get("nist_notice"):
            src = read_member(found, sid, s["nist_notice"]).decode("utf-8")
            m = re.match(r"\s*/\*(.*?)\*/", src, re.S)
            if not m or "NIST" not in m[1]:
                fail(f"{sid}: {s['nist_notice']} 에서 NIST 고지를 찾지 못했다")
            parts.append(f"\n----------------------------------------------------------------------\n"
                         f"NIST notice of rng.c (quoted from {sid}: {s['nist_notice']})\n"
                         f"----------------------------------------------------------------------\n\n{m[1].strip()}\n")
    return "".join(parts).encode("utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="compare with the files in the repository instead of writing")
    ap.add_argument("files", nargs="+", help="downloaded source archives and .rsp files")
    args = ap.parse_args(argv)
    out = build(load_inputs(args.files))
    stale = []
    kat_root = os.path.join(ROOT, KAT_DIR)
    for dirpath, _dirs, names in os.walk(kat_root):
        for name in names:
            rel = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
            if rel not in out:
                stale.append(rel)
    if args.check:
        bad = []
        for rel, data in sorted(out.items()):
            try:
                with open(os.path.join(ROOT, rel), "rb") as f:
                    if f.read() != data:
                        bad.append(rel)
            except OSError:
                bad.append(rel)
        for rel in bad + stale:
            print(f"다름: {rel}", file=sys.stderr)
        print(f"make_kat_manifest: {len(out)}개 파일 {'일치' if not bad and not stale else '불일치'}")
        return 1 if bad or stale else 0
    for rel, data in sorted(out.items()):
        path = os.path.join(ROOT, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    for rel in stale:
        print(f"make_kat_manifest: 표에 없는 옛 파일(지우지 않았다): {rel}", file=sys.stderr)
    total = sum(len(d) for d in out.values())
    print(f"make_kat_manifest: {len(out)}개 파일, {total} 바이트")
    return 0


if __name__ == "__main__":
    sys.exit(main())
