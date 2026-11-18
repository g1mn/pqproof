"""규칙 패턴별 행동 시험: 규칙의 대안마다 걸리는 줄과 안 걸리는 줄을 표로 두고 지금 동작을 그대로 고정한다.

- residue.sh(c-classic): GEN 규칙의 대안마다 양성·음성 줄, 분류(주석·시험 경로·같은 줄 legacy·Legacy*.java·같은 줄 ML-KEM·쓰기 연산),
  LWRITE, EXPECT. 표 트리를 만들어 residue.sh 를 한 번 돌리고 줄마다 어느 규칙에 어떤 상태로 잡혔는지 본다.
- prove.py 허용 규칙: 하이브리드 창(위아래 12줄은 잡고 13줄은 안 잡음), 허용 목록 쓰기 경로(아래 3줄은 보고 4줄은 안 봄),
  쓰기 연산 대안, 같은 줄 legacy·ML-KEM, a-input 공통 파일 50% 경계.
- pqlite/verify.py(b-weakening·r-review): RULES 하나하나에 걸리는 수정과 안 걸리는 수정, review 규칙의 언어별 행.
표에 없는 규칙이나 대안이 생기면 실패한다. 규칙을 더할 때 행동 행을 같이 넣는다.

알려진 실패(KNOWN_GAPS): 교차 리뷰에서 찾은 우회·오탐을 지금 동작 그대로 고정했다. 고치면 그 시험이 실패하니 기대값을 뒤집고
KNOWN_GAPS 에서 지운다. 판정이 바뀌는 고침이라 규칙 묶음을 올리고 golden 과 함께 바꾼다. 규칙 묶음 2(0.2.0)에서 X01·X02·X03·X04·X06·
X07·X58 을 고쳐 기대값을 뒤집었다(Bypasses 칸과 아래 표의 해당 행).
"""
import os
import pathlib
import re
import shutil
import sys
import subprocess
import tempfile
import unittest
import zipfile
from unittest import mock

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import rules  # noqa: E402
import rulesrc  # noqa: E402
from pqlite import receipt as rc  # noqa: E402
from pqlite import verify  # noqa: E402

EXAMPLES = PROOF / "examples"
KNOWN_GAPS = {
    "X11": "ML-KEM-1024·ML-DSA-87 은 EXPECT(c-expect)가 세지 않음",
    "X18": "Go 코드의 MaxVersion TLS 1.2(TLS 1.3 끄기)는 약화 규칙에 안 걸림",
    "X19": "소문자 ed25519·x25519 를 residue 가 못 셈",
    "X21": "파일 이름에 줄바꿈이 있으면 residue 가 그 파일을 통째로 놓침",
    "X22": "Python 독스트링 줄을 코드로 셈",
    "X23": "G-EC 짧은 토큰 오탐(AWS::EC2, CSS #EC4899)",
    "X24": "시험 경로 빈틈(.test.tsx, Django tests.py)",
    # 이번 행동 시험을 쓰다 찾은 것(교차 리뷰 목록 밖). 판정이 바뀌는 고침이라 0.2.0 에서 같이 고친다
    "N1": "-Djdk.internal.httpclient.disableHostnameVerification 꼴(JVM 옵션)은 앞 글자 D 때문에 \\b 가 안 맞아 약화 규칙에 안 걸림",
}
L, A, C, T = "LEFT", "ALLOW", "COMMENT", "TEST"


def gap_msg(gid):
    return f"알려진 실패 {gid}({KNOWN_GAPS[gid]})가 바뀌었다: 고쳤다면 기대값을 뒤집고 KNOWN_GAPS 에서 지운다"


# ---------------------------------------------------------------------------------------------
# residue.sh 표: (경로, 내용, {규칙: 기대 상태 또는 None(안 잡힘)}, 알려진 실패 번호)
def R(path, text, gap=None, **expect):
    return (path, text, {k.replace("_", "-"): v for k, v in expect.items()}, gap)


RESIDUE_CASES = [
    # G-RSA: (^|[^A-Za-z])[Rr][Ss][Aa]
    R("c/RsaCipher.java", 'Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");', G_RSA=L, G_OAEP_PKCS1=L),
    R("c/rsa_start.py", "rsa_key = load_key()", G_RSA=L),
    R("c/RsaMixed.java", 'KeyFactory kf = KeyFactory.getInstance("Rsa");', G_RSA=L),
    R("c/RsaNo.java", "int traversal = universal + parsable;", G_RSA=None),
    # G-EC
    R("c/Ec1.java", 'String a = "ECDSA";', G_EC=L),
    R("c/Ec2.java", 'String a = "ECDH";', G_EC=L, G_X25519=L),
    R("c/Ec3.java", 'String a = "ECIES";', G_EC=L, G_DH_DSA=L),
    R("c/Ec4.java", "ECPrivateKey k = null;", G_EC=L),
    R("c/Ec5.java", "Object k = (ECPublicKey) o;", G_EC=L),
    R("c/Ec6.java", "ECPoint w = p;", G_EC=L),
    R("c/Ec7.java", "Object s = new ECGenParameterSpec(n);", G_EC=L),
    R("c/Ec8.java", "ECNamedCurveSpec s = null;", G_EC=L),
    R("c/Ec9.java", "ECParameterSpec ps = null;", G_EC=L),
    R("c/Ec10.java", "ECCurve c = null;", G_EC=L),
    R("c/Ec11.java", 'KeyFactory.getInstance("EC");', G_EC=L),
    R("c/Ec12.java", "alg = EC", G_EC=L),
    R("c/EcNo1.java", "int ECHO_MODE = 1;", G_EC=None),
    R("c/EcNo2.java", "int RECORD = 2;", G_EC=None),
    R("c/EcNo3.java", 'String s = "SHA256withECDSA";', G_EC=None, G_CLASSIC_SIG=L),  # 앞이 글자면 G-EC 는 안 잡는다
    # G-CURVE
    R("c/Cv1.java", 'String c = "secp256r1";', G_CURVE=L),
    R("c/Cv2.java", 'String c = "secp256k1";', G_CURVE=L),
    R("c/Cv3.java", 'String c = "prime256v1";', G_CURVE=L),
    R("c/Cv4.java", 'String c = "P-256";', G_CURVE=L),
    R("c/Cv5.java", 'String c = "P384";', G_CURVE=L),
    R("c/Cv6.java", "curve = P-521", G_CURVE=L),
    R("c/Cv7.java", 'String c = "brainpoolP256r1";', G_CURVE=L),
    R("c/Cv7b.java", 'String c = "brainpoolT320t1";', G_CURVE=L),
    R("c/Cv8.java", 'String oid = "1.2.840.10045.2.1";', G_CURVE=L),
    R("c/Cv9.java", 'String oid = "1.3.132.0.34";', G_CURVE=L),
    R("c/CvNo1.java", "int P2560 = 0;", G_CURVE=None),
    R("c/CvNo2.java", 'String c = "secp256";', G_CURVE=None),
    R("c/CvNo3.java", 'String c = "prime256";', G_CURVE=None),
    # G-OAEP-PKCS1
    R("c/Pad1.java", "OAEPParameterSpec p = null;", G_OAEP_PKCS1=L),
    R("c/Pad2.java", "Object m = MGF1ParameterSpec.SHA256;", G_OAEP_PKCS1=L),
    R("c/Pad3.java", 'String p = "PKCS1Padding";', G_OAEP_PKCS1=L),
    R("c/Pad4.java", 'String p = "PKCS#1";', G_OAEP_PKCS1=L),
    R("c/Pad5.java", "p = PKCS1", G_OAEP_PKCS1=L),
    R("c/Pad6.java", "Object s = PSource.PSpecified.DEFAULT;", G_OAEP_PKCS1=L),
    R("c/PadNo1.java", 'KeyStore.getInstance("PKCS12");', G_OAEP_PKCS1=None),
    R("c/PadNo2.java", "Object k = new PKCS8EncodedKeySpec(b);", G_OAEP_PKCS1=None),
    # G-CLASSIC-SIG
    R("c/Sig1.java", 'String a = "SHA256withRSA";', G_CLASSIC_SIG=L),
    R("c/Sig2.java", 'String a = "SHA384withECDSA";', G_CLASSIC_SIG=L),
    R("c/Sig3.java", 'String a = "SHA1withDSA";', G_CLASSIC_SIG=L),
    R("c/Sig4.java", 'String a = "SHA256withPLAIN-ECDSA";', G_CLASSIC_SIG=L),
    R("c/Sig5.java", 'String a = "NONEwithEdDSA";', G_CLASSIC_SIG=L, G_EDDSA=L),
    R("c/Sig6.java", 'String a = "RSASSA-PKCS1-v1_5";', G_CLASSIC_SIG=L),
    R("c/Sig7.java", 'String a = "RSA-PSS";', G_CLASSIC_SIG=L),
    R("c/Sig8.java", 'String a = "RSAPSS";', G_CLASSIC_SIG=L),
    R("c/SigNo1.java", 'String a = "SHA256withMLDSA";', G_CLASSIC_SIG=None),
    R("c/SigNo2.java", 'String a = "ML-DSA-65";', G_CLASSIC_SIG=None, G_DH_DSA=None),
    # G-JWT-ALG
    R("c/Jwt1.java", 'String a = "RS256";', G_JWT_ALG=L),
    R("c/Jwt2.java", 'String a = "ES384";', G_JWT_ALG=L),
    R("c/Jwt3.java", 'String a = "PS512";', G_JWT_ALG=L),
    R("c/Jwt4.java", "alg = RS384", G_JWT_ALG=L),
    R("c/JwtNo1.java", 'String a = "HS256";', G_JWT_ALG=None),
    R("c/JwtNo2.java", 'String a = "XRS256";', G_JWT_ALG=None),
    R("c/JwtNo3.java", 'String a = "RS2560";', G_JWT_ALG=None),
    # G-EDDSA
    R("c/Ed1.java", 'String a = "Ed25519";', G_EDDSA=L),
    R("c/Ed2.java", 'String a = "Ed448";', G_EDDSA=L),
    R("c/Ed3.java", 'String a = "EdDSA";', G_EDDSA=L),
    R("c/Ed4.java", 'String a = "Curve25519";', G_EDDSA=L),
    R("c/EdNo.java", 'String e = "Ed2";', G_EDDSA=None),
    # G-X25519(같은 줄 ML-KEM 이면 허용, 쓰기 연산이 있으면 허용하지 않음)
    R("c/Kx1.java", "Object p = NamedParameterSpec.X25519;", G_X25519=L),
    R("c/Kx2.java", 'String a = "X448";', G_X25519=L),
    R("c/Kx3.java", 'String a = "XDH";', G_X25519=L),
    R("c/Kx4.java", "KeyAgreement ka = null;", G_X25519=L),
    R("c/Kx5.java", 'String g = "X25519MLKEM768";', G_X25519=A),
    R("c/Kx6.java", 'String g = "X25519+ML-KEM-768";', G_X25519=A),
    R("c/Kx7.java", 'KeyPairGenerator g = KeyPairGenerator.getInstance("X25519MLKEM768");', G_X25519=L),
    R("c/Kx8.java", 'String g = "X25519_ml_kem_768";', G_X25519=L),  # 대소문자를 가린다(prove.py 와 다름, test_rule_sync)
    R("c/KxNo.java", 'String x = "X255";', G_X25519=None),
    # G-DH-DSA
    R("c/Dh1.java", "Object d = DiffieHellman.group14();", G_DH_DSA=L),
    R("c/Dh2.java", 'String a = "DH";', G_DH_DSA=L),
    R("c/Dh3.java", 'String a = "DHE";', G_DH_DSA=L),
    R("c/Dh4.java", 'String a = "DSA";', G_DH_DSA=L),
    R("c/Dh5.java", "ElGamalEngine e = null;", G_DH_DSA=L),
    R("c/DhNo1.java", 'String d = "DHX";', G_DH_DSA=None),
    R("c/DhNo2.java", "int DSA_SIZE = 3;", G_DH_DSA=None),
    # G-AES128
    R("c/Aes1.java", 'String a = "AES-128";', G_AES128=L),
    R("c/Aes2.java", 'String a = "AES128";', G_AES128=L),
    R("c/Aes3.java", 'String a = "AES_128";', G_AES128=L),
    R("c/Aes4.java", 'String a = "aes-128-gcm";', G_AES128=L),
    R("c/Aes5.java", 'String a = "Aes128";', G_AES128=L),
    R("c/Aes6.java", "kg.init(128);", G_AES128=L),
    R("c/AesNo1.java", 'String a = "AES-256";', G_AES128=None),
    R("c/AesNo2.java", "kg.init(256);", G_AES128=None),
    # G-WEAK-PQC
    R("c/Wq1.java", 'String a = "ML-KEM-512";', G_WEAK_PQC=L),
    R("c/Wq2.java", 'String a = "MLKEM512";', G_WEAK_PQC=L),
    R("c/Wq3.java", 'String a = "ml_kem_512";', G_WEAK_PQC=L),
    R("c/Wq4.java", 'String a = "ML_KEM_512";', G_WEAK_PQC=L),
    R("c/Wq5.java", 'String a = "ML-DSA-44";', G_WEAK_PQC=L),
    R("c/Wq6.java", 'String a = "MLDSA44";', G_WEAK_PQC=L),
    R("c/Wq7.java", 'String a = "ml_dsa_44";', G_WEAK_PQC=L),
    R("c/Wq8.java", 'String a = "ML_DSA_44";', G_WEAK_PQC=L),
    R("c/Wq9.java", 'String a = "Kyber512";', G_WEAK_PQC=L),
    R("c/Wq10.java", 'String a = "Dilithium2";', G_WEAK_PQC=L),
    R("c/WqNo1.java", 'String a = "ML-KEM-768";', G_WEAK_PQC=None),
    R("c/WqNo2.java", 'String a = "Dilithium3";', G_WEAK_PQC=None),
    # 분류: 같은 줄 legacy(쓰기 연산이 없을 때만), Legacy*.java, 시험 경로, 주석·문서
    R("c/Gate1.java", 'Cipher c = Cipher.getInstance("RSA"); // legacy read path', G_RSA=L),  # 주석의 legacy 는 아니다(X01)
    R("c/Gate2.java", 'KeyFactory.getInstance("RSA"); // LEGACY', G_RSA=L),
    R("c/Gate3.java", "Key legacy_rsa_key = k;", G_RSA=A),
    R("c/Gate5.java", 'Cipher legacyRsa = Cipher.getInstance("RSA/ECB/OAEPPadding");', G_RSA=A, G_OAEP_PKCS1=A),
    R("c/lr.py", "legacy_rsa = serialization.load_pem_public_key(data)", G_RSA=A),
    R("c/lw.go", "legacyKey, _ := rsa.GenerateKey(rand.Reader, 2048)", G_RSA=L),  # 모든 언어의 새 키 생성은 이름 규칙 밖(X01)
    R("c/lw.js", "const legacyKeys = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});", G_RSA=L),
    R("c/ls.py", "legacy_sig = rsa_key.sign(data, padding.PKCS1v15(), h)", G_RSA=L, G_OAEP_PKCS1=L),
    R("c/Gate4.java", "c.init(Cipher.ENCRYPT_MODE, rsaKey); // legacy", G_RSA=L),
    R("c/LegacyReader.java", 'KeyFactory kf = KeyFactory.getInstance("RSA");', G_RSA=A, LW_legacy_write=None),
    R("c/LegacyWriter.java", 'KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");', G_RSA=L, LW_legacy_write=L),
    R("c/LegacyBox.kt", 'val c = Cipher.getInstance("RSA")', G_RSA=L, LW_legacy_write=None),
    R("c/Legacy-box.java", 'KeyFactory kf = KeyFactory.getInstance("RSA");', G_RSA=L),
    R("src/test/java/demo/BoxTest.java", 'KeyFactory.getInstance("RSA");', G_RSA=T),
    R("c/cm1.java", "// uses RSA keys", G_RSA=C),
    R("c/cm2.py", "# RSA key", G_RSA=C),
    R("c/cm3.java", "int n = 1; // RSA", G_RSA=C),
    R("c/cm4.java", "/* ECDSA */", G_EC=C),
    R("c/cm5.xml", '<!-- "ECDH" -->', G_EC=C),
    R("c/cm6.sql", "-- ECDSA", G_EC=C),
    R("c/cm7.md", "Ed25519 notes", G_EDDSA=C),
    # LWRITE: Legacy*.java 안 쓰기 경로(대안마다)
    R("c/LegacyW1.java", "c.init(Cipher.ENCRYPT_MODE, k);", LW_legacy_write=L),
    R("c/LegacyW2.java", "c.init(Cipher.WRAP_MODE, k);", LW_legacy_write=L),
    R("c/LegacyW3.java", "s.initSign(k);", LW_legacy_write=L),
    R("c/LegacyW4.java", "KeyPairGenerator g = null;", LW_legacy_write=L),
    R("c/LegacyW5.java", "g.generateKeyPair();", LW_legacy_write=L),
    R("c/LegacyW6.java", "Files.write(p, b);", LW_legacy_write=L),
    R("c/LegacyW7.java", "Files.writeString(p, s);", LW_legacy_write=L),
    R("c/LegacyW8.java", "Files.move(a, b);", LW_legacy_write=L),
    R("c/LegacyW9.java", "Files.copy(a, b);", LW_legacy_write=L),
    R("c/LegacyWNo.java", "c.init(Cipher.DECRYPT_MODE, k);", LW_legacy_write=None),
    R("c/NotLegacy.java", "Files.write(p, b);", LW_legacy_write=None),
    # 규칙 묶음 2에서 고친 우회(교차 리뷰 X01·X02·X07·X58)
    R("c/gw.py", "legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)", G_RSA=L),
    R("src/main/java/com/bank/vendor/PgClient.java", 'KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");', G_RSA=L),
    R("c/wpqc.js", "const a = crypto.generateKeyPairSync('ml-kem-512');", G_WEAK_PQC=L),
    R("c/wpqc2.js", "const s = crypto.generateKeyPairSync('ml-dsa-44');", G_WEAK_PQC=L),
    R("c/wpqc3.py", 'kem = oqs.KeyEncapsulation("Kyber-512")', G_WEAK_PQC=L),
    R("c/wpqc4.go", 'name := "mldsa44"', G_WEAK_PQC=L),
    R("c/WqNo3.java", 'String a = "Kyber768";', G_WEAK_PQC=None),
    R("c/WqNo4.java", 'String a = "Dilithium25519";', G_WEAK_PQC=None),
    R("c/Kx58.java", 'KeyAgreement ka = KeyAgreement.getInstance("X25519"); // ML-KEM-768 later', G_X25519=L),
    # 알려진 실패(지금 동작)
    R("c/kor.js", "const kp = crypto.generateKeyPairSync('ed25519');", gap="X19", G_EDDSA=None),
    R("c/kx.js", "const k = crypto.generateKeyPairSync('x25519');", gap="X19", G_X25519=None),
    R("c/notes.py", '"""Notes.\nThe payload used to be wrapped with RSA-OAEP.\n"""', gap="X22", G_RSA=L, G_OAEP_PKCS1=L),
    R("c/stack.yaml", "Type: AWS::EC2::Instance", gap="X23", G_EC=L),
    R("c/style.css", ".badge { color: #EC4899; }", gap="X23", G_EC=L),
    R("web/src/Sealer.test.tsx", "const k = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});", gap="X24", G_RSA=L),
    R("app/tests.py", "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", gap="X24", G_RSA=L),
]
# EXPECT: 시험 경로 밖 코드 줄만 센다(주석·문서·시험 경로는 안 센다)
EXPECT_TREE = {
    "e/Kem.java": 'String a = "ML-KEM-768";\nString b = "MLKEM768";\nString c = "ml_kem_768";\nString d = "ML_KEM_768";\n',
    "e/Sig.java": 'String a = "ML-DSA-65";\nString b = "MLDSA65";\nString c = "ml_dsa_65";\nString d = "ML_DSA_65";\n',
    "e/Cm.java": "// ML-KEM-768 ML-DSA-65\n",
    "e/README.md": "ML-KEM-768 and ML-DSA-65\n",
    "src/test/java/e/KemTest.java": 'String a = "ML-KEM-768"; String b = "ML-DSA-65";\n',
}


def alternatives(pattern):
    """정규식의 맨 위 '|' 대안들(괄호·대괄호·역슬래시 안의 '|' 는 가르지 않는다)."""
    out, depth, cls, cur, i = [], 0, False, "", 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            cur += pattern[i:i + 2]
            i += 2
            continue
        if cls:
            cls = c != "]"
        elif c == "[":
            cls = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            out.append(cur)
            cur = ""
            i += 1
            continue
        cur += c
        i += 1
    return out + [cur]


def write_tree(root, files):
    for rel, text in files.items():
        p = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")


def residue(root):
    code, out = prove.run_residue(prove.GENERIC_RESIDUE, root)
    parsed = rules.parse_residue(out)
    if parsed is None:
        raise AssertionError(f"residue.sh gave no SUMMARY (exit {code}):\n{out[-2000:]}")
    return parsed, out


class ResidueRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-rules-")
        root = os.path.join(cls.tmp, "t")
        write_tree(root, {p: t for p, t, _, _ in RESIDUE_CASES})
        # X04: 트리 밖 고전 파일을 가리키는 링크
        outside = os.path.join(cls.tmp, "outside", "One.java")
        write_tree(os.path.join(cls.tmp, "outside"), {"One.java": 'KeyFactory kf = KeyFactory.getInstance("RSA");'})
        os.symlink(outside, os.path.join(root, "c", "One.java"))
        cls.parsed, cls.out = residue(root)
        cls.seen = {}
        for rid, rule in cls.parsed["rules"].items():
            for x in rule["lines"]:
                cls.seen.setdefault((rid, x["path"]), set()).add(x["type"])
        er = os.path.join(cls.tmp, "e")
        write_tree(er, EXPECT_TREE)
        cls.expect, _ = residue(er)
        # X11 과 X21: 보안레벨 5 이름만 있는 파일, 이름에 줄바꿈이 든 고전 파일
        g = os.path.join(cls.tmp, "g")
        write_tree(g, {"L5.java": 'String a = "ML-KEM-1024";\nString b = "ML-DSA-87";\n',
                       "c/a\nb.java": 'KeyFactory kf = KeyFactory.getInstance("RSA");\n'})
        cls.gaps, cls.gaps_out = residue(g)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def status(self, rid, path):
        got = self.seen.get((rid, path), set())
        self.assertLessEqual(len(got), 1, f"{rid} {path}: {got}")
        return next(iter(got), None)

    def test_table(self):
        for path, text, expect, gap in RESIDUE_CASES:
            for rid, want in expect.items():
                with self.subTest(path=path, rule=rid):
                    self.assertIn(rid, self.parsed["rules"], f"residue.sh has no rule {rid}")
                    got = self.status(rid, path)
                    self.assertEqual(got, want, (gap_msg(gap) if gap else f"{path}: {text!r}"))

    def test_link_is_not_followed(self):
        # 링크는 따라가지 않는다(트리 밖을 읽지 않는다). 대신 prove 의 a-input 이 그 링크를 적고 미판정으로 둔다(X04, Bypasses)
        self.assertFalse([k for k in self.seen if k[1] == "c/One.java"])

    def test_known_gap_X11_level5_names_are_not_counted(self):
        self.assertEqual(self.gaps["expect"], {"E-MLKEM768": 0, "E-MLDSA65": 0}, gap_msg("X11"))

    def test_known_gap_X21_newline_in_a_file_name(self):
        self.assertIn("INFO 검사 파일 1개", self.gaps_out, gap_msg("X21"))

    def test_expect_counts_code_lines_outside_test_paths(self):
        self.assertEqual(self.expect["expect"], {"E-MLKEM768": 4, "E-MLDSA65": 4})

    def test_every_rule_and_alternative_has_rows(self):
        rules = rulesrc.residue_rules()
        for r in rules:
            if r["kind"] not in ("GEN", "LWRITE"):
                continue
            rows = [(text, e[r["id"]]) for _, text, e, _ in RESIDUE_CASES if r["id"] in e]
            with self.subTest(rule=r["id"]):
                self.assertTrue(any(s is not None for _, s in rows), f"{r['id']}: no row that it catches")
                self.assertTrue(any(s is None for _, s in rows), f"{r['id']}: no row that it must not catch")
                for alt in alternatives(r["re"]):
                    self.assertTrue(any(s is not None and re.search(alt, t) for t, s in rows),
                                    f"{r['id']}: alternative {alt!r} has no row it catches")
        for r in rules:
            if r["kind"] == "EXPECT":
                for alt in alternatives(r["re"]):
                    self.assertTrue(any(re.search(alt, t) for p, t in EXPECT_TREE.items() if p.startswith("e/K") or p.startswith("e/S")),
                                    f"{r['id']}: alternative {alt!r} has no row")
        self.assertEqual({r["id"] for r in rules if r["kind"] == "EXPECT"}, set(self.expect["expect"]))


# ---------------------------------------------------------------------------------------------
# prove.py 허용 규칙
class AllowRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-allowrules-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def lines(self, name, rows):
        root = os.path.join(self.tmp, name)
        write_tree(root, {"A.java": "\n".join(rows)})
        return rules.Lines(root)

    KX = 'KeyAgreement ka = KeyAgreement.getInstance("X25519");'

    def hybrid(self, name, gap):
        """KX 줄과 ML-KEM 줄 사이가 gap 줄(음수면 ML-KEM 이 위). 사이에는 함수 머리가 아닌 줄만."""
        filler = [f"int a{i} = {i};" for i in range(abs(gap) - 1)]
        rows = [self.KX] + filler + ['String k = "ML-KEM-768";'] if gap > 0 else ['String k = "ML-KEM-768";'] + filler + [self.KX]
        rows = ["int top = 0;"] * 3 + rows + ["int end = 0;"] * 20
        lines = self.lines(name, rows)
        line = rows.index(self.KX) + 1
        return rules.hybrid_ok(lines, "A.java", line, self.KX)

    def test_hybrid_window_is_twelve_lines(self):
        self.assertEqual(rules.HYB_WINDOW, 12)
        self.assertTrue(self.hybrid("h12", 12))
        self.assertFalse(self.hybrid("h13", 13))
        self.assertTrue(self.hybrid("hm12", -12))
        self.assertFalse(self.hybrid("hm13", -13))

    def test_hybrid_window_stops_at_a_function_head_and_skips_comments(self):
        rows = [self.KX, "int a = 1;", "void other() {", 'String k = "ML-KEM-768";']
        self.assertFalse(rules.hybrid_ok(self.lines("hf", rows), "A.java", 1, self.KX))
        rows = [self.KX, "// ML-KEM-768", "int b = 2; // ML-KEM-768"]
        self.assertFalse(rules.hybrid_ok(self.lines("hc", rows), "A.java", 1, self.KX))
        sig = 'Signature s = Signature.getInstance("SHA256withECDSA");'
        self.assertFalse(rules.hybrid_ok(self.lines("hs", [sig, 'String k = "ML-KEM-768";']), "A.java", 1, sig))  # 서명은 결합이 아니다

    def write(self, name, at, op="c.publicEncrypt(k, b);"):
        rows = ['Cipher c = Cipher.getInstance("RSA");'] + [f"int a{i} = {i};" for i in range(at - 1)] + [op] + ["int end = 0;"] * 5
        if at == 0:
            rows = [f'Cipher c = Cipher.getInstance("RSA"); {op}', "int end = 0;"]
        return rules.write_near(self.lines(name, rows), "A.java", 1, rows[0])

    def test_write_path_looks_three_lines_down(self):
        self.assertTrue(self.write("w0", 0))
        self.assertTrue(self.write("w3", 3))
        self.assertFalse(self.write("w4", 4))
        rows = ['Cipher c = Cipher.getInstance("RSA");', "void f() {", "c.publicEncrypt(k, b);"]
        self.assertFalse(rules.write_near(self.lines("wf", rows), "A.java", 1, rows[0]))
        rows = ['Cipher c = Cipher.getInstance("RSA");', "// c.publicEncrypt(k, b);"]
        self.assertFalse(rules.write_near(self.lines("wc", rows), "A.java", 1, rows[0]))

    # 허용 목록 쓰기 경로(ALLOW_WRITEOPS)의 대안마다 걸리는 줄, 그리고 안 걸리는 줄
    WRITES = ["c.init(Cipher.ENCRYPT_MODE, k);", "c.init(Cipher.WRAP_MODE, k);", "s.initSign(k);", "KeyPairGenerator g = null;",
              "g.generateKeyPair();", "key.sign(data, padding.PKCS1v15(), h)", "rsa.SignPKCS1v15(r, k, h, d)", "rsa.SignPSS(r, k, h, d, o)",
              "ecdsa.SignASN1(r, k, d)", "ed25519.Sign(k, m)", "pub.encrypt(m, padding.OAEP(...))", "rsa.EncryptOAEP(h, r, p, m, nil)",
              "rsa.EncryptPKCS1v15(r, p, m)", "rsa.generate_private_key(public_exponent=65537, key_size=2048)",
              "rsa.GenerateKey(rand.Reader, 2048)", "SigningKey.generate()", "crypto.createSign('SHA256')",
              "crypto.publicEncrypt(pub, buf)", "crypto.generateKeyPair('rsa', o, cb)", "crypto.generateKeyPairSync('ec', o)"]
    NOT_WRITES = ["pub.verify(sig, data)", "priv.decrypt(c)", "crypto.privateDecrypt(k, b)", "s.initVerify(k);", "x.generated()",
                  "c.init(Cipher.DECRYPT_MODE, k);", "byte[] signature = s;"]

    def test_write_operations(self):
        for t in self.WRITES:
            with self.subTest(line=t):
                self.assertTrue(rules.ALLOW_WRITEOPS.search(t))
        for t in self.NOT_WRITES:
            with self.subTest(line=t):
                self.assertFalse(rules.ALLOW_WRITEOPS.search(t))
        for alt in alternatives(rules.ALLOW_WRITEOPS.pattern):
            with self.subTest(alternative=alt):
                self.assertTrue(any(re.search(alt, t) for t in self.WRITES), f"no row for {alt!r}")

    def test_same_line_reasons(self):
        legacy_file, legacy_line = rules.LEGACY_REASONS
        rows = [
            ("src/LegacyBox.java", 'KeyFactory.getInstance("RSA");', "RSA", legacy_file),
            ("src/Box.java", 'KeyFactory legacyKf = KeyFactory.getInstance("RSA");', "RSA", legacy_line),
            ("src/Box.java", 'KeyFactory.getInstance("RSA"); // legacy', "RSA", None),  # 주석의 legacy 는 이름 규칙이 아니다(X01)
            ("src/LegacyBox.java", "c.init(Cipher.ENCRYPT_MODE, k);", "RSA", None),
            ("tools/gw.py", "legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)", "RSA", None),
            ("tools/gw.py", "legacy_sig = legacy_key.sign(data, padding.PKCS1v15(), hashes.SHA256())", "RSA", None),
            ("tools/gw.py", "legacy_pub = serialization.load_pem_public_key(blob)", "RSA", legacy_line),
            ("src/Box.java", 'KeyAgreement.getInstance("X25519"); String g = "MLKEM768";', "X25519", "같은 줄 ML-KEM(하이브리드)"),
            ("src/Box.java", 'KeyAgreement.getInstance("X25519"); // ML-KEM-768 later', "X25519", None),  # 주석 속 ML-KEM 은 아니다
            ("src/Box.java", 'Signature.getInstance("SHA256withRSA"); String g = "MLKEM768";', "RSA", None),
            ("src/Box.kt", 'val f = KeyFactory.getInstance("RSA")', "RSA", None),
        ]
        for path, text, alg, want in rows:
            with self.subTest(path=path, text=text):
                self.assertEqual(rules.allow_reason(path, text, alg), want)


class InputPair(unittest.TestCase):
    """a-input: 원본 파일 중 고친 판에도 같은 경로로 있는 몫이 MIN_COMMON(50%) 이상이어야 한다. 경계 위아래를 돌린다."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-input-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def a_input(self, extra):
        orig = os.path.join(self.tmp, f"orig{extra}")
        shutil.copytree(EXAMPLES / "classic", orig)
        write_tree(orig, {f"notes/n{i}.txt": "plain note" for i in range(extra)})
        env = {"EXPECT": "kem,sig", "ALLOW": "none", "RECON": "none"}
        r, _, _ = prove.run(orig, str(EXAMPLES / "pqc"), prove.Params(env), os.path.join(self.tmp, f"out{extra}"), quiet=True)
        return next(c["status"] for c in r["checks"] if c["id"] == "a-input")

    def test_half_of_the_original_files_is_the_boundary(self):
        self.assertEqual(rules.MIN_COMMON, 0.5)
        n = len(rc.tree_files(str(EXAMPLES / "classic")))
        self.assertEqual(self.a_input(n), "pass")             # 공통 n / 원본 2n = 50%
        self.assertEqual(self.a_input(n + 1), "undecided")    # 50% 미만


class KnownGapsOutsideResidue(unittest.TestCase):
    def test_build_folder_under_main_source_stays_in_the_tree(self):
        # X03: 운영 패키지 이름이 build·target 이어도 트리 목록(트리 해시·약화 검사)에 든다. 트리 맨 위와 빌드 파일 옆 build/ 는 뺀다
        tmp = tempfile.mkdtemp(prefix="pqproof-x03-")
        try:
            write_tree(tmp, {"src/main/java/demo/build/Http.java": "class Http {}", "src/main/java/demo/http/Http.java": "class Http {}",
                             "build/out/A.java": "class A {}", "svc/pom.xml": "<project/>", "svc/target/B.java": "class B {}"})
            got = sorted(rel for rel, _, _ in rc.tree_files(tmp))
            self.assertEqual(got, ["src/main/java/demo/build/Http.java", "src/main/java/demo/http/Http.java", "svc/pom.xml"])
            old = sorted(rel for rel, _, _ in rc.tree_files(tmp, rc.LEGACY))  # 증적 형식 1·2 의 걷기(--verify 가 옛 증적에 쓴다)
            self.assertEqual(old, ["src/main/java/demo/http/Http.java", "svc/pom.xml"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만

    def test_weak_pqc_from_cbom_scan_blocks_and_is_never_allowed(self):
        # X07: cbom-scan 이 보안레벨 3 미만 PQC 를 '보안레벨 3 미만(PQC)'로 내면 막는 위치다. 이름 규칙·하이브리드로도 허용하지 않는다
        tmp = tempfile.mkdtemp(prefix="pqproof-x07-")
        try:
            write_tree(tmp, {"web/kem.js": "const legacyKem = crypto.generateKeyPairSync('ml-kem-512');"})
            row = {"위치": "web/kem.js:1", "양자 위협": rules.CBOM_WEAK_PQC, "알고리즘·키 길이": "ml-kem-512", "용도": "키교환",
                   "근거·비고": "`const legacyKem = crypto.generateKeyPairSync('ml-kem-512');`"}
            items, counts, _ = rules.merge_cbom([row], [], rules.Lines(tmp), False)
            self.assertEqual((items[0]["status"], counts["block"]), ("block", 1))
            items, _, _ = rules.merge_cbom([dict(row, **{"근거·비고": "주석 · `// ml-kem-512`"})], [], rules.Lines(tmp), False)
            self.assertEqual(items[0]["status"], "comment")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만

    def test_residue_allow_lines_are_checked_again(self):
        # X01: residue 가 ALLOW 로 둔 줄도 CBOM 과 같은 규칙으로 다시 본다. 주석의 legacy(파이썬 꼬리 주석)와 아래 줄의 쓰기 경로는
        # 이름 규칙 허용이 아니라 남은 줄(relisted)이고, 코드의 legacy 로 읽기만 하는 줄은 이름 규칙 몫(name_rule)이다
        tmp = tempfile.mkdtemp(prefix="pqproof-relist-")
        try:
            write_tree(tmp, {"c/a.py": "pub = load_rsa_key(blob)  # legacy\n",
                             "c/B.java": 'Cipher legacyC = Cipher.getInstance("RSA");\nlegacyC.init(Cipher.ENCRYPT_MODE, k);\n',
                             "c/C.java": 'KeyFactory legacyKf = KeyFactory.getInstance("RSA");\n'})
            parsed, _ = residue(tmp)
            allowed = sorted(f"{x['path']}:{x['line']}" for x in parsed["rules"]["G-RSA"]["lines"] if x["type"] == "ALLOW")
            self.assertEqual(allowed, ["c/B.java:1", "c/C.java:1", "c/a.py:1"])
            got = rules.reclass_residue(parsed, rules.Lines(tmp), None)
            self.assertEqual((got["relisted"], got["name_rule"]), (2, ["c/C.java:1"]))
            j = {"families": parsed["families"], "listed": got}
            self.assertEqual(rules.java_left(j), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만

    def test_korean_word_in_the_note_is_not_a_flag(self):
        tmp = tempfile.mkdtemp(prefix="pqproof-x06-")
        try:
            line = "const kp = crypto.generateKeyPairSync('ed25519'); // 운영·테스트 서버 공통 키 형식"
            write_tree(tmp, {"web/keys.js": line})
            row = {"위치": "web/keys.js:1", "양자 위협": "쇼어로 깨짐", "알고리즘·키 길이": "Ed25519", "용도": "서명"}
            # X06: 비고의 원본 발췌(백틱 안)에 든 '테스트'·'주석'은 표시가 아니다. 표시는 비고 맨 앞에만 온다
            items, _, _ = rules.merge_cbom([dict(row, **{"근거·비고": f"`{line}`"})], [], rules.Lines(tmp), False)
            self.assertEqual(items[0]["status"], "block")
            for flag in ("주석", "테스트·예제", "주석 · 테스트·예제"):
                with self.subTest(flag=flag):
                    items, counts, _ = rules.merge_cbom([dict(row, **{"근거·비고": f"{flag} · `{line}`"})], [], rules.Lines(tmp), False)
                    self.assertEqual(items[0]["status"], "comment")
                    self.assertEqual(counts["tests"], int("테스트" in flag))
            self.assertEqual(rules.cbom_flags("라이브러리 기본값 · 테스트·예제"), set())  # 맨 앞이 아니면 표시가 아니다
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # 이 시험이 만든 자기 폴더만

    def test_known_gap_N1_jdk_hostname_flag_as_a_jvm_option(self):
        a = "FROM x\nENV JAVA_TOOL_OPTIONS=-Djdk.internal.httpclient.disableHostnameVerification=true\n"
        self.assertEqual(verify.weakening({"Dockerfile": ("FROM x\n", a)}), [], gap_msg("N1"))
        a = "FROM x\nRUN java -D jdk.internal.httpclient.disableHostnameVerification=true -jar a.jar\n"
        self.assertEqual(len(verify.weakening({"Dockerfile": ("FROM x\n", a)})), 1)  # 앞이 공백이면 잡는다

    def test_known_gap_X18_tls13_turned_off_in_go(self):
        b = "package a\nvar c = &tls.Config{MinVersion: tls.VersionTLS12}\n"
        a = "package a\nvar c = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}\n"
        self.assertEqual(verify.weakening({"svc/server.go": (b, a)}), [], gap_msg("X18"))


class Bypasses(unittest.TestCase):
    """규칙 묶음 2에서 막은 우회 중 변이 시험(tests/mutations)에 넣기 어려운 것: 심볼릭 링크(X04), 트리 밖 인증서·호스트 키(X05),
    인자 한도(X08). 나머지(X01·X02·X03·X06·X07)는 변이 시험 m12~m16 이 golden 과 함께 본다."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-bypass-")
        cls.outside = os.path.join(cls.tmp, "outside")
        shutil.copytree(EXAMPLES / "classic" / "src" / "main" / "java" / "demo" / "sealer", cls.outside)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def run_pair(self, name, prep=None, fixed=None, **env):
        fx = fixed or os.path.join(self.tmp, name)
        if fixed is None:
            shutil.copytree(EXAMPLES / "pqc", fx, symlinks=True)
            prep(fx)
        e = {"EXPECT": "kem,sig", "ALLOW": "none", "RECON": "none", **env}
        r, code, _ = prove.run(str(EXAMPLES / "classic"), fx, prove.Params(e), os.path.join(self.tmp, "out-" + name), quiet=True)
        return r, code, {c["id"]: c for c in r["checks"]}

    def link_out(self, fx):
        os.symlink(os.path.join(self.outside, "Sealer.java"), os.path.join(fx, "src", "main", "java", "demo", "sealer", "One.java"))

    def test_link_outside_the_tree_is_undecided(self):
        r, code, st = self.run_pair("link-out", self.link_out)
        self.assertEqual((r["verdict"], code, st["a-input"]["status"]), ("undecided", 3, "undecided"))
        self.assertIn("검사 밖을 가리키는 링크 1개", st["a-input"]["actual"])
        self.assertTrue(any(s.startswith("링크 src/main/java/demo/sealer/One.java -> ") and s.endswith("· 트리 밖")
                            for s in r["inputs"]["fixed"]["skipped"]), r["inputs"]["fixed"]["skipped"])
        r, code, st = self.run_pair("link-out-strict", self.link_out, REQUIRE_REVIEW="1")
        self.assertEqual((r["verdict"], code, st["a-input"]["status"]), ("fail", 1, "fail"))

    def test_link_inside_passes_and_an_outside_note_needs_review(self):
        def prep(fx):
            os.symlink("Sealer.java", os.path.join(fx, "src", "main", "java", "demo", "sealer", "Alias.java"))  # 트리 안
            os.symlink(os.path.join(self.outside, "NOTES.md"), os.path.join(fx, "NOTES.md"))  # 트리 밖, 코드 아님(대상은 없어도 된다)
        r, code, st = self.run_pair("link-in", prep)
        self.assertEqual((r["verdict"], code, st["a-input"]["status"]), ("pass", 0, "review"), st["a-input"]["actual"])
        self.assertNotIn("Alias.java", st["a-input"]["actual"])

    def test_zip_link_is_reported_like_a_folder_link(self):
        z = os.path.join(self.tmp, "fixed-link.zip")
        with zipfile.ZipFile(z, "w") as zf:
            for dirpath, _, names in os.walk(EXAMPLES / "pqc"):
                for n in names:
                    full = os.path.join(dirpath, n)
                    zf.write(full, "app/" + os.path.relpath(full, EXAMPLES / "pqc").replace(os.sep, "/"))
            info = zipfile.ZipInfo("app/src/main/java/demo/sealer/One.java")
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "../../../../../../outside/Sealer.java")
        r, code, st = self.run_pair("zip-link", fixed=z)
        self.assertEqual((r["verdict"], code, st["a-input"]["status"]), ("undecided", 3, "undecided"))
        self.assertIn("링크 src/main/java/demo/sealer/One.java -> ../../../../../../outside/Sealer.java · 트리 밖 · zip 에서 풀지 않음",
                      r["inputs"]["fixed"]["skipped"])

    def test_certificate_and_host_key_outside_the_tree_are_not_read(self):
        root = os.path.join(self.tmp, "x05")
        cert = os.path.join(self.tmp, "x05-host", "server.pem")
        os.makedirs(os.path.dirname(cert))
        openssl = prove.default_openssl()
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", cert + ".key", "-out", cert,
                        "-subj", "/CN=x05", "-days", "1"], capture_output=True, check=True)
        write_tree(root, {"nginx/site.conf": f"server {{\n    listen 443 ssl;\n    ssl_certificate {cert};\n}}\n",
                          "ssh/sshd_config": f"HostKey {cert}.key\n"})
        with mock.patch.dict(os.environ, {"HOST_FILES": "1"}):  # prove 는 HOST_FILES 를 cbom-scan 에 넘기지 않는다
            ok, _, rows = prove.run_cbom_scan(prove.CBOM_SCAN, root, os.path.join(self.tmp, "x05-a"), openssl)
        self.assertTrue(ok)
        self.assertFalse([x for x in rows if x["위치"].startswith(cert)], rows)
        ref = [x for x in rows if x["위치"] == "nginx/site.conf:3"]
        self.assertEqual([(x["용도"], x["양자 위협"]) for x in ref if "트리 밖" in x["용도"]], [("인증서(트리 밖 참조)", "미확인")])
        hk = [x for x in rows if x["위치"] == "ssh/sshd_config:1"]
        self.assertTrue(hk and "이름으로 추정" in hk[0]["근거·비고"], hk)
        # 단독 실행에서 HOST_FILES=1 이면 읽는다(그 인증서 행이 생긴다)
        out = os.path.join(self.tmp, "x05-b")
        r = subprocess.run(["bash", str(prove.CBOM_SCAN), root], capture_output=True, text=True,
                           env=dict(os.environ, HOST_FILES="1", OUT=out, OPENSSL=openssl))
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        csv_text = prove.slurp(os.path.join(out, next(n for n in os.listdir(out) if n.endswith(".csv"))))
        self.assertIn(cert, csv_text)

    def test_many_long_paths_stay_under_the_argument_limit(self):
        root = os.path.join(self.tmp, "x08")
        seg = "d" * max(20, min(200, (900 - len(root)) // 4))
        base = os.path.join(root, seg, seg, seg)
        os.makedirs(base)
        each = len(base) + 1 + len("f000000_" + "x" * 30 + ".txt")
        limit = os.sysconf("SC_ARG_MAX") if hasattr(os, "sysconf") else 1 << 21
        n = limit // each + 100
        for i in range(n):
            with open(os.path.join(base, f"f{i:06d}_{'x' * 30}.txt"), "w", encoding="utf-8") as f:
                f.write("plain\n")
        write_tree(root, {"K.java": 'KeyFactory kf = KeyFactory.getInstance("RSA");'})
        self.assertGreater(n * each, limit)
        code, out = prove.run_residue(prove.GENERIC_RESIDUE, root)
        parsed = rules.parse_residue(out)
        self.assertIsNotNone(parsed, out[-800:])
        self.assertIn(f"INFO 검사 파일 {n + 1}개", out)
        self.assertEqual(parsed["families"]["G-RSA"]["code"], 1)


# ---------------------------------------------------------------------------------------------
# pqlite/verify.py: RULES 마다 (경로, 전, 후) 걸리는 수정과 안 걸리는 수정
GO0 = "package a\n"
NG0 = "http { }\n"
PROPS0 = "server.port=8443\n"


def go(body):
    return f"package a\nvar c = &tls.Config{{{body}}}\n"


def ng(body):
    return f"http {{ server {{ {body} }} }}\n"


WEAK = {
    "InsecureSkipVerify": [("a.go", GO0, go("InsecureSkipVerify: true")), ("a.go", GO0, GO0 + "// InsecureSkipVerify: true\n")],
    "VerifyPeerCertificate callback": [("a.go", GO0, go("VerifyPeerCertificate: f")), ("a.go", GO0, GO0 + "var VerifyPeerCertificateX = 1\n")],
    "VerifyConnection callback": [("a.go", GO0, go("VerifyConnection: f")), ("a.go", GO0, GO0 + "var s VerifyConnectionState\n")],
    "client certificates no longer verified": [("a.go", GO0, go("ClientAuth: tls.RequestClientCert")),
                                               ("a.go", GO0, go("ClientAuth: tls.RequireAndVerifyClientCert"))],
    "TLS 1.0/1.1 or SSL 3.0 allowed": [("a.go", GO0, go("MinVersion: tls.VersionTLS11")), ("a.go", GO0, go("MinVersion: tls.VersionTLS12"))],
    "TLS version below 1.2 written as a number": [("a.go", GO0, go("MinVersion: 0x0301")), ("a.go", GO0, go("MinVersion: 0x0303"))],
    "TLS version set to a value the check cannot read (an expression, a variable)": [
        ("a.go", GO0, go("MinVersion: v")), ("a.go", GO0, go("MinVersion: tls.VersionTLS13"))],
    "MinVersion lowered": [("a.go", go("MinVersion: tls.VersionTLS13"), go("MinVersion: tls.VersionTLS12")),
                           ("a.go", go("MinVersion: tls.VersionTLS12"), go("MinVersion: tls.VersionTLS13"))],
    "MinVersion removed": [("a.go", go("MinVersion: tls.VersionTLS12"), go("")),
                           ("a.go", go("MinVersion: tls.VersionTLS12"), go("ServerName: s, MinVersion: tls.VersionTLS12"))],
    "weak cipher suite (3DES, RC4, NULL, EXPORT or RSA key exchange)": [
        ("a.go", GO0, go("CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}")),
        ("a.go", GO0, go("CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}"))],
    "cipher suite the check cannot name (a number or an expression)": [
        ("a.go", GO0, go("CipherSuites: []uint16{0x002f}")), ("a.go", GO0, go("CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}"))],
    "RootCAs removed": [("a.go", go("RootCAs: pool"), go("")), ("a.go", go("RootCAs: pool"), go("RootCAs: pool, ServerName: s"))],
    "ClientCAs removed": [("a.go", go("ClientCAs: pool"), go("")), ("a.go", go("ClientCAs: pool"), go("ClientCAs: pool, ServerName: s"))],
    "trusted CA pool changed": [("a.go", go("RootCAs: pool"), go("RootCAs: other")), ("a.go", go("RootCAs: pool"), go("RootCAs: pool"))],
    "system CA pool added": [("a.go", GO0, GO0 + "var p, _ = x509.SystemCertPool()\n"), ("a.go", GO0, GO0 + "var p = x509.NewCertPool()\n")],
    "RequireAndVerifyClientCert removed": [("a.go", go("ClientAuth: tls.RequireAndVerifyClientCert"), go("")),
                                           ("a.go", go("ClientAuth: tls.RequireAndVerifyClientCert"),
                                            go("ServerName: s, ClientAuth: tls.RequireAndVerifyClientCert"))],
    "go line lowered (older Go defaults include TLS 1.0 servers and RSA key exchange)": [
        ("go.mod", "module a\n\ngo 1.24\n", "module a\n\ngo 1.21\n"), ("go.mod", "module a\n\ngo 1.21\n", "module a\n\ngo 1.24\n")],
    "proxy_ssl_verify off": [("nginx.conf", NG0, ng("grpc_ssl_verify off;")), ("nginx.conf", NG0, ng("proxy_ssl_verify on;"))],
    "proxy_ssl_verify on removed (nginx's default is off)": [("nginx.conf", ng("proxy_ssl_verify on;"), NG0),
                                                             ("nginx.conf", ng("proxy_ssl_verify on;"), ng("proxy_ssl_verify on; listen 443;"))],
    "proxy_ssl_trusted_certificate removed": [("nginx.conf", ng("proxy_ssl_trusted_certificate /etc/ca.pem;"), NG0),
                                              ("nginx.conf", ng("proxy_ssl_trusted_certificate /etc/ca.pem;"),
                                               ng("listen 443; proxy_ssl_trusted_certificate /etc/ca.pem;"))],
    "ssl_trusted_certificate removed": [("nginx.conf", ng("ssl_trusted_certificate /etc/ca.pem;"), NG0),
                                        ("nginx.conf", ng("ssl_trusted_certificate /etc/ca.pem;"), ng("listen 443; ssl_trusted_certificate /etc/ca.pem;"))],
    "trusted CA file changed": [("nginx.conf", ng("ssl_trusted_certificate /etc/a.pem;"), ng("ssl_trusted_certificate /etc/b.pem;")),
                                ("nginx.conf", ng("ssl_trusted_certificate /etc/a.pem;"), ng("ssl_trusted_certificate /etc/a.pem;"))],
    "ssl_verify_client off or optional_no_ca": [("nginx.conf", NG0, ng("ssl_verify_client optional_no_ca;")),
                                                ("nginx.conf", NG0, ng("ssl_verify_client on;"))],
    "ssl_verify_client on removed": [("nginx.conf", ng("ssl_verify_client on;"), ng("ssl_verify_client optional;")),
                                     ("nginx.conf", ng("ssl_verify_client on;"), ng("listen 443; ssl_verify_client on;"))],
    "ssl_client_certificate removed": [("nginx.conf", ng("ssl_client_certificate /etc/ca.pem;"), NG0),
                                       ("nginx.conf", ng("ssl_client_certificate /etc/ca.pem;"), ng("listen 443; ssl_client_certificate /etc/ca.pem;"))],
    "TLS 1.0/1.1 or SSLv3 in a protocol list": [("nginx.conf", NG0, ng("ssl_protocols TLSv1.1 TLSv1.2;")),
                                                ("nginx.conf", NG0, ng("ssl_protocols TLSv1.2 TLSv1.3;"))],
    "TLS 1.0/1.1 or SSLv3 as MinProtocol": [("nginx.conf", NG0, ng("ssl_conf_command MinProtocol TLSv1;")),
                                            ("nginx.conf", NG0, ng("ssl_conf_command MinProtocol TLSv1.2;"))],
    "weak cipher suite (3DES, RC4, NULL, EXPORT, RSA key exchange or security level 0)": [
        ("nginx.conf", NG0, ng("ssl_ciphers HIGH:3DES;")), ("nginx.conf", NG0, ng("ssl_ciphers HIGH:!3DES;"))],
    "system CA bundle referenced": [("Dockerfile", "FROM x\n", "FROM x\nCOPY ca.pem /etc/ssl/certs/\n"),
                                    ("Dockerfile", "FROM x\n", "FROM x\nCOPY key.pem /etc/ssl/private/\n")],
    "GODEBUG brings back legacy TLS (tls10server, tlsrsakex, tls3des, tlsunsafeekm, tlssha1, x509sha1)": [
        ("Dockerfile", "FROM x\n", "FROM x\nENV GODEBUG=tlsrsakex=1\n"), ("Dockerfile", "FROM x\n", "FROM x\nENV GODEBUG=tlsrsakex=0\n")],
    f"godebug default before Go 1.{verify.GODEBUG_DEFAULT_MIN} (legacy TLS defaults)": [
        ("Dockerfile", "FROM x\n", "FROM x\nENV GODEBUG=default=go1.20\n"), ("Dockerfile", "FROM x\n", "FROM x\nENV GODEBUG=default=go1.24\n")],
    "OpenSSL security level 0": [("openssl.cnf", "", "CipherString = DEFAULT@SECLEVEL=0\n"),
                                 ("openssl.cnf", "", "CipherString = DEFAULT@SECLEVEL=2\n")],
    "OpenSSL MinProtocol below TLS 1.2 (openssl.cnf)": [("openssl.cnf", "", "MinProtocol = TLSv1.1\n"),
                                                        ("openssl.cnf", "", "MinProtocol = TLSv1.2\n")],
    "rejectUnauthorized: false": [("a.js", "", "https.request({rejectUnauthorized: false})\n"),
                                  ("a.js", "", "https.request({rejectUnauthorized: true})\n")],
    "NODE_TLS_REJECT_UNAUTHORIZED=0": [("Dockerfile", "FROM x\n", "FROM x\nENV NODE_TLS_REJECT_UNAUTHORIZED=0\n"),
                                       ("Dockerfile", "FROM x\n", "FROM x\nENV NODE_TLS_REJECT_UNAUTHORIZED=1\n")],
    "verify=False": [("a.py", "", "requests.get(u, verify=False)\n"), ("a.py", "", "requests.get(u, verify=True)\n")],
    "check_hostname = False": [("a.py", "", "ctx.check_hostname = False\n"), ("a.py", "", "ctx.check_hostname = True\n")],
    "CERT_NONE": [("a.py", "", "ctx.verify_mode = ssl.CERT_NONE\n"), ("a.py", "", "ctx.verify_mode = ssl.CERT_REQUIRED\n")],
    "unverified SSL context": [("a.py", "", "ctx = ssl._create_unverified_context()\n"), ("a.py", "", "ctx = ssl.create_default_context()\n")],
    "curl --insecure or -k": [("deploy.sh", "", "curl -k https://x\n"), ("deploy.sh", "", "curl -sS https://x\n")],
    "TrustManager that trusts every certificate (X509TrustManager, trustAll)": [
        ("A.java", "class A {}\n", "class A { Object t = new X509TrustManager() {}; }\n"),
        ("A.java", "class A {}\n", 'class A { Object f = TrustManagerFactory.getInstance("PKIX"); }\n')],
    "checkServerTrusted/checkClientTrusted with an empty body": [
        ("A.java", "class A {}\n", "class A { public void checkServerTrusted(X509Certificate[] c, String a) {} }\n"),
        ("A.java", "class A {}\n", "class A { public void checkServerTrusted(X509Certificate[] c, String a) { d.checkServerTrusted(c, a); } }\n")],
    "HostnameVerifier set or replaced (hostname check can be skipped)": [
        ("A.java", "class A {}\n", "class A { void f() { c.setHostnameVerifier(v); } }\n"),
        ("A.java", "class A {}\n", "class A { void f() { c.getHostnameVerifier(); } }\n")],
    "trust strategy that accepts self-signed or every certificate": [
        ("A.java", "class A {}\n", "class A { Object s = new TrustSelfSignedStrategy(); }\n"),
        ("A.java", "class A {}\n", "class A { Object s = new TrustStrategyImpl(); }\n")],
    "endpoint identification turned off": [
        ("A.java", "class A {}\n", "class A { void f() { p.setEndpointIdentificationAlgorithm(null); } }\n"),
        ("A.java", "class A {}\n", 'class A { void f() { p.setEndpointIdentificationAlgorithm("HTTPS"); } }\n')],
    "SSLContext for SSL 3.0 or TLS 1.0/1.1": [
        ("A.java", "class A {}\n", 'class A { Object c = SSLContext.getInstance("TLSv1.1"); }\n'),
        ("A.java", "class A {}\n", 'class A { Object c = SSLContext.getInstance("TLSv1.3"); }\n')],
    "TLS 1.0/1.1 or SSLv3 in setEnabledProtocols/setProtocols": [
        ("A.java", "class A {}\n", 'class A { void f() { s.setEnabledProtocols(new String[]{"TLSv1"}); } }\n'),
        ("A.java", "class A {}\n", 'class A { void f() { s.setEnabledProtocols(new String[]{"TLSv1.2"}); } }\n')],
    "jdk.tls/certpath disabledAlgorithms set or changed (can re-enable weak algorithms)": [
        ("java.security", "jdk.tls.disabledAlgorithms=SSLv3, RC4\n", "jdk.tls.disabledAlgorithms=RC4\n"),
        ("java.security", "jdk.tls.disabledAlgorithms=SSLv3, RC4\n", "jdk.tls.disabledAlgorithms=SSLv3, RC4\n")],
    "JDK HTTP client hostname verification turned off": [
        ("A.java", "class A {}\n", 'class A { static { System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true"); } }\n'),
        ("A.java", "class A {}\n", 'class A { static { System.setProperty("jdk.httpclient.HttpClient.log", "errors"); } }\n')],
    "server.ssl.enabled=false (Spring Boot TLS turned off)": [
        ("application.properties", PROPS0, PROPS0 + "server.ssl.enabled=false\n"),
        ("application.properties", PROPS0, PROPS0 + "server.ssl.enabled=true\n")],
    "TLS 1.0/1.1 or SSLv3 in a Spring or JDK protocol setting": [
        ("application.properties", PROPS0, PROPS0 + "jdk.tls.client.protocols=TLSv1\n"),
        ("application.properties", PROPS0, PROPS0 + "server.ssl.enabled-protocols=TLSv1.2,TLSv1.3\n")],
    "server.ssl.client-auth none or want (client certificate no longer required)": [
        ("application.properties", PROPS0, PROPS0 + "server.ssl.client-auth=want\n"),
        ("application.properties", PROPS0, PROPS0 + "server.ssl.client-auth=need\n")],
    "server.ssl.client-auth=need removed": [
        ("application.properties", PROPS0 + "server.ssl.client-auth=need\n", PROPS0),
        ("application.properties", PROPS0 + "server.ssl.client-auth=need\n", "server.ssl.client-auth=need\n" + PROPS0)],
    "trust store setting removed": [
        ("application.properties", PROPS0 + "server.ssl.trust-store=classpath:t.p12\n", PROPS0),
        ("application.properties", PROPS0 + "server.ssl.trust-store=classpath:t.p12\n", "server.ssl.trust-store=classpath:t.p12\n" + PROPS0)],
    "trust store changed": [
        ("application.properties", PROPS0 + "server.ssl.trust-store=classpath:t.p12\n", PROPS0 + "server.ssl.trust-store=file:/tmp/o.p12\n"),
        ("application.properties", PROPS0 + "server.ssl.trust-store=classpath:t.p12\n", PROPS0 + "server.ssl.trust-store=classpath:t.p12\n")],
}


def fired(path, before, after):
    return {w.split(": ", 1)[1].split(" (before")[0] for w in verify.weakening({path: (before, after)})}


class WeakeningRules(unittest.TestCase):
    def test_every_rule_has_a_row(self):
        self.assertEqual(set(WEAK), {name for name, _, _, _ in verify.RULES})

    def test_table(self):
        for name, (pos, neg) in WEAK.items():
            with self.subTest(rule=name, row="caught"):
                self.assertIn(name, fired(*pos))
            with self.subTest(rule=name, row="not caught"):
                self.assertNotIn(name, fired(*neg))

    def test_comments_count_only_for_approximate_scanners(self):
        # JavaScript·Python 은 'added' 규칙이 주석까지 센다. Go·Java 는 주석을 뺀다
        self.assertIn("rejectUnauthorized: false", fired("a.js", "", "// rejectUnauthorized: false\n"))
        self.assertIn("verify=False", fired("a.py", "", "# verify=False\n"))
        self.assertEqual(fired("a.go", GO0, GO0 + "// InsecureSkipVerify: true\n"), set())
        self.assertEqual(fired("A.java", "class A {}\n", "class A {} // X509TrustManager\n"), set())


# review(): 언어마다 검증 호출 감소·복호 호출 감소·성공만 돌려주는 메서드. (경로, 전, 후, 기대 규칙 또는 None)
VERIFY_RULE, DECRYPT_RULE = (name for name, _ in verify.REVIEW_TOTAL)
STUB_RULE = "verify/isValid/check method that only returns success"
REVIEW_ROWS = [
    ("A.java", "class A { boolean f() { v.initVerify(k); return v.verify(s); } }\n", "class A { boolean f() { return true; } }\n", VERIFY_RULE),
    ("a.go", "package a\nfunc f() error { return ed25519.Verify(p, m, s) }\n", "package a\nfunc f() error { return nil }\n", VERIFY_RULE),
    ("a.js", "function f() { return crypto.verify(null, d, k, s); }\n", "function f() { return true; }\n", VERIFY_RULE),
    ("a.py", "def f():\n    return pub.verify(s, m)\n", "def f():\n    return True\n", VERIFY_RULE),
    ("A.java", "class A { byte[] f() { c.init(Cipher.DECRYPT_MODE, k); return c.doFinal(x); } }\n",
     "class A { byte[] f() { return x; } }\n", DECRYPT_RULE),
    ("a.go", "package a\nfunc f() { k.Decapsulate(c) }\n", "package a\nfunc f() {}\n", DECRYPT_RULE),
    ("a.js", "function f() { return crypto.privateDecrypt(k, b); }\n", "function f() { return b; }\n", DECRYPT_RULE),
    ("a.py", "def f():\n    return k.decrypt(c)\n", "def f():\n    return c\n", DECRYPT_RULE),
    ("A.java", "class A {}\n", "class A { boolean verifySig(byte[] m) { return true; } }\n", STUB_RULE),
    ("a.go", GO0, GO0 + "func verifyToken(t string) bool { return true }\n", STUB_RULE),
    ("a.js", "", "function verifyToken(t) { return true; }\n", STUB_RULE),
    ("a.py", "", "def verify_sig(m, s) -> bool: return True\n", STUB_RULE),
    # 안 걸리는 수정: 검증 호출을 더하거나 그대로 두는 것, 몸통이 실제 검증인 메서드
    ("A.java", "class A {}\n", "class A { boolean verifySig(byte[] m) { return v.verify(m); } }\n", None),
    ("a.py", "def f():\n    return pub.verify(s, m)\n", "def f():\n    x = 1\n    return pub.verify(s, m)\n", None),
]


class ReviewRules(unittest.TestCase):
    def test_table(self):
        for path, before, after, want in REVIEW_ROWS:
            with self.subTest(path=path, want=want):
                got = {x["rule"] for x in verify.review({path: (before, after)})}
                self.assertEqual(got, {want} if want else set())

    def test_every_language_has_a_row(self):
        kinds = {(verify.kind_of(p), w) for p, _, _, w in REVIEW_ROWS if w}
        for name, table in verify.REVIEW_TOTAL:
            self.assertEqual({k for k, w in kinds if w == name}, set(table), name)
        self.assertEqual({k for k, w in kinds if w == STUB_RULE}, set(verify.STUB_VERIFY))


class KnownGapRegistry(unittest.TestCase):
    def test_each_known_gap_has_a_test(self):
        names = {n for cls in (ResidueRules, KnownGapsOutsideResidue) for n in dir(cls) if n.startswith("test_known_gap_")}
        in_table = {gap for _, _, _, gap in RESIDUE_CASES if gap}
        for gid in KNOWN_GAPS:
            with self.subTest(gap=gid):
                self.assertTrue(gid in in_table or any(n.startswith(f"test_known_gap_{gid}_") for n in names), f"{gid} has no test")


if __name__ == "__main__":
    unittest.main()
