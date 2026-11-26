"""CycloneDX 1.6 CBOM 내보내기(0.7.0, pqlite/cdx.py): 이름·primitive·보안 범주 대응, 결정성, 가림, 실행 산출물, 공식 스키마 검증."""
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import cdx  # noqa: E402
from pqlite import receipt as rc  # noqa: E402
from pqlite import version as ver  # noqa: E402

SCHEMA_FILES = ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")


def it(alg, use="", threat="", status="info", loc="src/a.py:1", tool="cbom-scan", reason="", note=""):
    return {"alg": alg, "use": use, "threat": threat, "status": status, "loc": loc, "tool": tool, "reason": reason, "note": note, "source": tool}


META = {"mode": "pair", "tree": "fixed", "tree_sha256": "0" * 64, "tool_version": "0.0.0", "ruleset_version": "7",
        "ruleset_sha256": "1" * 64, "scope": "all"}


def comp(doc, name, asset=None):
    """이름이 같은 컴포넌트 하나. 같은 이름이 알고리즘과 키처럼 assetType 이 다르면 asset 으로 고른다."""
    got = [c for c in doc["components"] if c["name"] == name
           and (asset is None or c.get("cryptoProperties", {}).get("assetType") == asset)]
    assert len(got) == 1, (name, [c["name"] for c in doc["components"]])
    return got[0]


def alg_props(c):
    return c["cryptoProperties"]["algorithmProperties"]


ALL_KINDS = [
    it("ML-KEM-768", "키교환", "안전(PQC)"), it("ML-KEM-512", "키교환", "보안레벨 3 미만(PQC)", "block", "src/w.py:3"),
    it("ML-DSA-44", "signature", "weak-pqc", "block", "W.java:9", "scan.py"), it("ML-DSA-65", "서명", "안전(PQC)", loc="S.java:4"),
    it("SLH-DSA-SHA2-192s", "서명", "안전(PQC)"), it("X25519MLKEM768", "키교환", "안전(PQC 하이브리드)"),
    it("x25519mlkem768", "키교환", "안전(PQC 하이브리드)", loc="nginx.conf:12"), it("SMAUG-T3", "키교환", "안전(PQC)"),
    it("NTRU+KEM768", "키교환", "안전(PQC)"), it("HAETAE3", "서명", "안전(PQC)"), it("AIMer128f", "서명", "안전(PQC)"),
    it("RSA-3072", "서명", "쇼어로 깨짐", "block"), it("RSA", "서명·암호화", "쇼어로 깨짐", "allow", reason="허용 목록 #1"),
    it("EC secp256r1", "키교환", "쇼어로 깨짐", loc="a.go:1"), it("EC SECP256R1", "키교환", "쇼어로 깨짐", loc="a.go:2"),
    it("EC-256 prime256v1", "개인키(파일)", "쇼어로 깨짐", loc="keys/k.pem"), it("", "미확인", "미확인"),
    it("ML-KEM,ML-DSA", "", "안전(PQC)"), it("cryptography 48", "라이브러리", "간접(라이브러리)", loc="requirements.txt:2"),
    it("RSA-2048 / 서명 sha256WithRSAEncryption", "인증서", "쇼어로 깨짐", loc="certs/s.crt"),
    it("TLSv1.2", "프로토콜", "고전 취약(양자 무관)", loc="nginx.conf:3"),
    it("X25519MLKEM768", "키교환(TLS 협상)", "안전(PQC 하이브리드)", loc="host.example:443"),
    it("RSA-2048", "서명", "쇼어로 깨짐", "comment", "gen/test/ks.p12", note="password=hunter2hunter2"),
]


class Mapping(unittest.TestCase):
    def setUp(self):
        self.doc = cdx.build(ALL_KINDS, META)

    def test_fips_levels_and_oids(self):
        c = comp(self.doc, "ML-KEM-768")
        self.assertEqual((alg_props(c)["primitive"], alg_props(c)["parameterSetIdentifier"], alg_props(c)["nistQuantumSecurityLevel"],
                          c["cryptoProperties"]["oid"]), ("kem", "768", 3, "2.16.840.1.101.3.4.4.2"))
        self.assertEqual(alg_props(comp(self.doc, "ML-KEM-512"))["nistQuantumSecurityLevel"], 1)
        self.assertEqual(alg_props(comp(self.doc, "ML-DSA-44"))["nistQuantumSecurityLevel"], 2)  # FIPS 204: category 2, not 1
        self.assertEqual(comp(self.doc, "ML-DSA-65")["cryptoProperties"]["oid"], "2.16.840.1.101.3.4.3.18")
        self.assertEqual(alg_props(comp(self.doc, "SLH-DSA-SHA2-192s"))["nistQuantumSecurityLevel"], 3)

    def test_the_verdict_is_copied_not_made(self):
        w = comp(self.doc, "ML-KEM-512")
        self.assertIn({"name": "pqproof:threat", "value": "보안레벨 3 미만(PQC)"}, w["properties"])
        self.assertIn({"name": "pqproof:status", "value": "block"}, w["properties"])
        self.assertIn("status=block", w["evidence"]["occurrences"][0]["additionalContext"])

    def test_hybrid_group_is_one_combiner(self):
        c = [x for x in self.doc["components"] if x["name"] == "X25519MLKEM768"]
        self.assertEqual(len(c), 1)
        self.assertEqual(alg_props(c[0]), {"primitive": "combiner"})
        self.assertNotIn("oid", c[0]["cryptoProperties"])
        self.assertEqual(len(c[0]["evidence"]["occurrences"]), 3)

    def test_kpqc_names_stay_as_written(self):
        for name, prim in (("SMAUG-T3", "kem"), ("NTRU+KEM768", "kem"), ("HAETAE3", "signature"), ("AIMer128f", "signature")):
            with self.subTest(name=name):
                p = alg_props(comp(self.doc, name))
                self.assertEqual(p, {"primitive": prim})

    def test_classical(self):
        r = alg_props(comp(self.doc, "RSA-3072"))
        self.assertEqual((r["primitive"], r["parameterSetIdentifier"], r["nistQuantumSecurityLevel"]), ("signature", "3072", 0))
        self.assertEqual(alg_props(comp(self.doc, "RSA"))["primitive"], "unknown")  # 서명·암호화 is ambiguous
        ec = comp(self.doc, "EC-secp256r1", "algorithm")
        self.assertEqual((alg_props(ec)["curve"], len(ec["evidence"]["occurrences"])), ("secp256r1", 2))
        self.assertEqual(sum(1 for p in ec["properties"] if p["name"] == "pqproof:alg_raw"), 2)
        for name in ("KCDSA", "EC-KCDSA", "ECKCDSA"):  # 규칙 묶음 9: 용도 칸이 비어도 서명으로 분류
            self.assertEqual(cdx.classify(name, "")[1], {"primitive": "signature"}, name)

    def test_unknown_and_lists_stay_raw(self):
        self.assertEqual(alg_props(comp(self.doc, "unknown")), {"primitive": "unknown"})
        self.assertEqual(alg_props(comp(self.doc, "ML-KEM,ML-DSA")), {"primitive": "unknown"})

    def test_asset_types(self):
        self.assertEqual(comp(self.doc, "cryptography 48")["type"], "library")
        self.assertNotIn("cryptoProperties", comp(self.doc, "cryptography 48"))
        self.assertEqual(comp(self.doc, "RSA-2048 / 서명 sha256WithRSAEncryption")["cryptoProperties"]["assetType"], "certificate")
        key = comp(self.doc, "EC-secp256r1", "related-crypto-material")  # same name as the algorithm, separate asset
        self.assertEqual(key["cryptoProperties"]["relatedCryptoMaterialProperties"], {"type": "private-key"})
        self.assertEqual(comp(self.doc, "TLSv1.2")["cryptoProperties"]["assetType"], "protocol")

    def test_locations(self):
        occ = {o["location"]: o for c in self.doc["components"] for o in c["evidence"]["occurrences"]}
        self.assertEqual(occ["src/a.py"]["line"], 1)
        self.assertNotIn("line", occ["gen/test/ks.p12"])
        self.assertNotIn("line", occ["host.example:443"])  # a TLS target is host:port, not file:line

    def test_one_occurrence_per_row(self):
        self.assertEqual(sum(len(c["evidence"]["occurrences"]) for c in self.doc["components"]), len(ALL_KINDS))

    def test_deterministic_and_order_free(self):
        a = json.dumps(cdx.build(ALL_KINDS, META), sort_keys=True, ensure_ascii=False)
        b = json.dumps(cdx.build(list(reversed(ALL_KINDS)), META), sort_keys=True, ensure_ascii=False)
        self.assertEqual(a, b)
        self.assertRegex(self.doc["serialNumber"], r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        self.assertNotIn("timestamp", self.doc["metadata"])

    def test_refs_and_property_names(self):
        refs = [c["bom-ref"] for c in self.doc["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertFalse(any(r.startswith("urn:cdx:") for r in refs))
        names = {p["name"] for c in self.doc["components"] for p in c.get("properties", [])} | {p["name"] for p in self.doc["metadata"]["properties"]}
        self.assertTrue(all(re.fullmatch(r"(cdx|pqproof)(:[a-z0-9_-]+)+", n) for n in names), names)

    def test_prove_masks_the_note(self):
        tmp = tempfile.mkdtemp(prefix="pqproof-cdx-")
        self.addCleanup(shutil.rmtree, tmp, True)
        art = rc.Artifacts(tmp)
        prove.write_cdx(art, "tables/x.cdx.json", ALL_KINDS, META)
        text = pathlib.Path(tmp, "tables", "x.cdx.json").read_text(encoding="utf-8")
        self.assertNotIn("hunter2hunter2", text)
        self.assertIn(prove.MASK, text)


@unittest.skipUnless(shutil.which("bash") and prove.default_openssl(), "bash 또는 openssl 없음")
class Run(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-cdx-run-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_inventory_writes_the_same_bytes_twice(self):
        outs = []
        for n in ("a", "b"):
            out = os.path.join(self.tmp, "inv-" + n)
            summary, _ = prove.inventory(str(PROOF / "examples" / "pqc"), prove.Params({}), out, quiet=True)
            outs.append(pathlib.Path(out, "tables", "cbom.cdx.json").read_bytes())
            self.assertIn("tables/cbom.cdx.json", [a["path"] for a in summary["artifacts"]])
            doc = json.loads(outs[-1])
            self.assertEqual(sum(len(c["evidence"]["occurrences"]) for c in doc["components"]), summary["cbom"]["rows"])
        self.assertEqual(outs[0], outs[1])

    def test_pair_lists_both_files_and_verifies(self):
        out = os.path.join(self.tmp, "pair")
        r, _, _ = prove.run(str(PROOF / "examples" / "classic"), str(PROOF / "examples" / "pqc"), prove.Params({"RECON": "none"}), out, {}, quiet=True)
        paths = [a["path"] for a in r["artifacts"]]
        self.assertIn("tables/cbom-orig.cdx.json", paths)
        self.assertIn("tables/cbom-fixed.cdx.json", paths)
        self.assertEqual([w for ok, w in rc.verify(out) if not ok], [])
        self.assertEqual(r["ruleset_version"], ver.ruleset_history()[0])  # no rule file changed for the export


def _schema_dir():
    d = os.environ.get("CDX_SCHEMA_DIR")
    return d if d and all(os.path.isfile(os.path.join(d, f)) for f in SCHEMA_FILES) else None


class Schema(unittest.TestCase):
    """CycloneDX 1.6.2 공식 스키마(CDX_SCHEMA_DIR 에 세 파일, CI 가 SHA-256 을 맞춰 받는다)와 jsonschema 로 검증한다. 네트워크는 쓰지 않는다."""

    def setUp(self):
        try:
            from jsonschema import Draft7Validator  # noqa: F401
            from referencing import Registry, Resource  # noqa: F401
        except ImportError:
            self.skipTest("jsonschema 없음(CI 는 설치한다)")
        if not _schema_dir():
            self.skipTest("CDX_SCHEMA_DIR 에 CycloneDX 1.6 스키마 세 파일 없음(CI 는 받는다)")

    def validator(self):
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7
        d = _schema_dir()
        schemas = [json.loads(pathlib.Path(d, f).read_text(encoding="utf-8")) for f in SCHEMA_FILES]
        reg = Registry().with_resources([(s["$id"], Resource.from_contents(s, default_specification=DRAFT7)) for s in schemas])
        return Draft7Validator(schemas[0], registry=reg)

    def errors(self, doc):
        return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in self.validator().iter_errors(doc)]

    def test_every_kind_fits(self):
        self.assertEqual(self.errors(cdx.build(ALL_KINDS, META)), [])

    def test_a_real_run_fits(self):
        out = os.path.join(tempfile.mkdtemp(prefix="pqproof-cdx-schema-"), "inv")
        self.addCleanup(shutil.rmtree, os.path.dirname(out), True)
        prove.inventory(str(PROOF / "examples" / "classic"), prove.Params({}), out, quiet=True)
        self.assertEqual(self.errors(json.loads(pathlib.Path(out, "tables", "cbom.cdx.json").read_text(encoding="utf-8"))), [])

    def test_the_schema_is_applied(self):
        doc = cdx.build(ALL_KINDS, META)
        alg_props(comp(doc, "ML-KEM-768"))["nistQuantumSecurityLevel"] = 7
        self.assertTrue(self.errors(doc))


if __name__ == "__main__":
    unittest.main()
