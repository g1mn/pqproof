"""구현 검증(pqproof impl, KpqC KAT 대조): NIST KAT DRBG 재현, 참조판 목록 읽기와 깨진 목록, 문제지 결정성, 답안 판정(최신판 통과,
옛 판 검토 필요와 판 이름, 한 바이트 실패, 변조 서명을 받아들이면 실패, 문항 누락·prompt_sha256 불일치 미판정, 판을 가르지 못하는 답안),
.rsp 대조(100건 통과와 'n/100', 건수 부족, HAETAE siglen·sig 와 AIMer sm = msg || sig 정규화), 별칭, 64 MiB 상한, 자기 점검,
그리고 prove.impl_judge 가 쓴 증적을 --verify 가 다시 판정하는지(사본을 바꾸면 실패)."""
import copy
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
import prove  # noqa: E402
from pqlite import impl  # noqa: E402
from pqlite import receipt as rc  # noqa: E402

MANIFEST = impl.load_manifest()
LATEST = {pid: next(V["version"] for V in P["versions"] if V["latest"]) for pid, P in MANIFEST["params"].items()}
ACCEPT_ALL = impl.resolve_accept(MANIFEST["params"], ["latest"], MANIFEST["order"])


def key_for(*pids):
    return impl.build_key(MANIFEST, pids)


def as_parsed(resp):
    """답안 dict 를 파일로 썼다가 읽은 것처럼(parse_input 을 거친다)."""
    return impl.parse_input(impl.dumps(resp).encode("utf-8"))


def judge(key, resp, accept=None):
    return impl.match_versions(key, as_parsed(resp), accept or ACCEPT_ALL)


def excerpt(pid, version):
    return next(V for V in MANIFEST["params"][pid]["versions"] if V["version"] == version)["excerpt"]


def rsp_text(header, records):
    out = [f"# {header}", ""] if header else []
    for rec in records:
        out += [f"{k} = {v}" for k, v in rec.items()] + [""]
    return "\n".join(out)


class Drbg(unittest.TestCase):
    def test_aes256_fips197_c3(self):
        rk = impl._aes256_round_keys(bytes(range(32)))
        self.assertEqual(impl._aes256_encrypt(rk, bytes.fromhex("00112233445566778899aabbccddeeff")).hex(),
                         "8ea2b7ca516745bfeafc49904b496089")

    def test_kat_request_seed(self):
        # PQCgenKAT .req: randombytes_init(0x00..0x2F) 뒤 count 0 의 seed 는 48바이트 한 번
        d = impl.NistDrbg(bytes(range(48)))
        self.assertEqual(d.take(48).hex().upper(), excerpt("smaug-t/mode1", "1.2.0")[0]["seed"])

    def test_haetae_context_matches_the_reference_library(self):
        # 참조 라이브러리(HAETAE 1.1.2 mode2)로 KAT 를 다시 돌려 뽑은 ctx(ctxlen 20, 201)
        rec = excerpt("haetae/mode2", "1.1.2")
        self.assertEqual(impl.haetae_context(rec[0]["seed"]), "311759FDC7DBD54C8A0C9D3F32B7E9ECA11A7F71")
        ctx2 = impl.haetae_context(rec[2]["seed"])
        self.assertEqual((len(ctx2) // 2, ctx2[:16], ctx2[-8:]), (201, "DFA32BC976E5023C", "E02CBB99"))
        self.assertEqual(impl.hashlib.sha256(ctx2.encode()).hexdigest(), "cc1694194dae8c774c3f3b0013af2601c4f751d98972e94d5772d016ee99f865")
        self.assertEqual(impl.haetae_context(excerpt("haetae/mode5", "1.2.0")[2]["seed"]), ctx2)  # seed 가 같으면 ctx 도 같다
        self.assertEqual(impl.context_of("aimer", rec[0]["seed"]), "")

    def test_call_boundaries_matter(self):
        a, b = impl.NistDrbg(bytes(48)), impl.NistDrbg(bytes(48))
        self.assertNotEqual(a.take(32), b.take(16) + b.take(16))  # 부를 때마다 Update 를 한다(rng.c 와 같다)


class Manifest(unittest.TestCase):
    def test_loads_and_counts(self):
        self.assertEqual(len(MANIFEST["params"]), 16)
        versions = [V for P in MANIFEST["params"].values() for V in P["versions"]]
        self.assertEqual((len(versions), sum(1 for V in versions if V["excerpt"])), (35, 29))
        for P in MANIFEST["params"].values():
            self.assertEqual(sum(1 for V in P["versions"] if V["latest"]), 1)
        self.assertEqual(LATEST["smaug-t/mode3"], "1.2.0")
        self.assertEqual(LATEST["aimer/128f"], "3.0")

    def test_aliases(self):
        names = MANIFEST["names"]
        for alias, pid in (("SMAUG-T3", "smaug-t/mode3"), ("smaugt_mode3", "smaug-t/mode3"), ("TiMER", "smaug-t/modet"),
                           ("haetae3", "haetae/mode3"), ("HAETAE-5", "haetae/mode5"), ("NTRU+KEM864", "ntruplus/864"),
                           ("AIMer128f", "aimer/128f"), ("aimer-192s", "aimer/192s"), ("samsungsds_aimer_256f_ref", "aimer/256f")):
            with self.subTest(alias=alias):
                self.assertEqual(names[alias.lower()], pid)
        self.assertEqual(prove.impl_names(MANIFEST, ["AIMer128f", "smaugt_mode1", "aimer-128f"]), ["smaug-t/mode1", "aimer/128f"])
        with self.assertRaises(prove.UsageError):
            prove.impl_names(MANIFEST, ["kyber768"])


class BrokenManifest(unittest.TestCase):
    """목록이나 발췌가 깨졌으면 ManifestError(rules.load_profiles 처럼)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-kat-")
        shutil.copytree(PROOF / "scan" / "kat", os.path.join(cls.tmp, "scan", "kat"))
        cls.doc = json.loads((PROOF / "scan" / "kat-kpqc.json").read_text(encoding="utf-8"))
        cls.path = os.path.join(cls.tmp, "scan", "kat-kpqc.json")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def load(self, change):
        doc = copy.deepcopy(self.doc)
        change(doc)
        pathlib.Path(self.path).write_text(json.dumps(doc), encoding="utf-8")
        return impl.load_manifest(self.path)

    def variant(self, doc, pid="smaug-t/mode3", i=0):
        return doc["algorithms"][pid.split("/")[0]]["params"][pid]["variants"][i]

    def test_copy_loads(self):
        self.assertEqual(len(self.load(lambda d: None)["params"]), 16)

    def test_breakages(self):
        def digest(d):
            self.variant(d)["record_digests"][7] = "0" * 64

        def two_latest(d):
            self.variant(d, i=1)["latest"] = True

        def alias(d):
            d["algorithms"]["haetae"]["params"]["haetae/mode3"]["aliases"].append("SMAUG-T3")

        def missing_excerpt(d):
            self.variant(d)["excerpt"] = "scan/kat/smaug-t/mode3/9.9.9.json"

        def outside(d):
            self.variant(d)["excerpt"] = "scan/kat/../kat-kpqc.json"

        def source(d):
            self.variant(d)["source"] = "nowhere"

        def fields(d):
            d["algorithms"]["aimer"]["fields"] = ["count", "seed", "pk"]
        for name, change, want in (("record digest", digest, "digest"), ("two latest", two_latest, "latest"),
                                   ("alias on two params", alias, "SMAUG-T3"), ("missing excerpt", missing_excerpt, "9.9.9.json"),
                                   ("excerpt outside scan/kat", outside, "scan/kat/"), ("unknown source", source, "nowhere"),
                                   ("unknown field layout", fields, "fields")):
            with self.subTest(name):
                with self.assertRaises(impl.ManifestError) as cm:
                    self.load(change)
                self.assertIn(want, str(cm.exception))

    def test_changed_excerpt_record(self):
        src = os.path.join(self.tmp, "scan", "kat", "smaug-t", "mode3", "1.2.0.json")
        bad = os.path.join(self.tmp, "scan", "kat", "smaug-t", "mode3", "bad.json")
        ex = json.loads(pathlib.Path(src).read_text(encoding="utf-8"))
        ex["records"][1]["ss"] = impl._flip_hex(ex["records"][1]["ss"])
        pathlib.Path(bad).write_text(json.dumps(ex), encoding="utf-8")
        with self.assertRaises(impl.ManifestError) as cm:
            self.load(lambda d: self.variant(d).update(excerpt="scan/kat/smaug-t/mode3/bad.json"))
        self.assertIn("record_digest", str(cm.exception))

    def test_broken_key_copy(self):
        key = json.loads(json.dumps(key_for("haetae/mode2")))
        self.assertEqual(impl.check_key(key), [])
        key["params"][0]["versions"][0]["excerpt"][0]["sig"] = impl._flip_hex(key["params"][0]["versions"][0]["excerpt"][0]["sig"])
        self.assertIn("record_digest", impl.check_key(key)[0])
        self.assertTrue(impl.check_key({"format": "x", "params": []}))


class Prompt(unittest.TestCase):
    def test_deterministic_and_hashed(self):
        key = key_for("smaug-t/mode3", "haetae/mode3", "aimer/128f")
        a, b = impl.emit_prompt(key), impl.emit_prompt(json.loads(json.dumps(key)))
        self.assertEqual(impl.dumps(a), impl.dumps(b))
        body = {k: a[k] for k in ("format", "params", "sizes", "items")}
        self.assertEqual(a["prompt_sha256"], impl._digest(body))
        with mock.patch.object(impl, "PROMPT_ABOUT", "other words"):
            self.assertEqual(impl.emit_prompt(key)["prompt_sha256"], a["prompt_sha256"])  # 설명 글은 해시에 안 든다
        self.assertEqual(a["params"], ["smaug-t/mode3", "haetae/mode3", "aimer/128f"])

    def test_items(self):
        p = impl.emit_prompt(key_for("smaug-t/mode3", "haetae/mode3", "aimer/128f"))
        by = {}
        for it in p["items"]:
            by.setdefault(it["param"], []).append(it)
        self.assertEqual({k: len(v) for k, v in by.items()}, {"smaug-t/mode3": 20, "haetae/mode3": 30, "aimer/128f": 30})
        dec = next(it for it in by["smaug-t/mode3"] if it["id"] == "smaug-t/mode3@1.2.0#0:decaps")
        rec = excerpt("smaug-t/mode3", "1.2.0")[0]
        self.assertEqual((dec["sk"], dec["ct"], dec["answer"]), (rec["sk"], rec["ct"], ["ss"]))
        self.assertNotIn("ss", dec)  # 기대값은 문제지에 없다
        good = next(it for it in by["haetae/mode3"] if it["id"] == "haetae/mode3@1.2.0#0:verify")
        bad = next(it for it in by["haetae/mode3"] if it["id"] == "haetae/mode3@1.2.0#0:verify-tampered")
        self.assertEqual(good["sig"], excerpt("haetae/mode3", "1.2.0")[0]["sig"])
        self.assertEqual((good["sig"][2:], good["sig"][:2] != bad["sig"][:2]), (bad["sig"][2:], True))
        self.assertTrue(good["ctx"])
        aim = next(it for it in by["aimer/128f"] if it["id"] == "aimer/128f@3.0#1:verify")
        arec = excerpt("aimer/128f", "3.0")[1]
        self.assertEqual((aim["ctx"], aim["msg"] + aim["sig"]), ("", arec["sm"]))  # AIMer sm = msg || sig
        drv = next(it for it in by["aimer/128f"] if it["op"] == "derand")
        self.assertEqual((drv["answer"], drv["optional"]), ([], ["pk", "sk", "sig", "sm"]))
        self.assertEqual(p["sizes"]["aimer/128f"], {"pk": 32, "sk": 48, "sig": 6944})
        self.assertEqual(p["sizes"]["smaug-t/mode3"], {"pk": 1088, "sk": 1312, "ct": 992, "ss": 32})


class Judge(unittest.TestCase):
    def test_latest_passes(self):
        key = key_for("smaug-t/mode3", "ntruplus/768", "haetae/mode3", "aimer/128f")
        res = judge(key, impl.example_answers(key, {pid: LATEST[pid] for pid in key_params(key)}))
        self.assertEqual([(r["status"], r["matched"]) for r in res], [("pass", [LATEST[r["param"]]]) for r in res])
        self.assertEqual(res[0]["summary"], "1.2.0 일치(문항 10/10)")
        row = impl.check_row(res)
        self.assertEqual((row["id"], row["status"]), ("i-kpqc", "pass"))

    def test_old_version_needs_review_with_its_name(self):
        for pid, old in (("haetae/mode3", "1.1.2"), ("smaug-t/mode1", "1.1.1"), ("aimer/192s", "aim2-2026-01")):
            with self.subTest(pid):
                key = key_for(pid)
                (r,) = judge(key, impl.example_answers(key, {pid: old}))
                self.assertEqual((r["status"], r["matched"]), ("review", [old]))
                self.assertIn(f"옛 판 {old} 일치", r["summary"])
        key = key_for("haetae/mode3")
        acc = impl.resolve_accept(MANIFEST["params"], ["latest", "haetae@1.1.2"], ["haetae/mode3"])
        (r,) = judge(key, impl.example_answers(key, {"haetae/mode3": "1.1.2"}), acc)
        self.assertEqual(r["status"], "pass")  # 프로필이 받아 주면 통과

    def test_one_byte_fails(self):
        key = key_for("smaug-t/mode3")
        resp = impl.example_answers(key, {"smaug-t/mode3": "1.2.0"})
        iid = "smaug-t/mode3@1.2.0#2:decaps"
        resp["answers"][iid]["ss"] = impl._flip_hex(resp["answers"][iid]["ss"])
        (r,) = judge(key, resp)
        self.assertEqual((r["status"], r["matched"]), ("fail", []))
        self.assertIn(f"첫 불일치 1.2.0: {iid} ss", r["summary"])
        self.assertIn("맞는 판 없음(1.2.0 문항 9/10, 1.1.1 문항 0/10)", r["summary"])

    def test_accepting_a_changed_signature_fails(self):
        key = key_for("aimer/128f")
        resp = impl.example_answers(key, {"aimer/128f": "3.0"})
        resp["answers"]["aimer/128f@3.0#4:verify-tampered"]["ok"] = True
        (r,) = judge(key, resp)
        self.assertEqual(r["status"], "fail")
        self.assertIn("변조 서명을 받아들임: aimer/128f@3.0#4:verify-tampered", r["summary"])

    def test_missing_item_is_undecided(self):
        key = key_for("ntruplus/864")
        resp = impl.example_answers(key, {"ntruplus/864": "2026-01"})
        del resp["answers"]["ntruplus/864@2026-01#3:decaps"]
        (r,) = judge(key, resp)
        self.assertEqual(r["status"], "undecided")
        self.assertIn("답 없는 문항 1개: ntruplus/864@2026-01#3:decaps", r["summary"])
        resp = impl.example_answers(key, {"ntruplus/864": "2026-01"})
        del resp["answers"]["ntruplus/864@2026-01#3:derand"]  # 선택 문항은 빠져도 된다
        self.assertEqual(judge(key, resp)[0]["status"], "pass")

    def test_wrong_fields_are_undecided(self):
        key = key_for("ntruplus/864")
        resp = impl.example_answers(key, {"ntruplus/864": "2026-01"})
        resp["answers"]["ntruplus/864@2026-01#0:decaps"]["ok"] = True
        self.assertIn("문항과 맞지 않는 답", judge(key, resp)[0]["summary"])

    def test_prompt_sha_mismatch_is_undecided(self):
        key = key_for("smaug-t/mode5", "haetae/mode2")
        resp = impl.example_answers(key, {"smaug-t/mode5": "1.2.0", "haetae/mode2": "1.2.0"})
        resp["prompt_sha256"] = "0" * 64
        res = judge(key, resp)
        self.assertEqual([r["status"] for r in res], ["undecided", "undecided"])
        self.assertIn("prompt_sha256", res[0]["summary"])
        resp = impl.example_answers(key, {"smaug-t/mode5": "1.2.0", "haetae/mode2": "1.2.0"})
        resp["answers"]["smaug-t/mode5@9.9#0:decaps"] = {"ss": "00"}
        self.assertIn("문제지에 없는 문항", judge(key, resp)[0]["summary"])

    def test_answers_that_cannot_tell_versions_apart(self):
        # HAETAE 1.2.0 은 서명 과정만 바꿨다: verify 만 답하면 두 판 모두와 맞는다. 통과가 아니라 검토 필요로 판을 가르지 못함을 적는다
        key = key_for("haetae/mode3")
        resp = impl.example_answers(key, {"haetae/mode3": "1.2.0"})
        resp["answers"] = {k: ({"ok": True} if k.endswith(":verify") else v) for k, v in resp["answers"].items() if not k.endswith(":derand")}
        (r,) = judge(key, resp)
        self.assertEqual((r["status"], r["matched"]), ("review", ["1.2.0", "1.1.2"]))
        self.assertIn("판을 가를 수 없다", r["summary"])

    def test_combine_and_check_row(self):
        self.assertEqual(impl.combine([]), "undecided")
        self.assertEqual(impl.combine(["pass", "review"]), "review")
        self.assertEqual(impl.combine(["review", "undecided", "pass"]), "undecided")
        self.assertEqual(impl.combine(["undecided", "fail"]), "fail")
        self.assertEqual(impl.check_row([{"param": "x", "status": "pass", "summary": "s"}], control="bad")["status"], "undecided")
        self.assertIn("자기 점검 실패: bad", impl.check_row([], control="bad")["actual"])

    def test_accept_spec(self):
        acc = impl.resolve_accept(MANIFEST["params"], ["latest", "aimer@aim2-2026-01", "haetae/mode3@1.1.2"],
                                  ["aimer/128f", "haetae/mode3", "haetae/mode5"])
        self.assertEqual(acc, {"aimer/128f": ["3.0", "aim2-2026-01"], "haetae/mode3": ["1.2.0", "1.1.2"], "haetae/mode5": ["1.2.0"]})
        for bad in (["latest", "haetae@9.9"], [], "latest"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    impl.resolve_accept(MANIFEST["params"], bad, ["haetae/mode3"])
        self.assertEqual(impl.accept_from_list(impl.accept_list(acc)), acc)


def key_params(key):
    return [P["id"] for P in key["params"]]


def synthetic_kem(n=100):
    """record_digests 가 100건 다 있는 가짜 KEM 파라미터(.rsp 전체 대조 시험용)."""
    recs = []
    for i in range(n):
        h = lambda tag, size, i=i: (impl.hashlib.sha256(f"{tag}{i}".encode()).hexdigest().upper() * 4)[:2 * size]  # noqa: E731
        recs.append({"count": str(i), "seed": h("seed", 48), "pk": h("pk", 8), "sk": h("sk", 8), "ct": h("ct", 8), "ss": h("ss", 4)})
    other = [dict(r, ss=impl._flip_hex(r["ss"])) for r in recs]
    vers = []
    for name, rs, latest in (("2.0", recs, True), ("1.0", other, False)):
        rd = [impl.record_digest(r) for r in rs]
        vers.append({"version": name, "latest": latest, "role": "reference", "source": "s", "rsp_sha256": "0" * 64,
                     "digest": impl.rsp_digest(rd), "records": len(rd), "record_digests": rd,
                     "sizes": {"pk": 8, "sk": 8, "ct": 8, "ss": 4}, "excerpt": rs[:5]})
    P = {"id": "toy-kem/one", "alg": "toy-kem", "name": "TOY", "kind": "kem", "fields": impl.KEM_FIELDS, "aliases": ["toy1"],
         "versions": vers}
    impl._check_param(P, "test")
    return P, recs, other


class Rsp(unittest.TestCase):
    def test_full_file_passes_with_count(self):
        P, recs, other = synthetic_kem()
        key = {"format": impl.KEY_FORMAT, "params": [P]}
        acc = {"toy-kem/one": ["2.0"]}
        (r,) = impl.match_versions(key, impl.parse_input(rsp_text("toy1", recs).encode()), acc)
        self.assertEqual((r["status"], r["summary"]), ("pass", "2.0 일치(100/100)"))
        self.assertEqual([v["records"] for v in r["versions"]], ["100/100", "0/100"])
        (r,) = impl.match_versions(key, impl.parse_input(rsp_text("toy1", other).encode()), acc)
        self.assertEqual((r["status"], r["matched"]), ("review", ["1.0"]))
        broken = [dict(x) for x in recs]
        broken[37]["ct"] = impl._flip_hex(broken[37]["ct"])
        (r,) = impl.match_versions(key, impl.parse_input(rsp_text("toy1", broken).encode()), acc)
        self.assertEqual(r["status"], "fail")
        self.assertIn("2.0 99/100", r["summary"])
        self.assertIn("count 37", r["summary"])
        (r,) = impl.match_versions(key, impl.parse_input(rsp_text("toy1", recs[:60]).encode()), acc)
        self.assertEqual(r["status"], "undecided")
        self.assertIn("레코드 60건뿐(100건 필요)", r["summary"])
        self.assertEqual(impl.control_problem(key, acc, "rsp"), None)

    def test_excerpt_only_and_field_diagnosis(self):
        key = key_for("smaug-t/mode3")
        (r,) = impl.match_versions(key, impl.parse_input(rsp_text("smaugt_mode3", excerpt("smaug-t/mode3", "1.2.0")).encode()), ACCEPT_ALL)
        self.assertEqual(r["status"], "undecided")
        self.assertIn("레코드 5건뿐(100건 필요). 있는 5건은 1.2.0 와 일치", r["summary"])
        recs = [dict(x) for x in excerpt("smaug-t/mode3", "1.2.0")]
        recs[0]["ct"] = impl._flip_hex(recs[0]["ct"])
        (r,) = impl.match_versions(key, impl.parse_input(rsp_text("smaugt_mode3", recs).encode()), ACCEPT_ALL)
        self.assertEqual(r["status"], "fail")
        self.assertIn("첫 불일치 1.2.0: count 0 ct", r["summary"])

    def test_haetae_and_aimer_layouts(self):
        hae = MANIFEST["params"]["haetae/mode2"]
        rec = excerpt("haetae/mode2", "1.2.0")[0]
        parsed = impl.parse_rsp(rsp_text("haetae_mode2", [rec]))
        self.assertEqual(list(parsed[0]), ["count", "seed", "mlen", "msg", "pk", "sk", "siglen", "sig"])
        self.assertEqual(int(parsed[0]["siglen"]) * 2, len(parsed[0]["sig"]))
        nist = {k: v for k, v in rec.items() if k not in ("siglen", "sig")}
        nist["smlen"], nist["sm"] = str(int(rec["siglen"]) + int(rec["mlen"])), rec["sig"] + rec["msg"]  # 참조 crypto_sign: sig || msg
        self.assertEqual(impl.record_digest(impl.canonical_record(hae, nist)), impl.record_digest(rec))
        aim = MANIFEST["params"]["aimer/128s"]
        arec = excerpt("aimer/128s", "3.0")[0]
        self.assertEqual(arec["sm"][:2 * int(arec["mlen"])], arec["msg"])  # sm = msg || sig
        split = {k: v for k, v in arec.items() if k not in ("smlen", "sm")}
        split["sig"] = impl.signature_of(arec)
        split["siglen"] = str(len(split["sig"]) // 2)
        self.assertEqual(impl.record_digest(impl.canonical_record(aim, split)), impl.record_digest(arec))
        self.assertEqual(impl.signed_message_of(rec), rec["sig"] + rec["msg"])

    def test_bom_and_haetae_message_first(self):
        recs = excerpt("smaug-t/mode3", "1.2.0")
        bom = impl.parse_input(b"\xef\xbb\xbf" + rsp_text("smaugt_mode3", recs).encode())
        self.assertEqual((bom["problem"], bom["header"], len(bom["records"])), (None, "smaugt_mode3", len(recs)))
        hae = MANIFEST["params"]["haetae/mode2"]
        rec = excerpt("haetae/mode2", "1.2.0")[0]
        swapped = {k: v for k, v in rec.items() if k not in ("siglen", "sig")}
        swapped["smlen"], swapped["sm"] = str(int(rec["siglen"]) + int(rec["mlen"])), rec["msg"] + rec["sig"]  # AIMer 처럼 msg || sig
        self.assertEqual(impl.record_digest(impl.canonical_record(hae, swapped)), impl.record_digest(rec))
        wrong_len = dict(swapped, smlen=str(int(swapped["smlen"]) + 1))  # 길이 칸이 틀리면 바꾸지 않는다
        self.assertIn("sm", impl.canonical_record(hae, wrong_len))

    def test_header_and_param(self):
        names = MANIFEST["names"]
        rsp = impl.parse_input(rsp_text("SMAUG-T3", excerpt("smaug-t/mode3", "1.2.0")[:1]).encode())
        self.assertEqual(rsp["header"], "SMAUG-T3")
        self.assertEqual(impl.input_params(rsp, names), (["smaug-t/mode3"], None))
        self.assertEqual(impl.input_params(rsp, names, "smaug-t/mode3"), (["smaug-t/mode3"], None))
        self.assertIn("smaug-t/mode3 의 이름이다", impl.input_params(rsp, names, "smaug-t/mode5")[1])  # 다른 파라미터의 알려진 이름
        own = impl.parse_input(rsp_text("my own library build", excerpt("smaug-t/mode3", "1.2.0")[:1]).encode())
        self.assertEqual(impl.input_params(own, names, "smaug-t/mode3"), (["smaug-t/mode3"], None))  # 모르는 이름이면 --param 을 따른다
        self.assertEqual(own["header"], "my own library build")
        none = impl.parse_input(rsp_text(None, excerpt("smaug-t/mode3", "1.2.0")[:1]).encode())
        self.assertIn("머리 줄이 없다", impl.input_params(none, names)[1])
        odd = impl.parse_input(rsp_text("kyber768", excerpt("smaug-t/mode3", "1.2.0")[:1]).encode())
        self.assertIn("아는 이름이 아니다", impl.input_params(odd, names)[1])
        resp = impl.parse_input(impl.dumps(dict(impl.example_answers(key_for("aimer/256s"), {}), params=["aimer256s"])).encode())
        self.assertIn("정식 이름", impl.input_params(resp, names)[1])


class InputLimits(unittest.TestCase):
    def test_hostile_numbers_depth_and_text(self):
        # 맥 기본 python 3.9 의 int() 는 긴 숫자에 자릿수 제곱 시간이 걸린다: .rsp 와 답안 JSON 모두 읽기 전에 자릿수로 막는다
        rsp = impl.parse_input(("# smaugt_mode1\ncount = " + "9" * 400000 + "\n").encode())
        self.assertIn("상한 18자리", rsp["problem"])
        self.assertEqual(impl.parse_rsp("count = 000000000000000000000000000033\n")[0]["count"], "33")  # 앞의 0 은 자릿수에 넣지 않는다
        big = impl.parse_input(b'{"format": "pqproof impl response 1", "answers": ' + b"1" * 400000 + b"}")
        self.assertIn("상한 40자", big["problem"])
        deep = impl.parse_input(b'{"format": "pqproof impl response 1", "answers": ' + b"[" * 200000 + b"]" * 200000 + b"}")
        self.assertIn("깊게", deep["problem"])
        with self.assertRaises(ValueError):
            rc.loads_strict(b"[" * 200000 + b"]" * 200000)
        # 남이 준 글(문항 id·칸·파라미터 이름)은 제어 문자를 적어 바꾸고 잘라서 판정 글에 넣는다
        key = key_for("smaug-t/mode1")
        good = impl.example_answers(key, {"smaug-t/mode1": "1.2.0"})
        nasty = "\x1b[31m|x\n" + "A" * 3000
        bad_id = dict(good, answers=dict(good["answers"], **{nasty: {"ss": "00"}}))
        got = judge(key, bad_id)[0]
        self.assertEqual(got["status"], "undecided")
        self.assertNotIn("\x1b", got["summary"])
        self.assertIn("\\x1b", got["summary"])
        self.assertLess(len(got["summary"]), 300)
        for doc, want in ((dict(good, params=[nasty]), "모르는 파라미터"), (dict(good, answers={"x": {nasty: "00"}}), "모르는 칸"),
                          (dict(good, implementation="lib\x1b[2J"), "인쇄할 수 없는")):
            with self.subTest(want=want):
                parsed = as_parsed(doc)
                why = parsed["problem"] or impl.input_params(parsed, MANIFEST["names"])[1]
                self.assertIn(want, why)
                self.assertNotIn("\x1b", why)
        self.assertEqual(impl.shown("a\x1bb\n", 80), "a\\x1bb\\n")

    def test_size_limit_and_bad_json(self):
        with mock.patch.object(impl, "MAX_INPUT", 100):
            got = impl.parse_input(b"{" + b" " * 120 + b"}")
        self.assertIn("상한", got["problem"])
        for data, want in ((b'{"format": "pqproof impl response 1", "format": 1}', "두 번"), (b"{nope", "JSON"),
                           (b'{"format": "pqproof impl response 1", "extra": 1}', "모르는 칸"),
                           ("count = 0\nseed = ZZ\n".encode(), "16진수"), (b"\xff\xfe", "ASCII"), (b"\xef\xbb\xbf{}", "BOM")):
            with self.subTest(want=want):
                self.assertIn(want, impl.parse_input(data)["problem"])


class Control(unittest.TestCase):
    def test_control_passes_on_the_real_list(self):
        key = key_for(*MANIFEST["order"])
        self.assertIsNone(impl.control_problem(key, ACCEPT_ALL, "response"))
        self.assertIsNone(impl.control_problem(key, ACCEPT_ALL, "rsp"))

    def test_control_catches_a_blind_judge(self):
        key = key_for("smaug-t/mode1")
        with mock.patch.object(impl, "_decide", lambda P, c, a, rows, unit: impl._result(P, "pass", "늘 통과", rows, ["1.2.0"])):
            self.assertIn("한 바이트 바꾼 답안이 실패하지 않았다", impl.control_problem(key, ACCEPT_ALL, "response"))
        self.assertIn("받아 줄 판", impl.control_problem(key, {"smaug-t/mode1": []}, "response"))


class Evidence(unittest.TestCase):
    """prove.impl_judge 가 쓴 증적: --verify 가 답안 사본을 다시 판정하고, 사본·결과를 바꾸면 실패한다."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqproof-impl-")
        key = key_for("smaug-t/modet", "haetae/mode2")
        cls.answer = os.path.join(cls.tmp, "answers.json")
        pathlib.Path(cls.answer).write_text(impl.dumps(impl.example_answers(key, {"smaug-t/modet": "1.2.0", "haetae/mode2": "1.1.2"})),
                                            encoding="utf-8")
        cls.out = os.path.join(cls.tmp, "out")
        cls.r, cls.code, cls.lines = prove.impl_judge(cls.answer, [], prove.Params({}, mode="impl"), cls.out, quiet=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)  # setUpClass 가 만든 자기 폴더만

    def fails(self, d):
        return "\n".join(w for ok, w in rc.verify(d) if not ok)

    def copy(self, name):
        d = os.path.join(self.tmp, name)
        shutil.copytree(self.out, d)
        return d

    def test_receipt(self):
        r = self.r
        self.assertEqual((r["verdict"], self.code, r["checks"][0]["status"]), ("pass", 0, "review"))
        self.assertEqual((r["format_version"], r["params"]["mode"], r["params"]["profile"]), (4, "impl", "kpqc"))
        self.assertEqual([x["status"] for x in r["impl"]["results"]], ["pass", "review"])
        self.assertEqual(r["impl"]["accept"], ["smaug-t/modet@1.2.0", "haetae/mode2@1.2.0"])
        self.assertTrue(r["impl"]["control"]["ok"])
        self.assertEqual(self.fails(self.out), "")
        self.assertEqual(rc.validate(r, rc.SCHEMA_IMPL), [])
        self.assertTrue(rc.validate(dict(r, cbom={}), rc.SCHEMA_IMPL))
        self.assertIn("통과(검토 필요 검사 i-kpqc)", rc.verdict_text(r))
        self.assertTrue(any("VERDICT=PASS (needs review: i-kpqc)" in x for x in self.lines))
        page = pathlib.Path(self.out, "receipt.html").read_text(encoding="utf-8")
        self.assertIn("KpqC 구현 KAT 대조", page)
        self.assertIn("옛 판 1.1.2 일치", page)
        deck = json.loads(pathlib.Path(self.out, "deck.json").read_text(encoding="utf-8"))
        self.assertEqual((deck["mode"], [x["status"] for x in deck["impl"]]), ("impl", ["pass", "review"]))

    def test_sarif(self):
        sys.path.insert(0, str(PROOF / "src"))
        from pqproof import sarif
        doc = sarif.convert(self.out)
        run = doc["runs"][0]
        self.assertIn("i-kpqc", {r["id"] for r in run["tool"]["driver"]["rules"]})
        self.assertTrue(any(n["descriptor"]["id"] == "i-kpqc" for n in run["invocations"][0]["toolExecutionNotifications"]))

    def test_changed_answer_copy_is_caught(self):
        d = self.copy("answer")
        p = os.path.join(d, "artifacts", "impl", "answer.json")
        doc = json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
        iid = "smaug-t/modet@1.2.0#1:decaps"
        doc["answers"][iid]["ss"] = impl._flip_hex(doc["answers"][iid]["ss"])
        rehash(d, "artifacts/impl/answer.json", impl.dumps(doc))
        got = self.fails(d)
        self.assertIn("judged again gives i-kpqc fail", got)

    def test_changed_result_is_caught(self):
        d = self.copy("result")

        def change(r):
            r["impl"]["results"][1]["status"] = "pass"
            r["checks"][0]["status"] = "pass"
        rewrite(d, change)
        got = self.fails(d)
        self.assertIn("does not fit matched versions", got)

    def test_changed_key_is_caught(self):
        d = self.copy("key")
        p = os.path.join(d, "artifacts", "impl", "key.json")
        key = json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
        key["params"][0]["versions"][0]["record_digests"][50] = "0" * 64
        rehash(d, "artifacts/impl/key.json", impl.dumps(key))
        self.assertIn("answer key is not consistent", self.fails(d))

    def test_broken_kat_list_is_not_a_pass(self):
        with mock.patch.object(impl, "load_manifest", side_effect=impl.ManifestError("gone")):
            self.assertIn("KAT list cannot be read", self.fails(self.out))

    def test_recorded_other_kat_list_uses_the_copy(self):
        real = impl.load_manifest()
        with mock.patch.object(impl, "load_manifest", return_value=dict(real, sha256="f" * 64)):
            res = rc.verify(self.out)
        self.assertEqual([w for ok, w in res if not ok], [])
        self.assertTrue(any("judged again with the copy" in w for ok, w in res))
        d = self.copy("other-kat-forged")  # 기록된 목록이라도 사본의 판 기록이 이 도구의 목록과 다르면 믿지 않는다
        p = os.path.join(d, "artifacts", "impl", "key.json")
        key = json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
        V = key["params"][0]["versions"][0]
        V["excerpt"][0]["ss"] = impl._flip_hex(V["excerpt"][0]["ss"])
        V["record_digests"][0] = impl.record_digest(V["excerpt"][0])
        V["digest"] = impl.rsp_digest(V["record_digests"])
        self.assertEqual(impl.check_key(key), [])
        rehash(d, "artifacts/impl/key.json", impl.dumps(key))
        with mock.patch.object(impl, "load_manifest", return_value=dict(real, sha256="f" * 64)):
            self.assertIn("disagrees with this tool's KAT list", self.fails(d))

    def test_other_rules_are_judged_again(self):
        v = rc._version_module()
        real = v.path_sha256
        with mock.patch.object(v, "path_sha256", lambda p: "0" * 64 if str(p).endswith("impl.py") else real(p)):
            res = rc.verify(self.out)
        self.assertEqual([w for ok, w in res if not ok], [])
        self.assertTrue(any("judged again with this tool's rules gives the same statuses" in w for ok, w in res))

    def _failing_copy(self, name):
        """한 바이트 바꾼 답안으로 실패 증적을 만든다(위조 시험의 바탕)."""
        key = key_for("smaug-t/mode1")
        good = impl.example_answers(key, {"smaug-t/mode1": "1.2.0"})
        iid = "smaug-t/mode1@1.2.0#0:decaps"
        bad = copy.deepcopy(good)
        bad["answers"][iid]["ss"] = impl._flip_hex(bad["answers"][iid]["ss"])
        ans = os.path.join(self.tmp, name + ".json")
        pathlib.Path(ans).write_text(impl.dumps(bad), encoding="utf-8")
        out = os.path.join(self.tmp, name)
        r, code, _ = prove.impl_judge(ans, [], prove.Params({}, mode="impl"), out, quiet=True)
        self.assertEqual((r["verdict"], code, self.fails(out)), ("fail", 1, ""))
        goodres = impl.match_versions(key, as_parsed(good), {"smaug-t/mode1": ["1.2.0"]})
        return out, key, bad, iid, goodres

    @staticmethod
    def _passify(r, results):
        r["verdict"] = "pass"
        r["impl"]["results"] = results
        r["checks"][0] = impl.check_row(results, None, None)

    def test_forged_pass_with_another_rules_hash_is_caught(self):
        # 리뷰 T3: 결과를 통과로 고치고 tools[] 의 impl.py 해시를 바꿔 규칙 묶음을 '3+modified' 로 적어도 다시 판정해 잡는다
        out, _, _, _, goodres = self._failing_copy("t3")
        v = rc._version_module()

        def change(r):
            self._passify(r, goodres)
            for t in r["tools"]:
                if t["name"] == "pqlite/impl.py":
                    t["sha256"] = "ab" * 32
            r["ruleset_version"] = "3+modified"
            r["ruleset_sha256"] = v.ruleset_from_tools(r["tools"], "3+modified")
        rewrite(out, change)
        self.assertIn("differs from the receipt", self.fails(out))

    def test_forged_key_with_unrecorded_kat_list_is_caught(self):
        # 리뷰 T4: 틀린 답에 맞게 정답 묶음을 고치고 KAT 목록 해시를 바꿔도 사본을 믿지 않는다
        out, _, bad, iid, _ = self._failing_copy("t4")
        p = os.path.join(out, "artifacts", "impl", "key.json")
        key = json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
        V = key["params"][0]["versions"][0]
        V["excerpt"][0]["ss"] = bad["answers"][iid]["ss"]
        V["record_digests"][0] = impl.record_digest(V["excerpt"][0])
        V["digest"] = impl.rsp_digest(V["record_digests"])
        rehash(out, "artifacts/impl/key.json", impl.dumps(key))
        v = rc._version_module()

        def change(r):
            r["impl"]["kat_manifest_sha256"] = "cd" * 32
            for t in r["tools"]:
                if t["name"] == "kat-kpqc":
                    t["sha256"] = "cd" * 32
            r["ruleset_version"] = "3+modified"
            r["ruleset_sha256"] = v.ruleset_from_tools(r["tools"], "3+modified")
        rewrite(out, change)
        self.assertIn("neither this tool's nor one recorded", self.fails(out))

    def test_forged_accept_list_is_caught(self):
        # 받아 줄 판을 옛 판까지 넓히고 프로필 해시를 바꿔도 이 도구의 프로필 내용과 맞춘다
        d = self.copy("accept")
        v = rc._version_module()

        def change(r):
            r["impl"]["accept"] = r["impl"]["accept"] + ["haetae/mode2@1.1.2"]
            for t in r["tools"]:
                if t["name"] == "profiles":
                    t["sha256"] = "ef" * 32
            r["ruleset_version"] = "3+modified"
            r["ruleset_sha256"] = v.ruleset_from_tools(r["tools"], "3+modified")
        rewrite(d, change)
        self.assertIn("of this tool gives", self.fails(d))

    def test_format_three_cannot_hold_impl(self):
        d = self.copy("fv3")
        rewrite(d, lambda r: r.update(format_version=3))
        self.assertIn("format_version: below 4", self.fails(d))  # 스키마가 먼저 막는다
        self.assertIn("params.mode impl is a field of format 4", "\n".join(rc.version_problems(dict(self.r, format_version=3))))


class Commands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pqproof-implcmd-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)  # setUp 이 만든 자기 폴더만

    def test_usage(self):
        for argv in (["--impl"], ["--impl", "judge"], ["--impl", "prompt", "x"], ["--impl", "judge", "a", "b"],
                     ["--impl", "prompt", "--param", "kyber768"], ["--impl", "judge", "a.json", "-o", "x"]):
            with self.subTest(argv=argv):
                self.assertEqual(prove.main(argv), 2)

    def test_prompt_file_and_rsp_judge(self):
        p = os.path.join(self.tmp, "prompt.json")
        prompt, code = prove.impl_prompt(["smaugt_mode3"], p, quiet=True)
        self.assertEqual((code, json.loads(pathlib.Path(p).read_text(encoding="utf-8"))["prompt_sha256"]), (0, prompt["prompt_sha256"]))
        with self.assertRaises(prove.UsageError):
            prove.impl_prompt(["smaugt_mode3"], p, quiet=True)  # 덮어쓰지 않는다
        rsp = os.path.join(self.tmp, "kat.rsp")
        pathlib.Path(rsp).write_text(rsp_text("smaugt_mode3", excerpt("smaug-t/mode3", "1.2.0")), encoding="ascii")
        out = os.path.join(self.tmp, "out")
        r, code, _ = prove.impl_judge(rsp, [], prove.Params({}, mode="impl"), out, quiet=True)
        self.assertEqual((r["verdict"], code, r["params"]["input"], r["impl"]["prompt"]), ("undecided", 3, "rsp", None))
        self.assertEqual(r["impl"]["input"]["header"], "smaugt_mode3")
        self.assertEqual("\n".join(w for ok, w in rc.verify(out) if not ok), "")

    def test_oversize_answer(self):
        big = os.path.join(self.tmp, "big.json")
        pathlib.Path(big).write_text("{" + " " * 300 + "}", encoding="utf-8")
        out = os.path.join(self.tmp, "big-out")
        with mock.patch.object(impl, "MAX_INPUT", 200):
            r, code, _ = prove.impl_judge(big, [], prove.Params({}, mode="impl"), out, quiet=True)
            bad = [w for ok, w in rc.verify(out) if not ok]
            r2, _, _ = prove.impl_judge(big, ["TiMER"], prove.Params({}, mode="impl"), out + "-param", quiet=True)
            bad2 = [w for ok, w in rc.verify(out + "-param") if not ok]
        self.assertEqual((r["verdict"], code, r["impl"]["input"]["file"], r["impl"]["results"]), ("undecided", 3, None, []))
        self.assertIn("상한", r["impl"]["problem"])
        self.assertEqual((bad, bad2, r2["params"]["params"]), ([], [], ["smaug-t/modet"]))

    def test_profile_without_accept_is_a_usage_error(self):
        a = os.path.join(self.tmp, "a.json")
        pathlib.Path(a).write_text("{}", encoding="utf-8")
        with self.assertRaises(prove.UsageError):
            prove.impl_judge(a, [], prove.Params({"PROFILE": "nist-cat3"}, mode="impl"), os.path.join(self.tmp, "o"), quiet=True)


def rewrite(d, change):
    p = pathlib.Path(d, "receipt.json")
    r = json.loads(p.read_text(encoding="utf-8"))
    change(r)
    r["receipt_id"] = rc.compute_id(r)
    p.write_text(rc.dumps(r), encoding="utf-8")


def rehash(d, rel, text):
    """산출물 하나를 바꾸고 receipt.json 의 해시·receipt_id 를 다시 써서 해시 검사는 통과하게 만든다(위조 흉내)."""
    data = text.encode("utf-8")
    pathlib.Path(d, *rel.split("/")).write_bytes(data)
    sha = impl.hashlib.sha256(data).hexdigest()

    def change(r):
        for a in r["artifacts"]:
            if a["path"] == rel:
                a["sha256"], a["bytes"] = sha, len(data)
        for part in (r["impl"]["input"], r["impl"]["key"], r["impl"]["prompt"] or {}):
            if part.get("file") == rel:
                part["file_sha256"] = sha
    rewrite(d, change)


if __name__ == "__main__":
    unittest.main()
