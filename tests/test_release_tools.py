"""릴리스 도구(교차 리뷰 X63·X65): SBOM 보강 스크립트가 파일 해시·tls_probe·바깥 실행 의존을 더하고, 빌드 도구가 해시로 고정돼 있으며,
릴리스가 CI 전체를 부르는지 본다. .github/ 가 없는 설치본에서는 건너뛴다."""
import hashlib
import importlib.util
import json
import pathlib
import re
import tempfile
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
GH = PROOF / ".github"


@unittest.skipUnless((GH / "scripts" / "sbom_extend.py").is_file(), ".github/ 없음(설치본)")
class Release(unittest.TestCase):
    def test_sbom_extend_adds_hashes_probe_and_external_programs(self):
        spec = importlib.util.spec_from_file_location("sbom_extend", GH / "scripts" / "sbom_extend.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as d:
            dist, probe = pathlib.Path(d, "dist"), pathlib.Path(d, "bin")
            dist.mkdir()
            probe.mkdir()
            whl = dist / "pqproof-9.9.9-py3-none-any.whl"
            whl.write_bytes(b"wheel bytes")
            (dist / "pqproof-9.9.9.tar.gz").write_bytes(b"sdist bytes")
            (probe / "SHA256SUMS").write_text("ab" * 32 + "  tls_probe-linux-amd64\n" + "cd" * 32 + "  tls_probe-darwin-arm64\n")
            (probe / "BUILDINFO").write_text("go: go version go1.27.4 linux/amd64\nflags: -trimpath\nsource: 11  go.mod\n")
            bom = {"specVersion": "1.6", "components": [{"bom-ref": "pqproof==9.9.9", "name": "pqproof", "version": "9.9.9"}],
                   "dependencies": [{"ref": "pqproof==9.9.9"}]}
            out = mod.extend(bom, str(dist), str(probe), "0.4.0")
        me = next(c for c in out["components"] if c["name"] == "pqproof")
        self.assertEqual(me["hashes"], [{"alg": "SHA-256", "content": hashlib.sha256(b"wheel bytes").hexdigest()}])
        names = {c["name"]: c for c in out["components"]}
        self.assertEqual(names["tls_probe-linux-amd64"]["hashes"][0]["content"], "ab" * 32)
        self.assertIn({"name": "pqproof:go", "value": "go version go1.27.4 linux/amd64"}, names["tls_probe-linux-amd64"]["properties"])
        self.assertEqual((names["bash"]["scope"], names["openssl"]["scope"], names["keytool"]["scope"], names["security"]["scope"]),
                         ("required", "required", "optional", "optional"))
        dep = next(x for x in out["dependencies"] if x["ref"] == "pqproof==9.9.9")
        self.assertEqual(len(dep["dependsOn"]), 6)
        json.dumps(out)

    def test_build_and_lint_tools_are_hash_pinned(self):
        for name in ("build", "sbom", "lint"):
            with self.subTest(name):
                text = (GH / "requirements" / f"{name}.txt").read_text(encoding="utf-8")
                pins = re.findall(r"(?m)^([A-Za-z0-9_.-]+)==", text)
                self.assertTrue(pins)
                blocks = re.split(r"(?m)^(?=[A-Za-z0-9_.-]+==)", text)
                for block in blocks:
                    if re.match(r"[A-Za-z0-9_.-]+==", block):
                        self.assertIn("--hash=sha256:", block, block.splitlines()[0])
        release = (GH / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("--require-hashes -r .github/requirements/build.txt", release)
        self.assertIn("-m build --no-isolation", release)
        self.assertIn("--require-hashes -r .github/requirements/sbom.txt", release)

    def test_hand_kept_locks_stay_out_of_dependabot(self):
        dep = (GH / "dependabot.yml").read_text(encoding="utf-8")
        for name in ("schema.in", "schema.txt", "pq-verify.in", "pq-verify.txt"):
            self.assertTrue(f'- "{name}"' in dep, f"dependabot.yml exclude-paths 에 {name} 이 있어야 한다(손으로 관리하는 잠금)")
        schema = (GH / "requirements" / "schema.txt").read_text(encoding="utf-8")
        for marker in ("python_full_version < '3.10'", "python_full_version >= '3.10'"):
            self.assertRegex(schema, rf"(?m)^jsonschema==\S+ ; {re.escape(marker)}", "schema.txt 는 3.9 와 3.10+ 를 함께 고정한 --universal 잠금이어야 한다")

    def test_release_reuses_the_whole_ci(self):
        release = (GH / "workflows" / "release.yml").read_text(encoding="utf-8")
        ci = (GH / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("uses: ./.github/workflows/ci.yml", release)
        self.assertIn("workflow_call:", ci)
        self.assertIn("merge-base --is-ancestor", release)
        self.assertIn("--ignore-missing", release)
        self.assertRegex(release, r"subject-path: \|[\s\S]*assets/BUILDINFO")


if __name__ == "__main__":
    unittest.main()
