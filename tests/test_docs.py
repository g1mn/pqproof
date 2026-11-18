"""문서 링크(교차 리뷰 X51·X69·X70): 저장소 안 마크다운의 상대 링크와 github.com/g1mn/pqproof/blob/main/ 링크가 있는 파일·제목을
가리키는지, SARIF helpUri 의 앵커가 사이트에 있는지, 도구가 출력에 찍는 문서 주소가 있는 파일인지 본다. 문서가 없는 설치본에서는 건너뛴다."""
import pathlib
import re
import sys
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
sys.path.insert(0, str(PROOF / "src"))
DOCS = [PROOF / n for n in ("README.md", "DESIGN.md", "HISTORY.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md")]
DOCS += sorted((PROOF / "guide").glob("*.md")) + sorted((PROOF / "examples").rglob("README.md"))
BLOB = "https://github.com/g1mn/pqproof/blob/main/"


def anchors(md):
    """GitHub 식 제목 앵커: 소문자, 글자·숫자·공백·하이픈만 남기고 공백은 하이픈."""
    out = set()
    for line in md.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^#{1,6}\s+(.*)$", line)
        if m:
            t = re.sub(r"[^\w\- ]", "", m.group(1).strip().lower().replace("`", ""))
            out.add(t.replace(" ", "-"))
    return out


@unittest.skipUnless((PROOF / "guide").is_dir() and (PROOF / "README.md").is_file(), "문서 없음(설치본)")
class Links(unittest.TestCase):
    def test_links_point_to_files_and_headings(self):
        bad = []
        for doc in DOCS:
            text = doc.read_text(encoding="utf-8")
            for url in re.findall(r"\]\(([^)\s]+)\)", text):
                if url.startswith(BLOB):
                    target = url[len(BLOB):]
                    base = PROOF
                elif re.match(r"[a-z]+:", url):
                    continue
                else:
                    target, base = url, doc.parent
                path, _, frag = target.partition("#")
                full = (base / path).resolve() if path else doc
                if not full.exists():
                    bad.append(f"{doc.name}: {url} (no such file)")
                elif frag and full.suffix == ".md" and frag not in anchors(full):
                    bad.append(f"{doc.name}: {url} (no heading #{frag})")
        self.assertEqual(bad, [])

    def test_sarif_help_anchor_exists_on_the_site(self):
        from pqproof import sarif
        anchor = sarif.HELP_URI.split("#", 1)[1]
        site = (PROOF / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn(f'id="{anchor}"', site)

    def test_pages_the_tool_prints_exist(self):
        import prove
        for page in ("guide/allowlist.md", "guide/configuration.md"):
            self.assertTrue((PROOF / page).is_file(), page)
        self.assertIn("guide/allowlist.md", prove.doc_url("guide/allowlist.md"))
        self.assertTrue((PROOF / "examples" / "allowlist" / "unconverted.json").is_file())


if __name__ == "__main__":
    unittest.main()
