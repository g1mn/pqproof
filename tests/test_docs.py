"""문서 링크(교차 리뷰 X51·X69·X70): 저장소 안 마크다운의 상대 링크와 github.com/g1mn/pqproof/blob/main/ 링크가 있는 파일·제목을
가리키는지, SARIF helpUri 의 앵커가 사이트에 있는지, 도구가 출력에 찍는 문서 주소가 있는 파일인지 본다. 문서가 없는 설치본에서는 건너뛴다."""
import collections
import pathlib
import re
import sys
import unittest

PROOF = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROOF))
sys.path.insert(0, str(PROOF / "src"))
DOCS = [PROOF / n for n in ("README.md", "README.ko.md", "DESIGN.md", "HISTORY.md", "CHANGELOG.md", "CONTRIBUTING.md", "CONTRIBUTING.ko.md",
                             "SECURITY.md")]
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


@unittest.skipUnless((PROOF / "docs" / "index.html").is_file(), "사이트 없음(설치본)")
class SiteMatchesVersion(unittest.TestCase):
    """README 는 짧고 모든 정보는 사이트에 있다. 그래서 판을 올리면 같은 커밋에서 사이트도 다시 만든다: docs/index.html 의 data-build 블록
    (사이트 생성기가 심는 판·규칙 묶음·증적 형식·KAT 숫자)이 지금 패키지와 같아야 한다. 검사는 tests/version_policy.py 의 check_site 한 곳."""

    def test_site_was_built_for_this_version(self):
        import version_policy as VP
        self.assertEqual(VP.site_problems(), [])

    def test_readme_sends_readers_to_the_site(self):
        readme = (PROOF / "README.md").read_text(encoding="utf-8")
        self.assertIn("https://g1mn.github.io/pqproof/", readme)

    def test_readme_is_english_only(self):
        # Korean text belongs on the site, which switches between Korean and English. README and the PyPI page stay English.
        readme = (PROOF / "README.md").read_text(encoding="utf-8")
        # 예외는 한국어 사본(README.ko.md)으로 가는 언어 전환 한 줄뿐이다
        hangul = [(n, line) for n, line in enumerate(readme.splitlines(), 1) if re.search("[\u1100-\u11ff\u3130-\u318f\uac00-\ud7a3]", line)
                  and "README.ko.md" not in line]
        self.assertEqual(hangul, [], "README.md must stay English; put Korean on the site or in README.ko.md")


KO_PAIRS = [("README.md", "README.ko.md"), ("CONTRIBUTING.md", "CONTRIBUTING.ko.md")]


def doc_shape(path):
    """번역해도 바뀌면 안 되는 것: 제목 단계별 수, 코드 블록의 명령(줄 끝 '# 주석'은 뺀다), 본문의 코드 표기, 표 행 수, 링크.
    링크는 .ko.md 를 .md 로 읽고 사이트 주소의 ?lang= 은 뺀다(그래서 서로를 가리키는 언어 전환 링크는 같은 것으로 센다)."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    heads = collections.Counter(len(m.group(1)) for m in (re.match(r"^(#{1,6})\s", line) for line in lines) if m)
    code, inside = [], False
    for line in lines:
        if line.startswith("```"):
            inside = not inside
        elif inside:
            code.append(re.sub(r"\s+#\s.*$", "", line).rstrip())
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    spans = set(re.findall(r"`([^`\n]+)`", prose))
    rows = sum(1 for line in lines if line.startswith("|"))
    links = {re.sub(r"\?lang=\w+", "", a or b).replace(".ko.md", ".md") for a, b in re.findall(r'\]\(([^)\s]+)\)|href="([^"]+)"', text)}
    return {"headings": heads, "commands": code, "code spans": spans, "table rows": rows, "links": links}


@unittest.skipUnless(all((PROOF / ko).is_file() for _, ko in KO_PAIRS), "한국어 사본 없음(설치본)")
class KoreanCopies(unittest.TestCase):
    """README.md·CONTRIBUTING.md 와 한국어 사본은 같은 커밋에서 함께 고친다(CONTRIBUTING.md, Layout). 한쪽만 고치면 여기서 어긋난다."""

    def test_korean_copies_match_the_english_files(self):
        for en, ko in KO_PAIRS:
            a, b = doc_shape(PROOF / en), doc_shape(PROOF / ko)
            for key in a:
                with self.subTest(file=ko, part=key):
                    self.assertEqual(b[key], a[key], f"{ko} and {en} differ in {key}")

    def test_each_copy_links_to_the_other(self):
        for en, ko in KO_PAIRS:
            self.assertIn(ko, (PROOF / en).read_text(encoding="utf-8"))
            self.assertIn(en, (PROOF / ko).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
