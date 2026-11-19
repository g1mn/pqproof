# skipdirs.py: 건너뛰는 폴더 규칙(scan/skip-dirs)을 읽고 트리를 걷는다(교차 리뷰 X02·X03·X09). 표준 라이브러리만 쓰고 pqlite 의 다른
# 모듈을 들여오지 않는다(pqlite/receipt.py 가 스크립트로 돌 때 이 파일을 경로로 읽는다).
# 이 걷기 방식이 증적 형식 3의 트리 목록과 tree_sha256 을 정한다. 걷기 방식을 바꾸면 증적 형식을 올린다. 목록(scan/skip-dirs)은
# 규칙 묶음에 들고 실행마다 증적에 사본이 남는다(--verify 는 그 사본으로 in/ 트리 해시를 다시 잰다).
# scan/residue.sh 와 scan/cbom-scan.sh 의 skip_dirs 함수가 같은 규칙을 셸로 쓴다(tests/test_rule_sync.py 가 세 곳의 결과를 맞춰 본다).
"""Skip-folder rules (scan/skip-dirs) and the tree walk that the tree hash, the scanners and the input check share."""
import os

SKIP_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scan", "skip-dirs")
SKIP_FILES = frozenset({".DS_Store"})  # 트리 목록에서 늘 빼는 파일(macOS 폴더 메타데이터)
KINDS = ("any", "output", "buildfile", "main")


class Rules:
    """scan/skip-dirs 를 읽은 값. any: 어느 깊이든 건너뛰는 이름, output: 조건부로 건너뛰는 이름, build_files: output 을 산출물로 보게
    하는 옆 파일, main: 운영 소스 표시(이 글이 경로에 있으면 output 규칙을 쓰지 않는다)."""

    def __init__(self, any_names, output_names, build_files, main):
        self.any, self.output, self.build_files, self.main = (frozenset(any_names), frozenset(output_names), frozenset(build_files),
                                                              main)

    def kind(self, parent_rel, name, sibling_files):
        """parent_rel('' = 트리 맨 위) 아래 폴더 name 을 건너뛰면 'any'(말없이) 또는 'output'(파일·코드 파일 수를 센다), 아니면 None.
        sibling_files: 그 부모 폴더의 파일 이름들(링크 포함, 대상은 읽지 않는다).
        any 이름도 제자리(트리 맨 위나 빌드 파일 옆)가 아니면 세고, main 표시 아래에서는 빌드 파일 옆일 때만 건너뛴다. 그래서
        src/main/java/com/bank/venv/ 는 운영 소스로 읽고, app/.tox/ 처럼 엉뚱한 곳의 의존성 폴더는 a-input 검토로 남는다(교차 리뷰 X02 후속)."""
        rel = f"{parent_rel}/{name}" if parent_rel else name
        in_main = bool(self.main) and self.main in f"/{rel}/"
        beside_build = not self.build_files.isdisjoint(sibling_files)
        if name in self.any:
            if in_main:
                return "output" if beside_build else None
            return "any" if not parent_rel or beside_build else "output"
        if name not in self.output or in_main:
            return None
        if not parent_rel or beside_build:
            return "output"
        return None


def parse(text, where="scan/skip-dirs"):
    """skip-dirs 글 → Rules. 모르는 종류나 값 없는 줄은 ValueError."""
    got = {k: [] for k in KINDS}
    for no, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, value = line.partition(" ")
        value = value.strip()
        if kind not in got or not value or " " in value or "/" in value and kind != "main":
            raise ValueError(f"{where}:{no}: not '<any|output|buildfile|main> <value>': {line!r}")
        got[kind].append(value)
    if len(got["main"]) > 1:
        raise ValueError(f"{where}: more than one main line")
    return Rules(got["any"], got["output"], got["buildfile"], got["main"][0] if got["main"] else "")


def load(path=SKIP_FILE):
    with open(path, encoding="utf-8") as f:
        return parse(f.read(), path)


def walk(root, rules):
    """root 를 이름 순으로 걷는다. (항목 [(상대 경로, 전체 경로, 'file'|'link'|'other')], 건너뛴 폴더 [(상대 경로, 종류)]).
    링크는 따라가지 않고 항목으로 남긴다(폴더 링크도). 건너뛴 폴더 안은 보지 않는다."""
    entries, skipped = [], []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        parent = os.path.relpath(dirpath, root).replace(os.sep, "/")
        parent = "" if parent == "." else parent
        siblings = set(filenames)
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            rel = f"{parent}/{d}" if parent else d
            k = rules.kind(parent, d, siblings)
            if k and d in rules.any:  # any 이름 폴더는 링크여도 건너뛴다(형식 1·2 와 같다). 링크는 따라가 세지 않는다
                skipped.append((rel, "any" if os.path.islink(full) else k))
                continue
            if os.path.islink(full):
                entries.append((rel, full, "link"))
                continue
            if k:
                skipped.append((rel, k))
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            if name in SKIP_FILES:
                continue
            full = os.path.join(dirpath, name)
            rel = f"{parent}/{name}" if parent else name
            entries.append((rel, full, "link" if os.path.islink(full) else "file" if os.path.isfile(full) else "other"))
    return sorted(entries), sorted(skipped)


def skipped_dirs(root, rules):
    """건너뛴 폴더의 상대 경로 목록(셸 스캐너가 쓰는 꼴과 같다, 시험이 대조한다)."""
    return [rel for rel, _ in walk(root, rules)[1]]
