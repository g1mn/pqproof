# rulesrc.py: 시험이 규칙 파일 원문에서 값을 읽는 도우미(test_rules.py·test_rule_sync.py 가 쓴다). 읽기만 한다.
# residue.sh 의 규칙 표(RES_RULES), export 한 정규식, Legacy*.java 이름 규칙, 건너뛰는 폴더를 원문 그대로 꺼낸다.
"""Read rule values from the source text of scan/residue.sh for the behaviour and sync tests."""
import pathlib
import re

PROOF = pathlib.Path(__file__).resolve().parent.parent
RESIDUE = PROOF / "scan" / "residue.sh"


def residue_text():
    return RESIDUE.read_text(encoding="utf-8")


def residue_rules(text=None):
    """RES_RULES 표의 규칙 [{kind, id, file, re, note, allow}], 표에 적힌 순서."""
    text = residue_text() if text is None else text
    m = re.search(r"<<'RULES'\n(.*?)\nRULES\n", text, re.S)
    if not m:
        raise ValueError("residue.sh: RES_RULES heredoc not found")
    out = []
    for line in m[1].split("\n"):
        if not line or line.startswith("#"):
            continue
        f = line.split("@@")
        out.append({"kind": f[0], "id": f[1], "file": f[3], "re": f[4], "note": f[5], "allow": f[6] if len(f) > 6 else ""})
    return out


def residue_export(name, text=None):
    """export NAME='값' 줄의 값(작은따옴표 안). 없으면 None."""
    text = residue_text() if text is None else text
    m = re.search(rf"^export {name}='([^']*)'$", text, re.M)
    return m[1] if m else None


def residue_legacy_file(text=None):
    """awk 의 Legacy*.java 이름 규칙(파일 이름에 맞춘다)."""
    text = residue_text() if text is None else text
    m = re.search(r"ISLEG = \(BASE ~ /(.+?)/\)", text)
    return m[1] if m else None


def residue_skips(text=None):
    """find 가 건너뛰는 폴더: ({어느 깊이든 -name}, {트리 맨 위만 -path "$ROOT/x"})."""
    text = residue_text() if text is None else text
    m = re.search(r"find \"\$ROOT\" \\\((.*?)\\\) -prune", text)
    if not m:
        raise ValueError("residue.sh: find -prune list not found")
    return set(re.findall(r"-name (\S+)", m[1])), set(re.findall(r'-path "\$ROOT/([^"]+)"', m[1]))
