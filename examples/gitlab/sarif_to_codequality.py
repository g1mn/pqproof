#!/usr/bin/env python3
# sarif_to_codequality.py: pqproof sarif 가 쓴 SARIF 2.1.0 을 GitLab Code Quality 보고서(JSON)로 바꾼다. 표준 라이브러리만 쓴다.
#   python3 -I sarif_to_codequality.py pqproof.sarif gl-code-quality-report.json
# 수준: error → critical, warning → major, note → info. 위치 없는 알림(toolExecutionNotifications)은 Code Quality 에 자리가
# 없어서 넣지 않는다(SARIF·증적 폴더에는 남는다). 지문은 SARIF 의 partialFingerprints 를 그대로 쓴다.
"""Convert PQ-Proof SARIF 2.1.0 to a GitLab Code Quality report."""
import hashlib
import json
import sys

SEVERITY = {"error": "critical", "warning": "major", "note": "info", "none": "info"}


def convert(sarif):
    out = []
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            path = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 1)
            fp = next(iter((res.get("partialFingerprints") or {}).values()), None)
            if not fp:
                fp = hashlib.sha256(f"{res.get('ruleId')}|{path}|{line}|{res['message']['text']}".encode()).hexdigest()
            out.append({"description": res["message"]["text"], "check_name": res.get("ruleId", "pqproof"), "fingerprint": fp,
                        "severity": SEVERITY.get(res.get("level", "warning"), "major"),
                        "location": {"path": path, "lines": {"begin": line}}})
    return out


def main(argv):
    if len(argv) != 2:
        print("usage: sarif_to_codequality.py <in.sarif> <out.json>", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as f:
        report = convert(json.load(f))
    with open(argv[1], "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    print(f"{len(report)} Code Quality issues -> {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
