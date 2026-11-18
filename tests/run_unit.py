# run_unit.py: 단위 시험 실행기(prove.sh --unit 이 부른다). 표준 라이브러리 unittest 로 tests/test_*.py 를 돌리고
# 건너뛴 시험을 통과와 따로 센다: 'unit: n 통과 · m 건너뜀 · k 실패'. 건너뛴 것은 이름과 까닭을 줄마다 적는다.
# 시험 모듈의 KNOWN_GAPS(지금 동작대로 고정한 알려진 실패, 교차 리뷰 항목 번호)는 끝에 한 줄로 번호만 찍는다.
#   python3 -I -B tests/run_unit.py [이름]     이름이 들어간 시험만(unittest -k 와 같다)
#   STRICT=1 python3 -I -B tests/run_unit.py   건너뛴 시험이 하나라도 있으면 종료 1(CI 가 쓴다: 건너뛴 시험은 통과가 아니다)
# 종료: 0 통과(STRICT 면 건너뜀 0까지) · 1 실패·오류(STRICT 면 건너뜀 포함)
"""Unit test runner that reports skipped tests apart from passed ones."""
import os
import sys
import unittest


def known_gaps(here):
    """불러온 시험 모듈(tests/ 바로 아래)의 KNOWN_GAPS 를 모은다: {항목 번호: 설명}."""
    gaps = {}
    for mod in list(sys.modules.values()):
        g = getattr(mod, "KNOWN_GAPS", None)
        f = getattr(mod, "__file__", None) or ""
        if isinstance(g, dict) and f and os.path.dirname(os.path.abspath(f)) == here:
            gaps.update(g)
    return gaps


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    loader = unittest.TestLoader()
    if argv:
        loader.testNamePatterns = [p if "*" in p else f"*{p}*" for p in argv]
    suite = loader.discover(here, pattern="test_*.py", top_level_dir=here)
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(res.failures) + len(res.errors) + len(getattr(res, "unexpectedSuccesses", []))
    skipped = len(res.skipped) + len(res.expectedFailures)
    passed = res.testsRun - failed - skipped
    strict = os.environ.get("STRICT") == "1"
    print(f"unit: {passed} 통과 · {skipped} 건너뜀 · {failed} 실패 (건너뛴 시험은 통과로 세지 않는다)")
    for test, why in res.skipped:
        print(f"  SKIP {test.id()}: {why}")
    if any("tls_probe" in why for _, why in res.skipped):
        print("  건너뛴 TLS 시험을 돌리려면 tls_probe 를 만든다: bash build-probe.sh 또는 pqproof build-probe(Go 1.27 이상, 인터넷 없음)")
    gaps = known_gaps(here)
    if gaps:
        print(f"알려진 실패 {len(gaps)}건은 지금 동작대로 고정했다(고치면 그 시험이 실패하니 기대값을 뒤집는다): {' '.join(sorted(gaps))}")
    if skipped and strict:
        print("STRICT=1: 건너뛴 시험이 있어 실패로 끝낸다")
    if res.testsRun == 0:
        print("시험을 하나도 찾지 못했다")
        return 1
    return 0 if failed == 0 and not (strict and skipped) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
