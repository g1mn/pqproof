#!/bin/bash
# prove.sh: PQC 전환 검증 한 명령. 원본과 고친 판을 받아 (a) CBOM (b) TLS (c) 공개키 집계 (d) 검증 증적을 낸다(설계 DESIGN.md).
#   bash prove.sh <원본 폴더|zip> <고친 폴더|zip>
#   bash prove.sh --selftest          examples/·orders-edge 스냅숏·참조 TLS 서버로 S1~S10(오프라인, 20초~1분)
#   bash prove.sh --verify <출력 폴더>  검증 증적 다시 확인(스키마·receipt_id·산출물 해시·in/ 트리·HTML)
#   bash prove.sh --unit [이름]        단위 시험(tests/, 표준 라이브러리 unittest). 'n 통과 · m 건너뜀 · k 실패'로 센다
#   bash prove.sh sarif <출력 폴더> [-o 파일] [--uri-prefix 경로/]   검증 증적을 SARIF 2.1.0 으로(GitHub code scanning)
#   bash prove.sh --version            도구 버전, 규칙 묶음 이름, 증적 형식(버전은 src/pqproof/__init__.py 한 곳)
# 건너뛴 시험은 통과로 세지 않는다. STRICT=1 이면 --unit·--selftest 에서 건너뛴 것이 하나라도 있을 때 실패(종료 1)로 끝난다(CI 가 쓴다)
# 환경 변수(모두 선택):
#   OUT=<출력 폴더>        기본: 원본이 <W>/orig 이고 <W>/evidence 가 있으면 <W>/evidence/proof-HHMMSS, 아니면 ./proof-out-HHMMSS. 있으면 멈춘다
#   TLS_TARGETS="127.0.0.1:8443@localhost#/abs/ca.pem 127.0.0.1:9443"   띄운 고친 판의 TLS 주소(CA 없으면 -tofu)
#   TLS_TARGETS_ORIG=...   원본 스택 주소(기준선, 판정에는 안 씀)
#   TLS_VIA=host | container:<컨테이너 이름>   container면 그 컨테이너 네트워크 이름공간에서 잰다(공개 안 된 내부 포트용)
#   CLASSIC=allow | deny   옛 클라이언트(X25519,P-256) 기대값. 기본 allow, PQC 단독(옛 클라이언트 거부)을 요구하면 deny
#   EXPECT=kem,sig         고친 판에 있어야 할 것(kem ML-KEM-768, sig ML-DSA-65, tls 하이브리드 TLS, cert ML-DSA-65 TLS 인증서, none)
#   SCOPE=all | kex        all(기본): 모든 고전 공개키가 막는 위치. kex: 키 교환만(서명·암호화는 '범위 밖'으로 표에만)
#   RESIDUE=<residue.sh>   서비스에 맞춘 residue.sh(SITE 규칙 포함). 기본: scan/residue.sh 일반판
#   EXTRA_EV="파일 ..."    검증 증적 묶음에 같이 넣을 다른 증거 파일(시험 로그 등)
#   OPENSSL=<openssl 3.5+> cbom-scan·교차 확인용. 기본: 찾은 것 중 3.5 이상, 없으면 처음 찾은 것
#   CBOM_SCAN=<cbom-scan.sh>   기본: scan/cbom-scan.sh
#   ALLOW=<unconverted.json>|none   허용 목록(where '파일:시작-끝'·why·kind, 선택 reviewed_by·reviewed_at). 그 줄의 고전은 사유와 함께
#                          '허용'으로 세고, 목록 밖 고전·없는 파일·범위 밖 줄은 허용하지 않는다(DESIGN.md Allow rules). 비우면 원본이 <W>/orig 일 때 <W>/notes/ 에서 찾는다
#   EXCLUDE="data/** *.db *.log"|none   검사에서 뺄 실행 데이터 글롭(앱 폴더 기준). 코드·설정·빌드 파일은 걸려도 뺀다고 치지 않는다
#   RECON=<recon.json>|none   DATA_DIR·앱 루트를 읽어 앱 폴더 안 데이터 폴더를 뺀다. 비우면 <W>/notes/recon.json
#   EV_NAME=<파일 이름>    deck.json·evidence-fragment.json 의 ev(이 실행의 화면 출력을 남긴 파일 이름). 비우면 <출력 폴더 이름>.txt
#   REQUIRE_REVIEW=1       허용 목록 항목(또는 목록 맨 위)에 reviewed_by·reviewed_at(사람 확인)이 없거나, 고친 판에서 고전 줄을 하나도
#                          덮지 않는 항목(안 쓰인 항목)이 있으면 실패(r-allow). 기본 0: 통과는 그대로 두고 판정 옆에 '허용 n건 사람 확인 전 ·
#                          허용 범위 쓰기 경로 n곳 검토 필요 · 안 쓰인 항목 n건'을 적는다. 맨 위 칸은 실행이 찍어 주는 reviewed_digest 가
#                          지금 목록과 맞을 때만 센다(확인 뒤 더하거나 고친 항목은 확인 전으로 돌아간다). 실무 검토에서는 1을 권한다
# 시험·예제 경로는 scan/test-paths.ere 한 곳에 있다(두 스캐너가 같이 쓴다). 그 경로의 고전 줄은 판정에 안 넣고 따로 센다
#   PROBE_BIN_DIR=<폴더>   tls_probe 바이너리 폴더. 기본 bin/(build-probe.sh가 만든다)
# 출력 폴더의 deck.json 은 발표 자료·대시보드용 요약이다(receipt.json에서 결정적으로 만든다)
# 종료: 0 통과 · 1 실패 · 2 사용법·입력 오류 · 3 미판정(TLS 신호가 있는데 TLS_TARGETS 없음, 대조 실패 등)
# 작업 폴더 꼴(선택): <W>/orig(원본) · <W>/repo(고친 판) · <W>/notes/unconverted.json(허용 목록) · <W>/notes/recon.json · <W>/evidence/
#   W=<작업 폴더>; ALLOW=$W/notes/unconverted.json EXCLUDE='data/** *.db *.sqlite3 *.log' bash prove.sh $W/orig $W/repo
# 오프라인: 인터넷·종량제 API·서버를 쓰지 않는다. 받은 소스의 코드는 실행하지 않는다. 지우는 명령 없음. bash 3.2 호환.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null || { echo "prove.sh: python3 없음" >&2; exit 2; }
case "${1:-}" in
  --verify) [ -n "${2:-}" ] || { echo "사용: prove.sh --verify <출력 폴더>" >&2; exit 2; }
    exec "$PY" -I -B "$HERE/pqlite/receipt.py" verify "$2";;
  --unit) exec "$PY" -I -B "$HERE/tests/run_unit.py" ${2:+"$2"};;
  --selftest) exec "$PY" -I -B "$HERE/prove.py" --selftest;;
  --version|-V) exec "$PY" -I -B "$HERE/pqlite/version.py";;
  sarif) shift
    for s in "$HERE/src/pqproof/sarif.py" "$HERE/../sarif.py"; do [ -f "$s" ] && exec "$PY" -I -B "$s" "$@"; done
    echo "prove.sh: sarif.py 없음(src/pqproof/sarif.py)" >&2; exit 2;;
  -h|--help|"") awk 'NR>1 && /^#/ {print; next} NR>1 {exit}' "$0"; exit 2;;
esac
[ $# -eq 2 ] || { echo "사용: bash prove.sh <원본 폴더|zip> <고친 폴더|zip>  (자세히: prove.sh --help)" >&2; exit 2; }
BIN=${PROBE_BIN_DIR:-$HERE/bin}
if ! ls "$BIN"/tls_probe-* >/dev/null 2>&1 && [ -n "${TLS_TARGETS:-}${TLS_TARGETS_ORIG:-}" ]; then
  echo "prove.sh: tls_probe 바이너리 없음($BIN). 먼저: bash $HERE/build-probe.sh" >&2; exit 2
fi
exec "$PY" -I -B "$HERE/prove.py" "$@"
