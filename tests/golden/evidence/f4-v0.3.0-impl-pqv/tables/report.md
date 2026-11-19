<!-- prove.sh --impl 이 만든 표. 답안 sha256 639fb9bc45b7cb72d941c534458bbbdf13ad928a69de80fa2a195b4c55b0ba15. receipt_id는 같은 폴더 receipt.json. -->

명령: `bash prove.sh --impl judge answers.json --pq-verify ...` · 판정 **통과(검토 필요 검사 i-kpqc)**

판정 근거: pqproof 0.3.0 · 규칙 묶음 3 (sha256 `d389e962e9847cee`) · 증적 형식 4 · PROFILE=kpqc · 받아 줄 판 smaug-t/modet@1.2.0

검사 결과

| # | 검사 | 기대 | 실제 |
|---|---|---|---|
| V1 | KpqC 구현의 KAT 대조(받아 줄 참조판과 일치하는가, 공인 시험 아님) | 파라미터마다 받아 줄 판(프로필의 impl_accept, 기본 최신판)의 KAT 와 일치, 변조 서명 거부, 자기 점검 통과 | 검토 필요: smaug-t/modet 검토 필요: 옛 판 1.1.1 일치(문항 10/10): 받아 줄 판(1.2.0)이 아니다 |
| V2 | NIST PQC 구현 감사(pq-verify, 사용자가 켠 바깥 도구) | pq-verify 감사(--require-full-coverage)가 종료 0·VERIFIED·검사 범위 완전이면 통과, 통과 못 한 검사 단계가 있으면 실패, 그 밖(입력 오류, DEGRADED, 범위 불완전, 돌지 못한 검사, 실행 파일 없음, 보고서 깨짐)은 미판정 | 통과: libmlkem768_good.dylib ML-KEM-768: pq-verify 2.19.0, VERIFIED, 검사 1436/1436, 범위 완전(KEM 필수 단계 9개 모두 돎) |

파라미터별 참조판 대조

| 파라미터 | 판 | 역할 | 받아 줌 | 대조 | 첫 불일치 | 결과 | 요약 |
|---|---|---|---|---|---|---|---|
| `smaug-t/modet` | 1.2.0 | 참조판 최신 | 예 | 문항 0/10 | smaug-t/modet@1.2.0#0:decaps ss | 검토 필요 | 옛 판 1.1.1 일치(문항 10/10): 받아 줄 판(1.2.0)이 아니다 |
| `smaug-t/modet` | 1.1.1 | 참조판 |  | 문항 10/10 |  |  |  |

NIST 구현 감사(pq-verify)

| 항목 | 값 |
|---|---|
| 결과 | 통과: libmlkem768_good.dylib ML-KEM-768: pq-verify 2.19.0, VERIFIED, 검사 1436/1436, 범위 완전(KEM 필수 단계 9개 모두 돎) |
| pq-verify | /opt/pq-verify/bin/pq-verify (2.19.0) |
| 감사 | --audit-kem ML-KEM-768 |
| 대상 | /tmp/work/lib/libmlkem768_good.dylib (sha256 21e5cdbd3da1531fe473cb7f0a4da039c551683c8fc8c6e1c400c923eaa9ac28) |
| 종료 코드 | 0 |
| 보고서 | VERIFIED, verified True, 검사 1436/1436, schema pq-verify/kem-audit-result 1.2 |
| 검사 범위 | KEM 필수 단계 9개 모두 돎 |
| 통과 못 한 단계 | 없음 |
| 뺀 환경 변수 | 없음 |

NIST 구현 감사는 사용자가 켠 바깥 도구 pq-verify 가 대상 라이브러리를 불러 실행했고, PQ-Proof 는 그 보고서와 종료 코드만 읽었다. pq-verify 는 샌드박스가 아니다: 믿지 못할 라이브러리는 컨테이너나 VM 안에서 돌린다.

참조판 KAT 와 일치하는지 본 것이다. 표준 준수 시험이나 공인 시험(KCMVP)이 아니고, PQ-Proof 는 구현을 빌드하거나 실행하지 않았다(답안은 사용자 하네스가 만들었다). 다시 확인: `bash prove.sh --verify <출력 폴더>`(답안·보고서 사본으로 다시 판정한다).
