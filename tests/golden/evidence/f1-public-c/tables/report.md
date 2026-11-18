<!-- prove.sh가 만든 표. 고친 판 트리 sha256 d24f82ad46fd4c839b56fd3acca4875380c6cb5bd71db1717f0725ccb373b0ba. receipt_id는 같은 폴더 receipt.json. -->

명령: `EXPECT=kem,sig bash prove.sh classic pqc` · 판정 **통과(안 쓰인 항목 2건)** · 실행 기록 s8a.txt

검사 결과

| # | 검사 | 도구 | 기대 | 실제 |
|---|---|---|---|---|
| V1 | 입력 확인(같은 서비스의 전·후, 원본에서 전환 대상을 찾음) | `입력 트리 해시·대조` | 공통 파일 50% 이상, 원본 막는 위치·공개키 code·TLS 실측 중 하나 이상 | 통과: 공통 파일 5/5 · 원본 막는 위치 13 · 원본 공개키 code 17 · TLS 실측 대상 0 |
| V2 | 고친 판 CBOM에 막는 위치 0 | `(a) cbom-scan.sh + scan.py` | 막는 위치 0, cbom-scan 정상 종료 | 통과: 막는 위치 0곳(원본 13) · 허용 0 · 주석·테스트 0 · 확인 4 |
| V3 | TLS 약화 수정 없음 | `(b) verify.weakening` | deny 0 | 통과: deny 0 · 본 파일 4 |
| V4 | TLS 하이브리드 협상·옛 클라이언트 | `(b) tls_probe connect + openssl s_client` | TLS 서버 신호 없음 | 해당 없음: TLS 서버·클라이언트 신호 0 |
| V5 | 고전 공개키 9계열 code 0, 보안레벨 3 미만 PQC 0, 레거시 쓰기 0 | `(c) residue.sh 공개키 9계열` | 모두 0(허용 목록·하이브리드 결합 줄은 사유와 함께 뺀다) | 통과: 공개키 code 0(원본 17) · 보안레벨 3 미만 0 · 레거시 쓰기 0 |
| V6 | EXPECT PQC 사용 | `(c) residue.sh EXPECT` | EXPECT=kem,sig 마다 1줄 이상(tls·cert는 b-tls 통과) | 통과: E-MLKEM768 3 · E-MLDSA65 2 |
| V7 | 검증 생략 흔적(검토 등급, 실패 아님) | `(b) verify.review` | 0 또는 줄마다 사유 | 통과: 0건 |
| V8 | 허용 항목 사람 확인(검토 등급, REQUIRE_REVIEW=1이면 실패) | `허용 목록 reviewed_by·reviewed_at·reviewed_digest` | 허용 항목마다 reviewed_by·reviewed_at(목록 맨 위 칸은 reviewed_digest 도), 고친 판에서 안 쓰인 항목 0(아니면 검토 필요, 실패 아님) | 검토 필요: 고친 판에서 안 쓰인 항목 2건(원본 고전 14줄을 덮음, 사람 확인 전): #1 src/main/java/demo/sealer/Sealer.java:1-52, #2 tools/sign_manifest.py:1-44 |

전환 뒤 남은 항목(허용·검토 필요·확인)

| 남은 고전 항목 | 위치 | 남은 이유 | 할 일 |
|---|---|---|---|
| 없음(허용·확인 행 0) |  |  |  |

변수로 넘긴 알고리즘 이름 4곳은 값을 따라가 PQC로 읽혀 표에서 뺐다(src/main/java/demo/sealer/Sealer.java:22, src/main/java/demo/sealer/Sealer.java:26, src/main/java/demo/sealer/Sealer.java:46, src/main/java/demo/sealer/Sealer.java:53).

이 도구는 기능·성능을 재지 않는다. 앱 기능 시험과 성능 측정은 따로 한다. 다시 확인: `bash prove.sh --verify <출력 폴더>`(트리·zip sha256과 receipt_id를 다시 계산).
