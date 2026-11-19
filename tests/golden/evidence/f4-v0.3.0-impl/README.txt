PQ-Proof 0.3.0 implementation check (KpqC KAT). Verdict: pass (needs review: i-kpqc)
판정: 통과(검토 필요 검사 i-kpqc) · 증적 해시(receipt_id): f194b5a85e15026308bc639499b0735446a07b2af39e953ad5fbecbc47353602

Open first / 먼저 볼 것
  receipt.html             the evidence as one page (사람이 볼 것)
  receipt.json             the evidence for programs (기계가 읽을 것, schemas/receipt-v4.schema.json)
  tables/report.md         a summary to paste into a document (문서에 붙일 표)
  tables/impl.csv          every parameter set and reference version with its count
  artifacts/impl/          the answer file, the answer key and the question sheet that were compared

What this is / 이것은
  A match with pinned reference KAT versions (scan/kat-kpqc.json). PQ-Proof did not build or run the implementation;
  your harness wrote the answers. It is not a conformance test or a certification (not KCMVP).
  참조판 KAT 와 일치하는지 본 것이다. 표준 준수 시험이나 공인 시험(KCMVP)이 아니다.

Check again / 다시 확인
  bash prove.sh --verify /tmp/work/impl-out
  The check judges the copied answer again. Adding, removing or editing any file here makes it fail.
  폴더 안 파일을 더하거나 지우거나 고치면 다시 확인이 실패한다.
