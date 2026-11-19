PQ-Proof 0.2.0 result folder. Verdict: pass
판정: 통과 · 증적 해시(receipt_id): ce6c4c9d6cb7027e5553cb290984cd83d37ed21c560f1289c505dbdf28b06b47

Open first / 먼저 볼 것
  receipt.html          the verification evidence as one page (사람이 볼 것)
  receipt.json          the verification evidence for programs (기계가 읽을 것, schemas/receipt-v3.schema.json)
  tables/report.md      a summary to paste into a document (문서에 붙일 표)
  tables/cbom-fixed.csv every cryptographic location in the fixed tree with its status

Check again / 다시 확인
  bash prove.sh --verify /tmp/work/proof-out
  Adding, removing or editing any file in this folder makes the check fail (README.txt included).
  폴더 안 파일을 더하거나 지우거나 고치면 다시 확인이 실패한다.

Before sharing / 넘기기 전에
  artifacts/ holds the raw scanner output with source lines, and in/ holds unpacked zip inputs.
  Paths on this machine are recorded in receipt.json. Read guide/outputs.md before handing the folder over.
  artifacts/ 에는 소스 줄이 든 스캐너 원문이, in/ 에는 푼 zip 입력이 있다. 넘기기 전에 확인한다.
