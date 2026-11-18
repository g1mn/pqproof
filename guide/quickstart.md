# Quick start

PQ-Proof judges two trees, the code before a post-quantum migration and the code after it, and writes an evidence folder. This page takes about five minutes.

## Install

```bash
pip install pqproof
pqproof doctor        # the external programs it found and what is missing
```

Judging needs Python 3.9 or later (standard library only), bash 3.2 or later and OpenSSL. With OpenSSL below 3.5 or LibreSSL the run still works; only the TLS cross-check is recorded as not possible. `keytool` (any JDK) is optional and reads `.jks` and `.p12` keystores. Go 1.27 or later is only needed to build the TLS probe (`pqproof build-probe`).

| System | Judge two trees | `--verify`, `sarif` |
|---|---|---|
| Linux, macOS | yes | yes |
| Windows | inside WSL (`wsl --install`, then `pip install pqproof` in Ubuntu) | yes, with Python alone |

## Run the bundled example

The wheel carries the example trees. `examples/classic` is a small Java and Python "sealer" that wraps a data key with RSA-OAEP and signs with ECDSA P-256; `examples/pqc` is the same code moved to ML-KEM-768 (with AES-256-GCM) and ML-DSA-65.

```bash
ex=$(python3 -c 'import os, pqproof; print(os.path.join(os.path.dirname(pqproof.__file__), "_tool", "examples"))')
pqproof "$ex/classic" "$ex/pqc"        # pass, exit 0
pqproof "$ex/classic" "$ex/classic"    # nothing migrated: fail, exit 1
```

From a clone, `bash prove.sh examples/classic examples/pqc` runs the same files.

While it runs, stderr shows the applied settings and one line per step. The console then prints one line per check, in Korean, and the verdict:

```
[a-input] 통과  공통 파일 5/5 · 원본 막는 위치 13 · 원본 공개키 code 17 · TLS 실측 대상 0
[a-cbom] 통과  막는 위치 0곳(원본 13) · 허용 0 · 주석·테스트 0 · 확인 0
[b-weakening] 통과  deny 0 · 본 파일 4
[b-tls] 해당 없음  TLS 서버·클라이언트 신호 0
[c-classic] 통과  공개키 code 0(원본 17) · 보안레벨 3 미만 0 · 레거시 쓰기 0
[c-expect] 통과  E-MLKEM768 2 + E-MLKEM1024 0 = 2 · E-MLDSA65 2 + E-MLDSA87 0 = 2
[r-review] 통과  0건
[r-allow] 해당 없음  허용 목록 없음
VERDICT=PASS  receipt_id=b17355b74d9f…
```

통과 is pass, 실패 fail, 해당 없음 not applicable, 검토 필요 needs review, 미판정 undecided. Only pass counts as passed: a check that could not run stays visible as not applicable or undecided.

## Look at the result

The output folder is `proof-out-YYYYMMDD-HHMMSS` (set another with `OUT=`). Open these first:

- `receipt.html`: the whole evidence on one page, for people.
- `receipt.json`: the same for programs (schema in `schemas/receipt-v3.schema.json`).
- `tables/report.md`: the check table, ready to paste into a document.
- `README.txt`: what is in the folder and how to re-check it.

[outputs.md](outputs.md) describes every file.

## When it fails

The console ends with "다음 할 일" (what to do next): the full list of blocking locations in `tables/cbom-fixed.csv`, the classical lines left in `artifacts/residue-fixed.txt`, any weakened TLS setting in `artifacts/weakening.json`, and the allowlist example. Fix the code, or record a line that must stay in an allowlist ([allowlist.md](allowlist.md)). Undecided usually means a TLS server with no address to measure ([configuration.md](configuration.md#tls-targets)).

## Re-check the evidence

```bash
pqproof --verify proof-out-20261119-101500
```

It recomputes the evidence hash (`receipt_id`) and every file hash and rebuilds the page. It needs only Python. Do not add files to the folder; an unlisted file fails the check.

Exit codes: 0 pass, 1 fail, 2 usage or input error, 3 undecided, 4 tool error, and 5 for a pass that needs review under `FAIL_ON_REVIEW=1`. `--verify` gives 0 or 1, 2 when the folder or its `receipt.json` is missing, and 4 on a tool error.

To look at one tree without an original, `pqproof check <tree>` judges it as it is now and `pqproof inventory <tree>` lists what it finds with no verdict ([ci.md](ci.md)).
