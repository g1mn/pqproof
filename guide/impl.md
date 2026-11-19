# Implementation check

`pqproof impl` (from 0.3.0; `bash prove.sh --impl` in a clone) checks a KpqC implementation (SMAUG-T, NTRU+, HAETAE, AIMer) against pinned reference KAT versions and says which version it matches. With `--pq-verify` it also puts an audit of a NIST PQC library (ML-KEM, ML-DSA, SLH-DSA) by pq-verify, a separate tool you install, into the same evidence.

PQ-Proof does not build or run your implementation. It writes a question sheet, your own harness answers it, and PQ-Proof compares the answers with the reference KAT. The result reads "matches the KAT of reference version X". It is not a conformance test or a certification, and it does not replace a KCMVP validation.

## Why the version matters

The KpqC reference KATs changed after the final release of January 2026:

| Algorithm | Parameter sets | Accepted by default | Also known (needs review) |
|---|---|---|---|
| SMAUG-T | `mode1`, `mode3`, `mode5`, `modet` (TiMER) | 1.2.0 | 1.1.1: the official page says it has implementation bugs; every KAT record differs (key generation and encapsulation changed), yet decapsulating the same `sk` and `ct` gives the same `ss` |
| NTRU+ | `768`, `864`, `1152` | 2026-01 | none |
| HAETAE | `mode2`, `mode3`, `mode5` | 1.2.0 | 1.1.2: every signature differs; the Bouncy Castle test data (bc-test-data, commit 1905b926) carries it |
| AIMer | `128f`, `128s`, `192f`, `192s`, `256f`, `256s` | 3.0 | `aim2-2026-01` (`pk`, `sk` and the signature all differ from 3.0, and the signature size changed: 5888 to 6944 bytes for `128f`), `bc-round2` (the Bouncy Castle KAT, same `pk` and `sk` as AIM2 but other signatures, which matches no published reference; digests only) |

`scan/kat-kpqc.json` lists every version with its source archive (URL, commit, SHA-256), the SHA-256 of each `.rsp`, a normalized digest of the whole file and one digest per record. `scan/kat/` holds the first five records of each version, which the question sheet is made from.

### Which version is accepted, and why the others need review

The judge accepts what `impl_accept` of the `kpqc` profile in `scan/profiles.json` names: `latest` by default, or `<parameter>@<version>`, `<algorithm>@<version>`. `latest` is the version `scan/kat-kpqc.json` marks as the newest reference. Its `sources` say where each one comes from:

- SMAUG-T 1.2.0: the KpqC page (kpqc.cryptolab.co.kr/smaug-t) says "Please use the reference implementation of version 1.2.0" and gives a SHA-256 that matches the archive.
- HAETAE 1.2.0: the KpqC page (kpqc.cryptolab.co.kr/haetae) offers it as "Hyperball sampler modified." next to 1.1.2, the "Original version announced in the KpqC homepage.", with SHA-256 values that match both archives.
- NTRU+ 2026-01: the only version. ntruplus.org links to the team repository and publishes no SHA-256.
- AIMer: `aim2-2026-01` is the KpqC final package of 2026-01-30 (AIM2). `3.0` (AIM3) is the reference the AIMer team put in its GitHub repository afterwards (commit 734cc76, "update AIMer V3.0 reference implementation"); it changed `pk`, `sk` and the signature size. aimer-signature.org links to that repository and publishes no SHA-256, and the list has no KpqC page for AIMer. The list marks 3.0 as latest because it is the newest reference the team published, so an implementation of the KpqC final package needs review by default. Which version Korean standardization will adopt is not recorded here.

A match with another reference version is not a wrong answer. PQ-Proof cannot know which version your project has to follow, so it names the version it matched and leaves the decision to you; the result line says how to accept it. To accept the KpqC final package of AIMer as well, edit `impl_accept` in `scan/profiles.json` (in a clone, or `pqproof/_tool/scan/profiles.json` inside a pip install):

```json
"impl_accept": ["latest", "aimer@aim2-2026-01"]
```

The profile is a rule file, so receipts written after that name ruleset `3+modified` and list the changed profile hash in `tools[]`. `--verify` checks `impl.accept` against the profile of the tool that runs it, so verify such a receipt with the same profile.

## The flow

```bash
pqproof impl prompt --param smaug-t/mode3 --param haetae/mode3 -o prompt.json   # 1. question sheet
h=$(python3 -c 'import os, pqproof; print(os.path.join(os.path.dirname(pqproof.__file__), "_tool", "examples", "impl", "kpqc_harness.py"))')
python3 -I "$h" prompt.json answers.json \
  --lib smaug-t/mode3=./libsmaugt-mode3.so --lib haetae/mode3=./libhaetae-mode3.so   # 2. your harness (here the example one)
pqproof impl judge answers.json                                                   # 3. judge
```

**1. Question sheet.** `prompt` takes parameter names as written in `scan/kat-kpqc.json` or one of their aliases, in any case (`TiMER`, `HAETAE-5`, `AIMer128f`). Without `--param` it writes all 16 parameter sets (380 items, about 4.2 MB). It stops with exit 2 when the `-o` file already exists. For every parameter set and every known version it writes items from five KAT records:

| Item | Given | Answer |
|---|---|---|
| KEM `decaps` (required) | `sk`, `ct` | `ss` |
| signature `verify` (required) | `pk`, `msg`, `sig`, `ctx` | `ok` (true); some items carry a signature with one changed byte and must give false |
| `derand` (optional) | `seed` (and `msg`, `ctx` for signatures) | KEM `pk`, `sk`, `ct`, `ss`; signature `pk`, `sk`, `sig` or `sm` (AIMer `msg \|\| sig`; HAETAE `sig \|\| msg` as its reference writes it, `msg \|\| sig` also taken) |

The `derand` items need a build that links the NIST KAT DRBG (`randombytes_init` from the reference `rng.c`). HAETAE KAT signatures use a context string that the `.rsp` does not print, so the sheet carries it; AIMer signs with an empty one. `prompt_sha256` covers the format, the parameter sets, the buffer sizes and the items, so changing the explanatory text does not change it.

**2. Harness.** You answer the sheet with your own code. [examples/impl/kpqc_harness.py](../examples/impl/kpqc_harness.py) (in a pip install, under `pqproof/_tool/examples/impl/`, as the `h=` line above finds it) loads shared libraries that export the NIST API through Python `ctypes`. A harness in any language works if it writes this JSON:

```json
{"format": "pqproof impl response 1", "prompt_sha256": "<from the sheet>", "params": ["smaug-t/mode3"],
 "implementation": "libsmaugt 1.2.0, our build 2026-11-19", "answers": {"smaug-t/mode3@1.2.0#0:decaps": {"ss": "8f..."}}}
```

The judge reads it strictly: a duplicate key, a byte order mark, an unknown field or a hexadecimal value of odd length leaves the run undecided. `params` may come in any order; the evidence lists them in the order of `scan/kat-kpqc.json`. `implementation` is free text up to 500 characters without control characters, line breaks or bidirectional controls, or null, and goes into the evidence. These text rules do not depend on the Unicode tables of the Python that runs the judge, so the same answer gets the same result on Python 3.9 and 3.15.

**3. Judge.** `judge` compares the answers with every known version. A version is a candidate when every item from it matches. The output folder is `impl-out-YYYYMMDD-HHMMSS` (set another with `OUT=`). The console shows one line per check and one per parameter set:

```
[i-kpqc] 검토 필요  smaug-t/mode3 통과: 1.2.0 일치(문항 10/10) · haetae/mode3 검토 필요: 옛 판 1.1.2 일치(문항 15/15): 받아 줄 판(1.2.0)이 아니다
[i-nist] 해당 없음  --pq-verify 를 주지 않았다(NIST 구현 감사를 하지 않음)
  smaug-t/mode3: 1.2.0(받아 줌) 10/10 · 1.1.1 5/10 첫 불일치 smaug-t/mode3@1.1.1#0:derand pk
  haetae/mode3: 1.2.0(받아 줌) 10/15 첫 불일치 haetae/mode3@1.2.0#0:derand sig · 1.1.2 15/15
자기 점검: 통과(정답 답안 통과, 한 바이트 바꾼 답안 실패)
VERDICT=PASS (needs review: i-kpqc)  receipt_id=64cb29e3…
```

This run answered SMAUG-T with a 1.2.0 build and HAETAE with a 1.1.2 build. Before it judges, the tool checks itself: answers built from the excerpts for an accepted version must pass and the same answers with one byte changed must fail, or the whole check is undecided.

## A full PQCgenKAT `.rsp`

```bash
pqproof impl judge PQCkemKAT_smaugt_mode3.rsp
pqproof impl judge PQCkemKAT_2336.rsp --param ntruplus/768
```

If your build has the reference KAT program, run it and give the judge the `.rsp` it writes. All 100 records are compared with the record digests of each version (`1.2.0 일치(100/100)`). The judge reads the parameter set from the header line; give `--param` when the header does not name a known parameter set (a port that prints its own name, for example). With `--param`, only a header that names another known parameter set stops the run; the header is kept in the evidence. A UTF-8 byte order mark at the start is skipped. A file with more than 1,000 records, or a field name longer than 32 characters, leaves the run undecided. HAETAE `smlen`/`sm` (as `sig || msg` or `msg || sig`) and AIMer `siglen`/`sig` forms are read as the reference forms when their length field fits. This path also separates versions that the decaps and verify items alone cannot.

## NIST PQC through pq-verify

```bash
PQ_VERIFY=/opt/pqv/bin/pq-verify pqproof impl judge answers.json --pq-verify "--audit-kem ./libmlkem768.so ML-KEM-768"
```

pq-verify ([PyPI](https://pypi.org/project/pq-verify/), MIT) audits a shared library against NIST vectors and edge cases. PQ-Proof calls it only when you pass `--pq-verify`, and the result becomes check `i-nist`. Leave out the answer file to run only the audit (`i-kpqc` is then not applicable).

**pq-verify runs your library.** It loads the library, so the library's initialization code runs, and pq-verify says itself that it is not a sandbox. Audit a library you did not build inside a container or a VM. The library audits need no network (pq-verify 2.19.0 audits ran to the end with network access blocked in our tests), so you can run that container with networking off. pq-verify supports macOS and Linux and needs `nm` on the path. `--audit-contained` needs Linux on x86-64 and a C compiler, and it draws fresh questions on every run unless you give `--fresh-seed`; the argv in the receipt records what you gave.

Install it in its own virtual environment, pinned by version and wheel hash. pq-verify releases have changed results before, so the version matters. The file [.github/requirements/pq-verify.txt](../.github/requirements/pq-verify.txt) holds the pin this release was tested with:

```bash
python3 -m venv /opt/pqv
/opt/pqv/bin/python -m pip install --no-deps --only-binary=:all: --require-hashes -r pq-verify.txt
# pq-verify.txt:
# pq-verify==2.19.0 --hash=sha256:2d492b621bde43fe0fe668bda0481a52568deb9176a5d92c3c6b5e08b45c2139
```

What PQ-Proof does around it:

- It accepts one audit option, `--audit-kem`, `--audit-dsa`, `--audit-slhdsa` or `--audit-contained`, each with a path and a parameter set, plus symbol, timeout and sample-count options (`--symbol-prefix`, `--kem-keypair`, `--dsa-abi`, `--accumulated`, `--audit-timeout`, `--constant-time` and the like). A smaller sample count (`--accumulated 1`, for example) audits less while the scope can still read complete, so every option you add besides the audit is shown next to the audit in `receipt.html`, `tables/report.md` and the console, and stays in the argv of the receipt. It refuses `--live` (network vectors), `--vector-dir`, `--json`, `--sarif`, `--prompt-out`, `--no-fail`, `--audit-harness`, `--audit-source`, other tasks, abbreviated option names and short options; a refused option is a usage error (exit 2) and pq-verify does not start.
- It splits the string with `shlex` and runs pq-verify without a shell, in an empty temporary folder, with `PQV_*`, `LD_*`, `DYLD_*`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP` and `PYTHONINSPECT` removed, and stops the process group after `PQ_VERIFY_TIMEOUT` seconds (1800 by default).
- It always adds `--require-full-coverage` and writes the report into the evidence folder. `artifacts/impl/pq-verify/log.json` keeps the argv, exit code, stdout and stderr, and `tools[]` lists the pq-verify executable with its SHA-256 and the version it prints. For a pip install that executable is a small launcher script whose SHA-256 depends on the virtual environment path, not on the pq-verify package, so it names the file that ran, not the code. The pinned install above is what ties the run to tested pq-verify code.
- `pqproof doctor` runs `pq-verify --version` on the pq-verify it finds, to show the version. That call loads no library.

## Results

The verdict is fail if a check fails, otherwise undecided if a check is undecided, otherwise pass. "Needs review" and "not applicable" do not change it.

| Check | Pass | Needs review | Fail | Undecided |
|---|---|---|---|---|
| `i-kpqc` | every parameter set matches only accepted versions, every changed signature is rejected, the self-check passed | an old version or a known variant matches, or the answers cannot tell an accepted version from another one (decaps and verify answers only) | no version matches every item, or a changed signature is accepted; the first mismatching item and field are named | a required answer is missing, the answers name another sheet, an unknown parameter set, a file over 64 MiB, a short `.rsp`, or a failed self-check |
| `i-nist` | exit 0, `VERIFIED`, a report bound to the library PQ-Proof hashed (a regular file), a complete scope, every check passed | never | exit 1, `FINDINGS PRESENT` and a stage below its total; when only the FIPS 203 input-check stages fail, the detail says the key checks are not done inside the API | input error, `DEGRADED RUN`, a partial scope, a check that could not run (`--constant-time` without valgrind), no executable, a target PQ-Proof could not hash, a timeout, a broken report or another report schema |

Exit codes: 0 pass (also with a check that needs review), 1 fail, 2 usage error, 3 undecided, 4 tool or tool data error, and 5 for a pass that needs review under `FAIL_ON_REVIEW=1`.

**In CI, set `FAIL_ON_REVIEW=1`.** "Needs review" covers a match with an old version or a known variant only, so without it an implementation that matches no accepted version still exits 0 and prints `VERDICT=PASS (needs review: i-kpqc)`; the console adds a line that says so. A job that reads only the exit code or the `VERDICT` line should run `FAIL_ON_REVIEW=1 pqproof impl judge answers.json` and treat exit 5 as a stop.

**`i-nist` follows pq-verify.** pq-verify reports `FINDINGS PRESENT` for a library that does not run the FIPS 203 key checks (`ekCheck`, `dkCheck`, `edgeEk`, `edgeDk`) inside its API, and `i-nist` fails with it, even when every KAT stage passes. PQClean ML-KEM-768 clean is one such library: FIPS 203 lets those checks sit outside the API, but then the caller must run them. The detail line names this case. If your design leaves the checks to the caller, record that decision next to the receipt; PQ-Proof does not turn the failure into a pass.

The evidence is format 4 (`schemas/receipt-v4.schema.json`) with `params.mode` `impl`. Besides `receipt.json`, `receipt.html`, `tables/report.md` and `tables/impl.csv`, it keeps the answer, the answer key and the question sheet under `artifacts/impl/`. `pqproof --verify <folder>` always judges the copied answer again with its own rules; there is no path that skips that. When its own KAT list is the one the receipt used, the answer key copy must be byte for byte the key it builds. Otherwise the receipt's KAT list must be one recorded in `scan/ruleset.json` and every version in the copy must match its own list; a copy it cannot trust fails the check. The accepted versions must be what its `kpqc` profile gives. For a receipt written with another `pqlite/impl.py` (another ruleset, or a `+modified` one), the statuses must match, while the wording may differ. Like a two-tree receipt, `impl.input.path` records the absolute path of the answer file, so check the folder before you share it.

## Limits

- **A KAT match, not a certification.** There is no official KpqC test vector program like NIST ACVP yet. The result says which published reference KAT your answers match. It does not say the implementation is correct in every case, and it is not a KCMVP validation.
- **The reference versions may change again.** The reference KATs already changed after the January 2026 final release (the table above). A new version means a new KAT list and a new ruleset (below); until then a newer reference fails or needs review.
- **`--verify` reads copies.** It judges the copied answer and the copied pq-verify report again. It does not run pq-verify again or hash the library again, so the library SHA-256, the pq-verify executable record and the run record are what the original run wrote. The evidence is not signed: someone who rewrites every copy and every hash gets a folder that verifies, with another `receipt_id`. Compare `receipt_id` with the one you received through a channel you trust.
- **Five records per version in the sheet.** The `.rsp` path compares all 100.
- **No negative decapsulation items.** The decaps items use valid ciphertexts only, so how an implementation handles a broken ciphertext (implicit rejection, or the all-zero secret NTRU+ returns) is not checked. Signatures do get a changed-byte item.
- **Versions that answer alike.** Builds of SMAUG-T 1.1.1 and 1.2.0 give the same decaps answers, and builds of HAETAE 1.1.2 and 1.2.0 the same verify answers. Without `derand` answers or a `.rsp`, the judge cannot tell them apart and says so (needs review).
- **The answers come from your harness.** PQ-Proof cannot see that they came from the build you ship. Keep the harness run with your build record. Production libraries without the KAT DRBG (Bouncy Castle, for example) answer decaps and verify only.
- **A signature pass rests on true or false answers.** Without `derand` answers, a signature parameter set passes on its `verify` answers alone: twenty true or false values for five records, half of them on a signature with one changed byte. The KATs are public and the item ids name the version and the changed signature, so such answers can be written without any implementation; they show what a harness reported, not that an implementation exists. KEM parameter sets need only the `decaps` answers, so an implementation with wrong key generation or encapsulation passes when it gives no `derand` answers. Give `derand` answers, or a full `.rsp`, for a stronger match.
- **No timing, side channel or performance checks.** The pq-verify bridge reports what pq-verify reports about your library with its pinned vectors; that is not a certification either.

## Updating the version list

When a reference version changes, the KAT list changes with it:

1. Edit `SOURCES` and `VARIANTS` in `tools/make_kat_manifest.py`: URL, commit, archive SHA-256 and size, and the official hash when the publisher gives one.
2. Download the archives into an empty folder and run `python3 -I tools/make_kat_manifest.py <files>`. It identifies each file by SHA-256, reads only the `.rsp`, license and `rng.c` members without unpacking or running anything, and rewrites `scan/kat-kpqc.json` and `scan/kat/`. `--check` confirms that the same files give the same bytes.
3. If the accepted version should move, edit `impl_accept` in `scan/profiles.json`.
4. These are rule files, so add a new ruleset entry to `scan/ruleset.json` (`python3 pqlite/version.py --ruleset-json` prints the hashes) and write the verdict impact in `CHANGELOG.md`: the same answers can now get another result, so it is a verdict change and bumps MINOR.
5. Run `STRICT=1 bash prove.sh --unit`, the mutation suite and the KpqC end-to-end workflow (`.github/workflows/kpqc-e2e.yml`), which builds pinned reference implementations from GitHub and runs this whole flow on them.
