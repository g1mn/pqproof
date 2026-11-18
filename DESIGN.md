# Design of PQ-Proof

PQ-Proof takes a codebase before and after a post-quantum migration and checks whether the migration is finished. It looks for classical public-key code left without a recorded reason, checks that ML-KEM-768 and ML-DSA-65 are in use, and checks that no TLS setting got weaker along the way. It runs offline and calls no AI model. It reads the code it inspects and never runs it. Each run leaves verification evidence: the raw tool output, a CBOM for both versions, and an evidence hash that anyone can recompute.

I built it for the finals of 2026년 양자내성암호 전환 해커톤 (2026 Post-Quantum Cryptography Transition Hackathon), organized by the Ministry of Science and ICT and hosted by KISA. I won 대상 (Grand Prize), given as the 과학기술정보통신부 장관상 (Minister of Science and ICT Award). The English names are my translations. An AI coding agent made the code changes, and PQ-Proof (then just `prove.sh`) was the completion check in its pipeline. This repository is based on the version that ran in the finals, minus contest material, local paths and contest-only report tables. I fixed two flaws found in testing after the finals and closed two gaps that a review of those fixes turned up; [Changes since the finals](#changes-since-the-finals) lists what moved. This is a participant's own tool; the organizers have not reviewed or endorsed it.

Some parts come from an earlier hackathon version of PQ-Proof (`g1mn/pq-proof` at commit `7b7803f`, MIT). Those files say so in their first line.

This page describes what one run decides, the rules behind each check, how the verification evidence and its evidence hash are built, and what the tool cannot tell you. The code is the reference: `prove.py` for the checks, `pqlite/allowlist.py` for the allowlist, `pqlite/receipt.py` for the evidence. The [site](https://g1mn.github.io/pqproof/) has the overview, the public test results and the KISA mapping. [CHANGELOG.md](CHANGELOG.md) lists releases and their verdict impact.

## Install and first run

You need Python 3.9 or later (standard library only), bash 3.2 or later and OpenSSL. The TLS cross-check wants OpenSSL 3.5 or later; with an older OpenSSL or LibreSSL the run still works and records the cross-check as not possible. Go 1.27 or later is only needed to build the TLS probe. On Windows, use WSL.

```bash
pip install pqproof
pqproof doctor        # lists the external programs it found and what is missing
```

`pqproof` and `bash prove.sh` run the same files and read the same environment variables (`pqproof --env` lists them). To try the bundled examples, clone the repository:

```bash
git clone https://github.com/g1mn/pqproof && cd pqproof
bash prove.sh examples/classic examples/pqc
```

`examples/classic` is a small Java and Python "sealer": it wraps a data key with RSA-OAEP and signs with ECDSA P-256. `examples/pqc` is the same code moved to ML-KEM-768 (with AES-256-GCM) and ML-DSA-65. Both versions compile, and both Python tools run; the Java classes have no `main`. The migrated version needs JDK 24 or later, and pyca/cryptography 48 or later on OpenSSL 3.5 or later. The tool prints one line per check, in Korean, and then the verdict:

```
[a-input] 통과  공통 파일 5/5 · 원본 막는 위치 13 · 원본 공개키 code 17 · TLS 실측 대상 0
[a-cbom] 통과  막는 위치 0곳(원본 13) · 허용 0 · 주석·테스트 0 · 확인 4
[b-weakening] 통과  deny 0 · 본 파일 4
[b-tls] 해당 없음  TLS 서버·클라이언트 신호 0
[c-classic] 통과  공개키 code 0(원본 17) · 보안레벨 3 미만 0 · 레거시 쓰기 0
[c-expect] 통과  E-MLKEM768 3 · E-MLDSA65 2
[r-review] 통과  0건
[r-allow] 해당 없음  허용 목록 없음
VERDICT=PASS  receipt_id=78c2995e6ef5…
검사 8개: 통과 6 · 해당 없음 2 (통과로 세는 것은 '통과'뿐) · 도구 0.1.0 · 규칙 묶음 1 · 증적 형식 2
```

(통과 = pass, 실패 = fail, 해당 없음 = not applicable, 검토 필요 = needs review. The last line counts the checks per state and names the tool version, ruleset and evidence format.) The `receipt_id` changes on every run (see [Outputs](#outputs)). Give it `examples/classic` on both sides and the run fails, listing each `file:line` that still uses RSA, ECDSA or P-256.

Exit codes: 0 pass, 1 fail, 2 usage or input error, 3 undecided.

## One run

```
bash prove.sh <original folder|zip> <fixed folder|zip>
```

1. **Prepare.** Unpack zip inputs, hash both trees, load the allowlist and the data exclusions.
2. **(a) CBOM.** Run `scan/cbom-scan.sh` and `pqlite/scan.py` on both trees and merge their rows by `path:line`.
3. **(c) Classical-line count.** Run `scan/residue.sh` on both trees and read its per-rule counts and line lists. Then resolve the allowlist against the original as well and count, per entry, the classical lines it covers there (see Allow rules).
4. **(b) TLS weakening.** Compare every changed file before and after with `pqlite/verify.py`.
5. **(b) TLS probe.** Only with `TLS_TARGETS`: check the probe against reference servers, then measure each target.
6. **Checks.** Turn the numbers into eight checks and one verdict.
7. **Evidence.** Write `receipt.json`, `receipt.html`, the tables and `deck.json`, then run the same verification as `--verify` on the folder just written.

The inputs are untrusted. The tool reads files and never runs them. zip entries with absolute paths, `..` or backslashes are refused, symlinks inside a zip are recorded by name and not unpacked, and unpacking stops past 1 GiB. A file over 1 MiB is skipped whole by `scan.py`, the weakening check and the allowlist check; the grep-based `cbom-scan.sh` and `residue.sh` still read it. The input tree leaves out `.git`, `node_modules`, `target`, `build`, `__pycache__`, `.gradle`, `.idea`, `__MACOSX`, `.venv` and `venv`. `scan.py` has its own list: `.git`, `vendor`, `node_modules`, `target`, `build`, `.gradle` and `__pycache__`. Only `cbom-scan.sh` (grep, awk, openssl) and `residue.sh` (grep, awk) run as subprocesses, plus `tls_probe` and `openssl s_client` for the TLS step.

## The eight checks

| Check | Fails when | Undecided when |
|---|---|---|
| `a-input` | never | fewer than half of the original's files exist at the same path in the fixed tree; or the original shows no blocking location, no classical code line and no TLS target, so there was nothing to check |
| `a-cbom` | the fixed CBOM has at least one blocking location | `cbom-scan.sh` did not finish cleanly |
| `b-weakening` | a changed file adds a weakening construct or removes a protection | never |
| `b-tls` | a target does not negotiate `X25519MLKEM768` when offered only that group, or the old client (`X25519,P-256`) is accepted under `CLASSIC=deny` or refused under `CLASSIC=allow`, or `EXPECT=cert` and the certificate key is not ML-DSA-65 | the code shows a TLS server but no `TLS_TARGETS` were given; the original had a TLS server and the fixed tree has none; the reference controls failed; or OpenSSL 3.5 disagrees with the probe |
| `c-classic` | the fixed tree has classical code lines left in the nine families after allowed lines are taken out, any ML-KEM-512 or ML-DSA-44 (below NIST security category 3), or a write inside a `Legacy*.java` file | `residue.sh` did not produce a summary |
| `c-expect` | a requested algorithm (`kem` for ML-KEM-768, `sig` for ML-DSA-65) has zero code lines, or `tls`/`cert` was requested and `b-tls` failed or did not apply | the count is missing, or `b-tls` is undecided |
| `r-review` | never | never |
| `r-allow` | `REQUIRE_REVIEW=1`, and either an allowlist entry that allows a line or sends one to review has no accepted review record (see Human review below), or an entry is unused (see Unused entries below) | never |

Besides pass, fail and undecided, a check can end as "needs review" or "not applicable". "Needs review" does not change the verdict. It shows up in `a-input` (a file that held a blocking location disappeared), `a-cbom` and `c-classic` (an allowlisted line sits on a write path), `b-tls` (only client-side TLS), `r-review` and `r-allow` (an allowlist entry in use has no review record, or an entry is unused). When the verdict is pass, every place that prints the verdict adds what is left for a person: removed verification calls (`r-review`, from evidence format 2), entries not yet reviewed, write paths left for review inside allowed ranges, and unused entries. The console shows `VERDICT=PASS (2 allowed entries not yet reviewed by a person; 2 write paths in allowed ranges need review; 1 allowlist entry unused in the fixed tree)`, and `report.md`, `receipt.html`, `tables/fragment.html`, `deck.json` (`verdict_text`, `verdict_text_en`) and `evidence-fragment.json` show 통과(허용 2건 사람 확인 전 · 허용 범위 쓰기 경로 2곳 검토 필요 · 안 쓰인 항목 1건). Each part appears only when its count is above zero. A `verify()` reduced to `return true` gives `VERDICT=PASS (2 removed verifications need review)`: the dropped call and the body that only returns success. Before 0.1.0 that pass carried no note.

The verdict is fail if any check fails, otherwise undecided if any check is undecided, otherwise pass. The exit code follows: 0, 1, 3. A failed self-verification of the written evidence also gives 3.

### Skipped is not passed

A check that did not run is not a check that passed. Every check ends in one of five states: pass, fail, needs review, undecided or not applicable, and only pass counts as passed. When a check cannot run, for example because no TLS address was given or there is no allowlist, the evidence keeps it by name as not applicable or undecided. A pass verdict means that no check failed or stayed undecided. The checks that did not apply are listed and never folded into the pass. After the verdict the console prints how many checks ended in each state, the SARIF file lists those checks under `notCountedAsPass`, and the GitHub Action prints them at the end of the job summary. The tests follow the same rule: the unit tests, the self-test and the mutation runner count skipped cases apart, and with `STRICT=1` (CI) a skipped case fails the run.

### What counts as blocking

A CBOM row blocks when it is a quantum-breakable public-key use (`cbom-scan.sh` threat "쇼어로 깨짐", which means broken by Shor's algorithm, or a `scan.py` row with threat `shor` or `weak-pqc`; a TLS group setting that leaves out hybrid groups is a `shor` row) and none of these apply:

- the line is a comment or sits in a test path (the list in `scan/test-paths.ere`, see Test paths below);
- `SCOPE=kex` and the row is not about key exchange (it is kept as "out of scope");
- an allow rule below covers it.

A runtime base image whose OpenSSL is too old to offer `X25519MLKEM768` blocks only when something in the tree terminates TLS with the system OpenSSL (nginx, HAProxy, Apache, Python). Otherwise it stays a row to check.

`a-cbom` and `c-classic` look at the same code with different tools on purpose. In testing, `cbom-scan.sh` missed a ternary such as `getInstance(flag ? "RSA" : "EC")` that `residue.sh` caught. The tool reports zero classical lines only when both agree.

### The classical families

`scan/residue.sh` counts code lines for these rules. Comments and docs are counted apart as `comment`, and code lines in test paths as `test`. The first nine rules make up `c-classic`.

| Rule | Matches |
|---|---|
| `G-RSA` | RSA anywhere in code |
| `G-EC` | EC, ECDSA, ECDH, EC key and parameter classes |
| `G-CURVE` | secp*, prime*v1, P-256/384/521, brainpool, EC OIDs |
| `G-OAEP-PKCS1` | OAEP, MGF1, PKCS#1, PSource |
| `G-CLASSIC-SIG` | `withRSA`, `withECDSA`, `withDSA`, RSASSA, RSA-PSS |
| `G-JWT-ALG` | RS256/384/512, ES*, PS* |
| `G-EDDSA` | Ed25519, Ed448, EdDSA, Curve25519 |
| `G-X25519` | X25519, X448, XDH, ECDH, KeyAgreement (same line with ML-KEM counts as hybrid) |
| `G-DH-DSA` | DiffieHellman, `"DH"`, `"DSA"`, ElGamal, ECIES |
| `G-WEAK-PQC` | ML-KEM-512, ML-DSA-44, Kyber512, Dilithium2 |
| `LW-legacy-write` | encryption, signing, key generation or file writes inside `Legacy*.java` |
| `E-MLKEM768`, `E-MLDSA65` | ML-KEM-768 and ML-DSA-65 in code outside test paths |

`G-AES128` is also printed for information. It does not take part in any check.

### Test paths

One file, `scan/test-paths.ere`, decides what counts as test or example code. `cbom-scan.sh` (comment flag "테스트·예제"), `residue.sh` (`test` lines), `pqlite/scan.py` (skips Go and Java test files) and the TLS signal check in `prove.py` all read it. Its first non-comment line is the test rule and its second is a main-source marker, both POSIX ERE, matched against `/` plus the path inside the tree. When the marker (`/src/main/`) matches, only the part of the path up to the marker's first `/` goes to the test rule. So nothing under `src/main/` is a test path, whatever its package or class name (`com/example/`, `SelfTest.java`), while `tests/it/src/main/` still is. The test rule covers the folders `test`, `tests`, `__tests__` and `testdata` at any depth, the folders `spec`, `fixtures`, `mock(s)`, `example(s)` and `sample(s)` only at the top of the tree, and the file names `*_test.go`, `test_*.py`, `*_test.py`, `conftest.py`, `*Test.java`, `*Tests.java`, `*Test(s).kt`, `*.test.*`/`*.spec.*` for JavaScript and TypeScript, and `test.js`-style files. Each run copies the file to `artifacts/test-paths.ere`, passes that copy to both scanners (`TEST_PATHS`), and records its hash. A scanner run without the file stops with a usage error. A file with only the first line works as before, with no marker.

Classical code lines in test paths do not count toward `c-classic` or `a-cbom`. `residue.sh` lists them as `TEST` lines, `c-classic` names the first few, and the evidence keeps the count and up to 60 locations (`java.*.tests`; `cbom.*.tests` counts CBOM locations flagged as tests). ML-KEM and ML-DSA lines in test paths do not count for `c-expect`.

The finals version decided this in three places. `cbom-scan.sh` flagged the folder names above at any depth plus the test file names. `pqlite/scan.py`, which feeds the Java and Go rows of `a-cbom`, skipped only Java under `src/test`, `test` or `tests` or named `*Test`, and Go `*_test.go`. `residue.sh` skipped only `src/test`, `test` and `tests`. A negative test in `seal_test.go` therefore passed `a-cbom` and failed `c-classic`. I merged them into one rule. The first merged rule matched every folder name at any depth, and an independent review found that it turned `src/main/java/com/example/`, the default Spring package, into test code: classical Java there passed and a Java-only migration there failed `c-expect`. The main-source marker and the top-of-tree limit for the example-style folders fix that. Skipping more paths risks missing production code kept in a folder named like a test folder. Skipping fewer fails migrations that test the rejection of old keys and pushes test code into the allowlist. The skipped lines stay in the output, so a wide rule costs less than a narrow one. A custom `RESIDUE` script keeps its own test rule unless it reads `TEST_PATHS`.

## Allow rules

A migration often has to keep a few classical lines, for example to read data written before the change. The tool lets a line out of the blocking count only when it can record why. Every allowed line appears in the evidence with its reason, in `receipt.json` under `allowlist` and on the HTML page.

1. **Allowlist** (`ALLOW=<file>`; with an `<W>/orig` input the tool also looks for `<W>/notes/unconverted.json`). Each entry has `where`, `why`, `kind` and an optional `what`.
   - `where` can be `file:line`, `file:start-end`, `file:15,24-40`, a path, or a glob. A bare file name must match exactly one file in the fixed tree. Container paths are resolved against the app root from `recon.json`.
   - An import line counts with an entry when every code line that uses the imported name is allowed. One use elsewhere keeps the import counted. Wildcard imports are never covered.
   - An entry is invalid, allows nothing and leaves a warning when `where` or `why` is empty, the file is missing, the name matches several files, a line range runs past the end of the file, or a glob catches several code files. One bad place invalidates the whole entry, because shifted line numbers should not be trusted.
   - A place the entry itself marks as outside the tree (outside the container or app folder) allows nothing and gives no warning.
   - **Human review.** `reviewed_by` (a name or account) and `reviewed_at` (ISO 8601: `2026-11-18`, `2026-11-18T10:30`, `2026-11-18T10:30:00+09:00`) record who read the reason and when. An entry with either field uses its own pair. A file of the form `{"unconverted": [...]}` can carry one pair at the top for the entries without one. The tool applies that top pair only with a matching `reviewed_digest`: the first 16 hex digits of SHA-256 over the `where`, `what`, `why` and `kind` of the entries it covers (trimmed, as a JSON array with sorted keys and no spaces). The console prints the current value, and `receipt.json` keeps it as `allowlist.top_digest`. Adding or editing an entry, or removing an entry's own pair, changes the value, and every entry under the top pair then counts as not reviewed. An entry's own pair can carry a `reviewed_digest` of that one entry; if present, it has to match. With neither field (or both `null`), the entry is not yet reviewed. An empty or whitespace-only name, a name with control, invisible or bidirectional characters, only one of the two fields, a `reviewed_at` that is not a real date, or a digest that does not match gets a warning and counts as not reviewed. The entry itself stays valid, so a mistake in a review field does not change which lines are allowed. A `reviewed_at` more than a day in the future passes with a warning. The tool counts entries that allow a line or send one to review without an accepted pair in `allowlist.unreviewed`; `r-allow` then needs review, or fails under `REQUIRE_REVIEW=1`. Hybrid and name-rule lines (rules 3 and 4) are not allowlist entries, so they are not counted.

     ```json
     {"reviewed_by": "j.kim", "reviewed_at": "2026-11-18T10:30:00+09:00", "reviewed_digest": "f80af1efdb7c95c5",
      "unconverted": [{"where": "Box.java:11-15", "why": "reads records sealed before the migration", "kind": "fallback"}]}
     ```
   - **Unused entries.** A valid entry that covers no classical line in the fixed tree gets status `unused`. The list is written for the fixed tree, but it applies to whatever tree it is run against, so such an entry allows the classical lines in its range when someone runs the list against the original. The tool therefore resolves the same list against the original too (it never judges the original) and records, for every entry, `lines_fixed` (classical lines it covers in the fixed tree, the same lines as `allowed` plus `review`) and `lines_orig` with the locations in `orig`. Each unused entry gets a warning that names the original lines it would cover. `allowlist.unused` and `allowlist.unused_orig_lines` hold the totals, and those original lines count as not reviewed. An unused entry makes `r-allow` need review, or fail under `REQUIRE_REVIEW=1`, whatever its review fields say. An entry that is invalid, excluded or outside the tree in the fixed tree allows nothing there, but it can be valid in the original: an entry for a file the fix deleted, or for lines past the end of a file that got shorter. When such an entry covers classical lines in the original it counts as unused too (its status stays; see `counts_unused` in `pqlite/allowlist.py`), with the same warning, totals and `r-allow` effect. The first version of this fix only warned about it, so a reviewed entry for a deleted file passed under `REQUIRE_REVIEW=1` and still hid the original's lines.
   - **Decision: no automatic blocking.** The tool does not turn those lines back into blocking locations. In one run, the lines an unused entry would hide are in the original, and the original is not judged. If the original goes in the fixed slot, the entry matches lines there and the list holds nothing that says which tree it was written for. So the tool flags the entry where it is unused and leaves deleting it to the person; `REQUIRE_REVIEW=1` enforces that. In a unit test (`tests/test_allowlist.py`, masked case), deleting the unused entry brings the original's blocking locations back. A list without unused entries can still allow the same kept lines in another tree, because those lines exist in both.
2. **Write path.** When an allowed line, or one of the three lines below it within the same function, creates a key, a signature or ciphertext (`ENCRYPT_MODE`, `WRAP_MODE`, `initSign`, `KeyPairGenerator`, `.sign(`, `.encrypt(`, `generate_private_key`, `GenerateKey(`, `createSign(`, `publicEncrypt(` and similar), the line goes to "needs review" instead of allowed. `allowlist.write_review` counts these locations across all entries, and the verdict line shows the count. They do not change the verdict, because a key-generating line can belong to a hybrid or a bootstrap step that a person has to judge.
3. **Hybrid.** A key-exchange line (X25519, X448, ECDH, KeyAgreement, `.exchange(`) counts as the classical half of a hybrid when non-comment ML-KEM code sits in the same function, within 12 lines either way and stopping at the next function header. A line with only a curve name also needs a key-exchange marker inside that window. Lines with signature markers (ECDSA, `Signature`, `sign(`, `verify(`, RSA, Ed25519, OAEP) never count. ML-KEM that appears only in a comment never counts.
4. **Name rule.** A line in a `Legacy*.java` file, or a line that contains `legacy`, is allowed when it has no write operation. These lines are listed apart (`allowlist.legacy`, and kind `legacy-name` in `deck.json`) so that nothing leaves the count without showing up.
5. **Weak PQC.** ML-KEM-512 and ML-DSA-44 are never allowed, listed or not.

**Runtime data.** `EXCLUDE="data/** *.db *.log"` and the `DATA_DIR` in `recon.json` (when it sits inside the app root) keep runtime data out of the CBOM, the counts and the weakening check. The input tree hash still covers those files. Code, config and build files (`.java`, `.py`, `.yml`, `.properties`, `Dockerfile`, `go.mod`, `package.json` and so on) are checked even when a glob matches them, so `EXCLUDE='src/**'` cannot hide classical code. Globs that would drop everything (`*`, `**`, `/`) are refused, and a run with nothing left to check is a usage error.

## Outputs

Each run writes a new folder (`OUT=...`, default `./proof-out-HHMMSS`) and refuses to reuse an existing one.

- `receipt.json`: the verification evidence. It records the tool version, the ruleset and the evidence format (see [Versions in the evidence](#versions-in-the-evidence)), the inputs (absolute path, tree SHA-256, zip SHA-256), every tool with its path and SHA-256, the parameters, each check with expected and actual values, the start and end time of each step, and every output file with its size and SHA-256.
- `receipt.html`: the same evidence as one self-contained page, with no external references.
- `deck.json`: a short summary for slides or a dashboard.
- `evidence-fragment.json`: the main numbers in a flat form (classical line count, PQC algorithms found, TLS group, verdict and check results), for copying into another record.
- `tables/cbom-orig.csv`, `tables/cbom-fixed.csv`: the CBOM of both versions, one row per location, with its verdict and reason.
- `tables/report.md`: the check table and what is left after the migration, ready to paste into a document. `tables/fragment.html` is the same for an HTML page.
- `tables/summary.csv` (the checks), `tables/java.csv` and `tables/java-usage.csv` (classical lines per rule and per location), `tables/tls.csv` (TLS results).
- `artifacts/`: raw scanner output, the copies of `residue.sh` and `scan/test-paths.ere` that ran, TLS probe transcripts, the weakening result and the list of changed files.

The output names absolute paths on your machine: the input folders, the tools and the output folder in `receipt.json` and `receipt.html`, and the scanned folder and command line at the top of each CBOM report. Check them before you hand the folder to someone else.

The evidence hash is the `receipt_id` field. It is the SHA-256 of `receipt.json` without that field, written in RFC 8785 canonical form (JSON Canonicalization Scheme). `bash prove.sh --verify <folder>` recomputes it, checks every file hash and the unpacked input tree, rebuilds the HTML page and `deck.json` to compare, and checks that `evidence-fragment.json` and `tables/report.md` give the same verdict. Anyone can edit the files and write fresh hashes, so the hash only tells you something when you compare it with a value from a place you trust, such as the console output of the run or a submission record.

Each run gets its own evidence hash. The evidence holds the run times, the absolute input paths and CBOM file names with a time stamp, so running the same inputs again gives the same verdict and check results but a new evidence hash.

## Verification evidence and the evidence hash

`receipt.json` is the verification evidence for one run. It holds:

- `inputs`: for each side, the absolute path, folder or zip, the zip SHA-256, the file count, the skipped folders and the tree SHA-256;
- `format_version`, `tool_version`, `ruleset_version` and `ruleset_sha256` (evidence format 2, see below);
- `tools`: name, path, version and SHA-256 of `cbom-scan.sh`, the `residue.sh` copy that ran, `scan/test-paths.ere`, `prove.sh`, `prove.py` and each `pqlite/` module, the `tls_probe` binary and source, Python and OpenSSL;
- `params` (including `require_review`), `changed` (added, removed and modified files), `cbom` (with `tests`), `java` (the residue counts, with `tests`), `tls`, `weakening`, `excluded`, `test_paths` (the copied list and its SHA-256);
- `allowlist`: each entry with its status, the lines it allowed, `lines_fixed`, `lines_orig` and `orig`, `reviewed_by` and `reviewed_at` (`null` when missing or not accepted), `reviewed_via` (`entry`, `top` or `null`) and `digest` (the entry's current `reviewed_digest` value), plus `unreviewed`, the number of entries in use without an accepted review, `unused`, `unused_orig_lines`, `write_review`, and `top_digest`, the current value for a pair at the top;
- `checks` and `verdict`, `timeline` (UTC start and end of each step);
- `artifacts`: every file the run wrote under `artifacts/` and `tables/`, plus `evidence-fragment.json`, with its size and SHA-256. Every field that names a file has a `*_sha256` partner.

**Tree hash.** List every regular file under the root (skipping the folders above and `.DS_Store`) as `(relative path, SHA-256 of the content)`; a symlink is recorded as `symlink:<target>`. Sort the list, then hash the concatenation of `path + "\0" + digest + "\n"` with SHA-256.

**Evidence hash.** Take `receipt.json` without the `receipt_id` field and write it in RFC 8785 canonical form: object keys sorted, no whitespace, UTF-8, numbers in ECMAScript notation. SHA-256 of those bytes is the evidence hash, stored as `receipt_id`. All keys in the file are ASCII, so code-point order and the UTF-16 order that RFC 8785 asks for give the same result. Values may contain Korean text, which does not affect key order. The number formatting follows the test vectors in `tests/test_receipt.py`, which come from PQ-Proof so that a verifier in another language gets the same hash.

The evidence hash names one run. `receipt.json` also holds the run times (`started_at`, `finished_at`, `timeline`), the absolute input and tool paths and CBOM file names with a time stamp, so two runs on the same inputs give different evidence hashes. The verdict and the check results come out the same.


**Recheck.** `bash prove.sh --verify <folder>` (or `python3 -I -B pqlite/receipt.py verify <folder>`) checks:

1. `receipt.json` fits the schema, and its format is one this tool reads (1 or 2);
2. `receipt_id` equals the recomputed evidence hash, and in format 2 `ruleset_sha256` equals the hash recomputed from the rule files in `tools`, with a `ruleset_version` that `scan/ruleset.json` gives that hash;
3. every listed file has the recorded size and SHA-256, and the folder holds no other file (apart from `receipt.json`, `receipt.html`, `deck.json` and the unpacked inputs under `in/`);
4. every `*_sha256` partner names a listed file with that hash, and the `residue` entry in `tools` has the hash of the residue copy under `artifacts/` (`java.script_sha256`);
5. for zip inputs, the unpacked tree under `in/` hashes to the recorded tree SHA-256;
6. the verdict and the check statuses agree with the numbers they come from, including `allowlist.unreviewed` against the entries, `r-allow` against that count, the unused entries and `require_review`, each entry's `lines_fixed` against its `allowed` and `review` lines and its status, `lines_orig` against `orig`, and `unused`, `unused_orig_lines` and `write_review` against the entries (an entry counts as unused when its status is `unused`, or `invalid`, `excluded` or `outside` with `lines_orig` above 0). Newer evidence, the kind with `test_paths` or `lines_fixed`, must keep `unused`, `unused_orig_lines` and `write_review`; deleting them to look like older evidence fails;
7. each allowlist entry's `reviewed_by`, `reviewed_at` and `reviewed_via` match what the copy of the allowlist under `artifacts/` gives;
8. `receipt.html` and `deck.json` are byte-for-byte what the evidence renders to;
9. for newer evidence, `evidence-fragment.json` and `tables/report.md` give the same verdict (and, in the fragment, the same check statuses) as `receipt.json`. `--verify` does not rebuild those two files, so editing only `receipt.json` to change the verdict shows up here.

A hash shows that a file is the one the evidence describes. It does not show who produced it: anyone can change a file and write new hashes. Compare `receipt_id` with a value from a place you trust, such as the console output of the run or a submission record.

### Versions in the evidence

From evidence format 2 (0.1.0), `receipt.json` also records:

- `format_version`: 2. Evidence without this field is format 1, written by the public copies before 0.1.0.
- `tool_version`: the package version, read from `src/pqproof/__init__.py`, the one place the version is set.
- `ruleset_version` and `ruleset_sha256`: which rules judged the run. The ruleset is six files: `scan/cbom-scan.sh`, `scan/residue.sh`, `scan/test-paths.ere`, `pqlite/scan.py`, `pqlite/verify.py` and `pqlite/allowlist.py`. Together they hold the detection patterns, the test-path rule, the allow rules and the TLS-weakening rules. `ruleset_sha256` is the SHA-256 of one line per file, `path + "\0" + SHA-256 + "\n"`, sorted by path, over the files that actually ran. `scan/ruleset.json` gives each published hash a name. A run with a changed rule file, a custom `RESIDUE` or another `CBOM_SCAN` is named `<current>+modified`.

`--verify` refuses a format it does not know (`format_version` above 2) and says to use a newer pqproof.

### Older evidence

`--verify` keeps reading format 1. It accepts the note the first public copy wrote (it said 영수증, receipt) and rebuilds its `receipt.html` and `deck.json` with the words it used, so the byte-for-byte page check still applies, and its verdict line keeps its old text. `tests/golden/evidence/` holds one evidence folder from each of three earlier public copies and one from 0.1.0. `tests/golden/make_fixture.py` replaced local paths in them and recomputed the hashes. The verdicts, checks and counts are as those versions wrote them. Development builds between those versions are not supported.

## TLS targets

`b-tls` needs a running server. Build the probe once (static Go binaries, nothing downloaded), start the fixed service, and pass its address:

```bash
bash build-probe.sh      # bin/tls_probe-{darwin-arm64,linux-amd64,linux-arm64}
EXPECT=kem,sig,tls TLS_TARGETS="127.0.0.1:8443@localhost#/abs/path/ca.pem" bash prove.sh orig/ fixed/
```

Before it measures your server, the probe tests itself against two local reference servers, one hybrid and one X25519-only. If either control comes out wrong, the run is undecided. When the probe runs on the host (the default, `TLS_VIA=host`) and OpenSSL 3.5 or later is found, the tool repeats the hybrid-only handshake with `openssl s_client` and compares the group. The binaries are not in git; build them with `build-probe.sh`.

`bash prove.sh --help` lists every setting, including `SCOPE=kex` (key exchange only) and `TLS_VIA=container:<name>` (measure inside a container's network).

## SARIF and the GitHub Action

`pqproof sarif <output folder> [-o file] [--uri-prefix path/] [--anchor file]` (or `bash prove.sh sarif ...` from a clone) turns the evidence into SARIF 2.1.0 for GitHub code scanning. It first recomputes `receipt_id` and the SHA-256 of every file it reads. On a mismatch it writes nothing and exits 2. Fingerprints hash the rule, path, algorithm and snippet without the line number, so an alert survives a line shift.

| Rule | Source | Level |
|---|---|---|
| `a-cbom` | blocking rows of `tables/cbom-fixed.csv`, one result per location, and rows left for review (a write path inside an allowed range) | error; review rows warning |
| `c-classic` | `LEFT` lines of the nine public-key families, weak PQC, legacy writes and site rules in `artifacts/residue-fixed.txt`, minus allowed and hybrid lines | error; listed review lines warning |
| `b-weakening` | `weakening.deny` | error, at file level |
| `r-review` | `weakening.review` | warning, at file level |
| `r-allow` | allowlist entries in effect without review, unused entries, write paths | warning; error under `REQUIRE_REVIEW=1` |
| `c-expect`, `b-tls`, `a-input` | the check status | error on fail, warning on review or undecided, attached to the `--anchor` file or kept as a run notification |

Checks that ended not applicable or undecided are listed in `run.properties.notCountedAsPass`.

`action.yml` is a composite Action. Inputs: `original`, `converted`, `allow-list`, `require-review`, `expect`, `scope`, `classic`, `exclude`, `tls-targets`, `probe-bin-dir`, `output-dir`, `sarif-file`, `sarif-anchor`, `fail-on` (`not-pass`, `fail` or `never`) and `python`. Outputs: `verdict`, `evidence-hash`, `exit-code`, `output-dir` and `sarif-file`. Inputs reach the scripts only through environment variables. The Action runs `--verify` on the evidence it wrote and reports `error` if that fails. `examples/github-actions/pqproof-sarif.yml` judges a pull request against its base commit and uploads the SARIF file to code scanning.

## Tests

```bash
bash prove.sh --unit                 # unit tests
bash prove.sh --selftest             # end-to-end self-test, S1 to S10 below
python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json
bash scan/cbom-scan.sh --selftest    # scanner assertions
```

`--unit` and `--selftest` print `n 통과 · m 건너뜀 · k 실패` (passed, skipped, failed) and name each skipped case. Without the `tls_probe` binary the TLS unit tests and self-test case S6 are skipped; the SARIF schema test needs `jsonschema` and a schema file in `SARIF_SCHEMA`. With `STRICT=1` any skip fails the run, which is how CI runs them. `cbom-scan.sh --selftest` has 140 assertions. Four need OpenSSL 3.5 or later (an ML-DSA-65 certificate, an ML-KEM-768 key and an ML-KEM TLS server), and seven need `ssh-keygen`, `keytool` or Ed25519 support. A missing tool drops its assertions without a skip line (OpenSSL 3.0 runs 136), so CI counts the dropped ones as skipped, not passed: four are allowed on Ubuntu's OpenSSL 3.0 and none on macOS. None of the tests touch the network; the TLS cases use servers on 127.0.0.1. An installed package runs the same tests with `pqproof --unit`, `pqproof --selftest` and `pqproof mutations`.

### Self-test

`bash prove.sh --selftest` runs these cases offline. S1 to S3 use `examples/`, small trees written for this test.

| Case | Original | Fixed | Expected |
|---|---|---|---|
| S1 | `examples/classic` as a zip | `examples/pqc` | pass; blocking locations above 0 and then 0; classical lines above 0 and then 0; ML-KEM-768 and ML-DSA-65 above 0; no weakening |
| S2 | `examples/pqc` | the same plus a trust-all `TrustManager` | `b-weakening` fails |
| S3 | `examples/pqc`, and `examples/classic` for S3b | the same with `verify` reduced to `return true` | `r-review` needs review; in S3b the verdict is pass and the verdict line counts the removed verification calls |
| S4 (with S5, skipped and counted as skipped without the snapshot) | orders-edge snapshot (`ORDERS_EDGE` to use a full clone) | the scripted TLS fix from PQ-Proof | `scan.py` blocking rows go away; TLS signal without targets is undecided |
| S5 | the same | the same fix plus `InsecureSkipVerify` | `b-weakening` fails |
| S6 (skipped and counted as skipped without the `tls_probe` binary) | reference servers from `tls_probe` | | hybrid plus X25519 passes and X25519-only fails under `CLASSIC=allow`; hybrid-only passes under `CLASSIC=deny` with trust on first use; an ML-DSA-65 certificate passes `EXPECT=cert` |
| S7 | the S1 output | one byte changed in a table | the original verifies; the copy fails on that file's hash |
| S8 | `examples/classic` | `examples/pqc`, then the classic tree plus a file with two PQC names, with an allowlist whose entries are unused in `examples/pqc` | unused entries keep the pass but make `r-allow` need review and fail it under `REQUIRE_REVIEW=1`; the masked tree shows zero blocking locations and a write-path count on the verdict line, fails under `REQUIRE_REVIEW=1`, and fails once the unused entries are deleted |
| S9 | `examples/classic` | `examples/pqc` plus a Go test that builds a P-256 key to check that it is rejected | pass; the test lines are counted apart |
| S8f | `examples/classic` plus `tools/old_rsa.py` | `examples/pqc` (that file deleted), with a reviewed entry for `tools/old_rsa.py:1-44` | the entry is invalid in the fixed tree and counts as unused; `REQUIRE_REVIEW=1` fails |
| S10 | `examples/classic` with its Java moved to `src/main/java/com/example/` | (a) the same with only the Python migrated, (b) a Java-only tree migrated to ML-KEM and ML-DSA | (a) fails `a-cbom` and `c-classic`, with no test lines; (b) passes |

`tests/e2e_orders_edge.py` goes further: it builds the orders-edge Go service from a full clone (with `vendor/`), runs it, and measures the original, the fix and an injected weakening over real TLS.

### Mutation suite

`tests/mutations/mutations.json` plants defects in temporary copies of `examples/` and states the result each one must give. `run_mutations.py` runs the tool, compares, and also checks the SARIF output. A case it cannot set up (a stale anchor, a missing tool) is SKIP and never counted as passed; any SKIP or FAIL makes it exit 1. `--spec tests/mutations/selfcheck.json` checks the runner itself: a wrong expectation must come out FAIL and a stale fixture SKIP.

| Case | Planted defect | Must give |
|---|---|---|
| `c01-examples-classic-to-pqc` | control: examples/classic against examples/pqc (the migration done right) | verdict pass; `a-cbom` pass; `c-classic` pass; `c-expect` pass; `b-weakening` pass; `r-review` pass; no silent pass on the verdict line |
| `c02-examples-classic-to-classic` | control: examples/classic on both sides (nothing migrated) | verdict fail; `a-cbom` fail; `c-classic` fail; `c-expect` fail |
| `m01-trust-all` | trust-all TrustManager added to the converted Java code | verdict fail; `b-weakening` fail |
| `m02-verify-always-true` | signature verify() body replaced by return true | verdict pass; `r-review` review; `weakening.review` at least 1; the verdict line counts the removed verification calls |
| `m03-cert-check-off` | certificate check turned off in Python (check_hostname False, CERT_NONE) | verdict fail; `b-weakening` fail |
| `m04-tls-below-1-2` | TLS below 1.2 allowed (SSLContext TLSv1.1, setEnabledProtocols TLSv1) | verdict fail; `b-weakening` fail |
| `m05-d1-allow-masks-revert` | D1: allow-list entries hide classical code that came back (original plus two PQC names) | `r-allow` not pass or na; `allowlist.write_review` at least 1; `allowlist.unreviewed` at least 1; no silent pass on the verdict line |
| `m05b-d1-strict` | D1 under REQUIRE_REVIEW=1: the same masking fails | verdict fail; `r-allow` fail |
| `m05c-d1-unused-entries` | D1: entries that cover nothing in the converted tree are reported as unused | `r-allow` review or fail; `allowlist.unused` = 2; `allowlist.unused_orig_lines` at least 1 |
| `m06-d2-test-file-key` | D2: classical key inside a Go test file (_test.go) is counted apart, the same way by both scanners | verdict pass; `a-cbom` pass; `c-classic` pass; `java.fixed.tests.count` at least 1; `cbom.fixed.tests` at least 1 |
| `m06b-d2-control` | D2 control: the same Go key code outside a test file must fail both checks | verdict fail; `a-cbom` fail; `c-classic` fail |
| `m07-evidence-one-byte` | evidence: one byte of tables/summary.csv flipped | `--verify` fails and names `summary.csv` |
| `m08-evidence-number` | evidence: a count in receipt.json changed (13 blocking positions in the original written as 12) | `--verify` fails and names `receipt_id` |
| `m08b-evidence-verdict-rehashed` | evidence: failed run rewritten as pass and receipt_id recomputed | `--verify` fails |
| `m09-review-stamp-forged` | allow-list human review forged (reviewed_by and reviewed_at with a made-up reviewed_digest), REQUIRE_REVIEW=1 | verdict fail; `r-allow` fail; `allowlist.unreviewed` = 1 |
| `m09c-review-stamp-genuine` | control for m09: the same list with the digest the run printed passes under REQUIRE_REVIEW=1 | verdict pass; `r-allow` pass; `allowlist.unreviewed` = 0 |
| `m10-evidence-review-copy-rehashed` | evidence: review stamp added to the allow-list copy, its hash and receipt_id rewritten | `--verify` fails |
| `m11-exclude-hides-source` | EXCLUDE glob tries to hide the source folders of an unconverted tree | verdict fail; `a-cbom` fail |

### Golden verdicts

`tests/golden/verdicts.json` keeps the verdict, the check statuses and the main counts (blocking locations, classical lines per family, ML-KEM and ML-DSA lines, weakening hits, allowlist counts) of every tree case above, including the two plain example runs. `run_mutations.py --golden tests/golden/verdicts.json` fails when any of them moves. After an intended rule change, rewrite the file with `--write-golden` and record the change under "Verdict impact" in `CHANGELOG.md`.

## Versioning and maintenance

- Semantic Versioning. A change that can move a verdict (a detection pattern, the test-path list, an allow rule, a check added or removed) bumps MINOR while the version is 0.x, and MAJOR from 1.0. A change that moves no verdict bumps PATCH. Only the latest MINOR release gets fixes.
- The version is set once, in `src/pqproof/__init__.py`. `pyproject.toml` reads it, and so do `bash prove.sh --version`, `pqproof --version` and `receipt.json`.
- A changed rule file needs a new ruleset name and hash in `scan/ruleset.json`, and `tests/test_versioning.py` fails until it is there. If verdicts moved, rewrite `tests/golden/verdicts.json` with `run_mutations.py --write-golden` and describe the change under "Verdict impact" in `CHANGELOG.md`, all in the same commit.
- A change to the evidence format raises `format_version` and keeps reading the older formats. Before such a release, save evidence from the current version with `tests/golden/make_fixture.py` so that `tests/test_golden.py` keeps checking it.
- A release starts from a tag `vX.Y.Z` (`.github/workflows/release.yml`). The tag must match the version and a dated `CHANGELOG.md` entry. The workflow builds the wheel and the sdist, the three `tls_probe` binaries with `SHA256SUMS` and `BUILDINFO`, and a CycloneDX SBOM of the package, attaches GitHub build provenance to every asset (`gh attestation verify <file> --repo g1mn/pqproof`), and publishes to PyPI with Trusted Publishing.
- Workflow actions are pinned to commit SHAs, and Dependabot proposes updates for actions and pip.

## Use in the finals

In the finals, `prove.sh` was the completion check at the end of my migration pipeline. On all five tasks the first run failed and listed the classical lines still left, and the last run passed. On four of them the fixed code did not change between those runs: the agent added or widened allowlist entries, each with a reason, and the verdict turned to pass. None of those entries had a review record, because the review fields came after the finals. That is why `r-allow` exists. The organizers' own grading made the final call.

I wanted the fixing and the judging kept apart. A coding agent changes code quickly, and it can also write changes that look finished when they are not. So the step that says "finished" has no model in it: the same inputs give the same verdict. The evidence hash still changes from run to run, because the evidence also records when and where the run happened.

## Changes since the finals

Three things changed after the finals: one new check, and fixes for two flaws I found while re-checking the tool. Both flaws were already in the finals version. A review of the first fixes then found a gap in each, and I closed both. The 0.1.0 packaging, SARIF output, Action, versioning and test changes are listed in [CHANGELOG.md](CHANGELOG.md).

### Review record (`r-allow`)

`r-allow` shows whether a person read each allowlist entry (see above). It changes the verdict only under `REQUIRE_REVIEW=1`.

### Unused allowlist entries

You write the allowlist for the fixed tree, but it applies to any tree you run it on. An entry that matched no classical line in the fixed tree used to stay in the list as "unused" with no warning. Run against the original, the same list let that entry allow the classical lines in its range, and in one case it hid every blocking location of the original. A key-generating line inside an allowed range showed up only as "needs review" in the check rows.

The tool now also resolves the list against the original and records, per entry, how many classical lines it covers in each tree (`lines_fixed`, `lines_orig`). It warns about every unused entry, names the original lines that entry would cover, and marks `r-allow` as needs review. Under `REQUIRE_REVIEW=1` an unused entry fails the run. The verdict line also counts write paths left inside allowed ranges, and `--verify` checks all of these counts against the entries.

The lines an unused entry would hide do not go back to being blocking locations. Within one run they sit in the original, which the tool never judges. If someone puts the original in the fixed slot, the entry matches lines there, and nothing in the list says which tree it was written for. So the tool flags the entry in the run where it is unused, and `REQUIRE_REVIEW=1` makes you delete it. A unit test shows it: with the unused entry deleted, the same tree fails and its blocking locations are listed (`tests/test_allowlist.py`, masked case).

The first version of this fix missed one case. An entry that points to a file deleted from the fixed tree, or to lines past the end of a file that got shorter, is invalid there and allows nothing, so it only got a warning. In the original the same entry is valid and hides those lines, and with a review record on it the run passed even under `REQUIRE_REVIEW=1`. Such an entry now counts as unused whenever it covers classical lines in the original, and so does an entry that points only outside the tree or at excluded data files. `--verify` recounts this from each entry's status and `lines_orig`, and fails newer evidence when someone deletes its unused and write-path counts.

### One list of test paths

In the finals version, three places decided what a test path was. `cbom-scan.sh` marked twelve test and example folder names and test file patterns such as `*_test.go` as tests. `pqlite/scan.py`, the other scanner behind `a-cbom`, skipped only Java files under `src/test/`, `test/` or `tests/` or named `*Test`, and Go files named `*_test.go`. `residue.sh`, which `c-classic` and `c-expect` read, skipped only `src/test/`, `test/` and `tests/`. A Go test in `seal_test.go` that builds a P-256 key to check that it gets rejected passed `a-cbom` and failed `c-classic`. Now one file, `scan/test-paths.ere`, holds the rule, and `cbom-scan.sh`, `residue.sh`, `pqlite/scan.py` and the TLS signal check all read it.

My first version of the shared rule matched folder names such as `example` anywhere in the path. That made `src/main/java/com/example/`, the default Spring package, test code: classical Java left there passed, and a correct Java-only migration there failed `c-expect`. The file now has a second line, a main-source marker (`/src/main/`). When a path contains it, the tool matches only the part before the marker, so nothing under `src/main/` is a test path, while `tests/it/src/main/` still is. `examples/`, `samples/`, `spec/`, `fixtures/` and `mock(s)/` count only at the top of the tree. `test/`, `tests/`, `__tests__/` and `testdata/` count at any depth, and so do test file names.

Skipping more paths risks missing production code kept in a folder named like a test folder. Skipping fewer fails good migrations that test the rejection of old keys and pushes test code into the allowlist. The skipped lines stay visible: `c-classic` prints how many classical lines sit in test paths and where, `a-cbom` counts them apart, and the evidence keeps them. ML-KEM and ML-DSA lines in test paths do not count as PQC use.

### Effect on verdicts

A tree whose only classical lines sit in test paths used to fail `c-classic` and now passes. The shared rule moved `a-cbom` and `c-expect` as well. Compared with the finals version, `c-classic` and `c-expect` now also skip test file names (`*_test.go`, `*Test.java`, `test_*.py` and the like), `__tests__/`, `testdata/` and the top-level example folders. `a-cbom` now also skips Go files in `test/` and `tests/`, and Java and Go files in `__tests__/`, `testdata/` and the top-level example folders. For Python, Node and the other files that only `cbom-scan.sh` reads, an `examples/`, `samples/`, `spec/`, `fixtures/` or `mock(s)/` folder below the top of the tree no longer counts as tests. Below `src/main/` nothing counts as a test path for any check, not even a class named `*Test.java`, unless a test folder sits above `src/main/`.

On the eight practice tasks I wrote for rehearsal the verdicts did not change, and the review fixes changed no verdict, check or count. One change does show up: a list whose entries are all unused now makes `r-allow` need review where it used to be not applicable. That happened on five rehearsal runs, and none of their verdicts moved.

## Limits

- **Rules, not proof.** A pass means the rules found nothing. Whether the rules are right, complete or fit your service is a human judgement.
- **Static detection.** Regular expressions with assignment tracking inside a file and `static final` constants across Java files. An algorithm name that arrives from configuration at run time cannot be read; those rows stay as "check" for a person.
- **Coverage.** Java, Go, Python, Node and nginx have the most rules. Other languages get what `cbom-scan.sh` and `residue.sh` find by name.
- **TLS.** The probe measures servers. TLS terminated outside the code (Caddy, Envoy, Traefik, a cloud load balancer) produces no signal; pass its address in `TLS_TARGETS` yourself. The tool cannot tell whether the server you measured runs this exact fixed tree.
- **Hybrid window.** The 12-line window and the function-header pattern are heuristics. If one function holds both a classical-only branch and an ML-KEM branch, the classical branch may count as hybrid. Every such line is listed in `allowlist.hybrid`.
- **Large files.** `scan.py`, the weakening check and the allowlist check skip any file over 1 MiB. Only `cbom-scan.sh` and `residue.sh` look at such a file.
- **Allowlist.** The allowlist changes the verdict, and the tool cannot judge a reason. It checks where an entry points, whether its lines exist, whether they write, and whether someone signed it. For real reviews run with `REQUIRE_REVIEW=1` and keep the list with a person.
- **Review fields.** The tool checks the form of `reviewed_by` and `reviewed_at` and whether `reviewed_digest` matches, not who wrote them. An agent that writes the allowlist can fill them and compute the digest too, so the review step has to stay with a person. The digest catches an entry added or changed after the review when the change is in the entry text. A change only in the code the entry points to goes unnoticed, and so does running the list against a tree it was not written for.
- **Test paths.** A path that matches the test rule counts as tests even if production code lives there. Those lines are listed, not judged. The marker protects only the `src/main/` layout. Production code in a top-level `examples/` folder counts as tests, and a test-looking folder deeper in a tree without `src/main/` (`internal/mocks/`) is scanned as code.
- **Policy data.** The tool does not read the values in JSON or YAML that pick an algorithm. Two trees that differ only in such a value get the same verdict.
- **Outside the tree.** TLS settings, certificates and services configured outside the given tree (a host's TLS configuration, for example) are out of view, so the verdict can differ from a check that tests the running service.
- **No function or performance testing.** Use your own tests for that.
- **Scale.** Run so far only on small services. Not yet tried on production codebases.

## Layout

| Path | What |
|---|---|
| `prove.sh`, `prove.py` | entry point and the checks |
| `pqlite/` | code scanner, TLS-weakening rules, probe output parser, evidence writer and verifier, allowlist, versions |
| `scan/` | `cbom-scan.sh` (CBOM scanner, bash and OpenSSL), `residue.sh` (classical-line counter), `test-paths.ere` (the test-path list both read), `ruleset.json` (ruleset names and hashes) |
| `src/pqproof/` | the `pqproof` command, the SARIF converter and the external-program check |
| `probe/`, `build-probe.sh` | `tls_probe` source (Go standard library) and its offline build script |
| `examples/` | the before and after trees used above and by the tests, and a GitHub Actions example |
| `tests/` | unit tests, the mutation suite, golden verdicts, older evidence and a snapshot of the orders-edge fixture |
| `action.yml`, `.github/` | the GitHub Action, CI, Pages and release workflows, Dependabot |
| `docs/` | the site, deployed to GitHub Pages |

Code comments and tool output are in Korean, as they were in the finals. Two words changed: the output now says 검증 증적 (verification evidence) where the finals version said 영수증 (receipt), and 보안레벨 (security level) where it said 범주 (category). Both Korean words stand for the NIST security category, and the English CBOM column keeps that term. File and field names still use `receipt`.

## 한국어 요약

2026년 양자내성암호 전환 해커톤 본선에서 실제로 쓴 검증 도구다. 이 대회에서 대상(과학기술정보통신부 장관상)을 받았다. 전환 전과 후의 소스를 넣으면 사유 없이 남은 기존 공개키 암호 코드가 없는지, ML-KEM-768과 ML-DSA-65를 쓰는지, TLS 설정을 약하게 바꾸지 않았는지 보고 전환이 끝났는지 판정한다. 판정에 AI 모델을 쓰지 않으므로 입력이 같으면 판정도 같다.

- 실행: `pip install pqproof` 뒤 `pqproof <전환 전 폴더|zip> <전환 후 폴더|zip>`, 저장소에서는 `bash prove.sh <전환 전> <전환 후>`. 예제로 돌려 보려면 `bash prove.sh examples/classic examples/pqc`.
- 출력: 판정(종료 코드 0 통과, 1 실패, 3 미판정), 전후 CBOM 표, 검증 증적(`receipt.json`, `receipt.html`), 증적 해시. 증적 해시는 증적 JSON을 RFC 8785 방식으로 정규화해 SHA-256으로 계산한 값이다. `bash prove.sh --verify <출력 폴더>`로 누구든 다시 계산해 볼 수 있다. 증적에 실행 시각과 입력 폴더의 절대 경로가 들어가서, 입력이 같아도 증적 해시는 실행할 때마다 달라진다.
- 용어: 본선판 출력의 '영수증'을 '검증 증적'으로, '범주 3'을 '보안레벨 3'으로 바꿨다. 둘 다 NIST의 security category를 가리키며 영어 출력(CBOM 표의 NIST 칸)은 security category를 그대로 쓴다. 파일과 칸 이름은 `receipt.json`, `receipt_id`처럼 receipt를 그대로 쓴다.
- 사람 확인: 도구는 허용 목록의 사유가 맞는지 모르므로 사람이 읽고 항목(또는 목록 맨 위)에 `reviewed_by`(이름·계정)와 `reviewed_at`(ISO 8601 날짜·시각)을 적는다. 목록 맨 위에 적을 때는 실행할 때 찍히는 `reviewed_digest` 값도 함께 적는다. 그 뒤에 항목을 더하거나 고치면 값이 맞지 않게 되어 맨 위 칸을 물려받던 항목이 모두 확인 전으로 돌아간다. 확인 전 허용 항목이 있어도 통과와 종료 코드 0은 그대로다. 판정을 '통과(허용 n건 사람 확인 전)'으로 적을 뿐이고 `REQUIRE_REVIEW=1`을 주면 실패로 끝난다. 칸 형식이 틀리거나 값이 맞지 않으면 경고를 남기고 확인 전으로 센다. 두 칸은 `receipt.json`에 들어가 증적 해시에 반영되며 `--verify`가 증적과 함께 남긴 허용 목록 사본과 맞춰 본다.
- 경로: 출력에는 입력 폴더, 도구, 출력 폴더의 절대 경로가 적힌다. 출력 폴더를 남에게 넘기기 전에 확인한다.
- 본선에서 코드는 AI 코딩 에이전트가 고쳤고 이 도구는 그 흐름 끝에서 전환이 끝났는지 확인하는 단계였다. 다섯 과제 모두 첫 판정은 실패, 마지막 판정은 통과였다. 네 과제는 고친 코드는 그대로 두고 허용 목록 항목을 더하거나 범위를 넓혀 통과로 바뀌었고, 그 항목에는 사람 확인 기록이 없다(확인 칸은 본선 뒤에 더했다). 그래서 `r-allow`를 더했다. 최종 판정은 주최 측 채점이 했다.
- 본선 뒤 바뀐 점은 셋이다. 하나는 새 검사이고 둘은 본선 뒤 다시 점검하다 찾은 결함(본선판에도 있던 것)을 고친 것이다. 이 고침을 따로 검토해서 나온 빈틈 두 개도 막았다. (1) 허용 목록 사람 확인 검사 `r-allow`를 더했다. (2) 고친 판에서 고전 줄을 하나도 덮지 않는 허용 항목(안 쓰인 항목)이 있으면 경고한다. 이런 항목은 같은 목록을 원본에 대면 그 범위의 고전 줄을 가린다. 원본에서 그 항목이 덮는 줄 수는 증적에 남기고 판정은 그대로 두되 `r-allow`를 검토 필요로 바꾸며 `REQUIRE_REVIEW=1`이면 실패로 끝낸다. 허용 범위 안 쓰기 경로 수도 판정 옆에 적어 둔다. 가린 줄을 막는 위치로 되돌리지는 않았다. 한 번 실행할 때 가려지는 줄은 판정하지 않는 원본 쪽에 있고 원본을 고친 판 자리에 넣으면 그 항목이 쓰이는 항목이 되어 구별할 수 없어서다. 대신 안 쓰인 항목을 지우게 했고, 단위 시험에서 지워 보면 원본의 막는 위치가 다시 나온다(`tests/test_allowlist.py` 가림 재현). 고친 판에서 지운 파일을 가리킨 항목처럼 고친 판에서는 무효인데 원본에서는 고전 줄을 덮는 항목도 안 쓰인 항목으로 센다. 처음 고친 판은 이런 항목에 경고만 남겨 사람 확인 칸이 있으면 `REQUIRE_REVIEW=1`에서도 통과했다. (3) 시험 경로 기준을 `scan/test-paths.ere` 한 곳으로 모았다. cbom-scan.sh, residue.sh, pqlite/scan.py, TLS 신호 검사가 모두 이 파일을 읽는다. 본선판은 세 곳이 따로 정했다. cbom-scan.sh는 시험·예제 폴더 열두 가지와 시험 파일 이름을 시험으로 봤지만 a-cbom의 Java·Go 행을 내는 pqlite/scan.py는 Java의 `src/test/`·`test/`·`tests/`·`*Test`와 Go의 `_test.go`만 뺐고 c-classic이 읽는 residue.sh는 `src/test/`·`test/`·`tests/`만 뺐다. 그래서 `_test.go` 같은 음성 시험이 c-classic에서만 실패했다. 처음 고친 판은 폴더 이름을 경로 어디서든 맞춰서 Spring 기본 패키지 `src/main/java/com/example/`이 통째로 시험이 됐다. 지금은 목록 둘째 줄의 본 소스 표시(`/src/main/`) 앞부분만 맞춰 보므로 `src/main/` 아래는 시험이 아니다. `examples/`·`samples/`·`spec/`·`fixtures/`·`mock(s)/`는 트리 맨 위 폴더일 때만 시험으로 본다. 시험 경로의 고전 줄은 줄마다 따로 세어 보이며 이 규칙은 c-classic뿐 아니라 a-cbom과 c-expect에도 똑같이 걸린다. 고전 줄이 시험 경로에만 있는 소스는 실패에서 통과로 바뀐다. 리허설용으로 직접 만든 연습 과제 여덟 개의 판정은 바뀌지 않았다. 안 쓰인 항목만 있는 목록이면 r-allow가 해당 없음에서 검토 필요로 바뀐다(리허설 5회, 판정은 그대로).
- 한계: 통과는 이 규칙으로 찾은 것이 없다는 뜻일 뿐, 규칙이 옳다는 보장은 아니다. 기능과 성능은 보지 않는다. 허용 목록은 판정을 바꾼다. 사유가 맞는지는 도구가 모르니 사람이 확인해야 하고 실무 검토에서는 `REQUIRE_REVIEW=1`로 돌리기를 권한다. JSON·YAML 설정 값이 고르는 알고리즘은 보지 않는다. 넣은 소스 밖의 설정(호스트의 TLS 설정 등)도 못 보므로 실행 중인 서비스를 직접 시험한 결과와 다를 수 있다. 작은 서비스에서만 써 봤고 실서비스 규모로는 아직 검증하지 않았다.
- 공개하면서 대회 문제와 관련된 내용, 개인 경로, 대회용 보고서 표를 뺐다. 참가자가 만든 도구이며 주최·주관기관이 검토하거나 보증하지 않았다.
- 건너뛴 검사는 통과로 세지 않는다. 돌지 못한 검사는 이름과 함께 '해당 없음'이나 '미판정'으로 남고, 판정 뒤에 상태별 개수를 따로 찍는다. 단위·셀프 시험도 '통과 n · 건너뜀 m'으로 세며 `STRICT=1`이면 건너뛴 것이 있을 때 실패한다.
- 버전: 도구 버전은 `src/pqproof/__init__.py` 한 곳에서 정한다. 증적에 도구 버전, 규칙 묶음 이름과 해시(스캐너 패턴·시험 경로·허용·약화 규칙 파일 여섯), 증적 형식을 남기고 `--verify`가 규칙 묶음 해시를 다시 계산한다. 이전 공개본이 쓴 옛 증적도 계속 읽는다. 판정이 바뀔 수 있는 규칙 변경은 0.x 동안 MINOR로 올리고 CHANGELOG.md의 '판정 영향' 칸에 적는다.
