# Changelog

All notable changes to PQ-Proof are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each release has a **Verdict impact (판정 영향)** line. It says whether the same two trees can get a different verdict, check status or count than they got with the previous release.

- A change that can move a verdict (detection pattern, test path, allow rule, a check added or removed) bumps MINOR while the version is 0.x, and MAJOR from 1.0 on. A rule change also gets a new ruleset name in `scan/ruleset.json`.
- A new command or option bumps MINOR; options of the test tools do not count. Other fixes bump PATCH, so a release that moves a verdict is never a PATCH release. CI and the release workflow check the verdict part against the previous release tag (`tests/version_policy.py`); new commands and options are checked by hand.
- Only the latest MINOR release gets fixes. See [SECURITY.md](SECURITY.md).

Every run records `tool_version`, `ruleset_version` and `ruleset_sha256` in `receipt.json`, so a receipt from years ago still names the rules that judged it. `--verify` keeps reading older evidence formats.

## [0.8.0] - 2026-11-26

Tool 0.8.0, ruleset 8, evidence format 4 (unchanged), `tls_probe` 0.6.0.

**Verdict impact (판정 영향): yes, for TLS targets only.** A target given without a CA used to be trusted on first use; now its certificate is verified against the system trust store. A handshake whose certificate does not verify was not measured, and each handshake is judged on its own (`b-tls`, and `c-expect` when `EXPECT` has `tls` or `cert`):
- A target without a CA whose certificate the system trust store does not accept (self-signed or private CA) moves from pass to undecided. So does a target with neither a CA nor `@servername` whose certificate does not hold the host of the address, even when the trust store accepts its CA: 0.7.0 checked the name `localhost`, 0.8.0 checks the address host, so a `localhost` certificate given as `127.0.0.1:<port>` no longer verifies. Add `@<a name in the certificate>`.
- The same target moves from fail to undecided when every failing handshake now fails verification, for example a server that accepts the old client under `CLASSIC=deny`, or the certificate key under `EXPECT=cert`. It stays fail when a handshake fails before the certificate is checked: a server that refuses the hybrid-only offer (an X25519-only server) still fails, with both reasons in `why`.
- A target with neither a CA nor `@servername` was checked against the name `localhost`, so a server whose certificate does not name `localhost` (a server with a publicly trusted certificate, for one) failed on the name error. Now it is checked against the host of the address and the system trust store. When its certificate verifies, each handshake is judged on what the server negotiates, so the target can move from fail to pass (or stay fail on the merits); when it does not verify, it moves from fail to undecided as above.
- A target whose certificate does not verify against its CA file (wrong CA or wrong name) moves from fail to undecided in the same way, and stays fail when the hybrid-only offer is refused.
- A CA-file target that verifies judges as before. So does a `#tofu` target (the old target without a CA) whose certificate holds the server name it is checked against. Without `@servername` that name is `localhost`, so a `#tofu` target whose certificate does not name `localhost` used to fail on the name error. Now that handshake failed verification, and the target moves from fail to undecided in the same way (it stays fail when another handshake fails outright, such as a refused hybrid-only offer). Add `@<a name in the certificate>` to measure it.
- A `tls_probe connect` that ends with a usage error or a timeout (an exit code other than 0 or 1) is a tool error: `b-tls` is undecided, even when another target has a measured failure. 0.7.0 parsed its empty output as `no cipher negotiated`, which failed the target (or, for the old client under `CLASSIC=deny`, counted as a refusal). A tool error on a `TLS_TARGETS_ORIG` baseline target makes `b-tls` undecided too, in a run that has `TLS_TARGETS` (0.7.0 did not judge the baseline).
- `b-tls` is undecided, and nothing is measured, when the `tls_probe` binary is not version 0.6.0 (see Changed). Without that check a 0.5.0 binary left on disk would turn a target without a CA into fail with `no cipher negotiated`.
- An OpenSSL cross-check that used to look like agreement can now disagree, which is undecided (see Fixed).

The 41 golden tree cases keep every verdict, check status and count (only the ruleset name in the golden file moved); they have no TLS target. Evidence from every earlier release still verifies byte for byte.

### Security

- TLS certificate verification by default (OpenSSF Best Practices silver, `crypto_certificate_verification`). When PQ-Proof connects to a TLS target, it now verifies the server certificate by default: `tls_probe` uses the system trust store and the server name (the `@servername`, or the host of the address when none is given; a CA-file or `#tofu` target still defaults to `localhost`), and the OpenSSL cross-check uses OpenSSL's default trust paths. Before, a target without a CA was trusted on first use: one unchecked handshake read the chain and the measured handshake trusted its last certificate, so it showed what a server negotiated but not which server answered.

### Changed

- Trust on first use is opt-in and documented as weaker: add `#tofu` to the target (`127.0.0.1:8443@svc.local#tofu`). The evidence records it as `trust: tofu`, as before. `tls.targets[].trust` is `system` for the new default, `ca-file` for `#/path/ca.pem`.
- A handshake that fails certificate verification (unknown CA, wrong name, expired) is no longer read as a refusal or a classical result. `tls_probe` 0.6.0 starts the error with `certificate verification failed:`, the target's `why` names the trust mode and the error, and `b-tls` is undecided (a measurement that did not happen is never a pass, and under `CLASSIC=deny` it is not a refusal either), unless the other handshake of the same target or another target fails outright; then `b-tls` fails and keeps both reasons.
- The OpenSSL cross-check always passes `-verify_return_error` and checks the name (`-verify_hostname`, or `-verify_ip` for an address), with `-CAfile` for a CA file or the `#tofu` anchor. It used to skip verification without a CA and never checked the name.
- `tls_probe connect` takes `-ca`, `-tofu` or neither (system trust store) and prints `trust: system` for the last.
- **Upgrade: rebuild or replace `tls_probe`.** This release needs `tls_probe` 0.6.0: a 0.5.0 binary rejects a target without a CA with a usage error. Binaries in `~/.cache/pqproof/bin`, in a clone's `bin/` and in a `PROBE_BIN_DIR` stay after an upgrade, so run `pqproof build-probe` (from a clone: `bash build-probe.sh`) or download the 0.8.0 release assets. Before a TLS run the tool now asks the binary for its version (`tls_probe version`): on a mismatch `b-tls` is undecided and names the fix, `pqproof doctor` warns, and `pqproof` stops before a run with `TLS_TARGETS`. `tools[]` records the version the binary reports, not the version the Python code expects. A `connect` that ends with a usage error or a timeout is a tool error (undecided), never read as a handshake.
- Container mode (`TLS_VIA=container:<name>`) clears `SSL_CERT_FILE` and `SSL_CERT_DIR` for the probe, so the target image's environment cannot point the system trust store at a CA of its choosing. The trust store files inside the image still belong to the image, so the `b-tls` line says so when a target in container mode used the system trust store; give the CA file to trust only that CA.
- On macOS a `trust: system` target is verified by the operating system, which can connect to other addresses to fetch a missing intermediate certificate or revocation data. A CA file (`#/abs/path/ca.pem`) keeps the run to the target address.
- Self-test: S6c opts in to `#tofu`, and the new S6f checks that a self-signed server without a CA or `#tofu` ends undecided, not passed. The reference controls always pass their own CA.

### Fixed

- The OpenSSL cross-check read a handshake that `s_client -verify_return_error` stopped on a verification error as a success: `s_client` still prints the cipher suite and the group chosen in the ServerHello. A `verify error:` line, `certificate verify failed` or a non-zero `Verify return code` now makes it a verification failure. With a CA file or the `#tofu` anchor the cross-check adds `-partial_chain`, so OpenSSL accepts the same anchors as `tls_probe` (Go trusts any certificate in its root pool, and a `#tofu` anchor is usually a leaf); without it the `#tofu` cross-check had been failing verification all along, hidden by the parsing bug.

## [0.7.0] - 2026-11-22

Tool 0.7.0, ruleset 7 (unchanged), evidence format 4 (unchanged).

**Verdict impact (판정 영향): none.** No rule file changed, so the same trees get the same verdict, check statuses and counts (golden: 0 of 41 cases moved). `--verify` lists two more artifacts per two-tree or one-tree run (the CycloneDX files), and evidence from every earlier release still verifies; a 0.6.0 two-tree folder joins the golden evidence to keep it so.

### Added

- CycloneDX 1.6 CBOM export (`pqlite/cdx.py`): every run also writes its CBOM rows as `tables/cbom-orig.cdx.json` and `tables/cbom-fixed.cdx.json` (`tables/cbom.cdx.json` for `pqproof inventory`), for tools that read that format. One component per asset type and name, one occurrence per CSV row with its status, tool, use, threat, reason and masked note; `nistQuantumSecurityLevel` from FIPS 203, 204 and 205, OIDs for ML-KEM and ML-DSA, the three IANA hybrid TLS groups as combiners, and KpqC and unknown names kept as written. No timestamp and a content-derived `serialNumber`, so the same trees give the same bytes. CI validates the output against the official 1.6.2 schemas, pinned by SHA-256 (`CDX_SCHEMA_DIR`). The EU PQC roadmap mapping item R4 (a standard CBOM format) is now covered.
- `pqproof examples` prints the folder of the bundled example trees, and `pqproof doctor` prints it with a ready command. The README quick start now runs the bundled pair (`pqproof "$ex/classic" "$ex/pqc"`) before your own trees.
- English for readers who do not read Korean, where it cost no change to old evidence: `README.txt` in a 0.7.0 folder explains each check and the status words, links the format 4 schema and the limits by URL; `receipt.html` gets a "How to read this page (English)" section and shows `MODE`, `PROFILE`, `REQUIRE_REVIEW`, `FAIL_ON_REVIEW` and `REQUIRE_RESOLVED`; `pqproof --env` starts with an English list of the settings (from `guide/configuration.md`, now in the wheel); SARIF with `--lang en` no longer carries Korean use labels. Pages written by earlier releases are drawn as before, because `--verify` compares them byte for byte.
- SARIF rules carry `security-severity` and a `help` text, so code scanning can sort and explain the alerts.

### Changed

- CI examples: the GitLab and Jenkins jobs wrote the base tree, the evidence folder and (Jenkins) a virtual environment inside the converted checkout, so a finished migration failed on its own copies; all of them now live in a temporary folder and the report is copied in afterwards. All three examples build the base tree with `git read-tree` and `git checkout-index` instead of `git archive`, which dropped `export-ignore` paths and made unchanged files look added. `guide/ci.md` explains both and adds a pinning section.
- The Action writes its SARIF file to `$RUNNER_TEMP/pqproof.sarif` by default (a later run in the same workspace scanned `pqproof.sarif` as code), and warns when `sarif-anchor` is not in the converted tree.
- Input errors say what is wrong in Korean and English (no such path, or a file that is not a folder or a .zip), start with `pqproof:` when run as `pqproof`, and come before the output folder is created, so no empty folder is left.
- Console: a one-tree `check` shows one tree; a pass with checks that need review lists where to look; a run whose original has nothing to migrate while the converted tree has classical code suggests the trees may be swapped; a tree with no cryptography suggests `EXPECT=none`; both zip hashes are shortened alike.
- `--verify` adds a line with the verdict the evidence records, because exit 0 there means the folder is unchanged, not that the migration passed.
- `tables/report.md` names a run log only when `EV_NAME` is set (PQ-Proof never writes that file).
- `guide/quickstart.md` shows the 0.6.0 example output and what each check means.

## [0.6.0] - 2026-11-22

Tool 0.6.0, ruleset 7, evidence format 4 (unchanged), `tls_probe` 0.5.0. This release follows the NIS and NSR drafts of the cryptographic security guideline and the PQC migration guidebook for national and public institutions (posted 2026-11-16): the four gaps of their mappings that a migration check can close.

**Verdict impact (판정 영향): yes, in one narrow case.** A classical key whose stated size is below 112-bit security now blocks even where an allow rule, a hybrid or an allowlist entry took it out of the blocking count before: RSA, DSA, DH or ElGamal under 2048 bits, or a curve under 224 bits. The 41 golden tree cases keep every verdict, check status and count (only the ruleset name in the golden file moved). Everything else in this release adds records and text, not verdicts.

### Added

- 112-bit key floor (ruleset 7, NIS guideline draft S1: classical public-key cryptography stays allowed until 2036 only at 112-bit strength). `below_floor` in `pqlite/rules.py` reads the size from the algorithm text, which `cbom-scan.sh` fills from the line and the three below it. Such a row blocks with the reason `112비트 미만 고전 키`, and `a-cbom` counts the locations. A row without a size is left as it was.
- PQ/PQ hybrids (NIS guideline draft S2: recommended from 2036). A post-quantum row whose code line names two post-quantum families of the same kind (ML-KEM with SMAUG-T, NTRU+ or HQC; ML-DSA with SLH-DSA, FN-DSA, HAETAE or AIMer) gets the reason `PQ/PQ 하이브리드` in `tables/cbom-*.csv`, and `a-cbom` counts them. No verdict effect.
- Exception records in the allowlist (NIS guidebook draft G9): optional `residual_risk`, `compensating_control` and `replacement_plan` per entry. They join the review digest when set and stay in the evidence's copy of the list (`artifacts/allow-list.json`). An `exception` entry in use with any of them missing gets a warning, and `r-allow` says how many exception entries have all three. No verdict effect. `schemas/unconverted.schema.json` lists them.
- TLS report detail (NIS guidebook draft G7): `tls_probe` 0.5.0 prints the negotiated cipher suite (`cipher`) and the leaf certificate's expiry (`cert_not_after`, RFC 3339 UTC). Both go to `tls.targets[]` and `tables/tls.csv`, and the expiry gets a column in the TLS table of `receipt.html` when a run has it. `b-tls` judges as before. The OpenSSL cross-check records the cipher suite too.
- The two NIS mappings follow: G9, S1 and S2 are now covered, G7 stays partial (only the negotiated suite, not every suite a server accepts).
- OpenSSF Scorecard (`.github/workflows/scorecard.yml`, actions pinned by commit, write permissions only in its one job) with a README badge, and CodeQL code scanning (`.github/workflows/codeql.yml`: Python, Go for `probe/`, and the workflows; test fixtures, examples and the site are left out in `.github/codeql/codeql-config.yml`).
- ClusterFuzzLite (`.clusterfuzzlite/`, `.github/workflows/cflite.yml`) fuzzes the two parsers that read files from other people: the `impl judge` answer file (`tests/fuzz/answer_fuzzer.py`: never raises, reports a problem instead) and `receipt.json` under `--verify` (`tests/fuzz/evidence_json_fuzzer.py`: raises only ValueError). Pull requests that touch them get a short run, and a weekly run fuzzes longer.
- Fuzz tests for `tls_probe` (`probe/fuzz_test.go`: the `-groups` list parser and the filter for names printed from peers). CI runs their seeds with `go test`; the release binaries are unchanged, since `go build` leaves test files out.
- Releases attach the build provenance as a Sigstore bundle (`pqproof-<tag>-provenance.intoto.jsonl`), so it can be checked with `gh attestation verify --bundle`. The bundles of 0.2.0 to 0.5.0 were added to those releases from the attestations they already had.
- Eight more standards mappings in `mappings/`, each quote checked against the published text: the NIS and NSR drafts of the PQC migration guidebook and the cryptographic security guideline for national and public institutions (posted 2026-11-16), the NIS notice of PQC validation candidates, NIST SP 800-227, the NSA CNSA 2.0 FAQ (for `PROFILE=cnsa2`), the CISA, NSA and NIST Quantum-Readiness factsheet, the UK NCSC migration timelines and the EU coordinated PQC roadmap. The site shows them as tables, and the gaps they found (CycloneDX CBOM export, LMS and XMSS) are on the roadmap.
- OpenSSF Best Practices passing badge (project 16982), linked from the README.
- `tools/mapping_draft.py` for the day a standard (such as the KISA guide) is published: it prints the PDF text with page markers and turns the chosen items into reviewable stubs, with the existing items on the same topic as suggestions. A draft fails `tests/test_mappings.py` until a person fills it in; `mappings/README.md` has the steps.

### Changed

- The orders-edge test fixture pins its two base images by digest (`tests/fixtures/orders-edge/Dockerfile`), and the two model edit files and `tests/e2e_orders_edge.py` follow it. Same images and tags; verdicts unchanged (selftest S4 and S5 pass, golden: 0 of 41 cases moved).
- CI installs jsonschema from a hash-pinned file (`.github/requirements/schema.txt`), like the other CI tools.
- `osv-scanner.toml` in the scanner test fixtures (`scan/fixtures/{python,go,java}`, `tests/fixtures/orders-edge`) marks their old dependency versions as fixtures, so vulnerability scanners no longer report them as the project's own. They are never installed or built.
- The same file in `examples/classic` and `examples/pqc`: their `requirements.txt` give only a lower bound (the old one in `classic` is part of what the demo flags), and the examples are never installed. Verdicts and counts for the examples are unchanged (golden: 0 of 41 cases moved).

## [0.5.0] - 2026-11-21

Tool 0.5.0, ruleset 6, evidence format 4 (unchanged).

**Verdict impact (판정 영향): yes, in one narrow case.** The 41 golden tree cases keep every verdict, check status and count (only the ruleset name in the golden file moved). The case: for a file larger than `MAX_FILE_MIB`, PQ-Proof cannot read the line itself and falls back to the excerpt `residue.sh` prints; that excerpt is now masked, so a secret value that contains a rule word such as `legacy` no longer feeds the allow rules.

### Security

- Secret values in the scanner output under `artifacts/`. `tables/`, `report.md` and SARIF already hid values that look like secrets, but the raw scanner output did not hide all of them: `residue.sh` quoted matching source lines as they were, and `cbom-scan.sh` missed a value after `secret_key` and similar names, AWS access key IDs and bare tokens with known prefixes. Nothing hid an `ssh-keygen -N` passphrase, not even the tables. A run on a tree with such values on lines that use classical crypto kept them in the evidence folder. Now one awk mask (`MASKFN`, the same text in `scan/cbom-scan.sh` and `scan/residue.sh`) hides the same values as `prove.py` `REDACT`, `residue.sh` masks its excerpts, and all of them hide an `ssh-keygen -N` passphrase. Only the input copy `in/` of a zip input keeps the original source. If you shared an evidence folder made before 0.5.0 from code with secrets on such lines, check `artifacts/residue-*.txt` and `artifacts/cbom-*/` and rotate what you find. The evidence published with PQ-Proof (the site, the examples, the golden evidence) holds no real secret: it was made from bundled examples and fake fixtures, and a scan of the full history of the repository found none.
- Advisory: [GHSA-6jq9-vjc7-xwm2](https://github.com/g1mn/pqproof/security/advisories/GHSA-6jq9-vjc7-xwm2) (low, CVSS 3.3).

### Changed

- Tests: the awk mask and `REDACT` are compared on the same lines, both ways (values to hide and values to keep, such as the `ssh-keygen -n` principals); the two copies of `MASKFN` must be the same text; an end-to-end run must leave no secret value anywhere in the output folder outside `in/`. The known-gap list of 0.4.1 is gone.
- SARIF `redactedSnippets` and the console count also count values the scanners hid first.

## [0.4.1] - 2026-11-21

Tool 0.4.1, ruleset 5, evidence format 4 (unchanged).

**Verdict impact (판정 영향): none.** Ruleset 5 has the same rules as ruleset 4; only comments changed. The 41 golden tree cases keep every verdict, check status and count (only the ruleset name in the golden file moved), and evidence from rulesets 1 to 4 still verifies the way it did.

### Changed

- Comments no longer rename a ruleset. From ruleset 5, `scan/ruleset.json` keeps the hash of the rule files without comments (`comment_free`), and an edit that changes only comments is recorded as an alias of the same ruleset with `python3 -I -B pqlite/version.py --alias`, which refuses when more than comments changed. Python comments are left out, and so are full-line comments and blank lines outside quotes and heredocs in the shell scanners; trailing comments in shell files still count. `--verify` still recomputes `ruleset_sha256` from the file hashes in `tools` and accepts the recorded hash or an alias. Tests check that the text without comments parses to the same Python AST, and that every shell line left out sits at the top level (`bash -n`).
- Comments: history notes that repeat the changelog, stale numbers and lines that restate the code are gone. Notes such as "this must match that file" moved into the tests that enforce them, whose failure messages now say what to change together. Comments that give a reason or a standard reference stay.
- Lint: ruff also checks `E402`, `E731` and `BLE001` (so every `noqa` marks a real exception), `ERA001` (no commented-out code) and `RUF100` (no unused `noqa`).
- CONTRIBUTING: when the same review comment comes up twice, it becomes a test or a lint rule.

### Added

- A test that puts the same lines through `scan/cbom-scan.sh` (MASKAWK) and `prove.py` (REDACT). The comment in `cbom-scan.sh` said they hide the same values; they do not. The scanner's raw output in `artifacts/` still shows a value after `secret_key`, an AWS access key ID and a bare GitHub token, while the tables and SARIF hide them. These three are pinned as known gaps until the scanner changes in a later ruleset.
- Korean copies of the README and the contributing guide, `README.ko.md` and `CONTRIBUTING.ko.md`, linked from the top of the English files. `tests/test_docs.py` checks that each copy keeps the same headings, commands, code spans, table rows and links as the English file, so a change to one side alone fails. The README site links open the site in the matching language (`?lang=en`, `?lang=ko`), and the site's Korean view links to the Korean contributing guide.
- The source distribution also ships `ROADMAP.md` and `mappings/`, which `tests/test_mappings.py` reads.

## [0.4.0] - 2026-11-21

Tool 0.4.0, ruleset 4 (new name and hash, the same fourteen rule files), evidence format 4 (unchanged). SLH-DSA from FIPS 205 counts as an expected signature at categories 3 and 5, standards mappings in `mappings/`, and a roadmap.

**Verdict impact (판정 영향): yes.** The 39 golden tree cases of 0.3.0 give the same verdicts, check statuses and counts; the only change in them is a new count, `E-SLHDSA`, which is 0 in all of them. Two new mutation cases show what moves:

| Change | 0.3.0 (ruleset 3) | Now (ruleset 4) |
|---|---|---|
| A migration that signs with an SLH-DSA 192 or 256 parameter set from FIPS 205 (`SLH-DSA-SHA2-192s`, `slh_dsa_shake_256f`) instead of ML-DSA (`m30`) | `c-expect` fail (no expected signature), and `a-cbom` fail because the CBOM scanner read the `DSA` in `SLH-DSA` as classical DSA | pass: `E-SLHDSA` counts for `EXPECT=sig` under `nist-cat3` and `kpqc`, and the CBOM scanner names the whole SLH-DSA parameter set |
| SLH-DSA 128 (category 1, `SLH-DSA-SHA2-128s`) (`m30b`) | `c-expect` fail, `a-cbom` fail as classical DSA, `c-classic` pass | `c-expect` fail, and `a-cbom` and `c-classic` fail as below category 3 (`G-WEAK-PQC`, the CBOM scanner and the Java scanner agree) |
| `cnsa2` profile | | unchanged: it does not count SLH-DSA |

Only names with the hash family count (`SLH-DSA-SHA2-192s`, not `SLH-DSA-192s`), and `SPHINCS+` names do not count, because FIPS 205 changed the scheme. The security categories follow NIST IR 8547 (SLH-DSA 128, 192 and 256 are categories 1, 3 and 5).

### Added

- `mappings/`: standards mappings, item by item, with the code that checks each item and a status (covered, partial, gap, not applicable). NIST IR 8547 (final, October 2026) has seven items and the 2026 Korean PQC pilot migration call (Ministry of Science and ICT and KISA) five. `kisa-pqc-guide.json` is empty until KISA publishes its PQC migration guide. `tests/test_mappings.py` checks that every named function or rule exists.
- `ROADMAP.md`, and a first-contribution section in `CONTRIBUTING.md`.

### Changed

- The README is short now; usage, verdict rules, public test results, the implementation check, limits and releases are on the site, [g1mn.github.io/pqproof](https://g1mn.github.io/pqproof/), which is rebuilt for 0.3.0 (test numbers, example output, KpqC versions and sources, FAQ).
- `tests/version_policy.py` also checks that `docs/index.html` was built for the current version, the ruleset that version ships, the evidence format, the KAT list and the release date (the `data-build` block the site generator writes), and that the version chip and build line people see agree with that block. CI, the release workflow and the Pages deploy (`--site-only`) stop when it was not, so a version bump and the site rebuild go in the same commit (CONTRIBUTING.md, Releases). A ruleset for the next release does not need a rebuild until the version moves.

## [0.3.0] - 2026-11-20

Tool 0.3.0, ruleset 3 (new name and hash, fourteen rule files), evidence format 4. New command `pqproof impl` (`prove.sh --impl`): it checks a KpqC implementation (SMAUG-T, NTRU+, HAETAE, AIMer) against pinned reference KAT versions without building or running it, and with `--pq-verify` it also runs pq-verify, a separate tool you install, on a NIST PQC library and puts that audit in the same receipt. `--verify` still reads evidence formats 1, 2 and 3.

**Verdict impact (판정 영향): none.** Existing verdicts do not move: the 39 golden tree cases of 0.2.0 give the same verdicts, check statuses and counts under ruleset 3 (only the ruleset name in the golden file changed). Two new checks, `i-kpqc` and `i-nist`, exist only in the new implementation check. Ruleset 3 adds three rule files (`pqlite/impl.py`, `scan/kat-kpqc.json` and the excerpts in `scan/kat/`) and the `impl_accept` key of the `kpqc` profile, so its hash and name are new and two-tree receipts now list those files in `tools[]`.

### Added

- `pqproof impl prompt [--param P ...] [-o file]` writes a question sheet from the reference KAT excerpts: per parameter set and known version, decapsulation items (`sk`, `ct`, answer `ss`), verification items (`pk`, `msg`, `sig`, `ctx`, answer `ok`) with a copy whose signature has one changed byte (answer must be false), and optional seed items for a build that links the NIST KAT DRBG (`pk`, `sk`, `ct`, `ss` or `pk`, `sk`, `sig`, `sm`). `prompt_sha256` covers the items, so the answers name the sheet they answer. HAETAE KAT signatures use a context string that the `.rsp` does not print; the sheet carries it, drawn from the record's seed with a pure Python copy of the PQCgenKAT AES-256-CTR DRBG (checked against FIPS 197 and against values replayed from the reference library).
- `pqproof impl judge [<answers.json|kat.rsp>] [--param P] [--pq-verify "ARGS"]` compares the answers with every known version. A version is a candidate when every item from it matches. Accepted versions only: pass. An old version or a known variant (for example HAETAE 1.1.2, which the Bouncy Castle test data carries), or answers that cannot tell an accepted version from another one: needs review, with the version named, and for an old reference version the result says which `impl_accept` entry would accept it (the console also names the source of each version, such as the AIMer KpqC final package of 2026-01-30 against the later AIMer V3.0). No candidate, or a changed signature accepted: fail, with the first mismatching item and field. A missing answer, another question sheet, an unknown parameter set, a file over 64 MiB or a failed self-check: undecided. A full PQCgenKAT `.rsp` is compared with the 100 record digests of each version (`n/100`); HAETAE `smlen`/`sm` and AIMer `siglen`/`sig` forms are read as the reference forms, and a HAETAE seed answer may give `sm` as `sig || msg` or `msg || sig`. The answers may list `params` in any order. A `.rsp` over 1,000 records or with a field name over 32 characters is undecided. Text from the answer is checked and shown by fixed character rules, not by the Unicode tables of the running Python, so Python 3.9 and 3.15 give the same result and the same receipt text.
- `impl judge --pq-verify "--audit-kem <library> ML-KEM-768"` (also `--audit-dsa`, `--audit-slhdsa`, `--audit-contained`) bridges to pq-verify for NIST PQC (check `i-nist`). PQ-Proof finds the executable through `PQ_VERIFY` or `PATH`, splits the argument string with `shlex` and runs it without a shell, in an empty temporary folder, with `PQV_*`, `LD_*`, `DYLD_*` and `PYTHONPATH`-style variables removed, and stops the process group after `PQ_VERIFY_TIMEOUT` seconds (1800 by default); its stdout and stderr are read with only the first and last MiB kept in memory. Network vectors (`--live`), other vector folders, output paths (`--json`, `--sarif`, `--prompt-out`), `--no-fail`, `--audit-harness`, `--audit-source`, other tasks and abbreviated option names are refused; `--require-full-coverage` is always added and the report goes into the evidence folder. Pass: exit 0, `VERIFIED`, a report bound to the file PQ-Proof hashed and a complete scope (for a KEM report, which has no scope field, all nine KEM stages ran). Fail: exit 1, `FINDINGS PRESENT` and a stage below its total (a stage that could not run, such as `--constant-time` without valgrind, is not counted as failed). Everything else is undecided: an input error, a `DEGRADED RUN`, a partial scope, a check that could not run, no executable, a timeout, a broken report or another report schema. With no answer file the receipt holds only the pq-verify audit and `i-kpqc` is not applicable; without `--pq-verify`, `i-nist` is not applicable. pq-verify loads and runs the library it audits and is not a sandbox, so audit untrusted libraries in a container or VM.
- Before judging, the tool checks itself: answers built from the excerpts for an accepted version must pass and the same answers with one byte changed must fail, or the whole check is undecided.
- `scan/profiles.json`: `impl_accept` in the `kpqc` profile lists the versions `impl judge` accepts (`latest` by default, or `<parameter>@<version>`, `<algorithm>@<version>`).
- Evidence format 4 (`schemas/receipt-v4.schema.json`): an implementation check receipt has `params.mode` `impl`, the top-level `impl` field (answer copy, answer key copy, question sheet copy, accepted versions, self-check, results per parameter set, and `impl.nist` for a pq-verify run: argv, exit code, report summary, status) and the checks `i-kpqc` and `i-nist`, with `receipt.html`, `deck.json`, `README.txt`, `tables/report.md`, `tables/summary.csv` and `tables/impl.csv`. The pq-verify report and its run record (`artifacts/impl/pq-verify/report.json` and `log.json`: argv, exit code, stdout and stderr) are kept, `tools[]` lists the pq-verify executable with its SHA-256 and version only when it was found (for a pip install that file is the launcher script, so its SHA-256 depends on the virtual environment and not on the pq-verify package; the pinned wheel install is what fixes the code), and `--verify` rebuilds the `i-nist` result from those copies. `--verify` always judges the copied answer again with its own rules, also for a receipt written with another or a `+modified` ruleset (then the statuses must match). It trusts the copied answer key only when it is the key its own KAT list builds, byte for byte, or when the receipt's KAT list is recorded in `scan/ruleset.json` and every version in the copy matches its own list, and it checks the accepted versions against its own `kpqc` profile. `impl.input` (kind, implementation text, header line, size and SHA-256) must match the answer copy, and the pq-verify version in `tools[]` and the time limit must match the run record. Two-tree and one-tree receipts keep the fields of format 3. SARIF reports `i-kpqc` and `i-nist` as checks without a file position.
- `examples/impl/kpqc_harness.py`: an example harness (standard library `ctypes`) that answers a question sheet with shared libraries that export the NIST API.
- `pqproof doctor` reports the KAT list and pq-verify (found or not, with the version `pq-verify --version` prints; that call loads no library); `pqproof impl` needs Python only, so it also runs on Windows (pq-verify itself supports macOS and Linux).
- Tests: `tests/test_impl.py`, `tests/test_pqverify.py` (19 real pq-verify 2.19.0 outputs in `tests/fixtures/pqverify/`, argument and environment rules, a fake pq-verify for runs, timeouts and changed reports, and a live test when pq-verify and two ML-KEM-768 libraries are present), eleven `impl` cases in the mutation suite (`i01` to `i10`, with `i02b`), self-test cases S11a to S11d, two format 3 fixtures written by 0.2.0 and two format 4 implementation check fixtures (without and with a pq-verify run) under `tests/golden/evidence/`. CI installs pq-verify from a hash-pinned requirements file and builds the two libraries from a pinned mlkem-native commit (`tests/pqverify_targets.sh`) for the live test; PQ-Proof does not depend on pq-verify at run time.

- `guide/impl.md`: the implementation check from question sheet to receipt, the PQCgenKAT `.rsp` path, the pq-verify bridge (run untrusted libraries in a container or VM, install pq-verify pinned by version and wheel hash), the result table, which source each accepted version comes from and how to accept another one, the limits (a KAT match, not a certification or a KCMVP validation; the reference versions may change again; `--verify` reads copies and does not rerun pq-verify; no negative decapsulation items) and how to update the KAT list. README, DESIGN, SECURITY, `guide/outputs.md`, `guide/quickstart.md` and the site (sections B, G and I, two FAQ answers, and the KISA mapping evidence for S03) describe it too.
- `.github/workflows/kpqc-e2e.yml`, run by hand or on a `v*` tag: it downloads pinned KpqC reference implementations from GitHub (SMAUG-T 1.2.0 and 1.1.1, HAETAE 1.1.2, NTRU+ 2026-01, AIMer 3.0) and PQClean ML-KEM-768, checks their SHA-256 and builds NIST API shared libraries (`tests/kpqc_targets.sh`, wrappers in `tests/kpqc/`). `tests/kpqc_e2e.py` then answers question sheets with the example harness and checks the results: the latest versions of SMAUG-T, NTRU+ and AIMer pass (HAETAE 1.2.0 is published only on Google Drive, so the workflow does not build it), SMAUG-T 1.1.1 and HAETAE 1.1.2 need review (exit 5 under `FAIL_ON_REVIEW=1`), decapsulation answers alone need review, a build with a planted decapsulation defect fails, and the `.rsp` written by the SMAUG-T 1.2.0 reference KAT program passes with 100/100. With pq-verify 2.19.0 installed by wheel hash, `i-nist` passes on mlkem-native, fails on the same library with a planted defect, and fails on PQClean ML-KEM-768 clean, whose only failing stages are the FIPS 203 input checks. Every receipt goes through `--verify`. The default CI does not download the KpqC sources; its lint job runs shellcheck on `tests/kpqc_targets.sh`.

### Changed

- `pqlite/version.py`: `scan/kat` is hashed as one digest over its `*.json` files (`path_sha256`).
- `tests/golden/make_fixture.py` renders `README.txt` again for format 3 and later.

## [0.2.0] - 2026-11-19

Tool 0.2.0, ruleset 2 (new name and hash, eleven rule files), evidence format 3. Bypasses from the November review (X01 to X10) are closed, and the rule gaps X11, X18 to X28, X30, X31, X47, X56 to X59 and X62 with them. New commands `pqproof check` and `pqproof inventory`, new settings `PROFILE`, `FAIL_ON_REVIEW`, `REQUIRE_RESOLVED`, `EXPECT_FROM`, `REVIEW_MAX_AGE_DAYS` and `MAX_FILE_MIB`, and exit codes 4 (tool error) and 5 (pass that needs review, only with `FAIL_ON_REVIEW=1`). `--verify` still reads evidence formats 1 and 2 (ruleset 1).

**Verdict impact (판정 영향): yes.** The 14 golden tree cases of 0.1.1 give the same verdicts and check statuses. Their counts move in four places: `E-MLKEM768` drops from 3 to 2 in the migrated example because a trailing `#` comment no longer counts as code, lower-case `ecdsa` now counts under `G-EC` (`m06b`), `m06` counts five test lines instead of three (the same lower-case `ecdsa` in its test file), and `m04` gets one more weakening hit (its TLS 1.0 protocol list also leaves out TLS 1.3); the four new `EXPECT` rules appear with 0. The `a-cbom` "check" count drops too: a row that `scan.py` traced to a post-quantum value is now informational (4 to 0 on `examples/pqc`). The golden file records that count from this release on. Nineteen new golden cases plant one bypass or false positive each, and 0.1.1 gives a different verdict or check status on every one of them. Six more (`m27` to `m29b`) guard fixes from the review of this release: `m27b` and `m27c` differ from 0.1.1 (skip-folder counting), `m27` and `m28` give the same result as 0.1.1, and `m29` and `m29b` use the new `check` command. Trees that used one of these bypasses get a different verdict, and a tree hash changes when the tree holds a folder that the skip rules now treat differently.

| Change | 0.1.1 (ruleset 1) | Now (ruleset 2) |
|---|---|---|
| X01: a `legacy` comment or name on lines that create a new key or signature in Python, Go or Node (`m12`) | pass | fail (`a-cbom`, `c-classic`) |
| X01: lines allowed by the name rule alone, read only (`m12c`, `m12b`) | `r-allow` not applicable | `r-allow` needs review, fails under `REQUIRE_REVIEW=1` |
| X01: a `legacy` line that signs a token or certificate (`jwt.encode`, `SignedString`, `signWith`, `x509.CreateCertificate`) | pass | fail (`a-cbom`, `c-classic`) |
| X02: RSA code in a production package named `vendor` under `src/main/` (`m13`) | pass | fail (`a-cbom`, `c-classic`) |
| X02, X09: a top-level `vendor/` with code (`m13b`) | `a-input` pass | `a-input` needs review, folder listed with its counts |
| X02: RSA code in a production package named `node_modules` under `src/main/` | pass | fail (`a-cbom`, `c-classic`); packages named `venv` or `.idea` there are read as before (`m27`) |
| X02, X09: `node_modules` next to `package.json` under `src/main/` (`m27b`) | skipped, `a-input` pass | skipped, folder listed with its counts, `a-input` needs review |
| X09: `.venv`, `venv`, `.idea`, `.gradle`, `__pycache__` or `.tox` with code, away from `src/main/` (`m27c`) | read by `residue.sh` and `cbom-scan.sh`, outside the tree hash | skipped: silently at the top of the tree or next to a build file, otherwise listed with its counts and `a-input` needs review |
| X03: trust-all TrustManager in a production package named `build` (`m16`) | pass | fail (`b-weakening`) |
| X06: a Korean trailing comment with 테스트 (test) on a key line (`m14`) | pass | fail (`a-cbom`, `c-classic`) |
| X07: Node `ml-kem-512`, `ml-dsa-44` (`m15`) | pass | fail (`a-cbom`, `c-classic`) |
| X04: a symbolic link in the fixed tree to code outside the tree | pass | `a-input` undecided (exit 3), fails under `REQUIRE_REVIEW=1` |
| X05: an nginx or Apache certificate path, or an SSH host key, outside the tree | read when the file was on the host, so the verdict depended on the machine | never read: a "check" row, or the host key named from its file name |
| X08: a tree whose file paths exceed the argument limit | `c-classic` undecided | judged |
| X09: `build`, `target` and `vendor` under `src/main/`; `.hg`, `.svn`, `.tox`, `.terraform`; `dist` next to a build file; top-level `data/` | judged by some scanners only, or outside the tree hash | one rule for the tree hash and all scanners (see DESIGN, Skipped folders) |
| X58 (found again here): ML-KEM named only in a comment on an X25519 line | `c-classic` allowed it as hybrid | counted |
| X11: a migration to ML-KEM-1024 and ML-DSA-87 (`m25`) | `c-expect` fail | pass (`PROFILE=nist-cat3`, the default) |
| X11: `PROFILE=cnsa2` on an ML-KEM-768 tree (`m25b`) | setting unknown, pass | `c-expect` fail |
| X18: `MaxVersion: tls.VersionTLS12` in Go (`m22`); `maxVersion: 'TLSv1.2'`, `OP_NO_TLSv1_3`, a Java or Spring protocol list without TLS 1.3 | pass | fail (`a-cbom`, and `b-weakening` when a change adds it) |
| X19: lower-case `ed25519`, `x25519`, `secp384r1`, `ecdsa`, `diffie-hellman`, `ssh-dss` (`m17`) | `c-classic` pass | `c-classic` fail |
| X20: PyNaCl `Box`, tweetnacl, libsodium, Go `x/crypto/nacl`, wolfSSL, Nimbus (`m23`) | pass | fail (`a-cbom`) |
| X22: RSA in a Python docstring or a trailing `#` comment (`m24`) | fail | pass (comment) |
| X22: `#include <openssl/rsa.h>` in C | `a-cbom` comment | blocks like other code |
| X22: a code line that starts with `--`, such as a PEM marker inside a Go string (`-----END RSA TESTING KEY-----`) | `a-cbom` comment | blocks like other code (`--` is a comment only in SQL, Lua and Haskell) |
| X23: `AWS::EC2`, CSS `#EC4899`, `0x00EC` (`m18`) | `c-classic` fail | pass |
| X24: `.test.tsx`, Django `tests.py`, `__mocks__`, `src/integrationTest`, `*_spec.rb` (`m19`) | fail | counted as tests |
| X25: Node `crypto.sign(null, ...)` with an ML-DSA-65 key (`m20`) | `a-cbom` fail | pass (a "check" row; the key generation decides) |
| X26: composite signature `MLDSA65-ECDSA-P256-SHA512` (`m21`) | `a-cbom` pass, `c-classic` fail | both need review, verdict pass |
| X28: HAETAE, AIMer, SMAUG-T, NTRU+ in Java | `scan.py` "check" row | post-quantum row; counted by `c-expect` under `PROFILE=kpqc` |
| X59: an `ssh-ed25519` host key in `known_hosts`, `HostKeyAlgorithms` in `~/.ssh/config` (`m26`) | pass | fail (`a-cbom`, `c-classic`) |
| N1: `-Djdk.internal.httpclient.disableHostnameVerification` as a JVM option | pass | `b-weakening` fail |
| X27: an encrypted PKCS#8 key, a keystore that does not open, a Java public-key API with an unreadable algorithm name | a "check" row | `a-cbom` needs review and the verdict line counts it; `REQUIRE_RESOLVED=1` fails |
| X31: an allowlist entry past its `expires_at` | the field was dropped, pass | `r-allow` needs review, fails under `REQUIRE_REVIEW=1` |
| X56: a code file over 1 MiB in the fixed tree | not shown | listed in `inputs.fixed.oversize`, `a-input` needs review |
| X30: a pass with `a-input` or `b-tls` needing review | `VERDICT=PASS` with no note | the note names the checks; `FAIL_ON_REVIEW=1` exits 5 |

### Added

- `scan/skip-dirs` and `pqlite/skipdirs.py`: one list of skipped folders for the tree hash, `pqlite/scan.py`, `residue.sh` and `cbom-scan.sh`, with a sync test that runs the three walks on one tree. Each run copies the list to `artifacts/skip-dirs`.
- `pqlite/rules.py`: the verdict rules that lived in `prove.py` (the nine classical families, the name rule, the write paths, the hybrid window, the 50% input threshold, how residue output is read, and each check's status), moved value for value. A test fails when a new pattern constant appears in `prove.py`.
- Evidence format 3 (`schemas/receipt-v3.schema.json`): `skip_dirs` (the copied list), tree hashes taken with the skip rules, `r-allow` and the verdict line count lines allowed by the name rule alone, and the note says `pqproof --verify`. SARIF reports those lines under `r-allow`.
- Eight mutation cases with golden entries (`m12` to `m16`), behaviour tests for links, out-of-tree files and the argument limit, a format 2 fixture from 0.1.1 (`tests/golden/evidence/f2-v0.1.1`), and eight more code mutants (30 in all).
- `HOST_FILES=1` for `cbom-scan.sh` run on its own: read the certificates and host keys a setting points to outside the tree. `prove.sh` never passes it.
- `PROFILE` and `scan/profiles.json` (X11, X28): `nist-cat3` (default), `cnsa2` and `kpqc`. `receipt.json` records `params.profile`; `b-tls` offers the profile's hybrid group and `EXPECT=cert` accepts its certificate keys.
- `residue.sh` rules `E-MLKEM1024`, `E-MLDSA87`, `E-KPQC-KEM` and `E-KPQC-SIG`, and composite signatures counted apart (`allowlist.composite`, format 3).
- Weakening rules for code that turns TLS 1.3 off in Go, Node, Python, Java and Spring (X18), and scanner rows for the same settings.
- Eleven mutation cases with golden entries (`m17` to `m26`), and 20 scanner assertions under `scan/fixtures/r2/`.
- Six mutation cases with golden entries (`m27` to `m29b`: dependency-folder names under `src/main/` and elsewhere, a key and certificate pair in a test path, check mode with a link outside the tree) and two scanner assertions for a test-path key pair (162 in all). The mutation runner can make a symbolic link, a key pair with `openssl` (no private key is stored in the repository) and a `check` run.
- Settings `FAIL_ON_REVIEW` (exit 5 for a pass that needs review), `REQUIRE_RESOLVED`, `EXPECT_FROM=api` (X30), `REVIEW_MAX_AGE_DAYS` (X31) and `MAX_FILE_MIB` (X56), recorded under `params`. The Action takes `fail-on: review` and gives `review-checks`.
- Allowlist fields `expires_at` and `approval_ref`, the `kind` words, and warnings for fields the tool does not read (X31).
- Exit code 4 for an unexpected exception in a run or in `--verify` (X62).
- `README.txt` in every result folder (format 3): the verdict, what to open first, the re-check command and what to check before sharing. `--verify` renders it again and compares.
- The release workflow ships the `SHA256SUMS` of its `tls_probe` builds in the package; a TLS run records whether the probe binary is the release build (`tls.probe_build`: `release`, `local` or `unchecked`) and says so on the `b-tls` line (X47).
- `pqproof check <tree>` (`prove.sh --check`): judge one tree with no original, to keep classical algorithms from coming back after the migration. The two-tree checks are not applicable, so check mode does not look at TLS weakening (`b-weakening`) or removed verification (`r-review`); keep the two-tree run on pull requests. `a-input` still reports counted folders, oversize files and links, and a code link outside the tree leaves it undecided (exit 3, a failure under `REQUIRE_REVIEW=1`). `receipt.json` records `params.mode`. `pqproof inventory <tree>` (`prove.sh --inventory`): no verdict, `inventory.json` with the CBOM and the counts, in `inventory-out-<time>` by default (X13). The Action takes `mode: check` and `profile`, and `examples/github-actions/pqproof-check.yml` shows a weekly check.
- Fourteen more code mutants (44 in all) for the rule changes of this release; every one fails a behaviour or sync test.
- `tests/test_options.py`: the new settings, exit codes 4 and 5, expiry, review age, the size limit and unresolved key material, each with a re-verified evidence folder.

### Changed

- Ruleset 2 hashes eleven files: the six of ruleset 1 plus `pqlite/rules.py`, `pqlite/tlsprobe.py` (the TLS target verdict), `pqlite/skipdirs.py`, `scan/skip-dirs` and `scan/profiles.json`. Before, `prove.py` could change a verdict while `ruleset_sha256` stayed the same (X10). `scan/ruleset.json` keeps a file list per ruleset, and `--verify` recomputes a receipt's hash from the files of the ruleset it names.
- Name rule (X01): only `legacy` in code counts, not in a comment, and a line is allowed only when neither it nor the three lines below it creates a key, a signature, a signed token or certificate, or ciphertext in Java, Python, Go or Node. `prove.py` reads the lines that `residue.sh` allowed again with the same rule.
- Skipped folders (X02, X03, X09): `build`, `target`, `dist` and `vendor` are skipped only at the top of the tree or next to a build file, never under `src/main/`. Dependency, cache and metadata folders (`node_modules`, `.venv`, `venv`, `.idea`, `.tox` and the rest of the `any` list) are skipped at any depth, but under `src/main/` only next to a build file, and away from the top of the tree and from a build file they are counted. `inputs.*.skipped` lists every counted folder with its file and code-file counts, and code in a counted folder of the fixed tree makes `a-input` need review.
- Symbolic links (X04): links in the fixed tree that point outside the tree or into a skipped folder are listed in `inputs.*.skipped` and in `a-input`, for folders and zips alike.
- `cbom-scan.sh` never opens files outside the tree it scans (X05). `G-WEAK-PQC` and the scanner match ML-KEM-512, ML-DSA-44, Kyber512 and Dilithium2 in any case and separator (X07). The comment and test flags are read only at the start of a CBOM note (X06). `residue.sh` passes its file list in a temporary file (X08).
- `cbom-scan.sh` is in the CI shellcheck job; three warnings in it are gone without a change in behaviour.
- `residue.sh` reads comments by language (Python docstrings and trailing `#`, `#` in shell, YAML, Terraform and `sshd_config`, more C-family extensions) and matches lower-case names (X19, X22). `cbom-scan.sh` reads a leading `#`, `--` or `;` as a comment only in the languages that use it, and `pqlite/rules.py` checks Go, JavaScript, Python and Java rows with the language tokenizer (X22). `G-EC` needs `EC` as its own word (X23). The test-path rule covers more frameworks, and keystores in test paths carry the flag (X24).
- `crypto.sign`/`crypto.verify` in Node is a "check" row (X25). `known_hosts` and `~/.ssh/config` are scanned (X59). PyNaCl, tweetnacl, libsodium, Go `x/crypto/nacl`, wolfSSL and Nimbus are matched by API (X20).
- A file name with a control character (newline, tab) is an input error (exit 2) for folders too, not only for zips (X21): the line-based scanners would miss the file.
- The verdict line names the checks that need review besides those it already counts (`needs review: a-input`), and counts composite signatures (format 3, X30).
- An `a-cbom` "check" row whose value `scan.py` traced to a post-quantum algorithm is informational now (X27), so the "check" count on `a-cbom` drops (`examples/pqc`: 4 to 0).
- `check` and `inventory` are commands of `pqproof`, so an original folder with one of these names goes in as `./check`. `pqproof` warns when it sees such a folder.
- `tables/report.md` writes `&`, `<` and `>` in table cells as entities, because a link target from the input can reach a cell. Number settings (`MAX_FILE_MIB`, `REVIEW_MAX_AGE_DAYS`) take ASCII digits only; a Unicode digit is a usage error (exit 2), not a traceback.
- `cbom-scan.sh` masks password-like values in its own excerpts and passes keystore passwords through environment variables, not the command line (X33). `--selftest` counts skipped assertions and prints the total, so CI no longer keeps the number.
- `tests/version_policy.py --base`: when the version was bumped but shipped the base's ruleset, and the current ruleset's `since` is a later release, the verdict change counts toward that later release and `[Unreleased]` has to say yes. Before, every commit after the 0.1.1 bump that changed a rule failed the check against `v0.1.0`.

## [0.1.1] - 2026-11-19

Tool 0.1.1, ruleset 1 (unchanged, same hash), evidence format 2 (unchanged). Fixes, tests, CI and documentation from the November review; no rule file changed.

**Verdict impact (판정 영향): none.** On the 14 golden tree cases every verdict, check status and count is the same as in 0.1.0, and 0.1.0 evidence still verifies. Exit codes moved in two places that never had a sound verdict: a zip whose entry names repeat or differ only in case or Unicode normalization is now an input error (exit 2; before, a repeated name ended in a traceback and a case-only pair unpacked as one file on macOS), and `--verify` on a missing folder exits 2 instead of 1.

### Added

- `CONTRIBUTING.md` (local checks, layout, a checklist for changing a rule or adding a language, site rules, evidence format changes) and a pull request template that asks for the verdict impact.
- A docs test: every relative link and every `github.com/g1mn/pqproof/blob/main/` link in the Markdown files points to a file and heading that exist, the SARIF help anchor exists on the site, and the pages the tool prints exist.
- CI outside GitHub: a GitLab merge request job (`examples/gitlab/`) that turns the SARIF file into a Code Quality report, a Jenkinsfile that records it with the Warnings Next Generation plugin, and a SonarQube note.
- JSON Schemas for the evidence and the allowlist (`schemas/receipt-v2.schema.json`, `schemas/unconverted.schema.json`), written from the code by `tests/make_schemas.py` and tested against the golden evidence, a fresh run and the allowlist example. DESIGN lists the fields that stay stable within a `format_version` and the text that is only for people.
- `examples/allowlist/`: an allowlist with an unreviewed fallback entry and a reviewed boundary entry, and what each field means.
- Behaviour tests per rule (`tests/test_rules.py`): every pattern alternative in `residue.sh` and every TLS-weakening rule in `pqlite/verify.py` has a line or a change it catches and a near miss it does not, and the allow rules in `prove.py` are tested at their thresholds (hybrid window 12 and 13 lines, write path 3 and 4 lines below, `a-input` at 50% common files). Bypasses found in the November review are pinned as known gaps with their review numbers, so the release that fixes them has to flip those tests. One more gap turned up while writing them: `-Djdk.internal.httpclient.disableHostnameVerification` passed as a JVM option is not flagged (`N1`).
- Code mutants (`tests/code_mutants.py`, weekly workflow): 22 small changes to the rule code, each of which must fail a behaviour or sync test. All 22 do. Before these tests, three of the reviewer's seven mutants passed every test and three more failed only the ruleset hash check.
- Sync tests (`tests/test_rule_sync.py`) for rule values that live in more than one file: the residue rule IDs against the nine families in `prove.py` and the rules SARIF reports, the write operations, the `legacy` word, the `Legacy*.java` name rule, and the order in which `prove.py` and `pqproof doctor` pick OpenSSL. The four skip-folder lists differ today; the test pins them as a known gap.

### Changed

- Documentation split: the README has a five-minute path, exit-code and platform tables and a word list; `guide/` holds the quick start, configuration (all settings in English), allowlist, outputs and CI pages; `DESIGN.md` keeps the rules and the evidence format; `HISTORY.md` keeps the contest story and the changes since the finals. The README's exit-code line used to leave out 2, and the docs told pip users to clone the repository for the bundled examples that the wheel already carries.
- The GitHub example workflow reads the allowlist from the base commit and warns when a pull request changes it, so the author of a change cannot also approve its allowlist entries. `CODEOWNERS.example` shows how to require a security owner. The Action reference is pinned to the `v0.1.0` commit instead of the movable tag, and permissions are set per job.
- Release workflow: it runs the whole CI workflow first (`workflow_call`), so a release no longer passes on one Ubuntu job alone. It checks that the tagged commit is on `main`, builds with `build` and `hatchling` pinned by hash, without build isolation, and attests `BUILDINFO` too. The SBOM now lists the wheel and sdist hashes, the `tls_probe` binaries with their Go version and the external programs (bash, OpenSSL, keytool), passes the CycloneDX schema check and gets an SBOM attestation. The release notes say `shasum -a 256 -c --ignore-missing SHA256SUMS`, which works when only one binary was downloaded.
- CI: a `lint` job (ruff with error rules, shellcheck, zizmor) with hash-pinned tools, and Python 3.15 in the test matrix. A fourth `tls_probe` binary for Intel Macs (`darwin-amd64`).
- Progress: a run prints the applied settings first, then one line per step with the time taken, to stderr. A large tree no longer looks stuck for minutes.
- A variable whose name is one letter off a setting (`REQUIRE_REVEIW`, `TLS_TARGET`, `EXPCET`) and an unknown `PQPROOF_` name get a warning at the start. Before, `REQUIRE_REVEIW=1` left strict mode off without a word.
- The default output folder is `proof-out-YYYYMMDD-HHMMSS` (`proof-YYYYMMDD-HHMMSS` under `<W>/evidence`), with `-2`, `-3` when two runs start in the same second. Before, it had only the time of day and a second run in the same second stopped with exit 2.
- The console ends with what to open first (`receipt.html`, `receipt.json`, `tables/report.md`) and the re-check command for the entry point that ran (`pqproof --verify` or `bash prove.sh --verify`, also in `deck.json` and `tables/report.md`). After a failure it lists where the full lists are and points to an allowlist example (`examples/allowlist/`). `tables/report.md` gets a "blocking locations" table, and its "left after the migration" table no longer says "none" without pointing to the cause.
- `tests/e2e_orders_edge.py` says it is a manual test (it needs a full clone and Go); DESIGN says the same, and `format` versus `format_version` is explained in the evidence section.
- Leftovers from the contest pipeline are gone: `a-input` no longer points to a `crypto-grep.sh` that is not shipped, and the console header says `PQ-Proof <version>` instead of `pqc-proof prove.sh`.
- `pqproof --verify` and `pqproof --env` run in Python alone, without bash, so evidence can be re-checked on Windows. A CI job on `windows-latest` re-verifies the golden evidence and converts one to SARIF. On Windows, judging stops with exit 2 and a note to use WSL, even when a Git Bash `bash` is on the PATH. `tests/golden/evidence/` is checked out byte for byte (`.gitattributes`).
- Version policy, as Semantic Versioning has it: a new command or option bumps MINOR too, not only a verdict change. Before, the policy said that any change that moved no verdict was a PATCH.
- `scan/ruleset.json` records, for each ruleset, the first version that shipped it (`since`), its verdict impact (`yes`, or `no` for a change in comments only) and the hash of each rule file. `--verify` and `pqproof --version` still read the old form. Ruleset 1 is unchanged: same name, same hash.
- `tests/version_policy.py` enforces the policy in CI (new `version-policy` job) and in the release workflow: a ruleset with verdict impact yes must first ship in a release with PATCH 0, every CHANGELOG entry (and `[Unreleased]`) has a verdict-impact line, an entry that says yes is not a PATCH release, and golden verdicts that moved since the previous release tag need a MINOR release and a "yes" entry.
- Golden comparison in `run_mutations.py`: a different ruleset name alone no longer fails every tree case. It is reported in one line at the top of the golden summary, and a case fails only when its verdict, a check status or a count moves. `--diff-golden FILE` writes the moved cases and fields as a Markdown table for the verdict-impact entry, and `--write-golden` prints what moved against the file it replaces before writing it.

### Fixed

- `--verify` and `pqproof sarif` read `receipt.json` strictly. A duplicate key, a byte order mark, `NaN` or `Infinity`, or bytes after the object fail, and so does any file whose bytes differ from the tool's own serialization of its values. Before, a second `"verdict"` key inserted at the top passed `--verify` with the same `receipt_id`, while a parser that keeps the first value read another verdict.
- The RFC 8785 form sorts object keys by UTF-16 code units, as the RFC says, and refuses integers beyond 2^53. Every key so far is ASCII, so no existing `receipt_id` changes. A test recomputes the golden receipts with a second implementation and, when Node.js is there, in JavaScript.
- `--verify` on a folder that does not exist, or one without `receipt.json`, exits 2 (input error) instead of 1.
- A zip input that would unpack differently on another machine is an input error (exit 2) with a one-line reason: a name that appears twice, names that differ only in case or Unicode normalization, control characters, a file and a folder with the same name, or more than 500,000 entries. Before, a repeated name stopped the run with a Python traceback and exit 1, and a case-only pair unpacked as one file on macOS. Well-formed zips and folders get the same verdicts as before.
- Secrets in excerpts: a script line such as `keytool ... -storepass changeit` or `openssl ... -passout pass:...` used to appear as is in `tables/cbom-*.csv`, `tables/report.md` and SARIF snippets, which code scanning shows to everyone with read access. Values after `-storepass`, `-keypass`, `pass:`, `password=`, `token=` and similar names, after `Bearer`, and strings with known token prefixes are now `***`, also in SARIF fingerprints. The console and `run.properties.redactedSnippets` give the count. The raw scanner output under `artifacts/` is unchanged until the next ruleset.
- A `tls_probe` binary that is not on the machine is no longer listed in `receipt.json` `tools` with version 0.4.0 and no hash, which read as if it had run. The source entry stays.
- The warning for OpenSSL below 3.5 or LibreSSL says what is really lost: the OpenSSL TLS cross-check and some key details in the CBOM notes. It used to say ML-DSA certificates could not be read, but the scanner reads them by OID.
- The five evidence tamper tests ran only with a `tls_probe` binary, so an installed copy without Go skipped them. They now use a run without TLS; only the TLS case still needs the binary, and `--unit` says how to build it.
- SARIF rule help links (`helpUri`) pointed to `#checks`, an anchor the site does not have, so they opened the top of the page. They now point to `#sec-checks`, the checks section.

## [0.1.0] - 2026-11-18

First public release: tool 0.1.0, ruleset 1, evidence format 2. The comparison point is the version that ran in the finals of the 2026 PQC Transition Hackathon on 2026-11-16 ("the finals version" below).

**Verdict impact (판정 영향): yes, compared with the finals version.** A tree whose only classical public-key lines sit in test paths used to fail `c-classic` and now passes (D2 below). The new `r-allow` check adds a row, and it fails a run only under `REQUIRE_REVIEW=1`. On 16 runs over the eight practice tasks, with the rules of this release (ruleset 1), every verdict matched the finals version; the rule files have changed since then only in comments. The one intended difference is a separate reproduction of the test-path case.

| Change | Verdict impact (판정 영향) |
|---|---|
| New check `r-allow`: was each allowlist entry read by a person (`reviewed_by`, `reviewed_at`, `reviewed_digest`)? | New row. The verdict moves only with `REQUIRE_REVIEW=1`, where an unreviewed entry fails the run. |
| D1: an allowlist entry that covers no classical line in the fixed tree is reported as unused, with the original lines it would hide. This includes an entry for a file the fix deleted. | `r-allow` needs review, or fails under `REQUIRE_REVIEW=1`. A list whose entries are all unused moves `r-allow` from not applicable to needs review. |
| D2: one test-path list (`scan/test-paths.ere`) for all scanners, and nothing under `src/main/` counts as a test path. | Can move verdicts: classical lines in `*_test.go`, `*Test.java`, `test_*.py`, `__tests__/`, `testdata/` and top-level example folders no longer count, and `src/main/java/com/example/` is no longer treated as tests. |
| The verdict line counts removed verification calls, for example `VERDICT=PASS (2 removed verifications need review)`. | Text only. Before, a `verify()` reduced to `return true` passed with no note on the verdict line. |
| The output says 검증 증적 (verification evidence) for 영수증 (receipt), and 보안레벨 (security level) for 범주 (category). | Text only. |

### Added

- `pqproof` console command and Python package (`pip install pqproof`). It runs the same files as `bash prove.sh`. There are no runtime Python dependencies.
- `pqproof sarif` and `bash prove.sh sarif`: evidence to SARIF 2.1.0 for GitHub code scanning. Checks that did not run are listed under `notCountedAsPass`.
- GitHub Action (`action.yml`) with outputs `verdict`, `evidence-hash` and `sarif-file`, and an example workflow in `examples/github-actions/`.
- Mutation suite (`tests/mutations/`): 18 cases, planted defects and their controls, each with the result it must give. A case that cannot be set up is SKIP and is not counted as passed.
- Golden verdicts (`tests/golden/verdicts.json`): the verdict, check statuses and counts of every mutation and example case. CI fails when a rule change moves one of them.
- Evidence format 2: `receipt.json` records `format_version`, `tool_version`, `ruleset_version` and `ruleset_sha256`, the hash of the six rule files that ran. `--verify` recomputes that hash from the tool hashes in the receipt.
- `bash prove.sh --version` and `pqproof --version`. The version lives in one place, `src/pqproof/__init__.py`.
- Backward-compatibility fixtures (`tests/golden/evidence/`): evidence written by three earlier public copies and by this release. `--verify` must keep reading them. Local paths were replaced with neutral text; verdicts and counts are unchanged.
- CI on Ubuntu and macOS with Python 3.9 to 3.14, Pages deployment, and a release workflow that builds the wheel, the sdist, three `tls_probe` binaries, a CycloneDX SBOM and build provenance attestations, then publishes to PyPI with Trusted Publishing.
- `SECURITY.md`, Dependabot for GitHub Actions and pip, and every action pinned to a commit SHA.

### Changed

- `--verify` reads evidence format 1 (no `format_version`), which the earlier public copies wrote. It accepts their notes and rebuilds their `receipt.html` with the words they used.
- Self-test and unit tests count skipped cases apart (`n 통과 · m 건너뜀 · k 실패`). With `STRICT=1` a skipped case fails the run. CI runs with `STRICT=1`.
- After the verdict, the console prints how many checks ended in each state. Only pass counts as passed.
- An explicit `OPENSSL` is used as given, even below 3.5. Before, a newer OpenSSL found elsewhere took its place.

### Fixed

- Every TLS target in `receipt.json` now has `openssl_agrees`. Without OpenSSL 3.5 (Ubuntu's 3.0, macOS LibreSSL) it is `null` and `openssl_note` says 교차 확인 불가 (cross-check not possible). Before, the field was missing and code that read it failed.
- `--verify` checks that the residue script hash in `tools[]` matches the copy in `artifacts/` (`java.script_sha256`). Before, the two could differ and the evidence still verified.

[Unreleased]: https://github.com/g1mn/pqproof/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/g1mn/pqproof/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/g1mn/pqproof/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/g1mn/pqproof/releases/tag/v0.1.0
