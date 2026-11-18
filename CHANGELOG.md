# Changelog

All notable changes to PQ-Proof are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each release has a **Verdict impact (판정 영향)** line. It says whether the same two trees can get a different verdict, check status or count than they got with the previous release.

- A change that can move a verdict (detection pattern, test path, allow rule, a check added or removed) bumps MINOR while the version is 0.x, and MAJOR from 1.0 on. A rule change also gets a new ruleset name in `scan/ruleset.json`.
- A new command or option bumps MINOR. Other fixes bump PATCH, so a release that moves a verdict is never a PATCH release. CI and the release workflow check this against the previous release tag (`tests/version_policy.py`).
- Only the latest MINOR release gets fixes. See [SECURITY.md](SECURITY.md).

Every run records `tool_version`, `ruleset_version` and `ruleset_sha256` in `receipt.json`, so a receipt from years ago still names the rules that judged it. `--verify` keeps reading older evidence formats.

## [Unreleased]

**Verdict impact (판정 영향): none.**

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

[Unreleased]: https://github.com/g1mn/pqproof/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/g1mn/pqproof/releases/tag/v0.1.0
