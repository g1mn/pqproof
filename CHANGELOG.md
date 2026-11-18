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

- Behaviour tests per rule (`tests/test_rules.py`): every pattern alternative in `residue.sh` and every TLS-weakening rule in `pqlite/verify.py` has a line or a change it catches and a near miss it does not, and the allow rules in `prove.py` are tested at their thresholds (hybrid window 12 and 13 lines, write path 3 and 4 lines below, `a-input` at 50% common files). Bypasses found in the November review are pinned as known gaps with their review numbers, so the release that fixes them has to flip those tests. One more gap turned up while writing them: `-Djdk.internal.httpclient.disableHostnameVerification` passed as a JVM option is not flagged (`N1`).
- Code mutants (`tests/code_mutants.py`, weekly workflow): 22 small changes to the rule code, each of which must fail a behaviour or sync test. All 22 do. Before these tests, three of the reviewer's seven mutants passed every test and three more failed only the ruleset hash check.
- Sync tests (`tests/test_rule_sync.py`) for rule values that live in more than one file: the residue rule IDs against the nine families in `prove.py` and the rules SARIF reports, the write operations, the `legacy` word, the `Legacy*.java` name rule, and the order in which `prove.py` and `pqproof doctor` pick OpenSSL. The four skip-folder lists differ today; the test pins them as a known gap.

### Changed

- Version policy, as Semantic Versioning has it: a new command or option bumps MINOR too, not only a verdict change. Before, the policy said that any change that moved no verdict was a PATCH.
- `scan/ruleset.json` records, for each ruleset, the first version that shipped it (`since`), its verdict impact (`yes`, or `no` for a change in comments only) and the hash of each rule file. `--verify` and `pqproof --version` still read the old form. Ruleset 1 is unchanged: same name, same hash.
- `tests/version_policy.py` enforces the policy in CI (new `version-policy` job) and in the release workflow: a ruleset with verdict impact yes must first ship in a release with PATCH 0, every CHANGELOG entry (and `[Unreleased]`) has a verdict-impact line, an entry that says yes is not a PATCH release, and golden verdicts that moved since the previous release tag need a MINOR release and a "yes" entry.
- Golden comparison in `run_mutations.py`: a different ruleset name alone no longer fails every tree case. It is reported in one line at the top of the golden summary, and a case fails only when its verdict, a check status or a count moves. `--diff-golden FILE` writes the moved cases and fields as a Markdown table for the verdict-impact entry, and `--write-golden` prints what moved against the file it replaces before writing it.

### Fixed

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
