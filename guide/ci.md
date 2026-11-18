# CI

PQ-Proof fits a pipeline as one step: judge the change against its base commit, keep the evidence folder, and show the remaining classical lines where reviewers look. Exit codes: 0 pass, 1 fail, 2 usage or input error, 3 undecided.

## GitHub Action

`action.yml` is a composite Action.

- Inputs: `original`, `converted`, `allow-list`, `require-review`, `expect`, `scope`, `classic`, `exclude`, `tls-targets`, `probe-bin-dir`, `output-dir`, `sarif-file`, `sarif-anchor`, `fail-on` (`not-pass`, `review`, `fail` or `never`; `review` also stops a pass that has a check needing review) and `python`.
- Outputs: `verdict` (`pass`, `fail`, `undecided`, or `error` when no evidence was written), `evidence-hash`, `exit-code`, `output-dir`, `sarif-file` and `review-checks` (the ids of the checks that need review).

Inputs reach the scripts only through environment variables. The Action runs `--verify` on the evidence it wrote and reports `error` if that fails. Its job summary lists the checks and the ones not counted as passed.

`examples/github-actions/pqproof-sarif.yml` judges a pull request against its base commit and uploads the SARIF file to code scanning:

- It reads the allowlist from the base commit and warns when the pull request changes it. An author cannot add entries and fill in their review fields in the same pull request; the new entries apply after they are merged.
- `CODEOWNERS.example` puts `notes/unconverted.json` behind a security owner's approval.
- The Action is pinned to a commit SHA, not a tag, because a tag can move. Release assets carry build provenance: `gh attestation verify <file> --repo g1mn/pqproof`.

## SARIF

`pqproof sarif <output folder> [-o file] [--uri-prefix path/] [--anchor file]` turns the evidence into SARIF 2.1.0. It first recomputes `receipt_id` and the hash of every file it reads; on a mismatch it writes nothing and exits 2.

| Rule | Source | Level |
|---|---|---|
| `a-cbom` | blocking rows of `tables/cbom-fixed.csv`, one result per location, and rows left for review (a write path inside an allowed range) | error; review rows warning |
| `c-classic` | `LEFT` lines of the nine public-key families, weak PQC, legacy writes and site rules in `artifacts/residue-fixed.txt`, minus allowed and hybrid lines | error; listed review lines warning |
| `b-weakening` | `weakening.deny` | error, at file level |
| `r-review` | `weakening.review` | warning, at file level |
| `r-allow` | allowlist entries in effect without review, unused entries, write paths | warning; error under `REQUIRE_REVIEW=1` |
| `c-expect`, `b-tls`, `a-input` | the check status | error on fail, warning on review or undecided, attached to the `--anchor` file or kept as a run notification |

Checks that ended not applicable or undecided are listed in `run.properties.notCountedAsPass`. Fingerprints hash the rule, path, algorithm and snippet without the line number, so an alert survives a line shift. Snippets are masked for secrets before they are written and hashed, and `run.properties.redactedSnippets` counts the masked values.

## GitLab, Jenkins, SonarQube

- GitLab: `examples/gitlab/pqproof.gitlab-ci.yml` runs on merge requests, converts the SARIF file into a Code Quality report with `examples/gitlab/sarif_to_codequality.py` (shipped in the wheel), and keeps the evidence folder.
- Jenkins: `examples/jenkins/Jenkinsfile` records the SARIF file with the Warnings Next Generation plugin and archives the evidence folder.
- SonarQube: set `sonar.sarifReportPaths=pqproof.sarif` to import the results as external issues.

All of them read the allowlist from the base commit.

## Offline runners

A runner without internet needs the wheel (from an internal package mirror, or `pip download pqproof` elsewhere), bash, OpenSSL and, for TLS targets, the `tls_probe` binary for its platform with `SHA256SUMS` from the release. PQ-Proof itself makes no network calls.
