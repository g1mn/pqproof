# Contributing

Issues and pull requests are welcome. Security problems go through [SECURITY.md](SECURITY.md), not a public issue.

## Check locally

```bash
STRICT=1 bash prove.sh --unit && STRICT=1 bash prove.sh --selftest \
  && python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json
cp -R . /tmp/pqproof-scan && (cd /tmp/pqproof-scan && bash scan/cbom-scan.sh --selftest)   # writes test keys, so use a copy
python3 -m pip install --require-hashes -r .github/requirements/lint.txt
ruff check . && shellcheck -S warning prove.sh build-probe.sh scan/residue.sh scan/cbom-scan.sh && zizmor --offline --min-severity medium .github/workflows/ action.yml
```

`STRICT=1` fails on any skipped test. The TLS tests need `tls_probe` (`bash build-probe.sh`, Go 1.27 or later) and the SARIF schema test needs `jsonschema` and the schema file in `SARIF_SCHEMA` (see `.github/workflows/ci.yml`). The weekly `python3 -I tests/code_mutants.py --baseline` checks that the behaviour tests still catch small changes to the rule code.

## Layout

| Path | What |
|---|---|
| `prove.sh`, `prove.py` | entry point, run order, tables and evidence |
| `pqlite/` | verdict rules and checks (`rules.py`), code scanner, TLS-weakening rules, probe output parser, evidence writer and verifier, allowlist, versions |
| `scan/` | `cbom-scan.sh` (CBOM scanner, bash and OpenSSL), `residue.sh` (classical-line counter), `test-paths.ere` (the test-path list), `ruleset.json` (ruleset names, hashes, first version and verdict impact) |
| `src/pqproof/` | the `pqproof` command, the SARIF converter and the external-program check |
| `schemas/` | JSON Schemas of `receipt.json` and the allowlist, written by `tests/make_schemas.py` |
| `probe/`, `build-probe.sh` | `tls_probe` source (Go standard library) and its offline build script |
| `examples/` | the before and after trees used by the tests, an allowlist, and CI examples for GitHub, GitLab and Jenkins |
| `tests/` | unit tests, the mutation suite, golden verdicts, older evidence and a snapshot of the orders-edge fixture |
| `guide/`, `DESIGN.md`, `HISTORY.md` | how to use it, the rules and the evidence format, and the contest story |
| `action.yml`, `.github/` | the GitHub Action, CI, Pages and release workflows, hash-pinned tool lists, Dependabot |
| `docs/` | the site, deployed to GitHub Pages |

Code comments and tool output are in Korean; documentation is in English, with a Korean summary in DESIGN.md.

## Changing a rule

The ruleset is the files in `RULESET_FILES` of `pqlite/version.py`: `scan/cbom-scan.sh`, `scan/residue.sh`, `scan/test-paths.ere`, `scan/skip-dirs`, `scan/profiles.json`, `pqlite/scan.py`, `pqlite/verify.py`, `pqlite/allowlist.py`, `pqlite/rules.py`, `pqlite/skipdirs.py`, `pqlite/tlsprobe.py`, `pqlite/impl.py`, `scan/kat-kpqc.json` and the excerpts in `scan/kat/` (fourteen files from ruleset 3). A folder to skip goes in `scan/skip-dirs`, nowhere else. A verdict constant or pattern belongs in `pqlite/rules.py`, not in `prove.py`; a test fails when `prove.py` gets a new pattern constant. Changing any byte of them, a comment included, changes the ruleset hash, and a run with a changed file is named `<current>+modified` until the change has its own ruleset name. So a lint fix in these files (CI runs shellcheck on `scan/cbom-scan.sh` and `scan/residue.sh`) goes in with a ruleset change.

A rule ID or a value can live in more than one file. For a new or changed rule:

1. Change the rule file, and the copies that `tests/test_rule_sync.py` checks: `FAMILIES`, `WRITEOPS`, `ALLOWLINE` and `LEGACY_FILE` in `pqlite/rules.py`, `COUNTED_GEN`, `FAMILY_EN` and `RULES` in `src/pqproof/sarif.py`.
2. Add a row that the rule catches and a near miss it must not catch to `tests/test_rules.py`. A rule or a pattern alternative without a row fails that test. If the change fixes a known gap, flip its test and remove the number from `KNOWN_GAPS`. Update the search strings in `tests/code_mutants.py` if the code they point to moved.
3. Run `python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json --diff-golden /tmp/moved.md`. If verdicts, check statuses or counts moved and that is intended, rewrite the golden file with `--write-golden`.
4. Add a ruleset entry to `scan/ruleset.json` (`python3 -I -B pqlite/version.py --ruleset-json` prints the hashes): a new name, `since` (the release that ships it), `verdict_impact` and `files`, and make it `current`.
5. In `CHANGELOG.md` under `[Unreleased]`, write "Verdict impact: yes" with the table from step 3. A verdict change ships in a MINOR release while the version is 0.x (`tests/version_policy.py` enforces it).
6. Update the tables in DESIGN.md.

## Adding a language

Detection lives in three places: name patterns in `scan/residue.sh` (the classical-line count), CBOM rows in `scan/cbom-scan.sh`, and the structural scanner `pqlite/scan.py` (Java, Go). Start with `residue.sh` patterns and their behaviour rows, then check the test-path rule (`scan/test-paths.ere`) for the language's test file names, and the comment detection, which goes by language: `residue.sh` reads comments per file extension (Python docstrings and trailing `#`, `#` in shell, YAML, TOML, Terraform and `sshd_config`, C-family block comments), `cbom-scan.sh` reads a leading `#`, `--` or `;` as a comment only in the languages that use it (a C `#include` is code), and `pqlite/rules.py` checks Go, JavaScript, Python and Java rows with the tokenizer of `pqlite/verify.py`. Add a small before and after pair to the tests. Each of these is a ruleset change.

## Site rules

A service can add its own rules by copying `scan/residue.sh`, adding `SITE` rules and passing it with `RESIDUE=`. Its `LEFT` lines count toward `c-classic`. The run is named `<ruleset>+modified`, and the evidence keeps the copy that ran.

## Evidence format

A field added, removed, renamed or changed in meaning raises `format_version` in `pqlite/version.py`. Before such a release, save evidence from the current version with `tests/golden/make_fixture.py`, so `tests/test_golden.py` keeps checking it, and regenerate the schemas with `python3 -I -B tests/make_schemas.py`.

## Releases

1. Set `__version__` in `src/pqproof/__init__.py` and turn `[Unreleased]` in `CHANGELOG.md` into a dated section with its verdict impact.
2. Rebuild `docs/index.html` for the new version and commit it with the version change. The README is short and the site carries everything else, so review its numbers, example output, release entry, limits and FAQ for the new version too. The maintainer runs the site generator, which is not in this repository. While the site names another version, ruleset, evidence format or KAT list, `tests/version_policy.py` fails, so CI, the release workflow and the Pages deploy stop.
3. Push `main` and wait for CI, then tag `vX.Y.Z` on that commit. The release workflow runs CI again and refuses a tag that is not on `main`.
4. After the release, move the pins in `examples/`: the `g1mn/pqproof@<commit>` line in `examples/github-actions/pqproof-sarif.yml` (commit SHA and comment) and the `pqproof==` versions in the GitHub, GitLab and Jenkins examples.

## Pull requests

Say in the description whether a verdict can move (the template asks). Keep commits small, with tests. Documentation: usage goes in `guide/`, rules and formats in `DESIGN.md`.
