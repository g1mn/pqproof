# Contributing

Issues and pull requests are welcome. Security problems go through [SECURITY.md](SECURITY.md), not a public issue.

## Check locally

```bash
STRICT=1 bash prove.sh --unit && STRICT=1 bash prove.sh --selftest \
  && python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json
cp -R . /tmp/pqproof-scan && (cd /tmp/pqproof-scan && bash scan/cbom-scan.sh --selftest)   # writes test keys, so use a copy
python3 -m pip install --require-hashes -r .github/requirements/lint.txt
ruff check . && shellcheck -S warning prove.sh build-probe.sh scan/residue.sh && zizmor --offline --min-severity medium .github/workflows/ action.yml
```

`STRICT=1` fails on any skipped test. The TLS tests need `tls_probe` (`bash build-probe.sh`, Go 1.27 or later) and the SARIF schema test needs `jsonschema` and the schema file in `SARIF_SCHEMA` (see `.github/workflows/ci.yml`). The weekly `python3 -I tests/code_mutants.py --baseline` checks that the behaviour tests still catch small changes to the rule code.

## Layout

| Path | What |
|---|---|
| `prove.sh`, `prove.py` | entry point and the checks |
| `pqlite/` | code scanner, TLS-weakening rules, probe output parser, evidence writer and verifier, allowlist, versions |
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

The ruleset is six files: `scan/cbom-scan.sh`, `scan/residue.sh`, `scan/test-paths.ere`, `pqlite/scan.py`, `pqlite/verify.py` and `pqlite/allowlist.py`. Changing any byte of them, a comment included, changes the ruleset hash, and a run with a changed file is named `<current>+modified` until the change has its own ruleset name. That is why lint warnings in these files wait for the next ruleset.

A rule ID or a value can live in more than one file. For a new or changed rule:

1. Change the rule file, and the copies that `tests/test_rule_sync.py` checks: `FAMILIES`, `WRITEOPS`, `ALLOWLINE` and `LEGACY_FILE` in `prove.py`, `COUNTED_GEN`, `FAMILY_EN` and `RULES` in `src/pqproof/sarif.py`.
2. Add a row that the rule catches and a near miss it must not catch to `tests/test_rules.py`. A rule or a pattern alternative without a row fails that test. If the change fixes a known gap, flip its test and remove the number from `KNOWN_GAPS`. Update the search strings in `tests/code_mutants.py` if the code they point to moved.
3. Run `python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json --diff-golden /tmp/moved.md`. If verdicts, check statuses or counts moved and that is intended, rewrite the golden file with `--write-golden`.
4. Add a ruleset entry to `scan/ruleset.json` (`python3 -I -B pqlite/version.py --ruleset-json` prints the hashes): a new name, `since` (the release that ships it), `verdict_impact` and `files`, and make it `current`.
5. In `CHANGELOG.md` under `[Unreleased]`, write "Verdict impact: yes" with the table from step 3. A verdict change ships in a MINOR release while the version is 0.x (`tests/version_policy.py` enforces it).
6. Update the tables in DESIGN.md.

## Adding a language

Detection lives in three places: name patterns in `scan/residue.sh` (the classical-line count), CBOM rows in `scan/cbom-scan.sh`, and the structural scanner `pqlite/scan.py` (Java, Go). Start with `residue.sh` patterns and their behaviour rows, then check the test-path rule (`scan/test-paths.ere`) for the language's test file names, and the comment detection, which goes by line prefix (`//`, `#`, `/*`, `--`, `<!--`): a docstring counts as code and a C `#include` as a comment. Add a small before and after pair to the tests. Each of these is a ruleset change.

## Site rules

A service can add its own rules by copying `scan/residue.sh`, adding `SITE` rules and passing it with `RESIDUE=`. Its `LEFT` lines count toward `c-classic`. The run is named `<ruleset>+modified`, and the evidence keeps the copy that ran.

## Evidence format

A field added, removed, renamed or changed in meaning raises `format_version` in `pqlite/version.py`. Before such a release, save evidence from the current version with `tests/golden/make_fixture.py`, so `tests/test_golden.py` keeps checking it, and regenerate the schemas with `python3 -I -B tests/make_schemas.py`.

## Pull requests

Say in the description whether a verdict can move (the template asks). Keep commits small, with tests. Documentation: usage goes in `guide/`, rules and formats in `DESIGN.md`.
