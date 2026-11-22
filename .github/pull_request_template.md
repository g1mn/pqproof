## What changes

## Verdict impact (판정 영향)

- [ ] None: no verdict, check status or count can move for the same two trees.
- [ ] Yes: golden verdicts moved (paste the `run_mutations.py --diff-golden` table), `scan/ruleset.json` has a new entry, and `CHANGELOG.md` `[Unreleased]` says "Verdict impact: yes".

## Checked

- [ ] `bash prove.sh --unit` (CI runs it with `STRICT=1`; skips for missing `tls_probe`, `jsonschema` or pq-verify are fine locally)
- [ ] For a rule change: `bash prove.sh --selftest` and `python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json`
- [ ] For a mapping change: `python3 -I tests/test_mappings.py`
- [ ] Commit subjects end with `Verdict impact: none` or `Verdict impact: yes`
- [ ] Docs: `guide/` for usage, `DESIGN.md` for rules and formats
