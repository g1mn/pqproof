## What changes

## Verdict impact (판정 영향)

- [ ] None: no verdict, check status or count can move for the same two trees.
- [ ] Yes: golden verdicts moved (paste the `run_mutations.py --diff-golden` table), `scan/ruleset.json` has a new entry, and `CHANGELOG.md` `[Unreleased]` says "Verdict impact: yes".

## Checked

- [ ] `STRICT=1 bash prove.sh --unit`
- [ ] `STRICT=1 bash prove.sh --selftest`
- [ ] `python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json`
- [ ] Docs: `guide/` for usage, `DESIGN.md` for rules and formats
