# Allowlist example

`unconverted.json` shows the two kinds of entry a migration usually keeps: a fallback that reads data written before the change, and a boundary with a partner that has not moved yet. The paths refer to your fixed tree, not to this repository.

- `where`: `file:line`, `file:start-end`, `file:15,24-40`, a path or a glob. Line ranges must exist in the fixed tree.
- `why`: the reason a person can check, with the condition for deleting the entry.
- `kind`: one of `fallback`, `boundary`, `kept`, `exception`, `false-positive` or `vendored`; another word gets a warning. `what` is optional.
- `expires_at` (`YYYY-MM-DD`) and `approval_ref` (a ticket or approval number) are optional. An entry in use past its date makes `r-allow` need review, and fails under `REQUIRE_REVIEW=1`. A date in another form gets a warning and is ignored.
- `reviewed_by` and `reviewed_at`: who read the entry and when. The first entry has none, so it counts as not reviewed: `r-allow` needs review, and fails under `REQUIRE_REVIEW=1`.

Run it with `ALLOW=examples/allowlist/unconverted.json pqproof <original> <fixed>`. The rules are in [guide/allowlist.md](https://github.com/g1mn/pqproof/blob/main/guide/allowlist.md) and the schema in [schemas/unconverted.schema.json](https://github.com/g1mn/pqproof/blob/main/schemas/unconverted.schema.json).
