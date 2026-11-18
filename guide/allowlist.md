# Allowlist

A migration often keeps a few classical lines on purpose: a reader for data sealed before the change, or a check of a partner's signature until the partner moves. The allowlist records each such place with a reason. Allowed lines leave the blocking count but stay in the evidence with their reason. The tool cannot judge a reason, so a person has to read it.

## Write one

```json
{"unconverted": [
  {"where": "src/main/java/com/acme/vault/OldKeyReader.java:18-41",
   "what": "RSA-OAEP unwrap of data keys sealed before the migration",
   "why": "Reads records written before the switch and re-seals them with ML-KEM-768. Delete after the re-seal job reports zero old records.",
   "kind": "fallback"}
]}
```

`examples/allowlist/unconverted.json` has a second, reviewed entry, and `schemas/unconverted.schema.json` is the schema. Pass the file with `ALLOW=path`, or keep it at `<W>/notes/unconverted.json` next to `<W>/orig`.

- `where`: `file:line`, `file:start-end`, `file:15,24-40`, a path, or a glob, in the fixed tree. A bare file name must match exactly one file. A line range past the end of the file, a missing file or a glob over several code files makes the whole entry invalid, so shifted line numbers are never trusted.
- `why`: required. Say why the line stays and when it goes.
- `kind` and `what`: free text.

Some lines never need an entry and some never get one. An X25519 or ECDH line in the same function as ML-KEM code counts as the classical half of a hybrid. A line in a `Legacy*.java` file, or one that contains `legacy`, is allowed when it does not write (no key generation, signing or encryption). ML-KEM-512 and ML-DSA-44 are never allowed.

## Review it

A person who read an entry adds `reviewed_by` (a name or account) and `reviewed_at` (`2026-11-18`, `2026-11-18T10:30` or with an offset). For a list whose entries have no pair of their own, one pair at the top works with a `reviewed_digest` that the run prints:

```
사람 확인: ... 맨 위에 reviewed_by·reviewed_at 과 reviewed_digest="f80af1efdb7c95c5" 를 적는다
```

```json
{"reviewed_by": "j.kim", "reviewed_at": "2026-11-18T10:30:00+09:00", "reviewed_digest": "f80af1efdb7c95c5",
 "unconverted": [ ... ]}
```

Adding or editing an entry changes the digest, and every entry under the top pair then counts as not reviewed again.

Without `REQUIRE_REVIEW=1`, unreviewed entries keep the pass and show on the verdict line (`VERDICT=PASS (2 allowed entries not yet reviewed by a person)`). With `REQUIRE_REVIEW=1` they fail `r-allow`. Use `1` for real reviews.

## What else it checks

- **Unused entries.** An entry that covers no classical line in the fixed tree would hide lines when the same list is run against another tree, such as the original. It fails `r-allow` under `REQUIRE_REVIEW=1`. Delete it.
- **Write paths.** An allowed line, or one of the three lines below it in the same function, that creates a key, a signature or ciphertext goes to "needs review" with its location.
- **Removed files.** An entry for a file the fix deleted counts as unused when it covers classical lines in the original.

## Keep it with a person

Whoever writes the code should not also approve its allowlist. In CI, read the list from the base commit, so a pull request cannot add an entry and its review fields together, and require a security owner for the file with CODEOWNERS. The examples in [ci.md](ci.md) do both. The full rules are in [DESIGN.md](../DESIGN.md#allow-rules).
