# Standards mappings

Each file maps the items of one public document to what PQ-Proof checks. A mapping says how the tool addresses an item. It does not say that a product meets the document, and no publisher has reviewed it.

| File | Document | Items |
|---|---|---|
| `nist-ir8547.json` | NIST IR 8547, Transition to Post-Quantum Cryptography Standards (final, October 2026) | 7 |
| `kr-pqc-pilot-2026.json` | 2026 Korean PQC pilot migration call (Ministry of Science and ICT and KISA, 2026-01-30) | 5 |
| `kisa-pqc-guide.json` | KISA PQC migration guide, not published yet | 0 |

The site shows them as tables. `tests/test_mappings.py` checks every file.

## Status

| Status | Meaning |
|---|---|
| `covered` | PQ-Proof checks the item within the scope the note gives. |
| `partial` | PQ-Proof checks part of it; `remaining_en` says what is left. |
| `gap` | PQ-Proof does not check it; `remaining_en` says so. |
| `na` | The item does not apply to a migration check. |

## Item fields

`id`, `ref` (section and page in the source), `quote` (a short quote in the source language, or `null` for a table or a list), `about_en` and `about_ko` (the item in a sentence), `status`, `note_en` and `note_ko` (how PQ-Proof addresses it), `evidence` (files and the names in them that do it; the test fails if a name is missing) and `remaining_en` and `remaining_ko`.

## When a document comes out

For the KISA guide, once it is published:

1. Set `published` to `true`, fill `source` (title, edition, URL) and add one item per guide item, quoting only the published text.
2. Run `python3 -I tests/test_mappings.py`.
3. Gaps that PQ-Proof can close become issues; a release that closes them says so in `CHANGELOG.md`.

Do not add items before the document is out. A new document gets a new file with its own `id`.

Quotes stay short and name their source. They are not covered by the MIT license of the code.
