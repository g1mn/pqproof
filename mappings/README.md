# Standards mappings

Each file maps the items of one public document to what PQ-Proof checks. A mapping says how the tool addresses an item. It does not say that a product meets the document, and no publisher has reviewed it.

| File | Document | Items |
|---|---|---|
| `nist-ir8547.json` | NIST IR 8547, Transition to Post-Quantum Cryptography Standards (final, October 2026) | 7 |
| `kr-pqc-pilot-2026.json` | 2026 Korean PQC pilot migration call (Ministry of Science and ICT and KISA, 2026-01-30) | 5 |
| `nist-sp800-227.json` | NIST SP 800-227, Recommendations for Key-Encapsulation Mechanisms (final, September 2025) | 7 |
| `nsa-cnsa2-faq.json` | NSA CNSA 2.0 and Quantum Computing FAQ (Ver. 2.2, October 2026), for `PROFILE=cnsa2` | 6 |
| `us-quantum-readiness-2023.json` | CISA, NSA and NIST factsheet Quantum-Readiness: Migration to Post-Quantum Cryptography (August 2023) | 4 |
| `uk-ncsc-pqc-timelines.json` | UK NCSC, Timelines for migration to post-quantum cryptography (March 2025) | 7 |
| `eu-pqc-roadmap-2025.json` | EU coordinated implementation roadmap for the transition to PQC (NIS Cooperation Group, June 2025) | 6 |
| `nis-pqc-guidebook-draft-2026.json` | NIS and NSR, PQC migration guidebook for national and public institutions (draft, posted 2026-11-16) | 17 |
| `nis-crypto-criteria-draft-2026.json` | NIS and NSR, cryptographic security guideline for national and public institutions (draft, posted 2026-11-16) | 5 |
| `nis-pqc-candidates-2026.json` | NIS notice of PQC candidates for cryptographic module validation (2026-09-01) | 2 |
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

`id`, `ref` (where it is in the source: `section`, `table`, `page`, `note`), `quote` (a short quote in the source language, or `null` for a table or a list), `about_en` and `about_ko` (the item in a sentence), `status`, `note_en` and `note_ko` (how PQ-Proof addresses it), `evidence` (files and the names in them that do it; the test fails if a name is missing) and `remaining_en` and `remaining_ko`.

## When a document comes out

For the KISA guide, once it is published:

1. Record the source in `source`: title, edition, publisher, date, URL. Keep the SHA-256 of the file you read.
2. `python3 -I tools/mapping_draft.py extract guide.pdf > guide.txt` prints the text with page markers. Pick the items a migration check can speak to and write them to a TSV with the columns `id`, `page`, `section`, `quote` (short and verbatim), `about_ko`, `about_en`.
3. `python3 -I tools/mapping_draft.py draft items.tsv --into mappings/kisa-pqc-guide.json > draft.json` turns each row into an item with the status `todo` and lists existing items on the same topic, with their status and evidence, under `_suggest`. A draft never passes the tests.
4. For each item, decide the status, write `note_*` and `remaining_*` in both languages, cite the evidence (files and the names in them) and delete `_suggest`. Then set `published` to `true` and update `checked`.
5. Run `python3 -I tests/test_mappings.py` and `bash prove.sh --unit`.
6. Gaps that PQ-Proof can close become issues; a release that closes them says so in `CHANGELOG.md`, with its verdict impact.

Do not add items before the document is out. A new document gets a new file with its own `id`.

Quotes stay short and name their source. They are not covered by the MIT license of the code.
