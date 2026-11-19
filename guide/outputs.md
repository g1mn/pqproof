# Outputs

Each run writes a new folder: `OUT=...`, or `./proof-out-YYYYMMDD-HHMMSS` (with `-2`, `-3` when two runs start in the same second; under `<W>/evidence` when the original is `<W>/orig`). A folder given in `OUT` that already exists stops the run.

## Open first

| File | For |
|---|---|
| `receipt.html` | people: the whole evidence on one self-contained page, dark and light theme |
| `receipt.json` | programs: the verification evidence ([schema](../schemas/receipt-v4.schema.json), format 4 from 0.3.0) |
| `tables/report.md` | a document: the check table, the blocking locations after a failure, and what is left after the migration |
| `README.txt` | the folder itself: the verdict, what to open first, the re-check command and what to look at before sharing (from 0.2.0) |

## Everything else

- `deck.json`: a short summary for slides or a dashboard. `evidence-fragment.json`: the main numbers in a flat form for another record.
- `tables/cbom-orig.csv`, `tables/cbom-fixed.csv`: the CBOM of both trees, one row per location, with its verdict and reason. `tables/fragment.html`: the report as an HTML fragment.
- `tables/summary.csv` (the checks), `tables/java.csv` and `tables/java-usage.csv` (classical lines per rule and per location), `tables/tls.csv` (TLS results).
- `artifacts/`: raw scanner output, the copies of `residue.sh` and `scan/test-paths.ere` that ran, TLS probe transcripts, the weakening result, the list of changed files and a copy of the allowlist.
- `in/`: zip inputs, unpacked.
- An implementation check (`pqproof impl judge`, folder `impl-out-YYYYMMDD-HHMMSS`) writes the same `receipt.*`, `deck.json`, `README.txt`, `tables/report.md` and `tables/summary.csv`, plus `tables/impl.csv` (one row per parameter set and version) and `artifacts/impl/` (the answer, the answer key, the question sheet, and the pq-verify report and run record when `--pq-verify` ran). See [impl.md](impl.md).

Re-check with `pqproof --verify <folder>`. It fails on any file that is not listed, and on a changed `README.txt`, so keep notes outside the folder.

## Before you share it

- Absolute paths on your machine: the input folders, the tools and the output folder in `receipt.json` and `receipt.html`, and the scanned folder and command line at the top of each CBOM report.
- For a zip input, `in/` holds the whole unpacked source.
- The scanner output under `artifacts/` quotes source lines as they are. The excerpts the tool writes itself (`tables/cbom-*.csv` notes, `tables/report.md`, SARIF snippets) and, from 0.2.0, the excerpts in the CBOM reports under `artifacts/cbom-*/` replace values that look like secrets with `***`: after `-storepass`, `-keypass`, `pass:`, `password=`, `token=` and similar names, after `Bearer`, and strings with known token prefixes. The console says how many.

## Evidence hash

`receipt_id` is the SHA-256 of `receipt.json` without that field, in RFC 8785 canonical form. Each run gets its own value, because the evidence records when and where it ran; the verdict and the checks come out the same for the same inputs. A hash shows that the files are the ones the evidence describes, not who made them: compare `receipt_id` with a value from a place you trust, such as the console output of the run. [DESIGN.md](../DESIGN.md#verification-evidence-and-the-evidence-hash) has the exact rules.

## Machine-readable contract

`schemas/receipt-v4.schema.json` (JSON Schema draft 2020-12) describes evidence format 4 (0.3.0 and later; two-tree and one-tree receipts keep the fields of format 3, and an implementation check adds `params.mode` `impl` and the `impl` field), `schemas/receipt-v3.schema.json` format 3 (0.2.x), `schemas/receipt-v2.schema.json` format 2 (0.1.x), and `schemas/unconverted.schema.json` the allowlist. Within one `format_version` these fields keep their name, type and meaning:

- `format_version`, `tool_version`, `ruleset_version`, `ruleset_sha256`, `receipt_id`, `verdict`
- `checks[].id`, `checks[].status` (the values the schema lists; only `pass` counts as passed)
- `inputs.*.tree_sha256`, `inputs.*.zip_sha256`, `artifacts[].path`, `artifacts[].sha256`
- the counts under `cbom`, `java` and `allowlist`
- the exit codes (0 pass, 1 fail, 2 usage or input error, 3 undecided, 4 tool error, 5 pass that needs review under `FAIL_ON_REVIEW=1`) and the Action outputs (`verdict`, `evidence-hash`, `exit-code`, `output-dir`, `sarif-file`, `review-checks`)

Text meant for people (`checks[].title`, `expected`, `actual`, `note`, warnings, the Korean words in tables) can change in any release. Do not parse it. `format` is the fixed string `pqc-proof receipt 1` from the first public copy; read `format_version`. The schema is closed, so adding, removing or renaming a field, or changing its type or meaning, raises `format_version`, and `--verify` keeps reading the older formats.
