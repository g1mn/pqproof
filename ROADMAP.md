# Roadmap

No dates. This is what comes next and why. Issues labelled `good first issue` are the easiest way in.

## 0.4.0

- SLH-DSA (FIPS 205): the 192 and 256 parameter sets count as an expected signature, and SLH-DSA 128 is blocked as below category 3 (ruleset 4).
- Standards mappings in [`mappings/`](mappings/): NIST IR 8547 and the 2026 Korean PQC pilot migration call, item by item, with the code that does each check.
- A first-contribution section in CONTRIBUTING.md and this roadmap.

## When the KISA PQC migration guide is published

KISA's plan to publish a PQC migration guide in 2026 was [reported in January 2026](https://byline.network/2026/01/28-578/). It is not out yet, so nothing here assumes what it will say. When it is published:

1. `mappings/kisa-pqc-guide.json` gets one item per guide item, quoting the published text, each marked covered, partial or gap.
2. A release closes the gaps PQ-Proof can close and the site shows the table.

## Next

- KpqC reference KATs: add new versions to `scan/kat-kpqc.json` when a KS standard or a new reference release comes out.
- A PQC-only profile that does not count a hybrid result as finished (NIST IR 8547, section 3.2).
- An agility signal: algorithm names fixed in code against names read from configuration (NIST IR 8547, section 1.1).
- More mappings, for example NIST SP 800-227.
- FIPS 206 (FN-DSA) and FIPS 207 (HQC) once NIST publishes them.

## Not planned

- Claims that a product meets a standard. A verdict says what PQ-Proof found in two trees.
- Running the code under test. PQ-Proof reads source and answers; it does not build or execute them (DESIGN.md).
