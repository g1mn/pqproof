# Roadmap

This covers the work planned through the end of 2027 and what is not planned. Items have no fixed dates. Released items stay here for context; [CHANGELOG.md](CHANGELOG.md) has the details. Issues labelled `good first issue` are the easiest way in.

## 0.4.0 (released)

- SLH-DSA (FIPS 205): the 192 and 256 parameter sets count as an expected signature, and SLH-DSA 128 is blocked as below category 3 (ruleset 4).
- Standards mappings in [`mappings/`](mappings/): NIST IR 8547 and the 2026 Korean PQC pilot migration call, item by item, with the code that does each check.
- A first-contribution section in CONTRIBUTING.md and this roadmap.

## 0.6.0 (released)

The four gaps in the NIS and NSR draft mappings (posted 2026-11-16) that a migration check can close:

- A 112-bit key floor: a classical key whose stated size is below 112-bit security is never allowed (draft guideline S1).
- PQ/PQ hybrid lines are marked in the inventory (draft guideline S2).
- Allowlist entries can record residual risk, compensating control and replacement plan (draft guidebook G9).
- The TLS report adds the cipher suite and the certificate expiry (draft guidebook G7).

## 0.7.0 (released)

- The inventory is also written as a CycloneDX 1.6 CBOM (EU PQC roadmap, section 6.2), validated in CI against the official schema.
- First-run and CI fixes from a new-user review: `pqproof examples`, English reading notes in the evidence, input errors, and CI examples that keep the base tree outside the converted tree.

## 0.8.0

- TLS targets are verified by default (OpenSSF Best Practices silver, `crypto_certificate_verification`): a target without a CA is checked against the system trust store and its host name, and trust on first use needs an explicit `#tofu`. A certificate that does not verify leaves `b-tls` undecided instead of passing.
- The tool checks that the `tls_probe` binary on disk is the version it needs (0.6.0) before a TLS run, and `pqproof doctor` warns about an old one left in the cache or `PROBE_BIN_DIR`.

## 0.9.0

- KCDSA and EC-KCDSA, the Korean discrete-log signatures, are caught by name and OID in the residue count (`G-DH-DSA`, ruleset 9) and by name in the inventory, the Java name classifier and the CBOM export. They were missed before: `G-DH-DSA` counted DSA only as a quoted literal, and the inventory's `dsa` pattern needs a word boundary.

## 0.10.0

- On macOS a TLS target without a CA file is verified by Go's own verifier against Apple's system roots (`tls_probe` 0.7.0, ruleset 10), the same way as on Linux: the operating system no longer fills in a missing intermediate or trusts keychain roots, so the same target gets the same answer on every Mac.

## When the KISA PQC migration guide is published

KISA's plan to publish a PQC migration guide in 2026 was [reported in January 2026](https://byline.network/2026/01/28-578/). It is not out yet, so nothing here assumes what it will say. The draft PQC migration guidebook for national and public institutions from NIS and NSR (posted 2026-11-16) is already mapped, and that table follows its final version. When it is published:

1. `mappings/kisa-pqc-guide.json` gets one item per guide item, quoting the published text, each marked covered, partial or gap. `tools/mapping_draft.py` turns the published PDF into reviewable stubs; `mappings/README.md` has the steps.
2. A release closes the gaps PQ-Proof can close and the site shows the table.

## Next

- KpqC reference KATs: add new versions to `scan/kat-kpqc.json` when a KS standard or a new reference release comes out.
- A PQC-only profile that does not count a hybrid result as finished (NIST IR 8547, section 3.2).
- An agility signal: algorithm names fixed in code against names read from configuration (NIST IR 8547, section 1.1).
- LMS and XMSS (NIST SP 800-208) as expected firmware signatures under the cnsa2 profile (CNSA 2.0 FAQ).
- More mappings as public documents come out, the KISA guide first.
- FIPS 206 (FN-DSA) and FIPS 207 (HQC) once NIST publishes them.

## Not planned

- Claims that a product meets a standard. A verdict says what PQ-Proof found in two trees.
- Running the code under test. PQ-Proof reads source and answers; it does not build or execute them (DESIGN.md).
