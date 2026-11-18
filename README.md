<p align="center">
  <a href="https://g1mn.github.io/pqproof/">
    <img src="https://raw.githubusercontent.com/g1mn/pqproof/main/assets/hero-readme.svg" alt="PQ-Proof" width="100%">
  </a>
</p>

<p align="center">
  <a href="https://github.com/g1mn/pqproof/actions/workflows/ci.yml"><img src="https://github.com/g1mn/pqproof/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/g1mn/pqproof/releases"><img src="https://img.shields.io/github/v/release/g1mn/pqproof?color=blue&label=release" alt="Release"></a>
  <a href="https://pypi.org/project/pqproof/"><img src="https://img.shields.io/pypi/v/pqproof?color=blue" alt="PyPI"></a>
  <a href="https://github.com/g1mn/pqproof/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://g1mn.github.io/pqproof/"><img src="https://img.shields.io/badge/site-g1mn.github.io%2Fpqproof-brightgreen" alt="Site"></a>
</p>

<p align="center">
  <b>Checks that a post-quantum migration is finished, offline, and leaves evidence anyone can recompute.</b><br>
  Give it the code before and after. The same rules judge both, with no AI model in the verdict.
</p>

---

### [Overview, verification results and the KISA mapping: g1mn.github.io/pqproof](https://g1mn.github.io/pqproof/)
> 소개, 공개 예제로 돌린 검증 결과, KISA AI 보안 매뉴얼 대응표는 사이트에 있습니다. 참가자가 만든 도구이며 과학기술정보통신부·KISA가 검토하거나 보증하지 않았습니다.

---

## Quick start

```bash
pip install pqproof                   # or from source: pip install git+https://github.com/g1mn/pqproof
pqproof doctor                        # external programs found and missing (bash, OpenSSL, keytool, tls_probe)
ex=$(python3 -c 'import os, pqproof; print(os.path.join(os.path.dirname(pqproof.__file__), "_tool", "examples"))')
pqproof "$ex/classic" "$ex/pqc"       # bundled example: RSA and ECDSA moved to ML-KEM-768 and ML-DSA-65, passes
pqproof <original> <converted>        # your two trees
pqproof --verify <output folder>      # recompute the evidence hash and every file hash
```

The run writes `proof-out-YYYYMMDD-HHMMSS/`. Open `receipt.html` (for people) or `receipt.json` (for programs); `tables/report.md` is ready to paste into a document. When the run fails, the console ends with where the full lists are and what to do next. A line that has to stay classical goes into an allowlist with its reason, and a person signs it off ([guide/allowlist.md](https://github.com/g1mn/pqproof/blob/main/guide/allowlist.md)).

| Exit code | Meaning |
|---|---|
| 0 | pass: no check failed or stayed undecided |
| 1 | fail |
| 2 | usage or input error (no verdict) |
| 3 | undecided, for example a TLS server with no address to measure; never counted as a pass |

| System | Judge two trees | `--verify`, `sarif` |
|---|---|---|
| Linux, macOS | yes (bash, OpenSSL; 3.5 or later for the TLS cross-check) | yes |
| Windows | in WSL | yes, Python alone |

## In CI

The GitHub Action judges a pull request against its base commit and uploads SARIF to code scanning; [examples/github-actions/](https://github.com/g1mn/pqproof/blob/main/examples/github-actions/pqproof-sarif.yml) reads the allowlist from the base commit so an author cannot approve their own entries. GitLab, Jenkins and SonarQube examples are in [guide/ci.md](https://github.com/g1mn/pqproof/blob/main/guide/ci.md). Release assets carry build provenance: `gh attestation verify <file> --repo g1mn/pqproof`.

## Words

| Word | Meaning |
|---|---|
| PQ-Proof, `pqproof` | the tool; the Python package and its command |
| original, converted (fixed) | the tree before and after the migration |
| check, verdict | eight checks (`a-cbom`, `c-classic`, `b-weakening` ...) and the one verdict they give |
| blocking location | a quantum-breakable public-key use in the converted tree with no recorded reason |
| allowlist | the classical lines a migration keeps on purpose, each with a reason and a reviewer |
| evidence (검증 증적), evidence hash | the output folder, and `receipt_id`, the SHA-256 of `receipt.json` in RFC 8785 form |
| ruleset | the rule files (`pqlite/version.py`); their hash is in every receipt |

## Documentation

[Quick start](https://github.com/g1mn/pqproof/blob/main/guide/quickstart.md) · [Configuration](https://github.com/g1mn/pqproof/blob/main/guide/configuration.md) · [Allowlist](https://github.com/g1mn/pqproof/blob/main/guide/allowlist.md) · [Outputs](https://github.com/g1mn/pqproof/blob/main/guide/outputs.md) · [CI](https://github.com/g1mn/pqproof/blob/main/guide/ci.md) · [Rules and evidence format (DESIGN.md)](https://github.com/g1mn/pqproof/blob/main/DESIGN.md) · [History](https://github.com/g1mn/pqproof/blob/main/HISTORY.md) · [Changelog](https://github.com/g1mn/pqproof/blob/main/CHANGELOG.md) · [Contributing](https://github.com/g1mn/pqproof/blob/main/CONTRIBUTING.md) · [Security](https://github.com/g1mn/pqproof/blob/main/SECURITY.md)

## Related

[PQ-Proof Agent](https://github.com/g1mn/pq-proof) (`g1mn/pq-proof`, a Vultr Agent Rush entry) is the AI agent that does the migration; this repository is the offline check. [pq-verify](https://pypi.org/project/pq-verify/) tests PQC implementations, and PQ-Proof checks that a codebase finished moving to them, so the two complement each other.

## License

MIT © 2026 [g1mn](https://github.com/g1mn)

Quotes from the AI Security Threat Mitigation Manual (Ministry of Science and ICT and KISA) on the site and in its data are not covered by MIT; they follow KOGL Type 4 (attribution, non-commercial, no derivatives). Fonts embedded in docs/index.html are under the SIL Open Font License 1.1, and the page includes the license text.
