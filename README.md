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
  The same rules judge the code before and after, with no AI model in the verdict. It also matches KpqC implementations against pinned reference KATs without running them.
</p>

---

### [Everything is on the site: g1mn.github.io/pqproof](https://g1mn.github.io/pqproof/)
> Usage, what it judges, public test results, the KpqC implementation check, PQC standards mappings (NIST IR 8547, the Korean pilot call, and the KISA guide once published), the KISA AI security manual mapping, limits and release notes, in English and Korean. Built by a contest participant; the Ministry of Science and ICT and KISA have not reviewed or endorsed it.

---

## Quick start

```bash
pip install pqproof
pqproof doctor                       # what it found and what is missing
pqproof <original> <converted>       # judge the two trees, write the evidence folder
pqproof --verify <output folder>     # recompute the evidence hash and every file hash
FAIL_ON_REVIEW=1 pqproof impl judge answers.json   # KpqC implementation check
```

Guides: [Quick start](https://github.com/g1mn/pqproof/blob/main/guide/quickstart.md) · [Configuration](https://github.com/g1mn/pqproof/blob/main/guide/configuration.md) · [Allowlist](https://github.com/g1mn/pqproof/blob/main/guide/allowlist.md) · [Outputs](https://github.com/g1mn/pqproof/blob/main/guide/outputs.md) · [CI](https://github.com/g1mn/pqproof/blob/main/guide/ci.md) · [Implementation check](https://github.com/g1mn/pqproof/blob/main/guide/impl.md) · [Design](https://github.com/g1mn/pqproof/blob/main/DESIGN.md) · [History](https://github.com/g1mn/pqproof/blob/main/HISTORY.md) · [Changelog](https://github.com/g1mn/pqproof/blob/main/CHANGELOG.md) · [Contributing](https://github.com/g1mn/pqproof/blob/main/CONTRIBUTING.md) · [Roadmap](https://github.com/g1mn/pqproof/blob/main/ROADMAP.md) · [Standards mappings](https://github.com/g1mn/pqproof/tree/main/mappings) · [Security](https://github.com/g1mn/pqproof/blob/main/SECURITY.md)

## Related

[PQ-Proof Agent](https://github.com/g1mn/pq-proof) (`g1mn/pq-proof`, a Vultr Agent Rush entry) is the AI agent that does the migration; this repository is the offline check. [pq-verify](https://pypi.org/project/pq-verify/) audits NIST PQC libraries, and `pqproof impl judge --pq-verify` puts that audit into the same evidence.

## License

MIT © 2026 [g1mn](https://github.com/g1mn)

Quotes from the AI Security Threat Mitigation Manual (Ministry of Science and ICT and KISA) on the site and in its data are not covered by MIT; they follow KOGL Type 4 (attribution, non-commercial, no derivatives). Short quotes from public documents in `mappings/` are not covered by MIT either; each file names its source. Fonts embedded in docs/index.html are under the SIL Open Font License 1.1, and the page includes the license text.
