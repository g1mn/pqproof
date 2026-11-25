<p align="center">
  <a href="https://g1mn.github.io/pqproof/?lang=en">
    <img src="https://raw.githubusercontent.com/g1mn/pqproof/main/assets/hero-readme.svg" alt="PQ-Proof" width="100%">
  </a>
</p>

<p align="center"><b>English</b> · <a href="https://github.com/g1mn/pqproof/blob/main/README.ko.md">한국어</a></p>

<p align="center">
  <a href="https://github.com/g1mn/pqproof/actions/workflows/ci.yml"><img src="https://github.com/g1mn/pqproof/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/g1mn/pqproof/releases"><img src="https://img.shields.io/github/v/release/g1mn/pqproof?color=blue&label=release" alt="Release"></a>
  <a href="https://pypi.org/project/pqproof/"><img src="https://img.shields.io/pypi/v/pqproof?color=blue&label=pypi" alt="PyPI"></a>
  <a href="https://github.com/g1mn/pqproof/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/g1mn/pqproof"><img src="https://api.scorecard.dev/projects/github.com/g1mn/pqproof/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://www.bestpractices.dev/projects/16982"><img src="https://www.bestpractices.dev/projects/16982/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://g1mn.github.io/pqproof/?lang=en"><img src="https://img.shields.io/badge/site-g1mn.github.io%2Fpqproof-brightgreen" alt="Site"></a>
</p>

<p align="center">
  <b>Checks that a post-quantum migration is finished, offline, and leaves evidence anyone can recompute.</b><br>
  The same rules judge the code before and after, with no AI model in the verdict. It also matches KpqC implementations against pinned reference KATs without running them.
</p>

---

### [Everything is on the site: g1mn.github.io/pqproof](https://g1mn.github.io/pqproof/?lang=en)
> Usage, what it judges, public test results, the KpqC implementation check, PQC standards mappings (NIST IR 8547, the Korean pilot call, and the KISA guide once published), the KISA AI security manual mapping, limits and release notes, in English and Korean. Built by a contest participant; the Ministry of Science and ICT and KISA have not reviewed or endorsed it.

---

## Quick start

```bash
pip install pqproof
pqproof doctor                       # what it found and what is missing
ex=$(pqproof examples)               # the bundled before and after trees
pqproof "$ex/classic" "$ex/pqc"       # try it: RSA and ECDSA moved to ML-KEM-768 and ML-DSA-65, a pass
pqproof <original> <converted>       # judge your two trees, write the evidence folder
pqproof --verify <output folder>     # recompute the evidence hash and every file hash
FAIL_ON_REVIEW=1 pqproof impl judge answers.json   # KpqC implementation check
```

Guides: [Quick start](https://github.com/g1mn/pqproof/blob/main/guide/quickstart.md) · [Configuration](https://github.com/g1mn/pqproof/blob/main/guide/configuration.md) · [Allowlist](https://github.com/g1mn/pqproof/blob/main/guide/allowlist.md) · [Outputs](https://github.com/g1mn/pqproof/blob/main/guide/outputs.md) · [CI](https://github.com/g1mn/pqproof/blob/main/guide/ci.md) · [Implementation check](https://github.com/g1mn/pqproof/blob/main/guide/impl.md) · [Design](https://github.com/g1mn/pqproof/blob/main/DESIGN.md) · [History](https://github.com/g1mn/pqproof/blob/main/HISTORY.md) · [Changelog](https://github.com/g1mn/pqproof/blob/main/CHANGELOG.md) · [Contributing](https://github.com/g1mn/pqproof/blob/main/CONTRIBUTING.md) · [Roadmap](https://github.com/g1mn/pqproof/blob/main/ROADMAP.md) · [Standards mappings](https://github.com/g1mn/pqproof/tree/main/mappings) · [Security](https://github.com/g1mn/pqproof/blob/main/SECURITY.md)

<p align="center"><img src="https://raw.githubusercontent.com/g1mn/pqproof/main/assets/demo.svg" alt="pqproof judging the bundled before and after trees, then re-checking the evidence" width="100%"></p>

## Contributing

Issues, pull requests and mapping corrections are welcome; start from [good first issues](https://github.com/g1mn/pqproof/contribute). PQC migration experience is enough for a mapping correction, and English is fine everywhere.

Read [CONTRIBUTING.md](https://github.com/g1mn/pqproof/blob/main/CONTRIBUTING.md) for local checks and the [Code of Conduct](https://github.com/g1mn/pqproof/blob/main/CODE_OF_CONDUCT.md). How the project is run is in [GOVERNANCE.md](https://github.com/g1mn/pqproof/blob/main/GOVERNANCE.md), and the security reasoning in [ASSURANCE.md](https://github.com/g1mn/pqproof/blob/main/ASSURANCE.md).

## Related

[PQ-Proof Agent](https://github.com/g1mn/pq-proof) (`g1mn/pq-proof`, a Vultr Agent Rush entry) is the AI agent that does the migration; this repository is the offline check. [pq-verify](https://pypi.org/project/pq-verify/) audits NIST PQC libraries, and `pqproof impl judge --pq-verify` puts that audit into the same evidence.

## License

MIT © 2026 [g1mn](https://github.com/g1mn)

Quotes from the AI Security Threat Mitigation Manual (Ministry of Science and ICT and KISA) on the site and in its data are not covered by MIT; they follow KOGL Type 4 (attribution, non-commercial, no derivatives). Short quotes from public documents in `mappings/` are not covered by MIT either; each file names its source. Fonts embedded in docs/index.html are under the SIL Open Font License 1.1, and the page includes the license text.
