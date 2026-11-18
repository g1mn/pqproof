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
> 소개, 공개 예제로 한 검증 결과, KISA AI 보안 매뉴얼 대응표는 사이트에 있습니다. 참가자가 만든 도구이며 과학기술정보통신부·KISA가 검토하거나 보증하지 않았습니다.

---

## Quick start

```bash
pip install pqproof                   # or from source: pip install git+https://github.com/g1mn/pqproof
pqproof <original> <converted>        # 0 pass · 1 fail · 3 undecided
pqproof --verify <output folder>      # recompute the evidence hash and every file hash
```

Rules, outputs and limits: [DESIGN.md](https://github.com/g1mn/pqproof/blob/main/DESIGN.md) · What changed: [CHANGELOG.md](https://github.com/g1mn/pqproof/blob/main/CHANGELOG.md) · Reporting a problem: [SECURITY.md](https://github.com/g1mn/pqproof/blob/main/SECURITY.md)

## Related

[PQ-Proof Agent](https://github.com/g1mn/pq-proof) (`g1mn/pq-proof`, a Vultr Agent Rush entry) is the AI agent that does the migration; this repository is the offline check. [pq-verify](https://pypi.org/project/pq-verify/) tests PQC implementations, and PQ-Proof checks that a codebase finished moving to them, so the two complement each other.

## License

MIT © 2026 [g1mn](https://github.com/g1mn)

Quotes from the AI Security Threat Mitigation Manual (Ministry of Science and ICT and KISA) in the site and its data are not covered by MIT; they follow KOGL Type 4 (attribution, non-commercial, no derivatives). Fonts embedded in docs/index.html are under the SIL Open Font License 1.1, whose text is in the page.
