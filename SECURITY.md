# Security policy

## Supported versions

Only the latest MINOR release gets fixes. While PQ-Proof is 0.x, that means the newest 0.N line. A release that can change verdicts says so under "Verdict impact" in [CHANGELOG.md](CHANGELOG.md).

## Reporting a vulnerability

Please report privately through GitHub: open [Report a vulnerability](https://github.com/g1mn/pqproof/security/advisories/new) on this repository (Security tab, then "Report a vulnerability"). Do not open a public issue for it. This is a one-person project, so replies are best effort. I aim to answer within a week.

Helpful things to include: the PQ-Proof version (`pqproof --version`), the two trees or a small tree that shows the problem, the command and environment variables you used, and the evidence folder the run wrote.

## What counts

PQ-Proof judges a migration and writes evidence that others may rely on. These are security problems for this project:

- a tree that still uses classical public-key code in a way the documented rules cover, and gets a pass;
- a weakened TLS setting covered by the `b-weakening` rules that is not caught;
- an evidence folder that someone changed and that `--verify` still accepts, apart from the documented limit that anyone can rewrite every file and hash at once;
- an input tree or zip that makes PQ-Proof run code from it, write outside the output folder, or read files outside the inputs;
- a SARIF file or GitHub Action output that reports pass when the run did not pass.

Known limits listed in [DESIGN.md](DESIGN.md#limits), for example policy values in JSON or YAML and TLS settings outside the given tree, are not vulnerabilities by themselves. A report that shows one of them hiding a real classical key in practice is still welcome.
